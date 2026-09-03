//! Integration tests for the `HandlerBackend` surface of [`BastionServer`],
//! against the shared dataset in `crate::database::fixture`.
//!
//! The two methods under test here are the ones with real logic in them:
//! `enforce` and `list_targets_for_user`. Both sit on top of
//! `crate::server::casbin::RoleManage` and answer their question by walking
//! the three rule graphs, so the interesting cases are about the *shape* of the
//! fixture's role, object and action trees rather than about any single row.
//! The trees are drawn in the fixture's module header; the policy indices used
//! throughout (`f.policy(3)` and so on) are the ones listed there.
//!
//! What the tests lean on, in both methods:
//!
//! * A Subject, object or action matches by walking **down** from the policy's group, so
//!   a policy naming a group covers everything under it.
//! * Policies are read from the database on every call, but the graphs are a
//!   cached snapshot. Editing a `p` row therefore takes effect immediately,
//!   while editing a `g1`/`g2`/`g3` row needs `load_role_manager`. Several tests
//!   assert exactly that split, because it is the easiest thing to get wrong
//!   when adding a cache.
#[cfg(test)]
mod tests {
    use crate::config::Config;
    use crate::database::common::{
        ACT_DIRECT_TCPIP, ACT_EXEC, ACT_LOGIN, ACT_PTY, ACT_SHELL, OBJ_ADMIN, OBJ_LOGIN, OBJ_PLAYER,
    };
    use crate::database::entity::{casbin_name, casbin_rule, secret, target, target_secret};
    use crate::database::fixture::{self, *};
    use crate::database::models::{GroupType, Ptype};
    use crate::database::{DatabaseRepository, Uuid};
    use crate::server::extend_policy::ExtendPolicyReq;
    use crate::server::{BastionServer, HandlerBackend};
    use chrono::{DateTime, Utc};
    use sea_orm::ActiveValue::{Set, Unchanged};
    use std::collections::{HashMap, HashSet};
    use std::net::IpAddr;
    use std::sync::LazyLock;
    use tokio::sync::Mutex;

    /// Serializes the first `BastionServer::with_config` in the process.
    ///
    /// `with_config` initializes the `InternalUuids` global behind an
    /// `is_initialized()` check, and `InternalUuids::init` panics if it is
    /// already set. That check-then-set is not atomic, so two tests building a
    /// server at once can both see `false` and the loser panics. Tests here run
    /// on one binary and in parallel, so they take this lock across the call.
    ///
    /// It also means the global holds whichever fixture won the race, and every
    /// fixture generates fresh uuids. So nothing below reads
    /// `InternalUuids::get()` — internal ids come from `f.name(ACT_SHELL)`,
    /// which is this database's.
    static SERVER_INIT: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    /// A seeded database and a server reading it.
    ///
    /// Writes in a test go through `server.db_repository()` rather than
    /// `db.repo()`: both point at the same SQLite file but hold their own pool,
    /// and one writer is one less way for a test to meet `database is locked`.
    struct Env {
        db: fixture::TestDb,
        server: BastionServer,
    }

    impl Env {
        async fn new() -> Self {
            let db = fixture::seed().await;
            let mut config = Config::default().gen_secret_token();
            config.database = db.url.clone();

            let _guard = SERVER_INIT.lock().await;
            let server = BastionServer::with_config(config)
                .await
                .expect("build server on the fixture database");
            Self { db, server }
        }

        fn f(&self) -> &Fixture {
            &self.db.fixture
        }

        fn repo(&self) -> &dyn DatabaseRepository {
            self.server.db_repository()
        }

        /// `enforce` with no extended-policy request. Every policy in the
        /// fixture but `p7` carries an empty `v3`, which accepts any request.
        async fn allows(&self, sub: Uuid, obj: Uuid, act: Uuid) -> bool {
            self.server
                .enforce(sub, obj, act, ExtendPolicyReq::default())
                .await
                .expect("enforce")
        }

        async fn allows_with(&self, sub: Uuid, obj: Uuid, act: Uuid, ext: ExtendPolicyReq) -> bool {
            self.server
                .enforce(sub, obj, act, ext)
                .await
                .expect("enforce")
        }

        /// `list_targets_for_user`, active rows only.
        async fn visible(&self, user: &str) -> Vec<crate::database::models::TargetSecretName> {
            self.list(user, true).await
        }

        /// `list_targets_for_user` with `active_only = false`, so deactivated
        /// hosts, secrets and bindings come back too.
        async fn visible_all(&self, user: &str) -> Vec<crate::database::models::TargetSecretName> {
            self.list(user, false).await
        }

        async fn list(
            &self,
            user: &str,
            active_only: bool,
        ) -> Vec<crate::database::models::TargetSecretName> {
            self.server
                .list_targets_for_user(&self.f().user(user), active_only)
                .await
                .expect("list targets")
        }

        /// Insert a `p` rule and hand back its id.
        ///
        /// No `load_role_manager` afterwards on purpose: policies are read per
        /// call, so a new one is live immediately as long as the ids it names are
        /// already in the graphs.
        async fn add_policy(&self, v0: Uuid, v1: Uuid, v2: Uuid, ext: &str) -> Uuid {
            self.repo()
                .create_casbin_rule(casbin_rule::ActiveModel {
                    id: Set(Uuid::now_v7()),
                    ptype: Set(Ptype::Policy),
                    v0: Set(v0),
                    v1: Set(v1),
                    v2: Set(v2),
                    v3: Set(ext.to_string()),
                    v4: Set(String::new()),
                    v5: Set(String::new()),
                    updated_by: Set(self.f().admin_id),
                    ..Default::default()
                })
                .await
                .expect("insert policy")
                .id
        }

        /// Insert a group membership row.
        ///
        /// Takes the columns in storage order rather than as `(parent, child)`,
        /// because the two hierarchies disagree about which side is which: `g1`
        /// puts the containing role in `v0`, `g2`/`g3` put the member there.
        /// Callers must `reload` afterwards — the graphs are a cached snapshot.
        async fn add_group_rule(&self, ptype: Ptype, v0: Uuid, v1: Uuid) {
            self.repo()
                .create_casbin_rule(casbin_rule::ActiveModel {
                    id: Set(Uuid::now_v7()),
                    ptype: Set(ptype),
                    v0: Set(v0),
                    v1: Set(v1),
                    v2: Set(Uuid::default()),
                    v3: Set(String::new()),
                    v4: Set(String::new()),
                    v5: Set(String::new()),
                    updated_by: Set(self.f().admin_id),
                    ..Default::default()
                })
                .await
                .expect("insert group rule");
        }

        async fn reload(&self) {
            self.server
                .load_role_manager()
                .await
                .expect("reload role manager");
        }

        async fn set_target_active(&self, name: &str, active: bool) {
            self.repo()
                .update_target(target::ActiveModel {
                    id: Unchanged(self.f().target(name)),
                    is_active: Set(active),
                    ..Default::default()
                })
                .await
                .expect("update target");
        }

        async fn set_secret_active(&self, name: &str, active: bool) {
            self.repo()
                .update_secret(secret::ActiveModel {
                    id: Unchanged(self.f().secret(name)),
                    is_active: Set(active),
                    ..Default::default()
                })
                .await
                .expect("update secret");
        }

        async fn set_binding_active(&self, host: &str, secret: &'static str, active: bool) {
            self.repo()
                .update_target_secret(target_secret::ActiveModel {
                    id: Unchanged(self.f().binding(host, secret)),
                    is_active: Set(active),
                    ..Default::default()
                })
                .await
                .expect("update binding");
        }

        async fn set_name_active(&self, name: &str, active: bool) {
            self.repo()
                .update_casbin_name(casbin_name::ActiveModel {
                    id: Unchanged(self.f().name(name)),
                    is_active: Set(active),
                    ..Default::default()
                })
                .await
                .expect("update name");
        }
    }

    /// A fixed instant, so an extended-policy assertion cannot drift with the
    /// wall clock. `+08:00` is the offset the fixture's policy is written in.
    fn at(rfc3339: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc3339)
            .expect("valid timestamp")
            .with_timezone(&Utc)
    }

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().expect("valid ip"))
    }

    /// Distinct binding ids in a `list_targets_for_user` result.
    ///
    /// The result is per (policy, binding): one binding reachable under two
    /// policies is returned twice, which is what the method's own NOTE warns
    /// about. Tests that care about reachability count this; tests that care
    /// about the duplication count the raw length.
    fn distinct(rows: &[crate::database::models::TargetSecretName]) -> HashSet<Uuid> {
        rows.iter().map(|r| r.id).collect()
    }

    /// Rows grouped by the policy that produced them.
    fn by_policy(
        rows: &[crate::database::models::TargetSecretName],
    ) -> HashMap<Uuid, Vec<&crate::database::models::TargetSecretName>> {
        let mut out: HashMap<Uuid, Vec<_>> = HashMap::new();
        for r in rows {
            out.entry(r.pid).or_default().push(r);
        }
        out
    }

    // ------------------------------------------------------------------ enforce

    /// `p0` sits on the root role, so every member of the tree inherits login —
    /// and `joe`, who holds no role, inherits nothing.
    ///
    /// This is the grant every other test assumes, and the one case where the
    /// policy's subject is four levels above the user asking.
    #[tokio::test]
    async fn login_is_inherited_from_the_root_role() {
        let env = Env::new().await;
        let (obj, act) = (env.f().name(OBJ_LOGIN), env.f().name(ACT_LOGIN));

        for user in [ADMIN, JOHN, MIKE, LUKA] {
            assert!(
                env.allows(env.f().user(user), obj, act).await,
                "{user} should reach login through r_staff"
            );
        }

        // `joe` is not in `g1` at all, so `match_sub` finds no policy for him.
        // Note this is about roles, not about his `is_active` flag: `enforce`
        // never looks at the subject's row.
        assert!(
            !env.allows(env.f().user(JOE), obj, act).await,
            "joe holds no role and should reach nothing"
        );
    }

    /// Deactivating the `__internal_object_login` name denies login to everyone
    /// at once, without touching a policy.
    ///
    /// `check_object_active` accepts an internal object only while its
    /// `casbin_name` row is active, which makes that row a kill switch. Worth
    /// pinning because it is the only object in the fixture that is neither a
    /// binding nor reachable any other way.
    #[tokio::test]
    async fn deactivating_the_login_object_locks_everyone_out() {
        let env = Env::new().await;
        let (obj, act) = (env.f().name(OBJ_LOGIN), env.f().name(ACT_LOGIN));
        assert!(env.allows(env.f().user(JOHN), obj, act).await);

        env.set_name_active(OBJ_LOGIN, false).await;

        // No reload: object activity is read per call, like the policies.
        assert!(!env.allows(env.f().user(JOHN), obj, act).await);
        assert!(!env.allows(env.f().user(ADMIN), obj, act).await);

        env.set_name_active(OBJ_LOGIN, true).await;
        assert!(env.allows(env.f().user(JOHN), obj, act).await);
    }

    /// An action group covers its own subtree and nothing above it.
    ///
    /// `john` holds `ag_all` on `tg_core` through `p2`, so he gets every action
    /// under the root group. `luka` holds only `ag_interactive` through `p3`, so
    /// he gets shell and pty but not the exec that hangs off the sibling
    /// `ag_batch`.
    #[tokio::test]
    async fn action_groups_grant_downward_only() {
        let env = Env::new().await;
        let john = env.f().user(JOHN);
        let luka = env.f().user(LUKA);
        // A binding both policies reach, so the only difference is the action.
        let mars1 = env.f().binding("mars1", S_MON);

        for act in [ACT_SHELL, ACT_PTY, ACT_EXEC] {
            assert!(
                env.allows(john, mars1, env.f().name(act)).await,
                "ag_all should cover {act}"
            );
        }

        assert!(env.allows(luka, mars1, env.f().name(ACT_SHELL)).await);
        assert!(env.allows(luka, mars1, env.f().name(ACT_PTY)).await);
        assert!(
            !env.allows(luka, mars1, env.f().name(ACT_EXEC)).await,
            "ag_interactive must not reach ag_batch's exec"
        );
    }

    /// An action name that is in `casbin_name` but in no `g3` group is
    /// unreachable, even under the root action group.
    ///
    /// `__internal_action_direct_tcpip` is exactly that in the fixture. The
    /// action arm of `enforce` matches by walking down from the policy's `v2`, so
    /// a name with no edge into the graph can only be granted by a policy naming
    /// it outright.
    #[tokio::test]
    async fn an_action_outside_every_group_is_unreachable() {
        let env = Env::new().await;
        let john = env.f().user(JOHN);
        let mars1 = env.f().binding("mars1", S_MON);
        let tcpip = env.f().name(ACT_DIRECT_TCPIP);

        assert!(
            !env.allows(john, mars1, tcpip).await,
            "ag_all does not contain direct-tcpip"
        );

        // Naming it directly in a policy does work — the gap is the `g3` edge,
        // not the name.
        env.add_policy(env.f().name(R_OPS), env.f().name(TG_CORE), tcpip, "{}")
            .await;
        assert!(env.allows(john, mars1, tcpip).await);
    }

    /// An object group covers every binding under it, however deep.
    ///
    /// `p2` names `tg_core`, which is three levels above the mars leaves and one
    /// above saturn and sun. All of it resolves in a single BFS.
    #[tokio::test]
    async fn object_groups_reach_the_whole_subtree() {
        let env = Env::new().await;
        let john = env.f().user(JOHN);
        let shell = env.f().name(ACT_SHELL);

        for (host, secret) in [
            ("mars1", S_MON),   // tg_core → tg_mars → tg_mars_web
            ("mars7", S_MON),   // tg_core → tg_mars → tg_mars_db
            ("saturn1", S_DEV), // tg_core → tg_saturn
            ("sun", S_ROOT),    // tg_core → tg_sun
        ] {
            assert!(
                env.allows(john, env.f().binding(host, secret), shell).await,
                "tg_core should reach {host}/{secret}"
            );
        }

        // `tg_lab` is the other branch of `tg_all`, so `tg_core` never reaches it.
        assert!(
            !env.allows(john, env.f().binding("venus2", S_DEV), shell)
                .await
        );
        assert!(
            !env.allows(john, env.f().binding("jupiter1", S_MON), shell)
                .await
        );
    }

    /// A user inherits the policies of roles above them and never those below.
    ///
    /// `admin` is in `r_ops_lead`, under `r_ops`, so he holds both `p1` and `p2`.
    /// `john` is in `r_ops` and holds `p2` only — the `g1` walk runs up.
    #[tokio::test]
    async fn roles_are_inherited_upward_not_downward() {
        let env = Env::new().await;
        let admin_obj = env.f().name(OBJ_ADMIN);
        let shell = env.f().name(ACT_SHELL);

        assert!(
            env.allows(env.f().user(ADMIN), admin_obj, shell).await,
            "admin is in r_ops_lead, which carries p1"
        );
        assert!(
            !env.allows(env.f().user(JOHN), admin_obj, shell).await,
            "r_ops is above r_ops_lead, so john does not inherit p1"
        );

        // The same asymmetry on the other branch: mike inherits r_dev's p3,
        // luka does not inherit r_dev_lead's p4.
        let mars1 = env.f().binding("mars1", S_MON);
        let venus2 = env.f().binding("venus2", S_DEV);
        assert!(env.allows(env.f().user(MIKE), mars1, shell).await);
        assert!(
            !env.allows(env.f().user(LUKA), venus2, env.f().name(ACT_EXEC))
                .await
        );
    }

    /// Two policies inherited by one user grant different actions on different
    /// hosts, and neither leaks into the other.
    ///
    /// `mike` holds `p4` (`ag_batch` on `tg_lab`) directly and `p3`
    /// (`ag_interactive` on `tg_mars_web`) from `r_dev`. So he can exec on venus
    /// but not shell, and shell on mars but not exec — the grants are per-policy,
    /// not unioned per axis.
    #[tokio::test]
    async fn two_policies_do_not_cross_their_axes() {
        let env = Env::new().await;
        let mike = env.f().user(MIKE);
        let (shell, exec) = (env.f().name(ACT_SHELL), env.f().name(ACT_EXEC));
        let venus2 = env.f().binding("venus2", S_DEV);
        let mars1 = env.f().binding("mars1", S_MON);

        assert!(env.allows(mike, venus2, exec).await, "p4: batch on the lab");
        assert!(!env.allows(mike, venus2, shell).await);

        assert!(
            env.allows(mike, mars1, shell).await,
            "p3: interactive on mars web"
        );
        assert!(!env.allows(mike, mars1, exec).await);
    }

    /// A group id is not something you can connect to.
    ///
    /// `enforce` accepts the object when `pol.v1 == obj`, so passing a group id
    /// as the object matches the object arm outright. `check_object_active` is
    /// what refuses: a `g2` name is neither an active binding nor an
    /// `InternalObjectType`.
    #[tokio::test]
    async fn a_group_id_is_not_a_connectable_object() {
        let env = Env::new().await;
        let john = env.f().user(JOHN);
        let shell = env.f().name(ACT_SHELL);

        for group in [TG_CORE, TG_MARS_WEB, TG_ALL] {
            assert!(
                !env.allows(john, env.f().name(group), shell).await,
                "{group} is a group, not an object"
            );
        }

        // The internal objects in `tg_selfservice` are the exception, because
        // they are `InternalObjectType` names rather than bindings.
        let player = env.f().name(OBJ_PLAYER);
        let exec = env.f().name(ACT_EXEC);
        assert!(
            env.allows(john, player, exec).await,
            "p8 grants staff ag_all on tg_selfservice, which holds the player"
        );
        assert!(
            !env.allows(env.f().user(DAISY), player, exec).await,
            "daisy is under r_vendor, not r_staff"
        );
    }

    /// Any one of binding, target or secret being inactive denies the object.
    ///
    /// `check_object_active` joins all three, so the three columns are one gate.
    /// Each step here restores what it deactivated, so the assertions stay
    /// independent of order.
    #[tokio::test]
    async fn an_inactive_row_anywhere_denies_the_object() {
        let env = Env::new().await;
        let john = env.f().user(JOHN);
        let shell = env.f().name(ACT_SHELL);
        let saturn1 = env.f().binding("saturn1", S_MON);
        assert!(env.allows(john, saturn1, shell).await);

        env.set_target_active("saturn1", false).await;
        assert!(!env.allows(john, saturn1, shell).await, "target inactive");
        env.set_target_active("saturn1", true).await;

        env.set_binding_active("saturn1", S_MON, false).await;
        assert!(!env.allows(john, saturn1, shell).await, "binding inactive");
        env.set_binding_active("saturn1", S_MON, true).await;

        // The secret is shared, so deactivating it takes every host with it.
        env.set_secret_active(S_MON, false).await;
        assert!(!env.allows(john, saturn1, shell).await, "secret inactive");
        assert!(
            !env.allows(john, env.f().binding("mars1", S_MON), shell)
                .await
        );
        env.set_secret_active(S_MON, true).await;

        assert!(env.allows(john, saturn1, shell).await, "restored");

        // `saturn5` and `venus1` ship inactive, so this holds without any write.
        assert!(
            !env.allows(john, env.f().binding("saturn5", S_MON), shell)
                .await
        );
        assert!(
            !env.allows(env.f().user(DAISY), env.f().binding("venus1", S_DEV), shell)
                .await
        );
    }

    /// `p6` names a user and a single binding, so neither side walks a graph.
    ///
    /// It is the narrowest grant the schema allows, and the one case where
    /// `match_sub` matches on `p.v0 == sub` and the object arm on
    /// `pol.v1 == obj`.
    #[tokio::test]
    async fn a_policy_can_name_one_user_and_one_binding() {
        let env = Env::new().await;
        let daisy = env.f().user(DAISY);
        let sun_mon = env.f().binding("sun", S_MON);
        let shell = env.f().name(ACT_SHELL);

        assert!(env.allows(daisy, sun_mon, shell).await);

        // Exactly one action: `p6` names `ACT_SHELL` outright, not a group.
        assert!(!env.allows(daisy, sun_mon, env.f().name(ACT_PTY)).await);
        // Exactly one binding: `sun`'s other three secrets are not granted.
        assert!(
            !env.allows(daisy, env.f().binding("sun", S_ROOT), shell)
                .await
        );
        // Exactly one user.
        assert!(!env.allows(env.f().user(LUKA), sun_mon, shell).await);
    }

    /// Editing a `p` row takes effect at once; editing a `g1` row does not.
    ///
    /// `enforce` reads the policies from the database on every call but answers
    /// the graph questions from a cached snapshot. Both halves are asserted here
    /// because the split is invisible from the outside until it bites.
    #[tokio::test]
    async fn policies_are_read_per_call_and_graphs_are_cached() {
        let env = Env::new().await;
        let luka = env.f().user(LUKA);
        let mars1 = env.f().binding("mars1", S_MON);
        let (shell, exec) = (env.f().name(ACT_SHELL), env.f().name(ACT_EXEC));

        assert!(env.allows(luka, mars1, shell).await);
        assert!(!env.allows(luka, mars1, exec).await);

        // Retarget `p3`'s action group from interactive to batch.
        env.repo()
            .update_casbin_rule(casbin_rule::ActiveModel {
                id: Unchanged(env.f().policy(3)),
                v2: Set(env.f().name(AG_BATCH)),
                ..Default::default()
            })
            .await
            .expect("retarget p3");

        // No reload, and it is already live.
        assert!(env.allows(luka, mars1, exec).await);
        assert!(!env.allows(luka, mars1, shell).await);

        // A `g1` write is the other half. `r_audit` has no members and carries
        // `p5` on `tg_jupiter`, so it grants nothing until daisy is put in it —
        // and not even then, until the graphs are rebuilt.
        let jupiter1 = env.f().binding("jupiter1", S_MON);
        let daisy = env.f().user(DAISY);
        assert!(!env.allows(daisy, jupiter1, exec).await);

        env.add_group_rule(Ptype::G1, env.f().name(R_AUDIT), daisy)
            .await;
        assert!(
            !env.allows(daisy, jupiter1, exec).await,
            "the g1 graph is a snapshot and has not been rebuilt"
        );

        env.reload().await;
        assert!(env.allows(daisy, jupiter1, exec).await);
    }

    /// An inactive role still grants. Only the *object* is checked for activity.
    ///
    /// `r_audit` ships with `is_active = false`, and
    /// `list_casbin_rule_group_by_ptype` does not filter on it, so the role is in
    /// the graph like any other. Whether that is the intended reading of the flag
    /// is a design question; this test records what the code does so a change to
    /// it is deliberate.
    #[tokio::test]
    async fn an_inactive_role_name_still_grants() {
        let env = Env::new().await;
        let daisy = env.f().user(DAISY);
        let jupiter1 = env.f().binding("jupiter1", S_MON);
        let exec = env.f().name(ACT_EXEC);

        env.add_group_rule(Ptype::G1, env.f().name(R_AUDIT), daisy)
            .await;
        env.reload().await;

        let role = env
            .repo()
            .get_casbin_name_by_name(R_AUDIT)
            .await
            .expect("read r_audit")
            .expect("r_audit exists");
        assert!(!role.is_active, "the fixture ships r_audit inactive");
        assert!(env.allows(daisy, jupiter1, exec).await);
    }

    /// `p7`'s extended policy gates on IP, time of day and expiry.
    ///
    /// Every instant here is fixed rather than `Utc::now()`, so the window
    /// assertions cannot start failing at 20:00 local time. The policy is written
    /// in `+08:00`, allows `10.20.0.0/16`, runs `08:00`–`20:00` and expires at
    /// 2030-01-01.
    #[tokio::test]
    async fn an_extended_policy_gates_ip_time_and_expiry() {
        let env = Env::new().await;
        let daisy = env.f().user(DAISY);
        let venus2 = env.f().binding("venus2", S_DEV);
        let shell = env.f().name(ACT_SHELL);

        let req = |addr: Option<IpAddr>, now: DateTime<Utc>| ExtendPolicyReq {
            ip: addr,
            now,
            open_direct_tcpip: None,
        };
        // 12:00 +08:00, mid-window and well before the expiry.
        let inside = at("2026-03-05T04:00:00Z");

        // `is_ip_in_cidr` reads `(None, Some(policy))` as a failure, so a request
        // carrying no address cannot satisfy an IP policy.
        assert!(!env.allows(daisy, venus2, shell).await);
        assert!(
            !env.allows_with(daisy, venus2, shell, req(None, inside))
                .await
        );

        assert!(
            env.allows_with(daisy, venus2, shell, req(ip("10.20.0.5"), inside))
                .await
        );
        assert!(
            !env.allows_with(daisy, venus2, shell, req(ip("10.21.0.5"), inside))
                .await,
            "outside the /16"
        );

        // The window is half-open: 08:00 +08:00 is in, 20:00 +08:00 is out.
        assert!(
            env.allows_with(
                daisy,
                venus2,
                shell,
                req(ip("10.20.0.5"), at("2026-03-05T00:00:00Z"))
            )
            .await,
            "start is inclusive"
        );
        assert!(
            !env.allows_with(
                daisy,
                venus2,
                shell,
                req(ip("10.20.0.5"), at("2026-03-05T12:00:00Z"))
            )
            .await,
            "end is exclusive"
        );
        assert!(
            !env.allows_with(
                daisy,
                venus2,
                shell,
                req(ip("10.20.0.5"), at("2026-03-04T23:59:00Z"))
            )
            .await,
            "before the window"
        );

        // Expiry, checked at an instant that is otherwise inside the window.
        assert!(
            !env.allows_with(
                daisy,
                venus2,
                shell,
                req(ip("10.20.0.5"), at("2030-06-05T04:00:00Z"))
            )
            .await
        );
    }

    /// The extended policy belongs to the policy, not to the request.
    ///
    /// `mike` reaches the same venus binding through `p4`, whose `v3` is empty, so
    /// the vendor policy's window does not apply to him. This is what stops a
    /// constraint on one grant from being read as a constraint on the object.
    #[tokio::test]
    async fn an_extended_policy_binds_to_its_own_policy() {
        let env = Env::new().await;
        let venus2 = env.f().binding("venus2", S_DEV);
        let exec = env.f().name(ACT_EXEC);

        // No IP, an instant outside the vendor window, and mike is still allowed.
        let ext = ExtendPolicyReq {
            ip: None,
            now: at("2026-03-05T20:00:00Z"),
            open_direct_tcpip: None,
        };
        assert!(env.allows_with(env.f().user(MIKE), venus2, exec, ext).await);
    }

    // ------------------------------------------------- list_targets_for_user

    /// Each user sees exactly the bindings their policies reach.
    ///
    /// The counts come from the fixture's 85 bindings, 5 of which are on the two
    /// inactive hosts (`saturn5`, `venus1`).
    #[tokio::test]
    async fn each_user_sees_the_bindings_their_policies_reach() {
        let env = Env::new().await;

        assert_eq!(
            env.visible(ADMIN).await.len(),
            TG_CORE_BINDING - 3 + TG_MARS_WEB_BINDING + TG_LAB_BINDING - 2
                + S_MON_TG_JUPITER
                + TG_VENUS_BINDING
                - 2
                + TG_LAB_BINDING
                - 2
        );
        assert_eq!(
            env.visible(JOHN).await.len(),
            TG_CORE_BINDING - 3 + TG_MARS_WEB_BINDING
        );

        // `p4` on `tg_lab` (venus 25 + jupiter 5 = 30) plus `p3` on `tg_mars_web`
        // (9). Disjoint branches, so the total is the sum.
        assert_eq!(env.visible(MIKE).await.len(), 39);

        // `p3` alone.
        assert_eq!(env.visible(LUKA).await.len(), 9);

        // `p7` on `tg_venus` (25) plus `p6`'s single binding.
        assert_eq!(env.visible(DAISY).await.len(), 26);

        // No role, so `match_sub` yields no policy at all.
        assert!(env.visible(JOE).await.is_empty());
    }

    /// The rows are bindings, and the group walk reaches the leaves.
    ///
    /// `luka` has the smallest result in the fixture, so it can be named in full:
    /// `tg_mars_web` holds the bindings on `mars1`-`mars5`, which is `s_mon` on
    /// all five, `s_dev` on 3-5 and `s_oper` on 5.
    #[tokio::test]
    async fn rows_are_bindings_not_targets() {
        let env = Env::new().await;
        let rows = env.visible(LUKA).await;

        let mut got: Vec<(String, String)> = rows
            .iter()
            .map(|r| (r.target_name.clone(), r.secret_user.clone()))
            .collect();
        got.sort();

        let mut want: Vec<(String, String)> = [
            ("mars1", "mon"),
            ("mars2", "mon"),
            ("mars3", "mon"),
            ("mars3", "dev"),
            ("mars4", "mon"),
            ("mars4", "dev"),
            ("mars5", "mon"),
            ("mars5", "dev"),
            ("mars5", "oper"),
        ]
        .iter()
        .map(|(t, s)| ((*t).to_string(), (*s).to_string()))
        .collect();
        want.sort();

        assert_eq!(got, want);
        // One row per binding, so no id repeats within a single policy.
        assert_eq!(distinct(&rows).len(), rows.len());
    }

    /// `active_only = false` brings back the deactivated rows.
    ///
    /// The five extra are `saturn5`'s three bindings and `venus1`'s two. Nothing
    /// else in the fixture is inactive, so the difference isolates the flag.
    #[tokio::test]
    async fn inactive_rows_come_back_when_asked_for() {
        let env = Env::new().await;

        assert_eq!(
            env.visible_all(ADMIN).await.len(),
            TG_CORE_BINDING
                + TG_MARS_WEB_BINDING
                + TG_LAB_BINDING
                + S_MON_TG_JUPITER
                + TG_VENUS_BINDING
                + TG_LAB_BINDING
        );
        assert_eq!(env.visible_all(MIKE).await.len(), 41, "+2 on venus1");
        assert_eq!(env.visible_all(DAISY).await.len(), 28, "+2 on venus1");
        // Neither inactive host is under `tg_mars_web`.
        assert_eq!(env.visible_all(LUKA).await.len(), 9);
    }

    /// Every row carries the policy that produced it, and two policies covering
    /// the same binding yield it twice.
    ///
    /// The duplication is what the method's own NOTE warns about. It is not
    /// incidental: the caller re-checks the extended policy before connecting, so
    /// it needs to know *which* grant a row came from, and the same binding
    /// reached under two policies is two different offers.
    #[tokio::test]
    async fn rows_are_tagged_with_their_policy_and_may_repeat() {
        let env = Env::new().await;

        // `daisy`'s 26 rows come from two policies: 25 from `p7`, 1 from `p6`.
        let rows = env.visible(DAISY).await;
        let grouped = by_policy(&rows);
        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped[&env.f().policy(7)].len(), 25);
        assert_eq!(grouped[&env.f().policy(6)].len(), 1);
        assert_eq!(
            grouped[&env.f().policy(6)][0].id,
            env.f().binding("sun", S_MON)
        );
        // Two policies, no overlap, so distinct == total here.
        assert_eq!(distinct(&rows).len(), 26);

        // Give `r_ops` a second policy over `tg_mars`, a subtree of the `tg_core`
        // it already holds. Both policies now cover the 22 mars bindings.
        let extra = env
            .add_policy(
                env.f().name(R_OPS),
                env.f().name(TG_MARS),
                env.f().name(AG_ALL),
                "{}",
            )
            .await;

        // No reload: the ids the new policy names are already in the graphs.
        let rows = env.visible(JOHN).await;
        assert_eq!(
            rows.len(),
            TG_CORE_BINDING + TG_MARS_WEB_BINDING + TG_MARS_BINDING - 3,
        );
        assert_eq!(
            distinct(&rows).len(),
            TG_CORE_BINDING - 3,
            "still the same 50 bindings"
        );

        let grouped = by_policy(&rows);
        assert_eq!(grouped[&env.f().policy(2)].len(), 50);
        assert_eq!(grouped[&extra].len(), 22);
    }

    /// A policy naming a binding directly is served by the fallback branch.
    ///
    /// `list_targets_for_user` resolves the policy's object as a group first, and
    /// only tries it as a binding id when that comes back empty. `p6` names a
    /// binding, which is *also* a member of `tg_sun`, so the group walk normally
    /// finds it and the fallback never runs. Dropping that `g2` row is what
    /// exposes the branch — and the row still comes back.
    #[tokio::test]
    async fn a_policy_on_a_bare_binding_falls_back() {
        let env = Env::new().await;
        let sun_mon = env.f().binding("sun", S_MON);
        assert_eq!(
            env.visible(JOHN).await.len(),
            TG_CORE_BINDING + TG_MARS_WEB_BINDING - 3
        );

        let deleted = env
            .repo()
            .delete_casbin_rule_by_group(GroupType::Object, sun_mon, env.f().name(TG_SUN))
            .await
            .expect("delete the g2 row");
        assert!(deleted, "the fixture binds sun/s_mon into tg_sun");
        env.reload().await;

        // `p6`'s object is no longer in the `g2` graph, so `fetch_role_from_start`
        // returns nothing and the fallback treats `v1` as a binding id.
        let rows = env.visible(DAISY).await;
        let grouped = by_policy(&rows);
        assert_eq!(grouped[&env.f().policy(6)].len(), 1);
        assert_eq!(grouped[&env.f().policy(6)][0].id, sun_mon);
        assert_eq!(rows.len(), 26, "unchanged: p7 never covered sun");

        // The group route is what actually lost the binding.
        assert_eq!(
            env.visible(JOHN).await.len(),
            TG_CORE_BINDING + TG_MARS_WEB_BINDING - 4
        );
    }

    /// A group of internal objects yields no rows, and does not fall through.
    ///
    /// `p8` names `tg_selfservice`, whose members are `__internal_object_*` names
    /// rather than bindings. The group walk succeeds and finds three ids, none of
    /// which is a `target_secret`, so `list_targets_by_ids` returns empty — and
    /// the fallback, keyed on the group id itself, finds nothing either. Without
    /// this, `p8` would have to be absent from every count above.
    #[tokio::test]
    async fn a_group_of_internal_objects_yields_no_bindings() {
        let env = Env::new().await;
        let rows = env.visible(ADMIN).await;

        // `admin` inherits all except `p6`
        let grouped = by_policy(&rows);
        assert_eq!(grouped.len(), 6);
        assert!(grouped.contains_key(&env.f().policy(2)));
        for unproductive in [0, 1, 6, 8] {
            assert!(
                !grouped.contains_key(&env.f().policy(unproductive)),
                "p{unproductive} names no binding"
            );
        }
    }

    /// `list_targets_for_user` reads the object's activity through the same join
    /// as `enforce`, so the two agree on what is connectable.
    ///
    /// They arrive at it separately — `enforce` calls `check_object_active`, this
    /// filters in SQL — which is exactly why it is worth asserting they match.
    #[tokio::test]
    async fn listing_and_enforcing_agree_on_activity() {
        let env = Env::new().await;
        let john = env.f().user(JOHN);
        let shell = env.f().name(ACT_SHELL);
        let mars1 = env.f().binding("mars1", S_MON);

        assert!(distinct(&env.visible(JOHN).await).contains(&mars1));
        assert!(env.allows(john, mars1, shell).await);

        env.set_binding_active("mars1", S_MON, false).await;

        assert!(!distinct(&env.visible(JOHN).await).contains(&mars1));
        assert!(!env.allows(john, mars1, shell).await);
        assert_eq!(
            env.visible(JOHN).await.len(),
            TG_CORE_BINDING + TG_MARS_WEB_BINDING - 3 - 1 - 1
        );
        assert_eq!(
            distinct(&env.visible(JOHN).await).len(),
            TG_CORE_BINDING - 3 - 1
        );
        // Still listed when the caller asks for everything.
        assert!(distinct(&env.visible_all(JOHN).await).contains(&mars1));
    }

    /// A `g1` write is invisible to listing until the graphs are rebuilt, for the
    /// same reason it is invisible to `enforce`.
    #[tokio::test]
    async fn listing_uses_the_cached_role_graph() {
        let env = Env::new().await;
        assert!(env.visible(JOE).await.is_empty());

        env.add_group_rule(Ptype::G1, env.f().name(R_OPS), env.f().user(JOE))
            .await;
        assert!(
            env.visible(JOE).await.is_empty(),
            "the g1 graph has not been rebuilt"
        );

        env.reload().await;
        // `joe`'s own row is inactive, but `list_targets_for_user` filters on the
        // target side only — the caller has already authenticated by this point.
        assert_eq!(env.visible(JOE).await.len(), 50);
    }
}
