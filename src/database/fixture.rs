//! The test dataset, built from the domain types in [`crate::database::models`].
//!
//! This replaces the `mock_data.json` fixture. A hand-maintained JSON blob had
//! to spell every uuid literally, which meant the relationships between rows —
//! which rule grants which binding, which binding reaches which host — were only
//! legible by cross-referencing ids. Here the shape is written as code: ids come
//! from `Uuid::now_v7()` and are looked up by name through [`Fixture`], so a
//! reader sees `(R_STAFF, R_OPS)` rather than two uuids.
//!
//! # Layout
//!
//! * **6 users** — `admin`, `john`, `mike`, `luka`, `daisy`, `joe`. `joe` is
//!   inactive and holds no role at all; `daisy` is granted directly by a policy
//!   rather than through a role.
//! * **36 targets** — `mars1`-`mars10`, `saturn1`-`saturn10`, `venus1`-`venus10`,
//!   `sun`, `jupiter1`-`jupiter5`, all sharing one ed25519 host key.
//!   `saturn5` and `venus1` are inactive.
//! * **4 secrets** — `s_root`/root, `s_dev`/dev, `s_oper`/oper, `s_mon`/mon.
//! * **85 bindings** — `s_mon` on every target; all four secrets on `sun`;
//!   `s_dev` on mars3-8, saturn1-7, venus1-10; `s_oper` on mars5-10,
//!   saturn1-10, venus3-9.
//! * **4-level role tree** (`g1`), **4-level object-group tree** (`g2`),
//!   **2-level action groups** (`g3`), and **10 policies** (`p`) — drawn below.
//!
//! # Role tree (`g1`)
//!
//! Parentheses hold the role's own members; the right-hand column is the policy
//! that role carries.
//!
//! ```text
//! r_manager(admin)                p1  ag_interactive on OBJ_ADMIN
//! ├── r_ops_lead (no members)     p9  ag_interactive on tg_lab
//! │   └── r_ops (john)            p2  ag_all         on tg_core
//! │       └── r_staff             p8  ag_all         on tg_selfservice
//! ├── r_dev_lead (mike)           p4  ag_batch       on tg_lab
//! │   └── r_dev (luka, john)      p3  ag_interactive on tg_mars_web
//! │       └── r_staff             p8  ag_all         on tg_selfservice
//! └── r_audit (no members)        p5  ACT_EXEC       on tg_jupiter
//!     └── r_vendor (daisy)        p7  ag_interactive on tg_venus
//! ```
//!
//! So `admin` inherits all, while `luka` gets `p3` and `p8`.
//! `joe` holds no role and so reaches nothing, not even login.
//! Two deliberate edge cases: `r_audit`'s name is inactive and has no
//! members, and `p7` is the only policy carrying a non-empty `v3`
//! ([`VENDOR_EXTEND_POLICY`]).
//!
//! On top of the tree, `p6` grants `daisy` [`ACT_SHELL`] on the concrete
//! `sun`/`s_mon` binding — a *user* subject and a *binding* object, so neither
//! side of that one resolves through a group.
//!
//! # Object tree (`g2`)
//!
//! Members are **bindings**, not targets: `tg_mars_web` holds `mars1`/`s_mon`,
//! `mars3`/`s_dev`, `mars5`/`s_oper` and so on, so walking down from `tg_all`
//! reaches all 85. Only the mars branch goes four deep.
//!
//! ```text
//! tg_all
//! ├── tg_core
//! │   ├── tg_mars
//! │   │   ├── tg_mars_web ── bindings on mars1-5
//! │   │   └── tg_mars_db  ── bindings on mars6-10
//! │   ├── tg_saturn ──────── bindings on saturn1-10
//! │   └── tg_sun ─────────── bindings on sun (all four secrets)
//! └── tg_lab
//!     ├── tg_venus ───────── bindings on venus1-10
//!     └── tg_jupiter ─────── bindings on jupiter1-5
//!
//! tg_selfservice ─────────── OBJ_PLAYER, OBJ_LOGIN
//! ```
//!
//! `tg_selfservice` is off the tree on purpose, and its members are internal
//! objects rather than bindings — a group can hold either.
//!
//! # Action groups (`g3`)
//!
//! ```text
//! ag_all ── ACT_LOGIN
//! ├── ag_interactive ── ACT_SHELL, ACT_PTY
//! └── ag_batch ──────── ACT_EXEC
//! ```
//!
//! [`ACT_LOGIN`] hangs off the root rather than either leaf, so a policy naming
//! `ag_interactive` grants a shell without granting login.

use std::collections::HashMap;

use argon2::password_hash::{PasswordHasher, SaltString};
use tempfile::TempDir;

use crate::database::common::{
    ACT_DIRECT_TCPIP, ACT_EXEC, ACT_LOGIN, ACT_PTY, ACT_SHELL, OBJ_ADMIN, OBJ_LOGIN, OBJ_PLAYER,
};
use crate::database::models::{
    CasbinName, CasbinRule, NamePtype, Ptype, Secret, Target, TargetSecret, User,
};
use crate::database::service::DatabaseService;
use crate::database::{DatabaseRepository, Uuid};

// ------------------------------------------------------------------- constants

/// Row counts, so a test can say what it expects without recounting the builders.
pub const USERS: usize = 6;
pub const ACTIVE_USERS: usize = 5;
pub const TARGETS: usize = 36;
pub const ACTIVE_TARGETS: usize = 34;
pub const SECRETS: usize = 4;
pub const TARGET_SECRETS: usize = 85;
pub const CASBIN_NAMES: usize = 30;
pub const CASBIN_RULES: usize = 126;
/// `p` rules. One per entry in [`Fixture::policies`].
pub const POLICIES: usize = 10;
/// `g1`: 8 nestings + 6 memberships.
pub const G1_RULES: usize = 14;
/// `g2`: 9 nestings + 85 bindings + 2 self-service objects.
pub const G2_RULES: usize = 96;
/// `g3`: 2 nestings + 4 actions.
pub const G3_RULES: usize = 6;
/// Internal action and object names, the ones `--init` would create.
pub const INTERNAL_NAMES: usize = 8;

/// Every target carries this key, so one `PublicKey::from_openssh` covers all 36.
pub const HOST_PUBLIC_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDykduj1fRNu4UoqrqfE1WDkotT7AH9AJYGsKAN0WEEy \
     rustion-fixture";

/// `john`'s `authorized_keys` entry — a client key, not the host key above.
pub const USER_PUBLIC_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPK9Cq0bfR/xUpRS0bU2PpzieaiNPatO0qSupyOiW2Vy \
     john@fixture";

/// The cleartext behind every `password_hash` in the fixture.
pub const PASSWORD: &str = "fixture-password";

/// `v3` of the `r_vendor` policy: a non-empty serialized `server::ExtendPolicy`.
///
/// Spelled as a literal because `server::extend_policy` is private to
/// `crate::server` and the database layer cannot depend on it. That makes it
/// possible for this to drift out of shape, so
/// `server::extend_policy::tests::fixture_extend_policy_still_parses` parses it.
/// Must stay within `varchar(256)`.
pub const VENDOR_EXTEND_POLICY: &str = concat!(
    r#"{"ip_policy":{"Allow":"10.20.0.0/16"},"#,
    r#""start_time":"08:00 +08:00","end_time":"20:00 +08:00","#,
    r#""expire_date":"2030-01-01T00:00:00+08:00","#,
    r#""open_direct_tcpip_host":null,"open_direct_tcpip_port":null}"#,
);

// Users.
pub const ADMIN: &str = "admin";
pub const JOHN: &str = "john";
pub const MIKE: &str = "mike";
pub const LUKA: &str = "luka";
pub const DAISY: &str = "daisy";
pub const JOE: &str = "joe";

// Secrets.
pub const S_ROOT: &str = "s_root";
pub const S_DEV: &str = "s_dev";
pub const S_OPER: &str = "s_oper";
pub const S_MON: &str = "s_mon";

// Roles (`g1`), four levels deep.
pub const R_MANAGER: &str = "r_manager";
pub const R_STAFF: &str = "r_staff";
pub const R_VENDOR: &str = "r_vendor";
pub const R_OPS: &str = "r_ops";
pub const R_DEV: &str = "r_dev";
pub const R_AUDIT: &str = "r_audit";
pub const R_OPS_LEAD: &str = "r_ops_lead";
pub const R_DEV_LEAD: &str = "r_dev_lead";

// Object groups (`g2`), four levels deep plus a self-service group.
pub const TG_ALL: &str = "tg_all";
pub const TG_CORE: &str = "tg_core";
pub const TG_LAB: &str = "tg_lab";
pub const TG_MARS: &str = "tg_mars";
pub const TG_SATURN: &str = "tg_saturn";
pub const TG_SUN: &str = "tg_sun";
pub const TG_VENUS: &str = "tg_venus";
pub const TG_JUPITER: &str = "tg_jupiter";
pub const TG_MARS_WEB: &str = "tg_mars_web";
pub const TG_MARS_DB: &str = "tg_mars_db";
pub const TG_SELFSERVICE: &str = "tg_selfservice";

// Object group counts
pub const S_MON_TG_MARS_WEB: usize = 5;
pub const S_MON_TG_MARS_DB: usize = 5;
pub const S_MON_TG_SATURN: usize = 10;
pub const S_MON_TG_VENUS: usize = 10;
pub const S_MON_TG_JUPITER: usize = 5;
pub const S_ALL_SUN: usize = 4;
pub const S_OPER_TG_MARS_WEB: usize = 1;
pub const S_OPER_TG_MARS_DB: usize = 5;
pub const S_OPER_TG_SATURN: usize = 10;
pub const S_OPER_TG_VENUS: usize = 7;
pub const S_DEV_TG_MARS_WEB: usize = 3;
pub const S_DEV_TG_MARS_DB: usize = 3;
pub const S_DEV_TG_SATURN: usize = 7;
pub const S_DEV_TG_VENUS: usize = 10;
pub const TG_MARS_WEB_BINDING: usize = S_MON_TG_MARS_WEB + S_OPER_TG_MARS_WEB + S_DEV_TG_MARS_WEB;
pub const TG_MARS_DB_BINDING: usize = S_MON_TG_MARS_DB + S_OPER_TG_MARS_DB + S_DEV_TG_MARS_DB;
pub const TG_MARS_BINDING: usize = TG_MARS_WEB_BINDING + TG_MARS_DB_BINDING;
pub const TG_SATURN_BINDING: usize = S_MON_TG_SATURN + S_DEV_TG_SATURN + S_OPER_TG_SATURN;
pub const TG_VENUS_BINDING: usize = S_MON_TG_VENUS + S_DEV_TG_VENUS + S_OPER_TG_VENUS;
pub const TG_CORE_BINDING: usize = TG_MARS_BINDING + TG_SATURN_BINDING + S_ALL_SUN;
pub const TG_LAB_BINDING: usize = TG_VENUS_BINDING + S_MON_TG_JUPITER;
// Action groups (`g3`), two levels deep.
pub const AG_ALL: &str = "ag_all";
pub const AG_INTERACTIVE: &str = "ag_interactive";
pub const AG_BATCH: &str = "ag_batch";

// ---------------------------------------------------------------- name lookups

/// Name → id maps for everything the fixture created.
///
/// Ids are generated, not literal, so tests address rows the way the fixture
/// declares them. Every accessor panics on an unknown name: a typo in a test is
/// a bug in the test, and a `None` would only surface later as a confusing
/// empty result.
pub struct Fixture {
    /// `updated_by` on every row, and `admin`'s own id.
    pub admin_id: Uuid,
    users: HashMap<&'static str, Uuid>,
    targets: HashMap<String, Uuid>,
    secrets: HashMap<&'static str, Uuid>,
    names: HashMap<&'static str, Uuid>,
    /// Keyed `(target, secret)` — the pair the unique index covers.
    bindings: HashMap<(String, &'static str), Uuid>,
    /// The `p` rule ids, in declaration order. See [`Fixture::policy`].
    pub policies: Vec<Uuid>,
}

impl Fixture {
    pub fn user(&self, name: &str) -> Uuid {
        self.users[name]
    }

    pub fn target(&self, name: &str) -> Uuid {
        self.targets[name]
    }

    pub fn secret(&self, name: &str) -> Uuid {
        self.secrets[name]
    }

    /// A `casbin_name` id: a role, an object group, an action group, or one of
    /// the internal action/object names.
    pub fn name(&self, name: &str) -> Uuid {
        self.names[name]
    }

    /// A binding id, by the `(target, secret)` pair it joins.
    pub fn binding(&self, target: &str, secret: &'static str) -> Uuid {
        self.bindings[&(target.to_string(), secret)]
    }

    /// One of the nine `p` rules, `0`-indexed in declaration order — see the
    /// policy list in [`build`].
    pub fn policy(&self, index: usize) -> Uuid {
        self.policies[index]
    }
}

/// The rows themselves, ready to write. Split from [`Fixture`] so a test that
/// wants to seed only part of the dataset can take what it needs.
pub struct Data {
    pub users: Vec<User>,
    pub targets: Vec<Target>,
    pub secrets: Vec<Secret>,
    pub target_secrets: Vec<TargetSecret>,
    pub casbin_names: Vec<CasbinName>,
    pub casbin_rules: Vec<CasbinRule>,
}

// -------------------------------------------------------------------- builders

/// `mars1`..`mars10`, `saturn1`..`saturn10`, `venus1`..`venus10`, `sun`,
/// `jupiter1`..`jupiter5` — 36 names, in the order they are created.
fn target_names() -> Vec<String> {
    let mut names: Vec<String> = Vec::with_capacity(TARGETS);
    for family in ["mars", "saturn", "venus"] {
        names.extend((1..=10).map(|n| format!("{family}{n}")));
    }
    names.push("sun".to_string());
    names.extend((1..=5).map(|n| format!("jupiter{n}")));
    names
}

/// Which targets each secret is bound to, as the request spelled it.
fn binding_spec() -> Vec<(&'static str, Vec<String>)> {
    let all: Vec<String> = target_names();
    let range = |family: &str, from: u32, to: u32| -> Vec<String> {
        (from..=to).map(|n| format!("{family}{n}")).collect()
    };

    let mut s_dev = range("mars", 3, 8);
    s_dev.extend(range("saturn", 1, 7));
    s_dev.extend(range("venus", 1, 10));

    let mut s_oper = range("mars", 5, 10);
    s_oper.extend(range("saturn", 1, 10));
    s_oper.extend(range("venus", 3, 9));

    vec![
        // Every target gets the monitoring credential.
        (S_MON, all),
        // `sun` gets all four; its `s_mon` binding is already above.
        (S_ROOT, vec!["sun".to_string()]),
        (S_DEV, {
            let mut v = s_dev;
            v.push("sun".to_string());
            v
        }),
        (S_OPER, {
            let mut v = s_oper;
            v.push("sun".to_string());
            v
        }),
    ]
}

/// The deepest `g2` group a target's bindings belong to.
///
/// `mars` splits across two leaf groups, which is what makes the tree four
/// levels deep on that branch (`tg_all` → `tg_core` → `tg_mars` → `tg_mars_web`).
fn host_group(target: &str) -> &'static str {
    match target {
        t if t.starts_with("mars") => {
            let n: u32 = t.trim_start_matches("mars").parse().expect("mars index");
            if n <= 5 { TG_MARS_WEB } else { TG_MARS_DB }
        }
        t if t.starts_with("saturn") => TG_SATURN,
        t if t.starts_with("venus") => TG_VENUS,
        t if t.starts_with("jupiter") => TG_JUPITER,
        "sun" => TG_SUN,
        other => panic!("no group for target {other}"),
    }
}

/// Argon2, so [`crate::database::models::User::verify_password`] really verifies.
fn password_hash() -> String {
    let salt = SaltString::generate(&mut aes_gcm::aead::OsRng);
    argon2::Argon2::default()
        .hash_password(PASSWORD.as_bytes(), &salt)
        .expect("hash fixture password")
        .to_string()
}

/// Build the whole dataset without touching a database.
pub fn build() -> (Fixture, Data) {
    let admin_id = Uuid::now_v7();

    // ------------------------------------------------------------------ users
    let mut users = Vec::with_capacity(USERS);
    let mut user_ids = HashMap::new();

    let mut push_user = |username: &'static str,
                         email: Option<&str>,
                         with_password: bool,
                         keys: Option<Vec<String>>,
                         force_init_pass: bool,
                         is_active: bool| {
        let mut u = User::new(admin_id);
        // `admin` updates itself, exactly as `--init` writes it.
        if username == ADMIN {
            u.id = admin_id;
        }
        u.username = username.to_string();
        u.email = email.map(str::to_string);
        u.password_hash = with_password.then(password_hash);
        u.authorized_keys = keys;
        u.force_init_pass = force_init_pass;
        u.is_active = is_active;
        user_ids.insert(username, u.id);
        users.push(u);
    };

    push_user(ADMIN, Some("admin@fixture.test"), true, None, false, true);
    // The only user with a public key, so pubkey auth has exactly one match.
    push_user(
        JOHN,
        Some("john@fixture.test"),
        true,
        Some(vec![USER_PUBLIC_KEY.to_string()]),
        false,
        true,
    );
    push_user(MIKE, Some("mike@fixture.test"), true, None, false, true);
    push_user(LUKA, None, true, None, false, true);
    // Never logged in: still on the forced first-password path.
    push_user(DAISY, Some("daisy@fixture.test"), true, None, true, true);
    // No password, no key, no role, and deactivated — the empty case on every
    // axis at once.
    push_user(JOE, None, false, None, true, false);

    // ---------------------------------------------------------------- targets
    let mut targets = Vec::with_capacity(TARGETS);
    let mut target_ids = HashMap::new();
    for name in target_names() {
        let mut t = Target::new(admin_id);
        t.name = name.clone();
        t.hostname = format!("{name}.fixture.test");
        // Two off-default ports, so a composed `user@target:port` label cannot
        // pass by hardcoding 22.
        t.port = match name.as_str() {
            "sun" => 2222,
            "jupiter5" => 65535,
            _ => 22,
        };
        t.server_public_key = HOST_PUBLIC_KEY.to_string();
        t.description = (name == "sun").then(|| "shared bastion-side host".to_string());
        // Storage-only here; the URI is parsed on the connection path.
        t.proxy = (name == "jupiter1").then(|| "http://proxy.fixture.test:3128".to_string());
        t.is_active = !matches!(name.as_str(), "saturn5" | "venus1");
        target_ids.insert(name, t.id);
        targets.push(t);
    }

    // ---------------------------------------------------------------- secrets
    let mut secrets = Vec::with_capacity(SECRETS);
    let mut secret_ids = HashMap::new();
    // The ciphertext columns hold whatever bytes they are given — the repository
    // does not encrypt — so these stand in for AES-256-GCM output.
    for (name, user, password, key) in [
        (S_ROOT, "root", true, false),
        (S_DEV, "dev", false, true),
        (S_OPER, "oper", true, true),
        (S_MON, "mon", false, false),
    ] {
        let mut s = Secret::new(admin_id);
        s.name = name.to_string();
        s.user = user.to_string();
        s.password = password.then(|| format!("ciphertext-password-{name}"));
        s.private_key = key.then(|| format!("ciphertext-private-key-{name}"));
        s.public_key = key.then(|| HOST_PUBLIC_KEY.to_string());
        secret_ids.insert(name, s.id);
        secrets.push(s);
    }

    // --------------------------------------------------------- target_secrets
    let mut target_secrets = Vec::with_capacity(TARGET_SECRETS);
    let mut binding_ids = HashMap::new();
    for (secret, hosts) in binding_spec() {
        for host in hosts {
            let ts = TargetSecret {
                id: Uuid::now_v7(),
                target_id: target_ids[&host],
                secret_id: secret_ids[secret],
                is_active: true,
                updated_by: admin_id,
                // Stamped by the single-row create; kept as-is by the batch.
                updated_at: 0,
            };
            binding_ids.insert((host, secret), ts.id);
            target_secrets.push(ts);
        }
    }
    assert_eq!(
        target_secrets.len(),
        TARGET_SECRETS,
        "binding count drifted"
    );

    // ----------------------------------------------------------- casbin_names
    let mut casbin_names = Vec::with_capacity(CASBIN_NAMES);
    let mut name_ids = HashMap::new();
    let mut push_name = |ptype: NamePtype, name: &'static str, is_active: bool| {
        let n = CasbinName::new(ptype, name.to_string(), is_active, admin_id);
        name_ids.insert(name, n.id);
        casbin_names.push(n);
    };

    // Roles. `r_audit` is inactive, and is also the one role with no members.
    for role in [
        R_MANAGER, R_STAFF, R_VENDOR, R_OPS, R_DEV, R_OPS_LEAD, R_DEV_LEAD,
    ] {
        push_name(NamePtype::G1, role, true);
    }
    push_name(NamePtype::G1, R_AUDIT, false);

    for group in [
        TG_ALL,
        TG_CORE,
        TG_LAB,
        TG_MARS,
        TG_SATURN,
        TG_SUN,
        TG_VENUS,
        TG_JUPITER,
        TG_MARS_WEB,
        TG_MARS_DB,
        TG_SELFSERVICE,
    ] {
        push_name(NamePtype::G2, group, true);
    }

    for group in [AG_ALL, AG_INTERACTIVE, AG_BATCH] {
        push_name(NamePtype::G3, group, true);
    }

    // The names `--init` creates. Protected against rename, re-type and delete.
    for action in [ACT_SHELL, ACT_PTY, ACT_EXEC, ACT_LOGIN, ACT_DIRECT_TCPIP] {
        push_name(NamePtype::InternalActionType, action, true);
    }
    for object in [OBJ_LOGIN, OBJ_ADMIN, OBJ_PLAYER] {
        push_name(NamePtype::InternalObjectType, object, true);
    }
    assert_eq!(casbin_names.len(), CASBIN_NAMES, "name count drifted");

    // ----------------------------------------------------------- casbin_rules
    let mut casbin_rules = Vec::with_capacity(CASBIN_RULES);
    let mut policies = Vec::with_capacity(POLICIES);

    // `p`: subject may perform action `v2` on object `v1`, under `v3`.
    let mut policy = |subject: Uuid, object: Uuid, action: Uuid, ext: &str| {
        let r = CasbinRule::new(
            Ptype::Policy,
            subject,
            object,
            action,
            ext.to_string(),
            String::new(),
            String::new(),
            admin_id,
        );
        policies.push(r.id);
        casbin_rules.push(r);
    };

    // 0: everyone may log in. The grant every other policy assumes.
    policy(
        name_ids[R_MANAGER],
        name_ids[OBJ_LOGIN],
        name_ids[ACT_LOGIN],
        "{}",
    );
    // 1: ops leads reach the admin TUI.
    policy(
        name_ids[R_OPS_LEAD],
        name_ids[OBJ_ADMIN],
        name_ids[AG_INTERACTIVE],
        "{}",
    );
    // 2: ops get everything on the core hosts.
    policy(name_ids[R_OPS], name_ids[TG_CORE], name_ids[AG_ALL], "{}");
    // 3: dev gets a shell on the mars web leaf only.
    policy(
        name_ids[R_DEV],
        name_ids[TG_MARS_WEB],
        name_ids[AG_INTERACTIVE],
        "{}",
    );
    // 4: dev leads get batch actions across the lab branch.
    policy(
        name_ids[R_DEV_LEAD],
        name_ids[TG_LAB],
        name_ids[AG_BATCH],
        "{}",
    );
    // 5: a bare internal action rather than an action group, and a role with no
    // members — the enforcement path has to handle both.
    policy(
        name_ids[R_AUDIT],
        name_ids[TG_JUPITER],
        name_ids[ACT_EXEC],
        "{}",
    );
    // 6: a *user* subject and a *concrete binding* object, so neither side
    // resolves through a group.
    policy(
        user_ids[DAISY],
        binding_ids[&("sun".to_string(), S_MON)],
        name_ids[ACT_SHELL],
        "{}",
    );
    // 7: the only policy carrying a non-empty extended policy.
    policy(
        name_ids[R_VENDOR],
        name_ids[TG_VENUS],
        name_ids[AG_INTERACTIVE],
        VENDOR_EXTEND_POLICY,
    );
    // 8: staff reach their own recordings, through a group of internal objects.
    policy(
        name_ids[R_STAFF],
        name_ids[TG_SELFSERVICE],
        name_ids[AG_ALL],
        "{}",
    );
    // 9: ops leads get shell across the lab branch.
    policy(
        name_ids[R_OPS_LEAD],
        name_ids[TG_LAB],
        name_ids[AG_INTERACTIVE],
        "{}",
    );
    assert_eq!(policies.len(), POLICIES, "policy count drifted");

    // `g1` runs `v0 = containing role`, `v1 = member`; `g2`/`g3` run the other
    // way. Both helpers take `(parent, child)`.
    let mut subject_rule = |parent: Uuid, child: Uuid| {
        casbin_rules.push(CasbinRule::new(
            Ptype::G1,
            child,
            parent,
            Uuid::default(),
            String::new(),
            String::new(),
            String::new(),
            admin_id,
        ));
    };

    // Role tree; see the module docs for the drawing.
    for (parent, child) in [
        (R_MANAGER, R_OPS_LEAD),
        (R_MANAGER, R_DEV_LEAD),
        (R_MANAGER, R_AUDIT),
        (R_AUDIT, R_VENDOR),
        (R_OPS_LEAD, R_OPS),
        (R_DEV_LEAD, R_DEV),
        (R_OPS, R_STAFF),
        (R_DEV, R_STAFF),
    ] {
        subject_rule(name_ids[parent], name_ids[child]);
    }

    // Memberships. `joe` is deliberately absent, and `r_audit` has no members.
    for (role, user) in [
        (R_MANAGER, ADMIN),
        (R_OPS, JOHN),
        (R_DEV, JOHN),
        (R_DEV_LEAD, MIKE),
        (R_DEV, LUKA),
        (R_VENDOR, DAISY),
    ] {
        subject_rule(user_ids[user], name_ids[role]);
    }

    let mut group_rule = |ptype: Ptype, parent: Uuid, child: Uuid| {
        casbin_rules.push(CasbinRule::new(
            ptype,
            // Inverted relative to `g1`: the member goes in `v0`.
            child,
            parent,
            Uuid::default(),
            String::new(),
            String::new(),
            String::new(),
            admin_id,
        ));
    };

    // Object tree; see the module docs for the drawing.
    for (parent, child) in [
        (TG_ALL, TG_CORE),
        (TG_ALL, TG_LAB),
        (TG_CORE, TG_MARS),
        (TG_CORE, TG_SATURN),
        (TG_CORE, TG_SUN),
        (TG_LAB, TG_VENUS),
        (TG_LAB, TG_JUPITER),
        (TG_MARS, TG_MARS_WEB),
        (TG_MARS, TG_MARS_DB),
    ] {
        group_rule(Ptype::G2, name_ids[parent], name_ids[child]);
    }

    // Every binding joins its host's deepest group, so walking down from
    // `tg_all` reaches all 85.
    for ((host, _secret), id) in binding_ids.iter() {
        group_rule(Ptype::G2, name_ids[host_group(host)], *id);
    }

    // Internal objects as group members, not just as direct policy objects.
    for object in [OBJ_PLAYER, OBJ_LOGIN] {
        group_rule(Ptype::G2, name_ids[TG_SELFSERVICE], name_ids[object]);
    }

    for (parent, child) in [(AG_ALL, AG_INTERACTIVE), (AG_ALL, AG_BATCH)] {
        group_rule(Ptype::G3, name_ids[parent], name_ids[child]);
    }
    for (group, action) in [
        (AG_INTERACTIVE, ACT_SHELL),
        (AG_INTERACTIVE, ACT_PTY),
        (AG_BATCH, ACT_EXEC),
        // Login hangs off the root rather than either leaf.
        (AG_ALL, ACT_LOGIN),
    ] {
        group_rule(Ptype::G3, name_ids[group], name_ids[action]);
    }
    assert_eq!(casbin_rules.len(), CASBIN_RULES, "rule count drifted");

    let fixture = Fixture {
        admin_id,
        users: user_ids,
        targets: target_ids,
        secrets: secret_ids,
        names: name_ids,
        bindings: binding_ids,
        policies,
    };

    let data = Data {
        users,
        targets,
        secrets,
        target_secrets,
        casbin_names,
        casbin_rules,
    };

    (fixture, data)
}

// ---------------------------------------------------------------------- seeding

/// A seeded SQLite database on a temp file, with the ids to address it.
///
/// The `TempDir` is held here rather than dropped at the end of the setup call:
/// the connection keeps reading the file, so the directory has to outlive it.
pub struct TestDb {
    pub service: DatabaseService,
    pub fixture: Fixture,
    /// The connection URL, so a second component — `server::BastionServer`, which
    /// opens the database from a `Config` — can be pointed at this same file.
    pub url: String,
    _dir: TempDir,
}

impl TestDb {
    pub fn repo(&self) -> &dyn DatabaseRepository {
        self.service.repository()
    }
}

/// A fresh database with the full dataset written to it.
///
/// Each caller gets its own file, so tests that write are independent and can
/// run in parallel. `sqlite::memory:` would be faster but is per-connection,
/// and sea-orm's pool opens more than one.
pub async fn seed() -> TestDb {
    let dir = tempfile::tempdir().expect("temp dir");
    let url = format!(
        "sqlite://{}?mode=rwc",
        dir.path().join("fixture.db").to_string_lossy()
    );
    let service = DatabaseService::new(&url).await.expect("open database");
    let (fixture, data) = build();
    write(service.repository(), data).await;
    TestDb {
        service,
        fixture,
        url,
        _dir: dir,
    }
}

/// Write a dataset, exercising both write paths for every kind of row.
///
/// The first row of each kind goes through the single-row create and the rest
/// through the batch. That is not just for coverage: the two disagree about
/// `updated_at` on purpose — the create stamps it, the batch writes what it is
/// given — so a seeded database has exactly one stamped row per table and the
/// rest at 0, and a test can tell which path wrote a row.
///
/// Ordered for the foreign keys: `target_secret` cascades from both `target` and
/// `secret`, so those come first.
pub async fn write(repo: &dyn DatabaseRepository, mut data: Data) {
    let first_user = data.users.remove(0);
    repo.create_user(first_user.into_active_model())
        .await
        .expect("create first user");
    let rest = data.users.len() as u64;
    assert_eq!(
        repo.create_users_batch(data.users).await.expect("users"),
        rest
    );

    let first_target = data.targets.remove(0);
    repo.create_target(first_target.into_active_model())
        .await
        .expect("create first target");
    let rest = data.targets.len() as u64;
    assert_eq!(
        repo.create_targets_batch(data.targets)
            .await
            .expect("targets"),
        rest
    );

    let first_secret = data.secrets.remove(0);
    repo.create_secret(first_secret.into_active_model())
        .await
        .expect("create first secret");
    let rest = data.secrets.len() as u64;
    assert_eq!(
        repo.create_secrets_batch(data.secrets)
            .await
            .expect("secrets"),
        rest
    );

    let first_binding = data.target_secrets.remove(0);
    repo.create_target_secret(first_binding.into_active_model())
        .await
        .expect("create first binding");
    let rest = data.target_secrets.len() as u64;
    assert_eq!(
        repo.create_target_secrets_batch(data.target_secrets)
            .await
            .expect("bindings"),
        rest
    );

    let first_name = data.casbin_names.remove(0);
    repo.create_casbin_name(first_name.into_active_model())
        .await
        .expect("create first name");
    let rest = data.casbin_names.len() as u64;
    assert_eq!(
        repo.create_casbin_names_batch(data.casbin_names)
            .await
            .expect("names"),
        rest
    );

    let first_rule = data.casbin_rules.remove(0);
    repo.create_casbin_rule(first_rule.into_active_model())
        .await
        .expect("create first rule");
    let rest = data.casbin_rules.len() as u64;
    assert_eq!(
        repo.create_casbin_rules_batch(data.casbin_rules)
            .await
            .expect("rules"),
        rest
    );
}
