//! Coverage for every method on [`DatabaseRepository`], against
//! [`crate::database::fixture`].
//!
//! Each test opens its own SQLite file through [`fixture::seed`], so they are
//! independent and the writing ones can run in parallel with the reading ones.
//! Seeding is not free (85 bindings, 124 rules, and an Argon2 hash per user), so
//! tests are grouped by area rather than one per method.

use crate::database::Uuid;
use crate::database::common::{ACT_EXEC, ACT_LOGIN, ACT_SHELL, OBJ_ADMIN, OBJ_LOGIN, OBJ_PLAYER};
use crate::database::entity::{
    casbin_name, casbin_rule as casbin_rule_entity, event_log, secret, session_recording,
    target as target_entity, target_secret as target_secret_entity, user,
};
use crate::database::error::DatabaseError;
use crate::database::fixture::{self, *};
use crate::database::models::{GroupType, NamePtype, Ptype, RecordingStatus, SessionRecording};
use crate::error::Error;
use sea_orm::ActiveValue::{NotSet, Set, Unchanged};
use std::collections::{HashMap, HashSet};

// --------------------------------------------------------------------- helpers

/// `(target, secret)` for every binding the fixture declares, as `(name, name)`
/// pairs — the readable form of the 85 rows.
fn binding_pairs() -> Vec<(String, &'static str)> {
    let mut out = Vec::new();
    for name in ["mars", "saturn", "venus"] {
        for n in 1..=10 {
            out.push((format!("{name}{n}"), S_MON));
        }
    }
    for n in 1..=5 {
        out.push((format!("jupiter{n}"), S_MON));
    }
    out.push(("sun".to_string(), S_MON));
    for s in [S_ROOT, S_DEV, S_OPER] {
        out.push(("sun".to_string(), s));
    }
    for n in 3..=8 {
        out.push((format!("mars{n}"), S_DEV));
    }
    for n in 1..=7 {
        out.push((format!("saturn{n}"), S_DEV));
    }
    for n in 1..=10 {
        out.push((format!("venus{n}"), S_DEV));
    }
    for n in 5..=10 {
        out.push((format!("mars{n}"), S_OPER));
    }
    for n in 1..=10 {
        out.push((format!("saturn{n}"), S_OPER));
    }
    for n in 3..=9 {
        out.push((format!("venus{n}"), S_OPER));
    }
    out
}

/// `Some(x)` unwrapped, or a panic naming what was missing.
fn expect_some<T>(v: Option<T>, what: &str) -> T {
    v.unwrap_or_else(|| panic!("expected {what} to exist"))
}

// ---------------------------------------------------------------- shape & seed
// `initialize`, `create_*`/`create_*_batch` (via the fixture's two write paths),
// and the plain list methods.

/// The dataset landed with the counts the fixture promises, and the two write
/// paths behaved differently in the one way that is documented: the single-row
/// create stamps `updated_at`, the batch does not.
#[tokio::test]
async fn seeding_writes_the_whole_dataset_through_both_paths() {
    let db = fixture::seed().await;
    let repo = db.repo();

    assert_eq!(repo.list_users(false).await.unwrap().len(), USERS);
    assert_eq!(repo.list_users(true).await.unwrap().len(), ACTIVE_USERS);
    assert_eq!(repo.list_targets(false).await.unwrap().len(), TARGETS);
    assert_eq!(repo.list_targets(true).await.unwrap().len(), ACTIVE_TARGETS);
    assert_eq!(repo.list_targets_info().await.unwrap().len(), TARGETS);
    assert_eq!(repo.list_secrets(false).await.unwrap().len(), SECRETS);
    assert_eq!(
        repo.list_target_secrets(false).await.unwrap().len(),
        TARGET_SECRETS
    );
    assert_eq!(
        repo.list_target_secrets(true).await.unwrap().len(),
        TARGET_SECRETS,
        "every fixture binding is active"
    );
    assert_eq!(
        repo.list_casbin_names(false).await.unwrap().len(),
        CASBIN_NAMES
    );
    assert_eq!(repo.list_casbin_rules().await.unwrap().len(), CASBIN_RULES);

    // One stamped row per table: the first of each kind, written through the
    // single-row create. Everything else came through a batch, which writes the
    // value it was handed — 0 for a freshly built domain type.
    let stamped = repo
        .list_casbin_rules()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.updated_at != 0)
        .count();
    assert_eq!(stamped, 1, "batch must not stamp updated_at");
    assert_eq!(
        repo.list_users(false)
            .await
            .unwrap()
            .iter()
            .filter(|u| u.updated_at != 0)
            .count(),
        1
    );

    // `initialize` runs in `DatabaseService::new`; calling it again is a no-op
    // because every table already exists, and must not disturb the rows.
    repo.initialize().await.unwrap();
    assert_eq!(repo.list_users(false).await.unwrap().len(), USERS);
    assert_eq!(repo.list_casbin_rules().await.unwrap().len(), CASBIN_RULES);
}

/// `list_targets`/`list_users`/`list_secrets` order by name, and `active_only`
/// filters without inverting.
#[tokio::test]
async fn list_methods_order_by_name_and_filter_on_active() {
    let db = fixture::seed().await;
    let repo = db.repo();

    let users: Vec<String> = repo
        .list_users(false)
        .await
        .unwrap()
        .into_iter()
        .map(|u| u.username)
        .collect();
    assert_eq!(users, vec![ADMIN, DAISY, JOE, JOHN, LUKA, MIKE]);
    // `joe` is the only inactive user, and `active_only` drops him rather than
    // selecting him.
    let active: Vec<String> = repo
        .list_users(true)
        .await
        .unwrap()
        .into_iter()
        .map(|u| u.username)
        .collect();
    assert_eq!(active, vec![ADMIN, DAISY, JOHN, LUKA, MIKE]);

    let targets = repo.list_targets(false).await.unwrap();
    let names: Vec<&str> = targets.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(&names[..3], &["jupiter1", "jupiter2", "jupiter3"]);
    assert!(names.windows(2).all(|w| w[0] <= w[1]), "not name-ordered");
    // Ports round-trip through the `i32` storage column, 65535 included.
    let by_name: HashMap<&str, &_> = targets.iter().map(|t| (t.name.as_str(), t)).collect();
    assert_eq!(by_name["sun"].port, 2222);
    assert_eq!(by_name["jupiter5"].port, 65535);
    assert_eq!(by_name["mars1"].port, 22);
    assert_eq!(
        by_name["jupiter1"].proxy.as_deref(),
        Some("http://proxy.fixture.test:3128")
    );
    assert_eq!(by_name["mars1"].proxy, None);
    assert!(!by_name["saturn5"].is_active);
    assert!(!by_name["venus1"].is_active);

    let active: HashSet<String> = repo
        .list_targets(true)
        .await
        .unwrap()
        .into_iter()
        .map(|t| t.name)
        .collect();
    assert!(!active.contains("saturn5"));
    assert!(!active.contains("venus1"));
    assert!(active.contains("saturn4"));

    // `list_targets_info` is the same set, projected to four columns.
    let info = repo.list_targets_info().await.unwrap();
    assert_eq!(info.len(), TARGETS, "info is unfiltered");
    let sun = info.iter().find(|t| t.name == "sun").unwrap();
    assert_eq!(sun.port, 2222);
    assert_eq!(sun.hostname, "sun.fixture.test");

    let secrets: Vec<String> = repo
        .list_secrets(false)
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.name)
        .collect();
    assert_eq!(secrets, vec![S_DEV, S_MON, S_OPER, S_ROOT]);
    assert_eq!(repo.list_secrets(true).await.unwrap().len(), SECRETS);
}

// ------------------------------------------------------------------ user reads

/// `get_user_by_id`, `get_user_by_username`, `list_users_with_role`, and the
/// credential accessors on the row that comes back.
#[tokio::test]
async fn user_reads_resolve_ids_names_and_roles() {
    let db = fixture::seed().await;
    let repo = db.repo();
    let f = &db.fixture;

    let john = expect_some(repo.get_user_by_id(f.user(JOHN)).await.unwrap(), "john");
    assert_eq!(john.username, JOHN);
    assert_eq!(john.email.as_deref(), Some("john@fixture.test"));
    assert_eq!(john.updated_by, f.admin_id);
    // The Argon2 hash survived the round trip, and the key list survived the
    // JSON-in-TEXT column.
    assert!(john.verify_password(PASSWORD));
    assert!(!john.verify_password("wrong"));
    assert_eq!(
        john.get_authorized_keys(),
        Some(&[USER_PUBLIC_KEY.to_string()][..])
    );
    assert_eq!(john.print_authorized_keys(), "********");
    assert_eq!(john.print_password(), "********");

    // `joe` has neither credential, so both accessors report absence rather than
    // an empty string.
    let joe = expect_some(repo.get_user_by_id(f.user(JOE)).await.unwrap(), "joe");
    assert!(!joe.verify_password(PASSWORD));
    assert_eq!(joe.get_authorized_keys(), None);
    assert_eq!(joe.print_password(), "");
    assert!(joe.force_init_pass);

    // `get_user_by_id` ignores `is_active`; `get_user_by_username` respects it.
    assert!(repo.get_user_by_id(f.user(JOE)).await.unwrap().is_some());
    assert!(
        repo.get_user_by_username(JOE, true)
            .await
            .unwrap()
            .is_none(),
        "a deactivated account must not authenticate"
    );
    assert!(
        repo.get_user_by_username(JOE, false)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        repo.get_user_by_username(JOHN, true)
            .await
            .unwrap()
            .is_some()
    );
    assert!(repo.get_user_by_id(Uuid::now_v7()).await.unwrap().is_none());
    assert!(
        repo.get_user_by_username("nobody", false)
            .await
            .unwrap()
            .is_none()
    );

    // Roles are aggregated per user; a user with none gets an empty string, not a
    // missing row.
    let roles: HashMap<String, String> = repo
        .list_users_with_role(false)
        .await
        .unwrap()
        .into_iter()
        .map(|u| (u.user.username.clone(), u.role))
        .collect();
    assert_eq!(roles.len(), USERS);
    assert_eq!(roles[ADMIN], R_MANAGER);
    assert_eq!(&roles[JOHN], &[R_OPS, ", ", R_DEV].concat());
    assert_eq!(roles[MIKE], R_DEV_LEAD);
    assert_eq!(roles[LUKA], R_DEV);
    // `daisy` is granted by a policy naming her directly, but her *role* is only
    // the one `g1` row — the policy must not leak into this column.
    assert_eq!(roles[DAISY], R_VENDOR);
    assert_eq!(roles[JOE], "");
    assert_eq!(
        repo.list_users_with_role(true).await.unwrap().len(),
        ACTIVE_USERS
    );
}

// ----------------------------------------------------------------- user writes

/// `update_user` writes only what was `Set`, and `delete_user` reports whether a
/// row went.
#[tokio::test]
async fn user_writes_are_partial_and_deletes_are_idempotent() {
    let db = fixture::seed().await;
    let repo = db.repo();
    let f = &db.fixture;

    let before = expect_some(repo.get_user_by_id(f.user(LUKA)).await.unwrap(), "luka");

    // Rename only: the password hash and the flags must survive untouched, which
    // is the whole point of taking an `ActiveModel`.
    let updated = repo
        .update_user(user::ActiveModel {
            id: Unchanged(f.user(LUKA)),
            email: Set(Some("luka@fixture.test".to_string())),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(updated.email.as_deref(), Some("luka@fixture.test"));
    assert_eq!(updated.username, LUKA);
    assert!(updated.verify_password(PASSWORD), "hash was clobbered");
    assert_eq!(updated.force_init_pass, before.force_init_pass);
    assert!(updated.updated_at >= before.updated_at, "not restamped");

    // Deactivation is a normal update, and closes the login path.
    repo.update_user(user::ActiveModel {
        id: Unchanged(f.user(LUKA)),
        is_active: Set(false),
        ..Default::default()
    })
    .await
    .unwrap();
    assert!(
        repo.get_user_by_username(LUKA, true)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(repo.list_users(true).await.unwrap().len(), ACTIVE_USERS - 1);

    // Clearing a credential is `Set(None)`, distinct from leaving it `NotSet`.
    let cleared = repo
        .update_user(user::ActiveModel {
            id: Unchanged(f.user(JOHN)),
            authorized_keys: Set(None),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(cleared.get_authorized_keys(), None);
    assert!(cleared.verify_password(PASSWORD));

    assert!(repo.delete_user(f.user(JOE)).await.unwrap());
    assert!(
        !repo.delete_user(f.user(JOE)).await.unwrap(),
        "second delete reports false rather than erroring"
    );
    assert!(repo.get_user_by_id(f.user(JOE)).await.unwrap().is_none());
    assert_eq!(repo.list_users(false).await.unwrap().len(), USERS - 1);
    assert!(!repo.delete_user(Uuid::now_v7()).await.unwrap());
}

// ---------------------------------------------------------------- target reads

/// The connection path: resolve a binding id to its host and its credential.
#[tokio::test]
async fn target_and_secret_resolve_through_a_binding() {
    let db = fixture::seed().await;
    let repo = db.repo();
    let f = &db.fixture;

    let mars1_mon = f.binding("mars1", S_MON);
    let target = expect_some(
        repo.get_target_by_target_secret_id(mars1_mon, true)
            .await
            .unwrap(),
        "mars1 via binding",
    );
    assert_eq!(target.name, "mars1");
    assert_eq!(target.server_public_key, HOST_PUBLIC_KEY);

    let secret = expect_some(
        repo.get_secret_by_target_secret_id(mars1_mon, true)
            .await
            .unwrap(),
        "s_mon via binding",
    );
    assert_eq!(secret.user, "mon");
    assert_eq!(secret.print_password(), "", "s_mon carries no password");

    // `venus1` is inactive, so `active_only` closes the route in both
    // directions while the row itself is still readable.
    let venus1_mon = f.binding("venus1", S_MON);
    assert!(
        repo.get_target_by_target_secret_id(venus1_mon, true)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repo.get_target_by_target_secret_id(venus1_mon, false)
            .await
            .unwrap()
            .is_some()
    );
    // The *secret* is active even though the target is not, so this side still
    // resolves — deactivating a host does not deactivate the credential.
    assert!(
        repo.get_secret_by_target_secret_id(venus1_mon, true)
            .await
            .unwrap()
            .is_some()
    );

    // Many ids collapse to targets: `sun` has four bindings but is one host.
    let sun_bindings: Vec<Uuid> = [S_ROOT, S_DEV, S_OPER, S_MON]
        .into_iter()
        .map(|s| f.binding("sun", s))
        .collect();
    let hosts = repo
        .get_targets_by_target_secret_ids(sun_bindings.clone(), true)
        .await
        .unwrap();
    assert_eq!(hosts.len(), 1, "four bindings, one host");
    assert_eq!(hosts[0].name, "sun");

    let mixed = repo
        .get_targets_by_target_secret_ids(vec![mars1_mon, venus1_mon], true)
        .await
        .unwrap();
    assert_eq!(mixed.len(), 1, "venus1 is inactive");
    assert_eq!(
        repo.get_targets_by_target_secret_ids(vec![mars1_mon, venus1_mon], false)
            .await
            .unwrap()
            .len(),
        2
    );
    assert!(
        repo.get_targets_by_target_secret_ids(vec![], true)
            .await
            .unwrap()
            .is_empty(),
        "empty input short-circuits"
    );

    // Direct lookups by the target's own id.
    let saturn5 = f.target("saturn5");
    assert!(
        repo.get_target_by_id(saturn5, false)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        repo.get_target_by_id(saturn5, true)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repo.get_target_by_id(Uuid::now_v7(), false)
            .await
            .unwrap()
            .is_none()
    );

    let s_dev = expect_some(
        repo.get_secret_by_id(f.secret(S_DEV)).await.unwrap(),
        "s_dev",
    );
    assert_eq!(s_dev.user, "dev");
    assert_eq!(s_dev.print_private_key(), "********");
    assert_eq!(s_dev.print_password(), "", "s_dev is key-only");
    assert!(
        repo.get_secret_by_id(Uuid::now_v7())
            .await
            .unwrap()
            .is_none()
    );
}

/// `list_secrets_by_target_id` returns every secret, flagged with whether this
/// host is bound to it.
#[tokio::test]
async fn secrets_for_target_flag_bound_and_unbound() {
    let db = fixture::seed().await;
    let repo = db.repo();
    let f = &db.fixture;

    // `mars1` is bound to `s_mon` only, but all four secrets come back — the bind
    // screen needs the unbound ones to offer them.
    let for_mars1: HashMap<String, bool> = repo
        .list_secrets_by_target_id(f.target("mars1"))
        .await
        .unwrap()
        .into_iter()
        .map(|s| (s.name, s.is_bound))
        .collect();
    assert_eq!(for_mars1.len(), SECRETS);
    assert!(for_mars1[S_MON]);
    assert!(!for_mars1[S_DEV]);
    assert!(!for_mars1[S_ROOT]);

    // `sun` is bound to all four.
    let for_sun = repo
        .list_secrets_by_target_id(f.target("sun"))
        .await
        .unwrap();
    assert_eq!(for_sun.iter().filter(|s| s.is_bound).count(), SECRETS);

    // A deactivated binding reads as unbound: `is_bound` counts active rows only.
    repo.upsert_target_secret(f.target("mars1"), f.secret(S_MON), false, f.admin_id)
        .await
        .unwrap();
    let after: HashMap<String, bool> = repo
        .list_secrets_by_target_id(f.target("mars1"))
        .await
        .unwrap()
        .into_iter()
        .map(|s| (s.name, s.is_bound))
        .collect();
    assert!(!after[S_MON], "deactivated binding still reads as bound");
}

// --------------------------------------------------------------- target writes

/// `create_target`/`update_target`/`delete_target`, and the cascade that takes
/// the bindings with the host.
#[tokio::test]
async fn target_writes_and_the_binding_cascade() {
    let db = fixture::seed().await;
    let repo = db.repo();
    let f = &db.fixture;

    let id = Uuid::now_v7();
    let created = repo
        .create_target(target_entity::ActiveModel {
            id: Set(id),
            name: Set("pluto".to_string()),
            hostname: Set("pluto.fixture.test".to_string()),
            port: Set(2022),
            server_public_key: Set(HOST_PUBLIC_KEY.to_string()),
            description: Set(None),
            proxy: Set(None),
            is_active: Set(true),
            updated_by: Set(f.admin_id),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(created.name, "pluto");
    assert_eq!(created.port, 2022);
    assert_ne!(created.updated_at, 0, "the create stamps updated_at");

    let renamed = repo
        .update_target(target_entity::ActiveModel {
            id: Unchanged(id),
            port: Set(2200),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(renamed.port, 2200);
    assert_eq!(renamed.hostname, "pluto.fixture.test", "hostname clobbered");
    assert_eq!(renamed.server_public_key, HOST_PUBLIC_KEY);

    // `target_secret` has a real cascading foreign key, unlike the `casbin_rule`
    // rows that reference bindings.
    let sun = f.target("sun");
    assert_eq!(
        repo.list_secrets_by_target_id(sun)
            .await
            .unwrap()
            .iter()
            .filter(|s| s.is_bound)
            .count(),
        SECRETS
    );
    assert!(repo.delete_target(sun).await.unwrap());
    assert_eq!(
        repo.list_target_secrets(false).await.unwrap().len(),
        TARGET_SECRETS - SECRETS,
        "sun's four bindings did not cascade"
    );
    assert!(!repo.delete_target(sun).await.unwrap());
    // The `g2` rules that named those bindings are still there — no foreign key
    // reaches them, which is the documented asymmetry.
    assert_eq!(repo.list_casbin_rules().await.unwrap().len(), CASBIN_RULES);
}

// --------------------------------------------------------------- secret writes

#[tokio::test]
async fn secret_writes_keep_unset_ciphertext() {
    let db = fixture::seed().await;
    let repo = db.repo();
    let f = &db.fixture;

    let id = Uuid::now_v7();
    let created = repo
        .create_secret(secret::ActiveModel {
            id: Set(id),
            name: Set("s_backup".to_string()),
            user: Set("backup".to_string()),
            password: Set(Some("ciphertext-backup".to_string())),
            private_key: Set(None),
            public_key: Set(None),
            is_active: Set(true),
            updated_by: Set(f.admin_id),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(created.name, "s_backup");
    assert_eq!(created.print_password(), "********");
    assert_ne!(created.updated_at, 0);

    // A rename must not force a re-encrypt: leaving `password` `NotSet` keeps the
    // stored ciphertext.
    let renamed = repo
        .update_secret(secret::ActiveModel {
            id: Unchanged(id),
            name: Set("s_backup2".to_string()),
            password: NotSet,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(renamed.name, "s_backup2");
    assert_eq!(renamed.print_password(), "********");

    let mut cleared = repo
        .update_secret(secret::ActiveModel {
            id: Unchanged(id),
            password: Set(None),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(cleared.print_password(), "");
    assert_eq!(cleared.take_password(), None);

    assert_eq!(repo.list_secrets(false).await.unwrap().len(), SECRETS + 1);
    assert!(repo.delete_secret(id).await.unwrap());
    assert!(!repo.delete_secret(id).await.unwrap());
    assert_eq!(repo.list_secrets(false).await.unwrap().len(), SECRETS);

    // Deleting a bound secret cascades its bindings, the mirror of the target
    // side. `s_root` is bound to `sun` alone.
    assert!(repo.delete_secret(f.secret(S_ROOT)).await.unwrap());
    assert_eq!(
        repo.list_target_secrets(false).await.unwrap().len(),
        TARGET_SECRETS - 1
    );

    // Deactivating a secret is what closes a route without deleting anything.
    repo.update_secret(secret::ActiveModel {
        id: Unchanged(f.secret(S_MON)),
        is_active: Set(false),
        ..Default::default()
    })
    .await
    .unwrap();
    assert_eq!(repo.list_secrets(true).await.unwrap().len(), SECRETS - 2);
    assert!(
        repo.get_secret_by_target_secret_id(f.binding("mars1", S_MON), true)
            .await
            .unwrap()
            .is_none()
    );
    let mut s_mon = expect_some(
        repo.get_secret_by_target_secret_id(f.binding("mars1", S_MON), false)
            .await
            .unwrap(),
        "inactive s_mon",
    );
    assert_eq!(s_mon.take_public_key(), None);
    assert_eq!(s_mon.take_private_key(), None);
}

// -------------------------------------------------------------- binding writes

/// `create_target_secret`, `update_target_secret`, `delete_target_secret`, and
/// the `upsert` the bind screen actually uses.
#[tokio::test]
async fn upsert_binding_preserves_the_id_across_a_toggle() {
    let db = fixture::seed().await;
    let repo = db.repo();
    let f = &db.fixture;

    let mars1 = f.target("mars1");
    let s_dev = f.secret(S_DEV);
    // `mars1` is outside the `s_dev` range (mars3-8), so this pair is new.
    repo.upsert_target_secret(mars1, s_dev, true, f.admin_id)
        .await
        .unwrap();
    let bindings = repo.list_target_secrets(false).await.unwrap();
    assert_eq!(bindings.len(), TARGET_SECRETS + 1);
    let inserted = bindings
        .iter()
        .find(|b| b.target_id == mars1 && b.secret_id == s_dev)
        .expect("inserted binding");
    assert!(inserted.is_active);
    assert_eq!(inserted.updated_by, f.admin_id);

    // Toggling off and back on must keep the id, or every rule granting it would
    // be left pointing at a row that no longer exists.
    let id = inserted.id;
    repo.upsert_target_secret(mars1, s_dev, false, f.user(JOHN))
        .await
        .unwrap();
    let off = repo
        .list_target_secrets(false)
        .await
        .unwrap()
        .into_iter()
        .find(|b| b.id == id)
        .expect("binding survived the toggle");
    assert!(!off.is_active);
    assert_eq!(off.updated_by, f.user(JOHN), "update writes updated_by");
    assert_eq!(
        repo.list_target_secrets(true).await.unwrap().len(),
        TARGET_SECRETS
    );

    repo.upsert_target_secret(mars1, s_dev, true, f.admin_id)
        .await
        .unwrap();
    assert_eq!(
        repo.list_target_secrets(true)
            .await
            .unwrap()
            .iter()
            .filter(|b| b.id == id)
            .count(),
        1,
        "the upsert re-inserted instead of updating"
    );

    // The plain create is the raw path: a duplicate pair violates the unique
    // index rather than updating.
    let dup = repo
        .create_target_secret(target_secret_entity::ActiveModel {
            id: Set(Uuid::now_v7()),
            target_id: Set(mars1),
            secret_id: Set(s_dev),
            is_active: Set(true),
            updated_by: Set(f.admin_id),
            ..Default::default()
        })
        .await;
    assert!(dup.is_err(), "UNIQUE(target_id, secret_id) not enforced");

    let fresh = repo
        .create_target_secret(target_secret_entity::ActiveModel {
            id: Set(Uuid::now_v7()),
            target_id: Set(mars1),
            secret_id: Set(f.secret(S_ROOT)),
            is_active: Set(true),
            updated_by: Set(f.admin_id),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_ne!(fresh.updated_at, 0);

    let deactivated = repo
        .update_target_secret(target_secret_entity::ActiveModel {
            id: Unchanged(fresh.id),
            is_active: Set(false),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!deactivated.is_active);
    assert_eq!(deactivated.target_id, mars1);

    assert!(repo.delete_target_secret(fresh.id).await.unwrap());
    assert!(!repo.delete_target_secret(fresh.id).await.unwrap());
}

// ------------------------------------------------------------ casbin_rule reads

/// `list_casbin_rules`, `list_casbin_rules_by_ptype`, `list_roles_by_user_id`.
#[tokio::test]
async fn rule_reads_group_by_ptype_and_resolve_roles() {
    let db = fixture::seed().await;
    let repo = db.repo();
    let f = &db.fixture;

    let all = repo.list_casbin_rules().await.unwrap();
    assert_eq!(all.len(), CASBIN_RULES);
    // Ordered by `ptype` then id: `p` first, then `g1`, `g2`, `g3`.
    let ptypes: Vec<Ptype> = all.iter().map(|r| r.ptype).collect();
    let mut expected = ptypes.clone();
    expected.sort_by_key(|p| match p {
        Ptype::Policy => 0,
        Ptype::G1 => 1,
        Ptype::G2 => 2,
        Ptype::G3 => 3,
    });
    assert_eq!(ptypes, expected, "not ptype-ordered");

    assert_eq!(
        repo.list_casbin_rules_by_ptype(Ptype::Policy)
            .await
            .unwrap()
            .len(),
        POLICIES
    );
    assert_eq!(
        repo.list_casbin_rules_by_ptype(Ptype::G1)
            .await
            .unwrap()
            .len(),
        G1_RULES
    );
    assert_eq!(
        repo.list_casbin_rules_by_ptype(Ptype::G2)
            .await
            .unwrap()
            .len(),
        G2_RULES
    );
    assert_eq!(
        repo.list_casbin_rules_by_ptype(Ptype::G3)
            .await
            .unwrap()
            .len(),
        G3_RULES
    );

    // The extended policy is stored verbatim, which is what `verify_extend_policy`
    // will parse.
    let vendor = all
        .iter()
        .find(|r| r.id == f.policy(7))
        .expect("vendor policy");
    assert_eq!(vendor.v3, VENDOR_EXTEND_POLICY);
    assert_eq!(vendor.v4, "");
    // Group rules leave `v2` at the zero uuid, not null — the 7-column unique
    // index needs them to compare equal.
    let g1 = repo.list_casbin_rules_by_ptype(Ptype::G1).await.unwrap();
    assert!(g1.iter().all(|r| r.v2 == Uuid::default()));
    assert!(g1.iter().all(|r| r.v3.is_empty()));

    // Every role comes back, with `casbin_rule_id` set only on the ones held.
    let admin_roles = repo.list_roles_by_user_id(f.admin_id).await.unwrap();
    assert_eq!(admin_roles.len(), 8, "all g1 names, held or not");
    let names: Vec<&str> = admin_roles.iter().map(|r| r.role.as_str()).collect();
    assert_eq!(
        names,
        vec![
            R_AUDIT, R_DEV, R_DEV_LEAD, R_MANAGER, R_OPS, R_OPS_LEAD, R_STAFF, R_VENDOR
        ]
    );
    let held: Vec<&str> = admin_roles
        .iter()
        .filter(|r| r.casbin_rule_id.is_some())
        .map(|r| r.role.as_str())
        .collect();
    assert_eq!(
        held,
        vec![R_MANAGER],
        "only the direct membership, not the inherited chain"
    );
    assert_eq!(admin_roles[5].casbin_name_id, f.name(R_OPS_LEAD));

    // `joe` holds nothing, so every row comes back unbound.
    let joe_roles = repo.list_roles_by_user_id(f.user(JOE)).await.unwrap();
    assert_eq!(joe_roles.len(), 8);
    assert!(joe_roles.iter().all(|r| r.casbin_rule_id.is_none()));
}

/// `list_casbin_rule_group_by_ptype` — the labelled view `RoleManage` builds its
/// graph from, for each of the three hierarchies.
#[tokio::test]
async fn rule_group_labels_hold_exactly_one_label_per_side() {
    let db = fixture::seed().await;
    let repo = db.repo();

    // `g1`: v0 is always a role; v1 is a user or a nested role.
    let g1 = repo
        .list_casbin_rule_group_by_ptype(Ptype::G1)
        .await
        .unwrap();
    assert_eq!(g1.len(), G1_RULES);
    assert!(
        g1.iter()
            .all(|r| r.v0_object_label.is_none() && r.v0_group_label.is_some()),
        "a g1 subject is always a group"
    );
    let nesting: HashSet<(String, String)> = g1
        .iter()
        .filter(|r| r.v1_group_label.is_some())
        .map(|r| {
            assert!(r.v1_object_label.is_none(), "both labels set on v1");
            (
                r.v0_group_label.clone().unwrap(),
                r.v1_group_label.clone().unwrap(),
            )
        })
        .collect();
    assert_eq!(nesting.len(), 8);
    // `(v0, v1)` is `(containing role, nested role)`, the same way round as a
    // membership row. `server::casbin` builds the edge `v1 → v0`, so this is what
    // makes a user walk *up* to their ancestors.
    assert!(nesting.contains(&(R_AUDIT.to_string(), R_MANAGER.to_string())));
    assert!(nesting.contains(&(R_STAFF.to_string(), R_OPS.to_string())));

    let members: HashSet<(String, String)> = g1
        .iter()
        .filter(|r| r.v1_object_label.is_some())
        .map(|r| {
            assert!(r.v1_group_label.is_none(), "both labels set on v1");
            (
                r.v0_group_label.clone().unwrap(),
                r.v1_object_label.clone().unwrap(),
            )
        })
        .collect();
    assert_eq!(members.len(), 6);
    assert!(members.contains(&(R_MANAGER.to_string(), ADMIN.to_string())));
    assert!(members.contains(&(R_VENDOR.to_string(), DAISY.to_string())));
    assert!(!members.iter().any(|(_, u)| u == JOE), "joe holds no role");

    // `g2`: v0 is a binding (composed label) or an internal object or a nested
    // group; v1 is always a group.
    let g2 = repo
        .list_casbin_rule_group_by_ptype(Ptype::G2)
        .await
        .unwrap();
    assert_eq!(g2.len(), G2_RULES);
    assert!(
        g2.iter()
            .all(|r| r.v1_object_label.is_none() && r.v1_group_label.is_some())
    );

    let bindings: HashMap<String, String> = g2
        .iter()
        .filter(|r| r.v0_object_label.is_some() && r.v0_group_label.is_none())
        .map(|r| {
            (
                r.v0_object_label.clone().unwrap(),
                r.v1_group_label.clone().unwrap(),
            )
        })
        .collect();
    // 85 bindings plus the two internal objects in `tg_selfservice`.
    assert_eq!(bindings.len(), TARGET_SECRETS + 2);
    // `user@target:port`, with the off-default port carried through.
    assert_eq!(bindings["mon@mars1:22"], TG_MARS_WEB);
    assert_eq!(bindings["mon@mars6:22"], TG_MARS_DB);
    assert_eq!(bindings["root@sun:2222"], TG_SUN);
    assert_eq!(bindings["mon@jupiter5:65535"], TG_JUPITER);
    assert_eq!(bindings[OBJ_PLAYER], TG_SELFSERVICE);

    let nesting: HashSet<(String, String)> = g2
        .iter()
        .filter(|r| r.v0_group_label.is_some())
        .map(|r| {
            assert!(r.v0_object_label.is_none(), "both labels set on v0");
            (
                r.v1_group_label.clone().unwrap(),
                r.v0_group_label.clone().unwrap(),
            )
        })
        .collect();
    assert_eq!(nesting.len(), 9);
    assert!(nesting.contains(&(TG_ALL.to_string(), TG_CORE.to_string())));
    assert!(nesting.contains(&(TG_MARS.to_string(), TG_MARS_WEB.to_string())));

    // `g3`: v0 is an internal action or a nested group; v1 is always a group.
    let g3 = repo
        .list_casbin_rule_group_by_ptype(Ptype::G3)
        .await
        .unwrap();
    assert_eq!(g3.len(), G3_RULES);
    assert!(
        g3.iter()
            .all(|r| r.v1_object_label.is_none() && r.v1_group_label.is_some())
    );
    let actions: HashMap<String, String> = g3
        .iter()
        .filter(|r| r.v0_object_label.is_some())
        .map(|r| {
            assert!(r.v0_group_label.is_none());
            (
                r.v0_object_label.clone().unwrap(),
                r.v1_group_label.clone().unwrap(),
            )
        })
        .collect();
    assert_eq!(actions.len(), 4);
    assert_eq!(actions[ACT_SHELL], AG_INTERACTIVE);
    assert_eq!(actions[ACT_EXEC], AG_BATCH);
    assert_eq!(actions[ACT_LOGIN], AG_ALL);

    // The invariant `RoleManage::parse_casbin_rule_group` enforces: across all
    // three hierarchies, exactly one label per side.
    for row in g1.iter().chain(g2.iter()).chain(g3.iter()) {
        assert!(
            row.v0_object_label.is_some() ^ row.v0_group_label.is_some(),
            "v0 of {} has both or neither label",
            row.id
        );
        assert!(
            row.v1_object_label.is_some() ^ row.v1_group_label.is_some(),
            "v1 of {} has both or neither label",
            row.id
        );
    }

    // Ids are stable across the labelled and raw views.
    let raw: HashSet<Uuid> = repo
        .list_casbin_rules_by_ptype(Ptype::G3)
        .await
        .unwrap()
        .iter()
        .map(|r| r.id)
        .collect();
    assert_eq!(g3.iter().map(|r| r.id).collect::<HashSet<_>>(), raw);
}

// ----------------------------------------------------------- casbin_rule writes

#[tokio::test]
async fn rule_writes_and_group_scoped_delete() {
    let db = fixture::seed().await;
    let repo = db.repo();
    let f = &db.fixture;

    // A new policy: `r_audit` gets interactive access to the saturn group.
    let id = Uuid::now_v7();
    let created = repo
        .create_casbin_rule(casbin_rule_entity::ActiveModel {
            id: Set(id),
            ptype: Set(Ptype::Policy),
            v0: Set(f.name(R_AUDIT)),
            v1: Set(f.name(TG_SATURN)),
            v2: Set(f.name(AG_INTERACTIVE)),
            v3: Set("{}".to_string()),
            v4: Set(String::new()),
            v5: Set(String::new()),
            updated_by: Set(f.admin_id),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(created.v0, f.name(R_AUDIT));
    assert_ne!(created.updated_at, 0);
    assert_eq!(
        repo.list_casbin_rules_by_ptype(Ptype::Policy)
            .await
            .unwrap()
            .len(),
        POLICIES + 1
    );

    // The same seven columns again: the unique index rejects it.
    let dup = repo
        .create_casbin_rule(casbin_rule_entity::ActiveModel {
            id: Set(Uuid::now_v7()),
            ptype: Set(Ptype::Policy),
            v0: Set(f.name(R_AUDIT)),
            v1: Set(f.name(TG_SATURN)),
            v2: Set(f.name(AG_INTERACTIVE)),
            v3: Set("{}".to_string()),
            v4: Set(String::new()),
            v5: Set(String::new()),
            updated_by: Set(f.admin_id),
            ..Default::default()
        })
        .await;
    assert!(dup.is_err(), "the 7-column unique index is not enforced");

    // Retarget one column without respelling the rest.
    let retargeted = repo
        .update_casbin_rule(casbin_rule_entity::ActiveModel {
            id: Unchanged(id),
            v2: Set(f.name(AG_BATCH)),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(retargeted.v2, f.name(AG_BATCH));
    assert_eq!(retargeted.v1, f.name(TG_SATURN), "v1 clobbered");

    assert!(repo.delete_casbin_rule(id).await.unwrap());
    assert!(!repo.delete_casbin_rule(id).await.unwrap());

    // Revoking a membership goes by `(v0, v1)`, not by id — `g1` puts the role in
    // v0 and the member in v1.
    assert!(
        repo.delete_casbin_rule_by_group(GroupType::Subject, f.name(R_OPS), f.user(JOHN))
            .await
            .unwrap()
    );
    assert_eq!(
        repo.list_casbin_rules_by_ptype(Ptype::G1)
            .await
            .unwrap()
            .len(),
        G1_RULES - 1
    );
    let roles = repo.list_users_with_role(false).await.unwrap();
    let john = roles.iter().find(|u| u.user.username == JOHN).unwrap();
    assert_eq!(john.role, R_DEV, "john's role survived the revoke");

    // Arguments the other way round match nothing: direction is load-bearing.
    assert!(
        !repo
            .delete_casbin_rule_by_group(GroupType::Subject, f.user(LUKA), f.name(R_DEV))
            .await
            .unwrap()
    );
    // `g2`/`g3` are inverted relative to `g1`: the member is in v0.
    assert!(
        repo.delete_casbin_rule_by_group(
            GroupType::Object,
            f.binding("mars1", S_MON),
            f.name(TG_MARS_WEB)
        )
        .await
        .unwrap()
    );
    assert!(
        repo.delete_casbin_rule_by_group(
            GroupType::Action,
            f.name(ACT_SHELL),
            f.name(AG_INTERACTIVE)
        )
        .await
        .unwrap()
    );
    assert_eq!(
        repo.list_casbin_rules_by_ptype(Ptype::G2)
            .await
            .unwrap()
            .len(),
        G2_RULES - 1
    );
    assert_eq!(
        repo.list_casbin_rules_by_ptype(Ptype::G3)
            .await
            .unwrap()
            .len(),
        G3_RULES - 1
    );
}

// ----------------------------------------------------------- casbin_name reads

#[tokio::test]
async fn name_reads_filter_by_ptype_and_hide_internals() {
    let db = fixture::seed().await;
    let repo = db.repo();
    let f = &db.fixture;

    let all = repo.list_casbin_names(false).await.unwrap();
    assert_eq!(all.len(), CASBIN_NAMES);
    // Ordered by `ptype` then name, so the `g1` roles come first and the two
    // internal blocks last.
    assert_eq!(all[0].ptype, NamePtype::G1);
    assert_eq!(all[0].name, R_AUDIT);
    assert_eq!(all.last().unwrap().ptype, NamePtype::InternalObjectType);
    let ptype_order: Vec<i32> = all
        .iter()
        .map(|n| match n.ptype {
            NamePtype::G1 => 1,
            NamePtype::G2 => 2,
            NamePtype::G3 => 3,
            NamePtype::InternalActionType => 4,
            NamePtype::InternalObjectType => 5,
        })
        .collect();
    assert!(ptype_order.windows(2).all(|w| w[0] <= w[1]));

    // `r_audit` is the one inactive name.
    assert_eq!(
        repo.list_casbin_names(true).await.unwrap().len(),
        CASBIN_NAMES - 1
    );

    assert_eq!(
        repo.list_casbin_names_by_ptype(NamePtype::G1, false)
            .await
            .unwrap()
            .len(),
        8
    );
    assert_eq!(
        repo.list_casbin_names_by_ptype(NamePtype::G1, true)
            .await
            .unwrap()
            .len(),
        7
    );
    assert_eq!(
        repo.list_casbin_names_by_ptype(NamePtype::G2, false)
            .await
            .unwrap()
            .len(),
        11
    );
    assert_eq!(
        repo.list_casbin_names_by_ptype(NamePtype::G3, false)
            .await
            .unwrap()
            .len(),
        3
    );
    assert_eq!(
        repo.list_casbin_names_by_ptype(NamePtype::InternalActionType, false)
            .await
            .unwrap()
            .len(),
        5
    );
    assert_eq!(
        repo.list_casbin_names_by_ptype(NamePtype::InternalObjectType, false)
            .await
            .unwrap()
            .len(),
        3
    );

    // The admin list drops the built-ins: they cannot be edited, so offering them
    // would only produce `InternalTypeModification`.
    let visible = repo.list_casbin_names_user_visible(false).await.unwrap();
    assert_eq!(visible.len(), CASBIN_NAMES - INTERNAL_NAMES);
    assert!(visible.iter().all(|n| !n.is_internal()));
    assert_eq!(
        repo.list_casbin_names_user_visible(true)
            .await
            .unwrap()
            .len(),
        CASBIN_NAMES - INTERNAL_NAMES - 1
    );

    // The reverse direction, which is how startup finds the built-ins.
    let act_shell = expect_some(
        repo.get_casbin_name_by_name(ACT_SHELL).await.unwrap(),
        ACT_SHELL,
    );
    assert_eq!(act_shell.id, f.name(ACT_SHELL));
    assert_eq!(act_shell.ptype, NamePtype::InternalActionType);
    assert!(act_shell.is_internal());
    let audit = expect_some(
        repo.get_casbin_name_by_name(R_AUDIT).await.unwrap(),
        R_AUDIT,
    );
    assert!(!audit.is_active);
    assert!(!audit.is_internal());
    assert!(
        repo.get_casbin_name_by_name("nope")
            .await
            .unwrap()
            .is_none()
    );
}

/// The internal names are resolved by name at startup, so renaming, re-typing or
/// deleting one has to be refused.
#[tokio::test]
async fn internal_names_are_protected_from_rename_and_delete() {
    let db = fixture::seed().await;
    let repo = db.repo();
    let f = &db.fixture;

    let internal = f.name(OBJ_ADMIN);

    let renamed = repo
        .update_casbin_name(casbin_name::ActiveModel {
            id: Unchanged(internal),
            name: Set("stolen".to_string()),
            ..Default::default()
        })
        .await;
    assert!(matches!(
        renamed,
        Err(Error::Database(DatabaseError::InternalTypeModification))
    ));

    let retyped = repo
        .update_casbin_name(casbin_name::ActiveModel {
            id: Unchanged(internal),
            ptype: Set(NamePtype::G2),
            ..Default::default()
        })
        .await;
    assert!(matches!(
        retyped,
        Err(Error::Database(DatabaseError::InternalTypeModification))
    ));

    // Only an explicit `Set` on `ptype` or `name` counts, so toggling
    // `is_active` on an internal row is allowed — that is how an internal object
    // gets revoked.
    let toggled = repo
        .update_casbin_name(casbin_name::ActiveModel {
            id: Unchanged(internal),
            is_active: Set(false),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!toggled.is_active);
    assert_eq!(toggled.name, OBJ_ADMIN);
    assert!(!repo.check_object_active(internal).await.unwrap());

    let deleted = repo.delete_casbin_name(internal).await;
    assert!(matches!(
        deleted,
        Err(Error::Database(DatabaseError::InternalTypeModification))
    ));
    assert!(
        repo.get_casbin_name_by_name(OBJ_ADMIN)
            .await
            .unwrap()
            .is_some()
    );

    // A user-created name has none of those guards.
    let id = Uuid::now_v7();
    let created = repo
        .create_casbin_name(casbin_name::ActiveModel {
            id: Set(id),
            ptype: Set(NamePtype::G1),
            name: Set("r_temp".to_string()),
            is_active: Set(true),
            updated_by: Set(f.admin_id),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(created.name, "r_temp");
    assert_ne!(created.updated_at, 0);
    // Names are unique.
    assert!(
        repo.create_casbin_name(casbin_name::ActiveModel {
            id: Set(Uuid::now_v7()),
            ptype: Set(NamePtype::G1),
            name: Set("r_temp".to_string()),
            is_active: Set(true),
            updated_by: Set(f.admin_id),
            ..Default::default()
        })
        .await
        .is_err()
    );

    let renamed = repo
        .update_casbin_name(casbin_name::ActiveModel {
            id: Unchanged(id),
            name: Set("r_temp2".to_string()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(renamed.name, "r_temp2");
    assert!(repo.delete_casbin_name(id).await.unwrap());
    assert!(!repo.delete_casbin_name(id).await.unwrap());
    assert_eq!(
        repo.list_casbin_names(false).await.unwrap().len(),
        CASBIN_NAMES
    );
}

// -------------------------------------------------------------------- event_log

#[tokio::test]
async fn logs_are_appended_and_read_newest_first() {
    let db = fixture::seed().await;
    let repo = db.repo();
    let f = &db.fixture;

    assert!(repo.list_logs().await.unwrap().is_empty());

    let connection = Uuid::now_v7();
    for detail in ["connected to mars1", "opened a shell", "disconnected"] {
        repo.insert_log(event_log::ActiveModel {
            connection_id: Set(connection),
            detail: Set(detail.to_string()),
            log_type: Set("session".to_string()),
            user_id: Set(f.user(JOHN)),
            ..Default::default()
        })
        .await
        .unwrap();
    }

    let logs = repo.list_logs().await.unwrap();
    assert_eq!(logs.len(), 3);
    assert!(logs.iter().all(|l| l.user_id == f.user(JOHN)));
    assert!(logs.iter().all(|l| l.created_at != 0), "created_at stamped");
    // Newest first. The three may share a millisecond, so assert the ordering
    // rather than which row is first.
    let stamps: Vec<i64> = logs.iter().map(|l| l.created_at).collect();
    assert!(stamps.windows(2).all(|w| w[0] >= w[1]));
    let details: HashSet<&str> = logs.iter().map(|l| l.detail.as_str()).collect();
    assert!(details.contains("opened a shell"));
}

// ------------------------------------------------------------ session_recording

#[tokio::test]
async fn recordings_open_close_and_list_per_user_and_target() {
    let db = fixture::seed().await;
    let repo = db.repo();
    let f = &db.fixture;

    assert!(repo.list_session_recordings(None).await.unwrap().is_empty());

    // Two for john, one for mike, so the per-user lists have something to filter.
    let mut ids = Vec::new();
    for (user, target, secret) in [
        (JOHN, "mars1", S_MON),
        (JOHN, "sun", S_ROOT),
        (MIKE, "jupiter5", S_MON),
    ] {
        let id = Uuid::now_v7();
        let created = repo
            .create_session_recording(session_recording::ActiveModel {
                id: Set(id),
                user_id: Set(f.user(user)),
                target_id: Set(f.target(target)),
                secret_id: Set(f.secret(secret)),
                file_path: Set(crate::database::models::session_recording::generate_path(
                    id,
                )),
                ended_at: Set(None),
                connection_id: Set(Uuid::now_v7()),
                status: Set(RecordingStatus::Active),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_ne!(created.started_at, 0, "started_at is the write stamp");
        assert_eq!(created.ended_at, None);
        assert_eq!(created.file_path, format!("{id}.cast"));
        ids.push(id);
    }

    let opened = expect_some(
        repo.get_session_recording_by_id(ids[0]).await.unwrap(),
        "first recording",
    );
    let started = opened.started_at;

    // Closing sets `ended_at` and `status`, and must not move `started_at` —
    // that would lose when the session began.
    let closed = repo
        .update_session_recording(session_recording::ActiveModel {
            id: Unchanged(ids[0]),
            ended_at: Set(Some(started + 5_000)),
            status: Set(RecordingStatus::Completed),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(closed.ended_at, Some(started + 5_000));
    assert_eq!(closed.started_at, started, "started_at was restamped");
    assert_eq!(closed.status, RecordingStatus::Completed);

    assert_eq!(repo.list_session_recordings(None).await.unwrap().len(), 3);
    assert_eq!(
        repo.list_session_recordings(Some(2)).await.unwrap().len(),
        2
    );
    assert_eq!(
        repo.list_session_recordings(Some(0)).await.unwrap().len(),
        0
    );
    let all = repo.list_session_recordings(None).await.unwrap();
    let stamps: Vec<i64> = all.iter().map(|r| r.started_at).collect();
    assert!(stamps.windows(2).all(|w| w[0] >= w[1]), "not newest-first");

    let johns: HashSet<Uuid> = repo
        .list_session_recordings_for_user(f.user(JOHN))
        .await
        .unwrap()
        .iter()
        .map(|r| r.id)
        .collect();
    assert_eq!(johns, HashSet::from([ids[0], ids[1]]));
    assert!(
        repo.list_session_recordings_for_user(f.user(JOE))
            .await
            .unwrap()
            .is_empty()
    );

    let per_target = repo
        .list_session_recordings_for_target(f.target("mars1"))
        .await
        .unwrap();
    assert_eq!(per_target.len(), 1);
    assert_eq!(per_target[0].id, ids[0]);
    assert!(
        repo.list_session_recordings_for_target(f.target("mars2"))
            .await
            .unwrap()
            .is_empty()
    );

    // The player's view: labelled `user@target:port`.
    let view = repo
        .list_recording_view_for_user(f.user(JOHN))
        .await
        .unwrap();
    assert_eq!(view.len(), 2);
    let labels: HashSet<&str> = view.iter().map(|v| v.target_secret.as_str()).collect();
    assert_eq!(labels, HashSet::from(["mon@mars1:22", "root@sun:2222"]));
    let first = view.iter().find(|v| v.id == ids[0]).unwrap();
    assert_eq!(first.status, RecordingStatus::Completed);
    assert_eq!(first.generate_path(), format!("{}.cast", ids[0]));

    // A recording outlives its target: the row stays, the label goes empty.
    // Deleting the target must not fail on a foreign key, which is why the
    // relation is `skip_fk`.
    assert!(repo.delete_target(f.target("mars1")).await.unwrap());
    let after = repo
        .list_recording_view_for_user(f.user(JOHN))
        .await
        .unwrap();
    assert_eq!(after.len(), 2, "the recording disappeared with its target");
    let orphan = after.iter().find(|v| v.id == ids[0]).unwrap();
    assert_eq!(orphan.target_secret, "", "label should be empty, not stale");
    assert!(
        repo.get_session_recording_by_id(ids[0])
            .await
            .unwrap()
            .is_some(),
        "the audit artefact must stay reachable"
    );
    assert!(
        repo.get_session_recording_by_id(Uuid::now_v7())
            .await
            .unwrap()
            .is_none()
    );
}

// ------------------------------------------------- authorization readers

/// `list_targets_by_ids` — the end of the permission path.
#[tokio::test]
async fn targets_by_ids_preserves_order_and_drops_non_bindings() {
    let db = fixture::seed().await;
    let repo = db.repo();
    let f = &db.fixture;

    let pid = f.policy(2);
    let ids = vec![
        f.binding("sun", S_ROOT),
        f.binding("mars1", S_MON),
        f.binding("jupiter5", S_MON),
    ];
    let rows = repo
        .list_targets_by_ids(ids.clone(), pid, true)
        .await
        .unwrap();
    assert_eq!(rows.len(), 3);
    // Output order follows the request, not the database's, so a refresh does not
    // reshuffle the rendered list.
    assert_eq!(rows.iter().map(|r| r.id).collect::<Vec<_>>(), ids);
    assert_eq!(rows[0].target_name, "sun");
    assert_eq!(rows[0].secret_user, "root");
    assert_eq!(rows[0].target_id, f.target("sun"));
    assert_eq!(rows[0].secret_id, f.secret(S_ROOT));
    // Every row is stamped with the policy it was reached through.
    assert!(rows.iter().all(|r| r.pid == pid));

    // Ids that are not bindings — internal objects reached through the same graph
    // — are dropped rather than erroring.
    let mixed = repo
        .list_targets_by_ids(
            vec![f.name(OBJ_ADMIN), f.binding("mars1", S_MON), Uuid::now_v7()],
            pid,
            true,
        )
        .await
        .unwrap();
    assert_eq!(mixed.len(), 1);
    assert_eq!(mixed[0].target_name, "mars1");

    // With `active_only`, all three of binding, target and secret must be active.
    let venus1 = f.binding("venus1", S_MON);
    assert!(
        repo.list_targets_by_ids(vec![venus1], pid, true)
            .await
            .unwrap()
            .is_empty(),
        "venus1 is an inactive target"
    );
    assert_eq!(
        repo.list_targets_by_ids(vec![venus1], pid, false)
            .await
            .unwrap()
            .len(),
        1
    );

    let saturn5 = f.binding("saturn5", S_DEV);
    assert!(
        repo.list_targets_by_ids(vec![saturn5], pid, true)
            .await
            .unwrap()
            .is_empty()
    );

    assert!(
        repo.list_targets_by_ids(vec![], pid, true)
            .await
            .unwrap()
            .is_empty(),
        "empty input short-circuits"
    );

    // Deactivating the binding closes it without touching either side.
    repo.upsert_target_secret(f.target("mars2"), f.secret(S_MON), false, f.admin_id)
        .await
        .unwrap();
    assert!(
        repo.list_targets_by_ids(vec![f.binding("mars2", S_MON)], pid, true)
            .await
            .unwrap()
            .is_empty()
    );
}

/// The three admin pickers, and `check_object_active`.
#[tokio::test]
async fn pickers_list_objects_then_groups() {
    let db = fixture::seed().await;
    let repo = db.repo();
    let f = &db.fixture;

    // Subjects: users first, then the `g1` roles.
    let subjects = repo.list_user_group().await.unwrap();
    assert_eq!(subjects.len(), USERS + 8);
    let (users, roles): (Vec<_>, Vec<_>) = subjects.iter().partition(|o| !o.is_group);
    assert_eq!(users.len(), USERS);
    assert_eq!(
        users.iter().map(|o| o.name.as_str()).collect::<Vec<_>>(),
        vec![ADMIN, DAISY, JOE, JOHN, LUKA, MIKE]
    );
    // Concrete objects come before the groups, so the section boundary is at
    // `USERS`.
    assert!(subjects[..USERS].iter().all(|o| !o.is_group));
    assert!(subjects[USERS..].iter().all(|o| o.is_group));
    assert_eq!(roles[0].name, R_AUDIT, "roles are name-ordered");
    assert_eq!(roles[0].id, f.name(R_AUDIT));
    assert!(
        roles.iter().any(|r| r.name == R_AUDIT),
        "the picker is unfiltered: an inactive role still lists"
    );

    // Objects: bindings labelled `user(name)@target:port`, then the `g2` groups
    // and the internal objects.
    let objects = repo.list_target_group().await.unwrap();
    assert_eq!(objects.len(), TARGET_SECRETS + 11 + 3);
    assert!(objects[..TARGET_SECRETS].iter().all(|o| !o.is_group));
    let labels: HashSet<&str> = objects[..TARGET_SECRETS]
        .iter()
        .map(|o| o.name.as_str())
        .collect();
    assert!(labels.contains("root(s_root)@sun:2222"));
    assert!(labels.contains("mon(s_mon)@jupiter5:65535"));
    assert!(
        labels.contains("dev(s_dev)@venus1:22"),
        "inactive rows still list"
    );

    let tail = &objects[TARGET_SECRETS..];
    // Internal objects are grantable in their own right, not containers.
    let internal: Vec<&_> = tail.iter().filter(|o| !o.is_group).collect();
    assert_eq!(internal.len(), 3);
    assert!(
        internal
            .iter()
            .all(|o| o.name.starts_with("__internal_object"))
    );
    assert_eq!(tail.iter().filter(|o| o.is_group).count(), 11);
    assert!(tail.iter().any(|o| o.name == TG_SELFSERVICE && o.is_group));

    // Actions: the `g3` groups and the internal actions.
    let actions = repo.list_action_group().await.unwrap();
    assert_eq!(actions.len(), 3 + 5);
    assert_eq!(actions.iter().filter(|o| o.is_group).count(), 3);
    let names: Vec<&str> = actions.iter().map(|o| o.name.as_str()).collect();
    assert!(names.windows(2).all(|w| w[0] <= w[1]), "not name-ordered");
    assert_eq!(
        actions.iter().find(|o| o.name == AG_ALL).unwrap().id,
        f.name(AG_ALL)
    );

    // `check_object_active`: an active binding with an active target and secret,
    // or an active internal object.
    assert!(
        repo.check_object_active(f.binding("mars1", S_MON))
            .await
            .unwrap()
    );
    assert!(repo.check_object_active(f.name(OBJ_ADMIN)).await.unwrap());
    assert!(
        !repo
            .check_object_active(f.binding("venus1", S_MON))
            .await
            .unwrap(),
        "the target is inactive"
    );
    assert!(
        !repo
            .check_object_active(f.binding("saturn5", S_OPER))
            .await
            .unwrap()
    );
    assert!(!repo.check_object_active(Uuid::now_v7()).await.unwrap());
    // A `g2` group is not itself grantable through this check — only internal
    // objects and bindings are.
    assert!(!repo.check_object_active(f.name(TG_CORE)).await.unwrap());
    assert!(!repo.check_object_active(f.name(ACT_SHELL)).await.unwrap());

    // Deactivating the secret revokes every route through it, without touching
    // the bindings or the hosts.
    repo.update_secret(secret::ActiveModel {
        id: Unchanged(f.secret(S_MON)),
        is_active: Set(false),
        ..Default::default()
    })
    .await
    .unwrap();
    assert!(
        !repo
            .check_object_active(f.binding("mars1", S_MON))
            .await
            .unwrap()
    );
    assert!(
        repo.check_object_active(f.binding("sun", S_ROOT))
            .await
            .unwrap()
    );
}

/// `list_permission_polices` resolves all three columns, across every source
/// each one can come from.
#[tokio::test]
async fn permission_policies_resolve_every_column_source() {
    let db = fixture::seed().await;
    let repo = db.repo();
    let f = &db.fixture;

    let policies = repo.list_permission_polices().await.unwrap();
    assert_eq!(policies.len(), POLICIES);
    let by_id: HashMap<Uuid, &_> = policies.iter().map(|p| (p.rule.id, p)).collect();

    let expected = [
        // subject,     object,          action
        (R_MANAGER, OBJ_LOGIN, ACT_LOGIN),
        (R_OPS_LEAD, OBJ_ADMIN, AG_INTERACTIVE),
        (R_OPS, TG_CORE, AG_ALL),
        (R_DEV, TG_MARS_WEB, AG_INTERACTIVE),
        (R_DEV_LEAD, TG_LAB, AG_BATCH),
        // A bare internal action rather than an action group.
        (R_AUDIT, TG_JUPITER, ACT_EXEC),
        // v0 is a username and v1 is a composed binding label — neither resolves
        // through a `casbin_name`.
        (DAISY, "mon(s_mon)@sun:2222", ACT_SHELL),
        (R_VENDOR, TG_VENUS, AG_INTERACTIVE),
        (R_STAFF, TG_SELFSERVICE, AG_ALL),
    ];
    for (i, (subject, object, action)) in expected.iter().enumerate() {
        let p = by_id[&f.policy(i)];
        assert_eq!(&p.user_role, subject, "policy {i} subject");
        assert_eq!(&p.target_group, object, "policy {i} object");
        assert_eq!(&p.action_group, action, "policy {i} action");
    }

    // The extended policy rides along on the rule.
    assert_eq!(by_id[&f.policy(7)].rule.v3, VENDOR_EXTEND_POLICY);
    assert_eq!(by_id[&f.policy(0)].rule.v3, "{}");
    assert!(policies.iter().all(|p| p.rule.ptype == Ptype::Policy));
}

// ------------------------------------------------------------- batch edge cases

/// Every batch short-circuits to `Ok(0)` on empty input rather than emitting an
/// `INSERT` with no rows, which is a syntax error on every backend.
#[tokio::test]
async fn batches_short_circuit_on_empty_input() {
    let db = fixture::seed().await;
    let repo = db.repo();

    assert_eq!(repo.create_users_batch(vec![]).await.unwrap(), 0);
    assert_eq!(repo.create_targets_batch(vec![]).await.unwrap(), 0);
    assert_eq!(repo.create_secrets_batch(vec![]).await.unwrap(), 0);
    assert_eq!(repo.create_target_secrets_batch(vec![]).await.unwrap(), 0);
    assert_eq!(repo.create_casbin_names_batch(vec![]).await.unwrap(), 0);
    assert_eq!(repo.create_casbin_rules_batch(vec![]).await.unwrap(), 0);

    // Nothing moved.
    assert_eq!(repo.list_users(false).await.unwrap().len(), USERS);
    assert_eq!(repo.list_casbin_rules().await.unwrap().len(), CASBIN_RULES);
}

/// The fixture's own accounting: every declared binding really landed, under the
/// id the fixture hands out.
#[tokio::test]
async fn every_declared_binding_exists_under_its_fixture_id() {
    let db = fixture::seed().await;
    let repo = db.repo();
    let f = &db.fixture;

    let stored: HashMap<Uuid, (Uuid, Uuid)> = repo
        .list_target_secrets(false)
        .await
        .unwrap()
        .into_iter()
        .map(|b| (b.id, (b.target_id, b.secret_id)))
        .collect();

    let pairs = binding_pairs();
    assert_eq!(pairs.len(), TARGET_SECRETS, "spec and count disagree");
    for (target, secret) in pairs {
        let id = f.binding(&target, secret);
        let (target_id, secret_id) = *stored
            .get(&id)
            .unwrap_or_else(|| panic!("{target}/{secret} missing"));
        assert_eq!(target_id, f.target(&target), "{target}/{secret} target");
        assert_eq!(secret_id, f.secret(secret), "{target}/{secret} secret");
    }

    // Per-host totals, as a cross-check on the ranges in the spec.
    let counts = |target: &str| -> usize {
        let tid = f.target(target);
        stored.values().filter(|(t, _)| *t == tid).count()
    };
    assert_eq!(counts("mars1"), 1, "s_mon only");
    assert_eq!(counts("mars5"), 3, "s_mon + s_dev + s_oper");
    assert_eq!(counts("mars9"), 2, "s_mon + s_oper");
    assert_eq!(counts("saturn8"), 2, "s_mon + s_oper");
    assert_eq!(counts("venus1"), 2, "s_mon + s_dev");
    assert_eq!(counts("venus5"), 3);
    assert_eq!(counts("sun"), SECRETS, "all four");
    assert_eq!(counts("jupiter3"), 1, "s_mon only");
}

/// `SessionRecording`'s fields survive a round trip unchanged — the type is
/// read-only, so nothing else asserts its mapping.
#[tokio::test]
async fn recording_round_trips_every_column() {
    let db = fixture::seed().await;
    let repo = db.repo();
    let f = &db.fixture;

    let id = Uuid::now_v7();
    let connection = Uuid::now_v7();
    repo.create_session_recording(session_recording::ActiveModel {
        id: Set(id),
        user_id: Set(f.user(MIKE)),
        target_id: Set(f.target("venus3")),
        secret_id: Set(f.secret(S_DEV)),
        file_path: Set("nested/dir/recording.cast".to_string()),
        ended_at: Set(Some(1)),
        connection_id: Set(connection),
        status: Set(RecordingStatus::Active),
        ..Default::default()
    })
    .await
    .unwrap();

    let SessionRecording {
        id: got_id,
        user_id,
        target_id,
        secret_id,
        file_path,
        started_at,
        ended_at,
        connection_id,
        status,
    } = expect_some(
        repo.get_session_recording_by_id(id).await.unwrap(),
        "recording",
    );

    assert_eq!(got_id, id);
    assert_eq!(user_id, f.user(MIKE));
    assert_eq!(target_id, f.target("venus3"));
    assert_eq!(secret_id, f.secret(S_DEV));
    assert_eq!(file_path, "nested/dir/recording.cast");
    assert_ne!(started_at, 0, "create stamps started_at");
    assert_eq!(ended_at, Some(1));
    assert_eq!(connection_id, connection);
    assert_eq!(status, RecordingStatus::Active);
}

/// `RecordingStatus` reaches the column as its `num_value`, not as a name.
///
/// Nothing else checks this: every other assertion reads back a value this same
/// code wrote, so renumbering the variants would round-trip happily while
/// reinterpreting every stored row. Reading the column raw is the only way to
/// catch it. The unit test beside the enum pins the numbers themselves.
#[tokio::test]
async fn recording_status_is_stored_as_an_integer() {
    use sea_orm::{FromQueryResult, Statement};

    let db = fixture::seed().await;
    let repo = db.repo();
    let f = &db.fixture;

    let id = Uuid::now_v7();
    repo.create_session_recording(session_recording::ActiveModel {
        id: Set(id),
        user_id: Set(f.user(MIKE)),
        target_id: Set(f.target("venus3")),
        secret_id: Set(f.secret(S_DEV)),
        file_path: Set(crate::database::models::session_recording::generate_path(
            id,
        )),
        connection_id: Set(Uuid::now_v7()),
        status: Set(RecordingStatus::Active),
        ..Default::default()
    })
    .await
    .unwrap();

    // A second connection to the same file: the repository deliberately offers no
    // way to read a column outside its model.
    let conn = sea_orm::Database::connect(&db.url).await.unwrap();

    #[derive(FromQueryResult)]
    struct Raw {
        status: i32,
        kind: String,
    }

    // `typeof` is SQLite's, which is the only backend the fixture runs on. It
    // distinguishes a stored 0 from a stored "0" — the point of the assertion.
    let raw = Raw::find_by_statement(Statement::from_string(
        conn.get_database_backend(),
        "SELECT status, typeof(status) AS kind FROM session_recording LIMIT 1",
    ))
    .one(&conn)
    .await
    .unwrap()
    .expect("the recording");

    assert_eq!(raw.kind, "integer", "status is not stored as an integer");
    assert_eq!(raw.status, 0, "Active's discriminant changed");

    // The names live on for display only, and are no longer what is stored.
    assert_eq!(RecordingStatus::Active.as_str(), "active");
    assert_eq!(RecordingStatus::Completed.as_str(), "completed");
}
