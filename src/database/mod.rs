pub mod common;
pub(crate) mod entity;
pub mod error;
pub(crate) mod models;
pub(crate) mod query;
pub(crate) mod repository;
pub(crate) mod service;

use crate::{
    database::{
        entity::{
            casbin_name, casbin_rule as casbin_rule_entity, event_log, secret, session_recording,
            target as target_entity, target_secret as target_secret_entity, user,
        },
        models::UserWithRole,
    },
    error::Error,
};
use async_trait::async_trait;
use models::{
    CasbinName, CasbinRule, CasbinRuleGroup, GroupType, Log, NamePtype, ObjectGroup,
    PermissionPolicy, Ptype, RecordingView, Role, Secret, SecretInfo, SessionRecording, Target,
    TargetInfo, TargetSecret, TargetSecretName, User,
};
pub use uuid::Uuid;

//TODO: Replace with database URL.
/// Database configuration enum to support multiple database backends
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum DatabaseConfig {
    Sqlite {
        path: String,
    },
    Postgres {
        host: String,
        #[serde(default = "default_postgres_port")]
        port: u16,
        database: String,
        username: String,
        #[serde(default)]
        password: String,
    },
    Mysql {
        host: String,
        #[serde(default = "default_mysql_port")]
        port: u16,
        database: String,
        username: String,
        #[serde(default)]
        password: String,
    },
}

fn default_postgres_port() -> u16 {
    5432
}

fn default_mysql_port() -> u16 {
    3306
}

impl DatabaseConfig {
    /// Build the connection URL sea-orm dispatches its backend on.
    ///
    /// The scheme selects the driver, so this is the only place the backend
    /// choice is made — the repository implementation is identical for all three.
    pub fn connection_url(&self) -> String {
        match self {
            // `mode=rwc` = read/write/create, replacing sqlx's
            // `create_if_missing(true)`.
            DatabaseConfig::Sqlite { path } => format!("sqlite://{}?mode=rwc", path),
            DatabaseConfig::Postgres {
                host,
                port,
                database,
                username,
                password,
            } => format!(
                "postgres://{}:{}@{}:{}/{}",
                encode_userinfo(username),
                encode_userinfo(password),
                host,
                port,
                database
            ),
            DatabaseConfig::Mysql {
                host,
                port,
                database,
                username,
                password,
            } => format!(
                "mysql://{}:{}@{}:{}/{}",
                encode_userinfo(username),
                encode_userinfo(password),
                host,
                port,
                database
            ),
        }
    }
}

/// Percent-encode the reserved characters that would otherwise terminate the
/// userinfo section of the URL, so passwords containing `@`, `:`, `/` and
/// friends connect instead of producing a confusing parse error.
fn encode_userinfo(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

impl std::fmt::Display for DatabaseConfig {
    /// Credentials are deliberately omitted: this is printed in the startup
    /// banner (`config/mod.rs`).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DatabaseConfig::Sqlite { path } => {
                write!(f, "sqlite({})", path)
            }
            DatabaseConfig::Postgres {
                host,
                port,
                database,
                username,
                ..
            } => {
                write!(f, "postgres({}@{}:{}/{})", username, host, port, database)
            }
            DatabaseConfig::Mysql {
                host,
                port,
                database,
                username,
                ..
            } => {
                write!(f, "mysql({}@{}:{}/{})", username, host, port, database)
            }
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        DatabaseConfig::Sqlite {
            path: "rustion.db".to_string(),
        }
    }
}

/// Every database operation the rest of the program is allowed to perform.
///
/// One implementation, [`repository::SeaOrmRepository`], serves SQLite,
/// PostgreSQL and MySQL — sea-orm resolves the driver from the connection URL,
/// so adding a backend it already supports means adding a [`DatabaseConfig`]
/// variant, not another impl. This is also the seam
/// [`crate::server::HandlerBackend`] hands to the application layer.
///
/// Three conventions hold across the whole trait, so they are not repeated on
/// each method:
///
/// * **Writes take an `entity::*::ActiveModel`, not a domain type.** An
///   `ActiveModel` records which columns were assigned, so an `UPDATE` names
///   only the fields that actually changed and a caller cannot clobber a column
///   it never read. Callers build them in the admin editors; field validation
///   lives in `server::app::admin::validate` rather than here.
/// * **The repository stamps the write timestamp itself.** `updated_at` for
///   most tables, `created_at` for `event_log`, `started_at` for
///   `session_recording`. Whatever a caller puts there is overwritten, so there
///   is no way to forget it. The `*_batch` methods are the deliberate exception
///   — see their note below.
/// * **`active_only` filters, it does not invert.** `true` adds
///   `is_active = true`; `false` adds nothing and returns active and inactive
///   rows alike. It is not a "give me the inactive ones" switch.
///
/// Deletes return `false` when no row matched rather than erroring, so a
/// double-delete is not an error.
#[async_trait]
pub trait DatabaseRepository: Send + Sync {
    /// Create any missing tables, columns and indexes for the registered
    /// entities, in the connected backend's own dialect.
    ///
    /// Called once from [`repository::SeaOrmRepository::new`], so a repository
    /// is always usable by the time a caller holds one. Additive only: it never
    /// drops or alters an existing table, and it is skipped outright when every
    /// table is already present. That means a renamed table is created empty
    /// beside the old one rather than migrated — see the schema notes in
    /// `repository.rs`.
    async fn initialize(&self) -> Result<(), Error>;

    // ------------------------------------------------------------------ users

    /// Insert a user and return the stored row.
    ///
    /// The caller supplies the id (`Uuid::now_v7()`); `updated_at` is stamped
    /// here.
    async fn create_user(&self, user: user::ActiveModel) -> Result<User, Error>;

    /// Look up one user by id, active or not.
    ///
    /// Authentication deliberately does not use this — it needs the active
    /// check, so it goes through [`Self::get_user_by_username`].
    async fn get_user_by_id(&self, id: Uuid) -> Result<Option<User>, Error>;

    /// Look up one user by username, the authentication entry point.
    ///
    /// Usernames are unique, so this is a single-row lookup. Pass
    /// `active_only = true` on any login path: a deactivated account must not
    /// authenticate.
    async fn get_user_by_username(
        &self,
        username: &str,
        active_only: bool,
    ) -> Result<Option<User>, Error>;

    /// Apply a partial update and return the whole stored row.
    ///
    /// Only the columns the caller `Set` are written, which is what lets the
    /// admin editor save a password change without touching the authorized keys
    /// (and vice versa). The returned row is current, so a caller can keep
    /// editing from it.
    async fn update_user(&self, user: user::ActiveModel) -> Result<User, Error>;

    /// Delete a user; `false` when no such row.
    ///
    /// Rows that reference the user by id — `casbin_rule.v1` bindings, logs,
    /// recordings — are not cleaned up, and no foreign key does it either. See
    /// the note on [`Self::delete_casbin_name`].
    async fn delete_user(&self, id: Uuid) -> Result<bool, Error>;

    /// All users, ordered by username.
    async fn list_users(&self, active_only: bool) -> Result<Vec<User>, Error>;

    /// All users, each with their `g1` role names joined into one
    /// comma-separated string for display.
    ///
    /// Aggregated in SQL, so the spelling is backend-specific
    /// (`GROUP_CONCAT` vs `STRING_AGG`); a user with no roles gets an empty
    /// string, not a missing row.
    async fn list_users_with_role(&self, active_only: bool) -> Result<Vec<UserWithRole>, Error>;

    // ---------------------------------------------------------------- targets

    /// Insert an SSH target and return the stored row.
    ///
    /// `port` is `i32` in storage because sea-orm cannot read a `u16` on
    /// PostgreSQL; [`Target`] narrows it back on the way out.
    async fn create_target(&self, target: target_entity::ActiveModel) -> Result<Target, Error>;

    /// Look up one target by its own id.
    async fn get_target_by_id(&self, id: Uuid, active_only: bool) -> Result<Option<Target>, Error>;

    /// Look up the target reached through one `target_secret` binding.
    ///
    /// This is the connection path: a permission grants a `target_secret` id,
    /// and the host to dial has to be resolved from it. With
    /// `active_only = true` both the binding and the target must be active, so
    /// deactivating either one closes the route.
    async fn get_target_by_target_secret_id(
        &self,
        id: Uuid,
        active_only: bool,
    ) -> Result<Option<Target>, Error>;

    /// [`Self::get_target_by_target_secret_id`] for many ids in one query.
    ///
    /// Returns targets, so duplicates collapse: several bindings pointing at the
    /// same host yield one row. Empty input short-circuits without a query. No
    /// in-tree caller at present.
    async fn get_targets_by_target_secret_ids(
        &self,
        ids: Vec<Uuid>,
        active_only: bool,
    ) -> Result<Vec<Target>, Error>;

    /// Apply a partial update and return the whole stored row.
    async fn update_target(&self, target: target_entity::ActiveModel) -> Result<Target, Error>;

    /// Delete a target; `false` when no such row.
    ///
    /// `target_secret` rows do have a real cascading foreign key here, so the
    /// bindings go with it — unlike the `casbin_rule` rows that referenced them.
    async fn delete_target(&self, id: Uuid) -> Result<bool, Error>;

    /// All targets, ordered by name.
    async fn list_targets(&self, active_only: bool) -> Result<Vec<Target>, Error>;

    /// Just the display columns of every target: id, name, hostname, port.
    ///
    /// Ordered by name. Skips the connection fields the admin list does not
    /// render, so the rendered list does not pull them into memory.
    async fn list_targets_info(&self) -> Result<Vec<TargetInfo>, Error>;

    // ---------------------------------------------------------------- secrets

    /// Insert a credential and return the stored row.
    ///
    /// The password and private key must already be AES-256-GCM ciphertext —
    /// encryption happens in the admin editor, which holds the backend, not
    /// here. The repository stores whatever bytes it is given.
    async fn create_secret(&self, secret: secret::ActiveModel) -> Result<Secret, Error>;

    /// Apply a partial update and return the whole stored row.
    ///
    /// Leaving the password or private key `NotSet` keeps the stored ciphertext,
    /// which is how an edit that only renames a secret avoids a re-encrypt.
    async fn update_secret(&self, secret: secret::ActiveModel) -> Result<Secret, Error>;

    /// All secrets, ordered by name. Ciphertext included.
    async fn list_secrets(&self, active_only: bool) -> Result<Vec<Secret>, Error>;

    /// Look up one secret by id, active or not. No in-tree caller at present.
    async fn get_secret_by_id(&self, id: Uuid) -> Result<Option<Secret>, Error>;

    /// Look up the credential reached through one `target_secret` binding.
    ///
    /// The companion to [`Self::get_target_by_target_secret_id`]: that resolves
    /// where to connect, this resolves what to authenticate with. With
    /// `active_only = true` both the binding and the secret must be active.
    async fn get_secret_by_target_secret_id(
        &self,
        id: Uuid,
        active_only: bool,
    ) -> Result<Option<Secret>, Error>;

    /// Delete a secret; `false` when no such row.
    async fn delete_secret(&self, id: Uuid) -> Result<bool, Error>;

    /// Every secret, each flagged with whether it is bound to `target_id`.
    ///
    /// Returns all secrets, not just the bound ones — this drives the bind
    /// screen's checkbox list, which needs the unbound ones to offer them.
    /// `is_bound` comes from a left join and counts only *active* bindings, so a
    /// deactivated binding reads as unbound. Carries no ciphertext.
    async fn list_secrets_by_target_id(&self, target_id: Uuid) -> Result<Vec<SecretInfo>, Error>;

    // ---------------------------------------------------------- target_secrets
    // The junction table: one row means "this credential may be used to reach
    // this host". Its id is what permission policies actually grant, which is
    // why so much of the connection path resolves through a `target_secret` id
    // rather than a target or a secret on its own.

    /// All bindings, ordered by target then secret. Ids only, no labels.
    async fn list_target_secrets(&self, active_only: bool) -> Result<Vec<TargetSecret>, Error>;

    /// Insert a binding and return the stored row.
    ///
    /// Prefer [`Self::upsert_target_secret`] from the bind screen: a unique index
    /// covers `(target_id, secret_id)`, so inserting a pair that already exists
    /// errors. Currently reached only from tests and fixture loading.
    async fn create_target_secret(
        &self,
        target_secret: target_secret_entity::ActiveModel,
    ) -> Result<TargetSecret, Error>;

    /// Apply a partial update and return the whole stored row.
    async fn update_target_secret(
        &self,
        target_secret: target_secret_entity::ActiveModel,
    ) -> Result<TargetSecret, Error>;

    /// Delete a binding by id; `false` when no such row.
    ///
    /// No in-tree caller: the bind screen deactivates through
    /// [`Self::upsert_target_secret`] instead of deleting, which keeps
    /// `updated_by` as an audit trail.
    async fn delete_target_secret(&self, id: Uuid) -> Result<bool, Error>;

    /// Bind a target to a secret, or flip an existing binding's `is_active`.
    ///
    /// What the bind screen's checkboxes call. Keyed on the `(target_id,
    /// secret_id)` pair rather than an id, because that is what the operator is
    /// choosing and what the unique index enforces. On the update path only
    /// `is_active` and `updated_by` are written, so toggling a binding off and
    /// back on preserves its id — and every rule that grants that id keeps
    /// working, rather than silently pointing at a row that no longer exists.
    async fn upsert_target_secret(
        &self,
        target_id: Uuid,
        secret_id: Uuid,
        is_active: bool,
        updated_by: Uuid,
    ) -> Result<(), Error>;

    // ------------------------------------------------------------ casbin_rule
    // The RBAC table. `ptype` says how to read `v0`..`v5`: `p` is a permission
    // policy (subject, object, action, serialized `ExtendPolicy`), `g1` binds a
    // user to a role, `g2` an object to an object group, `g3` an action to an
    // action group. `v0`/`v1` are therefore polymorphic — a `casbin_name`, a
    // `user` or a `target_secret` depending on `ptype` — which is why the entity
    // declares its relations `skip_fk` and the table carries no foreign keys.

    /// Every rule, ordered by `ptype` then id.
    async fn list_casbin_rules(&self) -> Result<Vec<CasbinRule>, Error>;

    /// Every rule of one `ptype`, raw ids and no labels.
    async fn list_casbin_rules_by_ptype(&self, ptype: Ptype) -> Result<Vec<CasbinRule>, Error>;

    /// Group-membership rules of one `ptype`, with a display label on each side.
    ///
    /// Feeds both the role trees and `RoleManage` (`server::casbin`), which builds
    /// the membership graph from these rows. Exactly one of the two labels per
    /// side comes back `Some` — object *or* group — and `RoleManage` errors on any
    /// row where that does not hold, since it cannot classify a node that is both
    /// or neither.
    ///
    /// # Panics
    ///
    /// With [`Ptype::Policy`]. A permission policy is not a group membership, so
    /// there is nothing to label; use [`Self::list_permission_polices`].
    async fn list_casbin_rule_group_by_ptype(
        &self,
        ptype: Ptype,
    ) -> Result<Vec<CasbinRuleGroup>, Error>;

    /// Every `g1` role, each carrying this user's binding id when one exists.
    ///
    /// Returns all roles, not just the user's — the grant screen needs the
    /// unheld ones to offer them. `casbin_rule_id` is `Some` exactly when the
    /// user holds the role, so it doubles as the checkbox state and as the id to
    /// pass to [`Self::delete_casbin_rule`] when revoking.
    async fn list_roles_by_user_id(&self, user_id: Uuid) -> Result<Vec<Role>, Error>;

    /// Insert a rule and return the stored row.
    ///
    /// Unused `v` columns are stored as empty strings or `Uuid::default()`, not
    /// null — a unique index spans `(ptype, v0..v5)`, so they have to compare
    /// equal for the duplicate check to work.
    async fn create_casbin_rule(
        &self,
        rule: casbin_rule_entity::ActiveModel,
    ) -> Result<CasbinRule, Error>;

    /// Apply a partial update and return the whole stored row.
    ///
    /// Used to retarget one column of an existing rule — an action, say —
    /// without respelling the other five.
    async fn update_casbin_rule(
        &self,
        rule: casbin_rule_entity::ActiveModel,
    ) -> Result<CasbinRule, Error>;

    /// Delete one rule by id; `false` when no such row.
    ///
    /// Callers that change RBAC state must follow up with
    /// [`crate::server::HandlerBackend::load_role_manager`] — the membership
    /// graph is cached in memory and will not notice the write.
    async fn delete_casbin_rule(&self, id: Uuid) -> Result<bool, Error>;
    /// Deletes a single group membership.
    ///
    /// Takes [`GroupType`] rather than [`Ptype`] because a `p` row cannot be
    /// addressed this way: policies are identified by `v0`/`v1`/`v2` together,
    /// so a `Ptype::Policy` here would delete every action for the pair. That
    /// used to be a doc caveat; the type now rules it out.
    async fn delete_casbin_rule_by_group(
        &self,
        group_type: GroupType,
        v0: Uuid,
        v1: Uuid,
    ) -> Result<bool, Error>;

    // ------------------------------------------------------------ casbin_name
    // The id → human-readable name table for everything `casbin_rule` refers to
    // by id: roles (`g1`), object groups (`g2`), action groups (`g3`), and the
    // built-in actions and objects created at `--init`. Those built-ins are
    // `Internal*Type` and are resolved by name at startup, so they are protected
    // against rename, re-type and deletion.

    /// Insert a name and return the stored row.
    async fn create_casbin_name(&self, name: casbin_name::ActiveModel)
    -> Result<CasbinName, Error>;

    /// Apply a partial update and return the whole stored row.
    ///
    /// Rejects a rename or re-type of an internal name; see
    /// [`error::DatabaseError::InternalTypeModification`]. Only an explicit `Set`
    /// that reaches `ptype` or `name` counts, so an edit that just toggles
    /// `is_active` on an internal row is allowed.
    async fn update_casbin_name(&self, name: casbin_name::ActiveModel)
    -> Result<CasbinName, Error>;

    /// Delete a name; `false` when no such row.
    ///
    /// Refuses internal names with
    /// [`error::DatabaseError::InternalTypeModification`], since the startup path
    /// resolves those by name and would not find them again.
    ///
    /// Deleting a non-internal name does **not** delete the `casbin_rule` rows
    /// that reference it, and `casbin_rule` carries no foreign key to cascade
    /// (`v0`/`v1` are polymorphic). Those rules are left pointing at a missing
    /// name, which the label-resolving readers cannot render.
    async fn delete_casbin_name(&self, id: Uuid) -> Result<bool, Error>;

    /// Look up one name by its text, the reverse direction of this table.
    ///
    /// Used at startup to find the built-in actions and objects, whose ids are
    /// not known ahead of time. Names are unique.
    async fn get_casbin_name_by_name(&self, name: &str) -> Result<Option<CasbinName>, Error>;

    /// Every name of one `ptype`, unordered. No in-tree caller at present.
    async fn list_casbin_names_by_ptype(
        &self,
        ptype: NamePtype,
        active_only: bool,
    ) -> Result<Vec<CasbinName>, Error>;

    /// Every name including the internal ones, ordered by `ptype` then name.
    async fn list_casbin_names(&self, active_only: bool) -> Result<Vec<CasbinName>, Error>;

    /// Every name except the internal actions and objects, unordered.
    ///
    /// What the admin name list renders: the built-ins cannot be edited or
    /// deleted, so offering them would only produce
    /// [`error::DatabaseError::InternalTypeModification`].
    async fn list_casbin_names_user_visible(
        &self,
        active_only: bool,
    ) -> Result<Vec<CasbinName>, Error>;

    /// Returns the number of rows inserted.
    ///
    /// Batch path: writes `updated_at` as given. See the note on the other
    /// `*_batch` methods below.
    async fn create_casbin_names_batch(&self, names: Vec<CasbinName>) -> Result<u64, Error>;

    // ------------------------------------------------------------- event_log

    /// Append one audit event.
    ///
    /// `created_at` is stamped here, like every other write. Returns nothing —
    /// the row is never read back, and callers log on the connection path where
    /// there is nothing useful to do with the id.
    async fn insert_log(&self, log: event_log::ActiveModel) -> Result<(), Error>;

    /// Every audit event, newest first. Unbounded — the table only grows.
    async fn list_logs(&self) -> Result<Vec<Log>, Error>;

    // ------------------------------------------------------ session_recording

    /// Open a recording row and return it.
    ///
    /// `started_at` is this table's write stamp and is set here; `ended_at` stays
    /// null until [`Self::update_session_recording`] closes the row.
    async fn create_session_recording(
        &self,
        recording: session_recording::ActiveModel,
    ) -> Result<SessionRecording, Error>;

    /// Close or amend a recording — typically `ended_at` and `status`.
    ///
    /// The one write in the trait that stamps no timestamp: `started_at` is the
    /// stamp and belongs to the create, so overwriting it here would lose when
    /// the session actually began.
    async fn update_session_recording(
        &self,
        recording: session_recording::ActiveModel,
    ) -> Result<SessionRecording, Error>;

    /// Look up one recording by id. No in-tree caller at present.
    async fn get_session_recording_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<SessionRecording>, Error>;

    /// Recordings newest first, optionally capped at `limit`.
    ///
    /// `None` means no limit.
    async fn list_session_recordings(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<SessionRecording>, Error>;

    /// A user's recordings as the player lists them: newest first, each labelled
    /// `user@target:port`.
    ///
    /// Left-joined, so a recording whose target or secret has since been deleted
    /// still lists, with an empty label rather than disappearing — the recording
    /// is the audit artefact and must stay reachable.
    async fn list_recording_view_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<RecordingView>, Error>;

    /// A user's recordings, newest first, ids only.
    ///
    /// No in-tree caller — the player uses
    /// [`Self::list_recording_view_for_user`], which carries the labels.
    async fn list_session_recordings_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<SessionRecording>, Error>;

    /// One target's recordings, newest first. No in-tree caller at present.
    async fn list_session_recordings_for_target(
        &self,
        target_id: Uuid,
    ) -> Result<Vec<SessionRecording>, Error>;

    // --------------------------------------------------------------- batches
    // Bulk fixture import, used by `--init` and the tests. These take domain
    // types rather than `ActiveModel`s and write the row exactly as given,
    // `updated_at` included — the point is to reproduce a fixture faithfully,
    // not to record when the import ran. That is the opposite of every
    // single-row create above, so do not reach for a batch to insert a *new*
    // row: it will land with whatever timestamp the value carried, which for a
    // freshly built domain value is 0.
    //
    // Each returns the number of rows inserted, as reported by the driver, and
    // short-circuits to 0 on empty input. Inserted without `RETURNING`, which
    // sea-orm does not enable for SQLite or MySQL.

    /// Insert users verbatim. Rows inserted.
    async fn create_users_batch(&self, users: Vec<User>) -> Result<u64, Error>;

    /// Insert targets verbatim. Rows inserted.
    async fn create_targets_batch(&self, targets: Vec<Target>) -> Result<u64, Error>;

    /// Insert secrets verbatim, ciphertext as given. Rows inserted.
    async fn create_secrets_batch(&self, secrets: Vec<Secret>) -> Result<u64, Error>;

    /// Insert target/secret bindings verbatim. Rows inserted.
    async fn create_target_secrets_batch(
        &self,
        target_secrets: Vec<TargetSecret>,
    ) -> Result<u64, Error>;

    /// Insert RBAC rules verbatim. Rows inserted.
    ///
    /// Callers must reload the role manager afterwards; the membership graph is
    /// cached and will not see these rows.
    async fn create_casbin_rules_batch(&self, rules: Vec<CasbinRule>) -> Result<u64, Error>;

    // ------------------------------------------------- authorization readers

    /// Resolve `target_secret` ids to the labelled rows the target selector
    /// renders, tagging each with the policy that granted it.
    ///
    /// The end of the permission path: the caller has walked the object graph in
    /// `RoleManage` (`server::casbin`) down to a set of candidate ids, and `pid`
    /// is the `casbin_rule` id of the policy it walked from — stamped onto every
    /// row so a later connection can point at the rule that allowed it.
    ///
    /// Ids that are not `target_secret`s — internal objects reached through the
    /// same graph — simply do not match and are dropped. Output preserves the
    /// order of `ids` rather than the database's, so the rendered list stays put
    /// between refreshes. With `active_only = true` the binding, its target and
    /// its secret must all be active.
    async fn list_targets_by_ids(
        &self,
        ids: Vec<Uuid>,
        pid: Uuid,
        active_only: bool,
    ) -> Result<Vec<TargetSecretName>, Error>;

    /// Users, then `g1` groups — the subject picker.
    ///
    /// Each of the three pickers returns concrete objects first, then the groups
    /// they can belong to, with `is_group` telling them apart. Ordered within
    /// each section: the lists render unsorted, and only SQLite happens to return
    /// a stable scan order.
    async fn list_user_group(&self) -> Result<Vec<ObjectGroup>, Error>;

    /// `target_secret`s labelled `user(name)@target:port`, then `g2` groups and
    /// the internal objects — the object picker.
    ///
    /// Internal objects report `is_group: false`: they are grantable targets in
    /// their own right, like the admin TUI itself, not containers.
    async fn list_target_group(&self) -> Result<Vec<ObjectGroup>, Error>;

    /// `g3` groups and the internal actions — the action picker.
    async fn list_action_group(&self) -> Result<Vec<ObjectGroup>, Error>;

    /// Whether `id` still names something a policy can grant.
    ///
    /// True for an active `target_secret` whose target *and* secret are also
    /// active, or for an active internal object. Called on the connection path,
    /// where a policy may name an object that has since been deactivated —
    /// deactivating any one of the three links revokes access without touching
    /// the rules.
    async fn check_object_active(&self, id: Uuid) -> Result<bool, Error>;

    /// Every `p` rule with its subject, object and action resolved to display
    /// names, for the admin permission list.
    ///
    /// Each column resolves against a different set of sources — `v0` a role name
    /// or a username, `v1` a composed `target_secret` label or a group name, `v2`
    /// an action group name.
    ///
    /// # Panics
    ///
    /// If any of the three ids has no name in any of its sources. A rule left
    /// behind by [`Self::delete_casbin_name`] will do it.
    async fn list_permission_polices(&self) -> Result<Vec<PermissionPolicy>, Error>;
}

/// Database factory. sea-orm resolves the backend from the URL scheme, so a
/// single [`repository::SeaOrmRepository`] serves SQLite, PostgreSQL and MySQL.
pub async fn create_repository(
    config: &DatabaseConfig,
) -> Result<Box<dyn DatabaseRepository>, Error> {
    let repo = repository::SeaOrmRepository::new(config).await?;
    Ok(Box::new(repo))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_url_creates_missing_file() {
        let cfg = DatabaseConfig::Sqlite {
            path: "rustion.db".into(),
        };
        // `mode=rwc` is what replaces sqlx's `create_if_missing(true)`.
        assert_eq!(cfg.connection_url(), "sqlite://rustion.db?mode=rwc");
    }

    #[test]
    fn postgres_and_mysql_urls() {
        let pg = DatabaseConfig::Postgres {
            host: "db.internal".into(),
            port: 5432,
            database: "rustion".into(),
            username: "svc".into(),
            password: "hunter2".into(),
        };
        assert_eq!(
            pg.connection_url(),
            "postgres://svc:hunter2@db.internal:5432/rustion"
        );

        let my = DatabaseConfig::Mysql {
            host: "db.internal".into(),
            port: 3306,
            database: "rustion".into(),
            username: "svc".into(),
            password: "hunter2".into(),
        };
        assert_eq!(
            my.connection_url(),
            "mysql://svc:hunter2@db.internal:3306/rustion"
        );
    }

    /// A password containing URL-reserved characters must not corrupt the URL.
    #[test]
    fn credentials_are_percent_encoded() {
        let cfg = DatabaseConfig::Postgres {
            host: "localhost".into(),
            port: 5432,
            database: "rustion".into(),
            username: "user@corp".into(),
            password: "p@ss:w/rd?#".into(),
        };
        assert_eq!(
            cfg.connection_url(),
            "postgres://user%40corp:p%40ss%3Aw%2Frd%3F%23@localhost:5432/rustion"
        );
    }

    /// `Display` reaches the startup banner, so it must never leak the password.
    #[test]
    fn display_redacts_password() {
        let cfg = DatabaseConfig::Mysql {
            host: "localhost".into(),
            port: 3306,
            database: "rustion".into(),
            username: "svc".into(),
            password: "topsecret".into(),
        };
        let shown = cfg.to_string();
        assert!(!shown.contains("topsecret"), "password leaked: {shown}");
        assert_eq!(shown, "mysql(svc@localhost:3306/rustion)");
    }

    #[test]
    fn existing_sqlite_toml_still_parses() {
        let cfg: DatabaseConfig =
            toml::from_str("type = \"sqlite\"\npath = \"rustion.db\"").unwrap();
        assert!(matches!(cfg, DatabaseConfig::Sqlite { path } if path == "rustion.db"));
    }

    #[test]
    fn backend_ports_default_when_omitted() {
        let pg: DatabaseConfig =
            toml::from_str("type = \"postgres\"\nhost = \"h\"\ndatabase = \"d\"\nusername = \"u\"")
                .unwrap();
        assert!(matches!(pg, DatabaseConfig::Postgres { port, .. } if port == 5432));

        let my: DatabaseConfig =
            toml::from_str("type = \"mysql\"\nhost = \"h\"\ndatabase = \"d\"\nusername = \"u\"")
                .unwrap();
        assert!(matches!(my, DatabaseConfig::Mysql { port, .. } if port == 3306));
    }
}
