//! Backend-agnostic [`DatabaseRepository`] implementation.
//!
//! One implementation serves SQLite, PostgreSQL and MySQL — sea-orm resolves the
//! driver from the connection URL, and every query here is built through
//! sea-query so identifiers, booleans and parameter placeholders are emitted in
//! each backend's own dialect.

use async_trait::async_trait;
use chrono::Utc;
use log::{debug, info};
use sea_orm::ActiveValue::{Set, Unchanged};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait,
    QueryFilter, QueryOrder, QuerySelect, Schema,
};
use uuid::Uuid;

use crate::database::entity::{
    casbin_name, casbin_rule, event_log, secret, session_recording, target, target_secret, user,
};
use crate::database::error::DatabaseError;
use crate::database::models::{
    CasbinName, CasbinRule, CasbinRuleGroup, EventLog, GroupType, NamePtype, ObjectGroup,
    PermissionPolicy, Ptype, RecordingView, Role, Secret, SecretInfo, SessionRecording, Target,
    TargetInfo, TargetSecret, TargetSecretName, User, UserWithRole,
};
use crate::database::{DatabaseRepository, redact_url};
use crate::error::Error;

/// Matches the sqlx pool default. sea-orm defaults SQLite to a single
/// connection, which would serialise every database call.
const MAX_CONNECTIONS: u32 = 10;

pub struct SeaOrmRepository {
    pub(in crate::database) db: DatabaseConnection,
}

impl SeaOrmRepository {
    /// `url` is handed to sea-orm verbatim; its scheme picks the driver.
    pub async fn new(url: &str) -> Result<Self, Error> {
        info!("Connecting to database: {}", redact_url(url));

        let mut options = ConnectOptions::new(url);
        options
            .max_connections(MAX_CONNECTIONS)
            // Statements are logged through our own `debug!` calls; sea-orm's
            // own logging would duplicate them at info level.
            .sqlx_logging(false);

        let db = Database::connect(options).await?;

        let repo = Self { db };
        repo.initialize().await?;

        Ok(repo)
    }

    /// Whether every table exists, probed with a zero-row select per entity.
    ///
    /// Portable across backends and cheap (the planner short-circuits `LIMIT 0`),
    /// unlike querying each backend's own catalogue tables. Any error is treated
    /// as "not complete", so the caller falls through to sync.
    async fn schema_is_complete(&self) -> bool {
        macro_rules! exists {
            ($entity:path) => {
                <$entity>::find().limit(0).all(&self.db).await.is_ok()
            };
        }

        exists!(user::Entity)
            && exists!(target::Entity)
            && exists!(secret::Entity)
            && exists!(target_secret::Entity)
            && exists!(casbin_rule::Entity)
            && exists!(casbin_name::Entity)
            && exists!(event_log::Entity)
            && exists!(session_recording::Entity)
    }
}

#[async_trait]
impl DatabaseRepository for SeaOrmRepository {
    /// Creates any missing tables, columns and indexes for the registered
    /// entities, in the dialect of whichever backend is connected.
    ///
    /// Additive only — it never drops or alters existing tables, which is the
    /// same guarantee the previous `CREATE TABLE IF NOT EXISTS` gave.
    ///
    /// Skipped entirely when every table already exists. Sync compares declared
    /// column types against the live ones and warns on each difference; against
    /// a database created by the previous sqlx implementation that means ~30
    /// warnings per start (`blob` vs `uuid_text`, `text` vs `varchar`) which are
    /// all benign — the stored bytes are identical, only the declared type name
    /// differs. Skipping when nothing is missing keeps the steady-state path
    /// silent, exactly as `CREATE TABLE IF NOT EXISTS` was.
    async fn initialize(&self) -> Result<(), Error> {
        debug!("Initializing database schema");

        if self.schema_is_complete().await {
            debug!("All tables present; skipping schema sync");
            return Ok(());
        }

        info!("Creating missing database tables");
        Schema::new(self.db.get_database_backend())
            .builder()
            .register(user::Entity)
            .register(target::Entity)
            .register(secret::Entity)
            .register(target_secret::Entity)
            .register(casbin_rule::Entity)
            .register(casbin_name::Entity)
            .register(event_log::Entity)
            .register(session_recording::Entity)
            .sync(&self.db)
            .await?;

        info!("Database tables and indexes are up to date");
        Ok(())
    }

    // ---------------------------------------------------------------- users

    async fn create_user(&self, mut user: user::ActiveModel) -> Result<User, Error> {
        let now = Utc::now().timestamp_millis();
        user.updated_at = Set(now);
        let res = user.insert(&self.db).await?;
        Ok(res.into())
    }

    async fn get_user_by_id(&self, id: Uuid) -> Result<Option<User>, Error> {
        Ok(user::Entity::find_by_id(id)
            .one(&self.db)
            .await?
            .map(User::from))
    }

    async fn get_user_by_username(
        &self,
        username: &str,
        active_only: bool,
    ) -> Result<Option<User>, Error> {
        let mut q = user::Entity::find().filter(user::Column::Username.eq(username));
        if active_only {
            q = q.filter(user::Column::IsActive.eq(true));
        }
        Ok(q.one(&self.db).await?.map(User::from))
    }

    async fn update_user(&self, mut user: user::ActiveModel) -> Result<User, Error> {
        user.updated_at = Set(Utc::now().timestamp_millis());
        let res = user::Entity::update(user).exec(&self.db).await?;
        Ok(res.into())
    }

    async fn delete_user(&self, id: Uuid) -> Result<bool, Error> {
        debug!("Deleting user: id={}", id);
        let res = user::Entity::delete_by_id(id).exec(&self.db).await?;
        let deleted = res.rows_affected > 0;
        if deleted {
            debug!("User deleted successfully: id={}", id);
        }
        Ok(deleted)
    }

    async fn list_users(&self, active_only: bool) -> Result<Vec<User>, Error> {
        let mut q = user::Entity::find();
        if active_only {
            q = q.filter(user::Column::IsActive.eq(true));
        }
        Ok(q.order_by_asc(user::Column::Username)
            .all(&self.db)
            .await?
            .into_iter()
            .map(User::from)
            .collect())
    }

    async fn list_users_with_role(&self, active_only: bool) -> Result<Vec<UserWithRole>, Error> {
        super::query::list_users_with_role(&self.db, active_only).await
    }

    async fn create_users_batch(&self, users: Vec<User>) -> Result<u64, Error> {
        if users.is_empty() {
            return Ok(0);
        }
        let rows = user::Entity::insert_many(
            users
                .into_iter()
                .map(User::into_active_model)
                .collect::<Vec<_>>(),
        )
        .exec_without_returning(&self.db)
        .await?;
        Ok(rows)
    }

    // -------------------------------------------------------------- targets

    async fn create_target(&self, mut target: target::ActiveModel) -> Result<Target, Error> {
        target.updated_at = Set(Utc::now().timestamp_millis());
        let res = target.insert(&self.db).await?;
        Ok(res.into())
    }

    async fn get_target_by_id(&self, id: Uuid, active_only: bool) -> Result<Option<Target>, Error> {
        let mut q = target::Entity::find_by_id(id);
        if active_only {
            q = q.filter(target::Column::IsActive.eq(true));
        }
        Ok(q.one(&self.db).await?.map(Target::from))
    }

    async fn update_target(&self, mut target: target::ActiveModel) -> Result<Target, Error> {
        target.updated_at = Set(Utc::now().timestamp_millis());
        let res = target::Entity::update(target).exec(&self.db).await?;
        Ok(res.into())
    }

    async fn delete_target(&self, id: Uuid) -> Result<bool, Error> {
        debug!("Deleting target: id={}", id);
        let res = target::Entity::delete_by_id(id).exec(&self.db).await?;
        let deleted = res.rows_affected > 0;
        if deleted {
            debug!("Target deleted successfully: id={}", id);
        }
        Ok(deleted)
    }

    async fn list_targets(&self, active_only: bool) -> Result<Vec<Target>, Error> {
        let mut q = target::Entity::find();
        if active_only {
            q = q.filter(target::Column::IsActive.eq(true));
        }
        // Ordered for the same reason as the pickers in `query.rs`: only SQLite
        // returns unordered rows consistently, and these feed rendered lists.
        Ok(q.order_by_asc(target::Column::Name)
            .all(&self.db)
            .await?
            .into_iter()
            .map(Target::from)
            .collect())
    }

    async fn list_targets_info(&self) -> Result<Vec<TargetInfo>, Error> {
        Ok(target::Entity::find()
            .select_only()
            .column(target::Column::Id)
            .column(target::Column::Name)
            .column(target::Column::Hostname)
            .column(target::Column::Port)
            .order_by_asc(target::Column::Name)
            .into_model::<TargetInfo>()
            .all(&self.db)
            .await?)
    }

    async fn create_targets_batch(&self, targets: Vec<Target>) -> Result<u64, Error> {
        if targets.is_empty() {
            return Ok(0);
        }
        let rows = target::Entity::insert_many(
            targets
                .into_iter()
                .map(Target::into_active_model)
                .collect::<Vec<_>>(),
        )
        .exec_without_returning(&self.db)
        .await?;
        Ok(rows)
    }

    // -------------------------------------------------------------- secrets

    async fn create_secret(&self, mut secret: secret::ActiveModel) -> Result<Secret, Error> {
        secret.updated_at = Set(Utc::now().timestamp_millis());
        let res = secret.insert(&self.db).await?;
        Ok(res.into())
    }

    async fn update_secret(&self, mut secret: secret::ActiveModel) -> Result<Secret, Error> {
        secret.updated_at = Set(Utc::now().timestamp_millis());
        let res = secret::Entity::update(secret).exec(&self.db).await?;
        Ok(res.into())
    }

    async fn list_secrets(&self, active_only: bool) -> Result<Vec<Secret>, Error> {
        let mut q = secret::Entity::find();
        if active_only {
            q = q.filter(secret::Column::IsActive.eq(true));
        }
        Ok(q.order_by_asc(secret::Column::Name)
            .all(&self.db)
            .await?
            .into_iter()
            .map(Secret::from)
            .collect())
    }

    async fn get_secret_by_id(&self, id: Uuid) -> Result<Option<Secret>, Error> {
        Ok(secret::Entity::find_by_id(id)
            .one(&self.db)
            .await?
            .map(Secret::from))
    }

    async fn delete_secret(&self, id: Uuid) -> Result<bool, Error> {
        debug!("Deleting secret: id={}", id);
        let res = secret::Entity::delete_by_id(id).exec(&self.db).await?;
        let deleted = res.rows_affected > 0;
        if deleted {
            debug!("Secret deleted successfully: id={}", id);
        }
        Ok(deleted)
    }

    async fn create_secrets_batch(&self, secrets: Vec<Secret>) -> Result<u64, Error> {
        if secrets.is_empty() {
            return Ok(0);
        }
        let rows = secret::Entity::insert_many(
            secrets
                .into_iter()
                .map(Secret::into_active_model)
                .collect::<Vec<_>>(),
        )
        .exec_without_returning(&self.db)
        .await?;
        Ok(rows)
    }

    // ------------------------------------------------------- target_secrets

    async fn list_target_secrets(&self, active_only: bool) -> Result<Vec<TargetSecret>, Error> {
        let mut q = target_secret::Entity::find();
        if active_only {
            q = q.filter(target_secret::Column::IsActive.eq(true));
        }
        Ok(q.order_by_asc(target_secret::Column::TargetId)
            .order_by_asc(target_secret::Column::SecretId)
            .all(&self.db)
            .await?
            .into_iter()
            .map(TargetSecret::from)
            .collect())
    }

    async fn create_target_secret(
        &self,
        mut target_secret: target_secret::ActiveModel,
    ) -> Result<TargetSecret, Error> {
        target_secret.updated_at = Set(Utc::now().timestamp_millis());
        let res = target_secret.insert(&self.db).await?;
        Ok(res.into())
    }

    async fn update_target_secret(
        &self,
        mut target_secret: target_secret::ActiveModel,
    ) -> Result<TargetSecret, Error> {
        target_secret.updated_at = Set(Utc::now().timestamp_millis());
        let res = target_secret::Entity::update(target_secret)
            .exec(&self.db)
            .await?;
        Ok(res.into())
    }

    async fn delete_target_secret(&self, id: Uuid) -> Result<bool, Error> {
        let res = target_secret::Entity::delete_by_id(id)
            .exec(&self.db)
            .await?;
        Ok(res.rows_affected > 0)
    }

    /// Upsert the binding between a target and a secret.
    ///
    /// * If the pair `(target_id, secret_id)` does **not** exist yet → insert a new row
    /// * If it **does** exist → flip `is_active` to the provided value
    async fn upsert_target_secret(
        &self,
        target_id: Uuid,
        secret_id: Uuid,
        is_active: bool,
        updated_by: Uuid,
    ) -> Result<(), Error> {
        let existing = target_secret::Entity::find_by_target_secret((target_id, secret_id))
            .one(&self.db)
            .await?;

        match existing {
            Some(m) => {
                // `is_active` is the only column that moves. `updated_by` stays
                // as it was, which is what this did before the row was expressed
                // as an `ActiveModel` — the parameter feeds the insert only.
                self.update_target_secret(target_secret::ActiveModel {
                    id: Unchanged(m.id),
                    is_active: Set(is_active),
                    updated_by: Set(updated_by),
                    ..Default::default()
                })
                .await?;
            }
            None => {
                self.create_target_secret(target_secret::ActiveModel {
                    id: Set(Uuid::now_v7()),
                    target_id: Set(target_id),
                    secret_id: Set(secret_id),
                    is_active: Set(is_active),
                    updated_by: Set(updated_by),
                    ..Default::default()
                })
                .await?;
            }
        };

        Ok(())
    }

    async fn create_target_secrets_batch(
        &self,
        target_secrets: Vec<TargetSecret>,
    ) -> Result<u64, Error> {
        if target_secrets.is_empty() {
            return Ok(0);
        }
        let rows = target_secret::Entity::insert_many(
            target_secrets
                .into_iter()
                .map(TargetSecret::into_active_model)
                .collect::<Vec<_>>(),
        )
        .exec_without_returning(&self.db)
        .await?;
        Ok(rows)
    }

    // ---------------------------------------------------------- casbin_rule

    async fn list_casbin_rules(&self) -> Result<Vec<CasbinRule>, Error> {
        Ok(casbin_rule::Entity::find()
            .order_by_asc(casbin_rule::Column::Ptype)
            .order_by_asc(casbin_rule::Column::Id)
            .all(&self.db)
            .await?
            .into_iter()
            .map(CasbinRule::from)
            .collect())
    }

    async fn list_casbin_rules_by_ptype(&self, ptype: Ptype) -> Result<Vec<CasbinRule>, Error> {
        Ok(casbin_rule::Entity::find()
            .filter(casbin_rule::Column::Ptype.eq(ptype))
            .all(&self.db)
            .await?
            .into_iter()
            .map(CasbinRule::from)
            .collect())
    }

    async fn create_casbin_rule(
        &self,
        mut rule: casbin_rule::ActiveModel,
    ) -> Result<CasbinRule, Error> {
        rule.updated_at = Set(Utc::now().timestamp_millis());
        let res = rule.insert(&self.db).await?;
        Ok(res.into())
    }

    async fn update_casbin_rule(
        &self,
        mut rule: casbin_rule::ActiveModel,
    ) -> Result<CasbinRule, Error> {
        rule.updated_at = Set(Utc::now().timestamp_millis());
        let res = casbin_rule::Entity::update(rule).exec(&self.db).await?;
        Ok(res.into())
    }

    async fn delete_casbin_rule(&self, id: Uuid) -> Result<bool, Error> {
        debug!("Deleting casbin_rule: '({})'", id);
        let res = casbin_rule::Entity::delete_by_id(id).exec(&self.db).await?;
        let deleted = res.rows_affected > 0;
        if deleted {
            debug!("Casbin_rule deleted successfully: '({})'", id);
        }
        Ok(deleted)
    }

    async fn delete_casbin_rule_by_group(
        &self,
        group_type: GroupType,
        v0: Uuid,
        v1: Uuid,
    ) -> Result<bool, Error> {
        let ptype = Ptype::from(group_type);
        debug!(
            "Deleting casbin_rule where ptype={} v0={} v1={}",
            ptype, v0, v1
        );
        let res = casbin_rule::Entity::delete_many()
            .filter(casbin_rule::Column::Ptype.eq(ptype))
            .filter(casbin_rule::Column::V0.eq(v0))
            .filter(casbin_rule::Column::V1.eq(v1))
            .exec(&self.db)
            .await?;

        let deleted = res.rows_affected > 0;
        if deleted {
            debug!(
                "Casbin_rule deleted successfully: ptype={} v0={} v1={}",
                ptype, v0, v1
            );
        }
        Ok(deleted)
    }

    async fn create_casbin_rules_batch(&self, rules: Vec<CasbinRule>) -> Result<u64, Error> {
        if rules.is_empty() {
            return Ok(0);
        }
        let rows = casbin_rule::Entity::insert_many(
            rules
                .into_iter()
                .map(CasbinRule::into_active_model)
                .collect::<Vec<_>>(),
        )
        .exec_without_returning(&self.db)
        .await?;
        Ok(rows)
    }

    // --------------------------------------------------------- casbin_names

    async fn create_casbin_name(
        &self,
        mut name: casbin_name::ActiveModel,
    ) -> Result<CasbinName, Error> {
        name.updated_at = Set(Utc::now().timestamp_millis());
        let res = name.insert(&self.db).await?;
        Ok(res.into())
    }

    async fn update_casbin_name(
        &self,
        mut name: casbin_name::ActiveModel,
    ) -> Result<CasbinName, Error> {
        // Internal types may not be renamed or re-typed. A `NotSet` column is not
        // being written, so it cannot be a modification — only an explicit `Set`
        // that differs from the stored row counts.
        if let Some(id) = name.id.try_as_ref()
            && let Some(existing) = casbin_name::Entity::find_by_id(*id)
                .one(&self.db)
                .await?
                .map(CasbinName::from)
            && existing.is_internal()
            && (name.ptype.is_set() || name.name.is_set())
        {
            return Err(Error::Database(DatabaseError::InternalTypeModification));
        }

        name.updated_at = Set(Utc::now().timestamp_millis());
        let res = casbin_name::Entity::update(name).exec(&self.db).await?;
        Ok(res.into())
    }

    async fn delete_casbin_name(&self, id: Uuid) -> Result<bool, Error> {
        debug!("Deleting casbin_name: id={}", id);

        if let Some(casbin_name) = casbin_name::Entity::find_by_id(id)
            .one(&self.db)
            .await?
            .map(CasbinName::from)
            && casbin_name.is_internal()
        {
            return Err(Error::Database(DatabaseError::InternalTypeModification));
        }

        let res = casbin_name::Entity::delete_by_id(id).exec(&self.db).await?;
        let deleted = res.rows_affected > 0;
        if deleted {
            debug!("Casbin_name deleted successfully: id={}", id);
        }
        Ok(deleted)
    }

    async fn get_casbin_name_by_name(&self, name: &str) -> Result<Option<CasbinName>, Error> {
        Ok(casbin_name::Entity::find_by_name(name)
            .one(&self.db)
            .await?
            .map(CasbinName::from))
    }

    async fn list_casbin_names_by_ptype(
        &self,
        ptype: NamePtype,
        active_only: bool,
    ) -> Result<Vec<CasbinName>, Error> {
        let mut q = casbin_name::Entity::find().filter(casbin_name::Column::Ptype.eq(ptype));
        if active_only {
            q = q.filter(casbin_name::Column::IsActive.eq(true));
        }
        Ok(q.all(&self.db)
            .await?
            .into_iter()
            .map(CasbinName::from)
            .collect())
    }

    async fn list_casbin_names(&self, active_only: bool) -> Result<Vec<CasbinName>, Error> {
        let mut q = casbin_name::Entity::find();
        if active_only {
            q = q.filter(casbin_name::Column::IsActive.eq(true));
        }
        Ok(q.order_by_asc(casbin_name::Column::Ptype)
            .order_by_asc(casbin_name::Column::Name)
            .all(&self.db)
            .await?
            .into_iter()
            .map(CasbinName::from)
            .collect())
    }

    async fn list_casbin_names_user_visible(
        &self,
        active_only: bool,
    ) -> Result<Vec<CasbinName>, Error> {
        let mut q = casbin_name::Entity::find().filter(casbin_name::Column::Ptype.is_not_in([
            casbin_name::NamePtype::InternalActionType,
            casbin_name::NamePtype::InternalObjectType,
        ]));
        if active_only {
            q = q.filter(casbin_name::Column::IsActive.eq(true));
        }
        Ok(q.all(&self.db)
            .await?
            .into_iter()
            .map(CasbinName::from)
            .collect())
    }

    async fn create_casbin_names_batch(&self, names: Vec<CasbinName>) -> Result<u64, Error> {
        if names.is_empty() {
            return Ok(0);
        }
        let rows = casbin_name::Entity::insert_many(
            names
                .into_iter()
                .map(CasbinName::into_active_model)
                .collect::<Vec<_>>(),
        )
        .exec_without_returning(&self.db)
        .await?;
        Ok(rows)
    }

    // ------------------------------------------------------------------ logs

    async fn insert_log(&self, mut log: event_log::ActiveModel) -> Result<(), Error> {
        log.created_at = Set(Utc::now().timestamp_millis());
        // `exec`, not `ActiveModel::insert`: the row is discarded, and with a
        // generated key `insert` would follow the write with a `SELECT` to
        // reconstruct a model nobody reads (SQLite and MySQL have no `RETURNING`
        // here). `id` is left `NotSet` so the database assigns it.
        event_log::Entity::insert(log).exec(&self.db).await?;
        Ok(())
    }

    async fn list_logs(&self) -> Result<Vec<EventLog>, Error> {
        Ok(event_log::Entity::find()
            // `id` breaks ties: `created_at` is milliseconds, and a burst on one
            // connection shares a stamp. Descending id puts the later write first,
            // which is the order they were appended in.
            .order_by_desc(event_log::Column::CreatedAt)
            .order_by_desc(event_log::Column::Id)
            .all(&self.db)
            .await?
            .into_iter()
            .map(EventLog::from)
            .collect())
    }

    // ------------------------------------------------------ session records

    async fn create_session_recording(
        &self,
        mut recording: session_recording::ActiveModel,
    ) -> Result<SessionRecording, Error> {
        // `started_at` is this table's write stamp; the others use `updated_at`.
        recording.started_at = Set(Utc::now().timestamp_millis());
        let res = recording.insert(&self.db).await?;
        Ok(res.into())
    }

    async fn update_session_recording(
        &self,
        recording: session_recording::ActiveModel,
    ) -> Result<SessionRecording, Error> {
        let res = session_recording::Entity::update(recording)
            .exec(&self.db)
            .await?;
        Ok(res.into())
    }

    async fn get_session_recording_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<SessionRecording>, Error> {
        Ok(session_recording::Entity::find_by_id(id)
            .one(&self.db)
            .await?
            .map(SessionRecording::from))
    }

    async fn list_session_recordings(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<SessionRecording>, Error> {
        let mut q =
            session_recording::Entity::find().order_by_desc(session_recording::Column::StartedAt);
        if let Some(l) = limit {
            q = q.limit(l as u64);
        }
        Ok(q.all(&self.db)
            .await?
            .into_iter()
            .map(SessionRecording::from)
            .collect())
    }

    async fn list_session_recordings_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<SessionRecording>, Error> {
        Ok(session_recording::Entity::find()
            .filter(session_recording::Column::UserId.eq(user_id))
            .order_by_desc(session_recording::Column::StartedAt)
            .all(&self.db)
            .await?
            .into_iter()
            .map(SessionRecording::from)
            .collect())
    }

    async fn list_session_recordings_for_target(
        &self,
        target_id: Uuid,
    ) -> Result<Vec<SessionRecording>, Error> {
        Ok(session_recording::Entity::find()
            .filter(session_recording::Column::TargetId.eq(target_id))
            .order_by_desc(session_recording::Column::StartedAt)
            .all(&self.db)
            .await?
            .into_iter()
            .map(SessionRecording::from)
            .collect())
    }

    // ------------------------------------- queries with joins / aggregation
    // Delegated to `super::query`, which builds them through sea-query so the
    // emitted SQL is valid on every backend.

    async fn get_target_by_target_secret_id(
        &self,
        id: Uuid,
        active_only: bool,
    ) -> Result<Option<Target>, Error> {
        super::query::get_target_by_target_secret_id(&self.db, id, active_only).await
    }

    async fn get_targets_by_target_secret_ids(
        &self,
        ids: Vec<Uuid>,
        active_only: bool,
    ) -> Result<Vec<Target>, Error> {
        super::query::get_targets_by_target_secret_ids(&self.db, ids, active_only).await
    }

    async fn get_secret_by_target_secret_id(
        &self,
        id: Uuid,
        active_only: bool,
    ) -> Result<Option<Secret>, Error> {
        super::query::get_secret_by_target_secret_id(&self.db, id, active_only).await
    }

    async fn list_secrets_by_target_id(&self, target_id: Uuid) -> Result<Vec<SecretInfo>, Error> {
        super::query::list_secrets_for_target(&self.db, target_id).await
    }

    async fn list_roles_by_user_id(&self, user_id: Uuid) -> Result<Vec<Role>, Error> {
        super::query::list_roles_by_user_id(&self.db, user_id).await
    }

    async fn list_casbin_rule_group_by_ptype(
        &self,
        ptype: Ptype,
    ) -> Result<Vec<CasbinRuleGroup>, Error> {
        super::query::list_casbin_rule_group_by_ptype(&self.db, ptype).await
    }

    async fn list_targets_by_ids(
        &self,
        ids: Vec<Uuid>,
        pid: Uuid,
        active_only: bool,
    ) -> Result<Vec<TargetSecretName>, Error> {
        super::query::list_targets_by_ids(&self.db, ids, pid, active_only).await
    }

    async fn list_user_group(&self) -> Result<Vec<ObjectGroup>, Error> {
        super::query::list_user_group(&self.db).await
    }

    async fn list_target_group(&self) -> Result<Vec<ObjectGroup>, Error> {
        super::query::list_target_group(&self.db).await
    }

    async fn list_action_group(&self) -> Result<Vec<ObjectGroup>, Error> {
        super::query::list_action_group(&self.db).await
    }

    async fn check_object_active(&self, id: Uuid) -> Result<bool, Error> {
        super::query::check_object_active(&self.db, id).await
    }

    async fn list_recording_view_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<RecordingView>, Error> {
        super::query::list_recording_view_for_user(&self.db, user_id).await
    }

    async fn list_permission_polices(&self) -> Result<Vec<PermissionPolicy>, Error> {
        super::query::list_permission_polices(&self.db).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads a database written by the previous sqlx implementation and checks
    /// the storage-level assumptions this refactor depends on: UUIDs held as
    /// BLOB decode, `port` reads back in range, `authorized_keys` still parses
    /// as JSON-in-TEXT, and `event_log`'s pre-surrogate-key columns are queryable.
    ///
    /// Skipped unless `RUSTION_LEGACY_DB` points at such a file, so the normal
    /// test run stays self-contained:
    ///
    /// ```text
    /// RUSTION_LEGACY_DB=/path/to/old.db cargo test reads_legacy_sqlx_database -- --nocapture
    /// ```
    ///
    /// Uses the real entities rather than copies, so it fails if one drifts away
    /// from the on-disk layout.
    #[tokio::test]
    async fn reads_legacy_sqlx_database() {
        let Ok(path) = std::env::var("RUSTION_LEGACY_DB") else {
            eprintln!("RUSTION_LEGACY_DB not set; skipping");
            return;
        };

        // Read-only: this may be pointed at a real database.
        let db = sea_orm::Database::connect(format!("sqlite://{path}?mode=ro"))
            .await
            .expect("connect to legacy database");

        let users = user::Entity::find().all(&db).await.expect("read users");
        assert!(!users.is_empty(), "expected users in {path}");
        for u in &users {
            assert!(!u.id.is_nil(), "user id decoded as nil: {}", u.username);
            assert!(!u.updated_by.is_nil(), "updated_by decoded as nil");
        }

        let targets = target::Entity::find().all(&db).await.expect("read targets");
        for t in &targets {
            assert!(
                (1..=65535).contains(&t.port),
                "target {} port {} out of range",
                t.name,
                t.port
            );
        }

        // Exercises the StringArray JSON-in-TEXT value type.
        let keyed = users
            .iter()
            .filter_map(|u| u.authorized_keys.as_ref())
            .count();

        // `id` is excluded for the same reason as `ptype` below: a legacy row
        // predates the surrogate key, so selecting it would assert the opposite of
        // the intended change. The columns that were the old composite key still
        // have to read, along with the widest legacy `detail` values.
        let logs: Vec<(i64, Uuid, String)> = event_log::Entity::find()
            .select_only()
            .columns([
                event_log::Column::CreatedAt,
                event_log::Column::ConnectionId,
                event_log::Column::Detail,
            ])
            .into_tuple()
            .all(&db)
            .await
            .expect("read logs");
        for (created_at, connection_id, _) in &logs {
            assert!(*created_at > 0, "log created_at decoded as {created_at}");
            assert!(!connection_id.is_nil(), "log connection_id decoded as nil");
        }

        // `ptype` is deliberately excluded from both casbin reads below.
        //
        // It used to hold the strings `p`/`g1`/`g2`/`g3`; it is now
        // `Ptype`/`NamePtype`, stored as an integer. A legacy row therefore
        // cannot decode, and asserting that it does would be asserting the
        // opposite of the intended change. The rest of each row still has to
        // read, which is what this test is for — so select the other columns and
        // let `ptype` be the one thing that needs a migration.
        let rules: Vec<(Uuid, Uuid, Uuid)> = casbin_rule::Entity::find()
            .select_only()
            .columns([
                casbin_rule::Column::Id,
                casbin_rule::Column::V0,
                casbin_rule::Column::V1,
            ])
            .into_tuple()
            .all(&db)
            .await
            .expect("read casbin_rule");
        for (id, v0, v1) in &rules {
            assert!(!id.is_nil(), "rule id decoded as nil");
            assert!(!v0.is_nil() || !v1.is_nil(), "rule uuids decoded as nil");
        }

        session_recording::Entity::find()
            .all(&db)
            .await
            .expect("read session_recordings");
        secret::Entity::find().all(&db).await.expect("read secrets");
        target_secret::Entity::find()
            .all(&db)
            .await
            .expect("read target_secrets");
        let names: Vec<(Uuid, String)> = casbin_name::Entity::find()
            .select_only()
            .columns([casbin_name::Column::Id, casbin_name::Column::Name])
            .into_tuple()
            .all(&db)
            .await
            .expect("read casbin_names");

        eprintln!(
            "legacy read OK: {} users ({} with keys), {} targets, {} logs, {} rules, {} names \
             (ptype excluded: needs migration to integer; event_log.id excluded: needs 003)",
            users.len(),
            keyed,
            targets.len(),
            logs.len(),
            rules.len(),
            names.len()
        );
    }
}
