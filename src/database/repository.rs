//! Backend-agnostic [`DatabaseRepository`] implementation.
//!
//! One implementation serves SQLite, PostgreSQL and MySQL — sea-orm resolves the
//! driver from the connection URL, and every query here is built through
//! sea-query so identifiers, booleans and parameter placeholders are emitted in
//! each backend's own dialect.

use async_trait::async_trait;
use chrono::Utc;
use log::{debug, info};
use sea_orm::sea_query::ExprTrait;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait,
    PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, Schema,
};
use uuid::Uuid;

use crate::database::entity::{
    casbin_names, casbin_rule, logs, secret, session_recordings, target, target_secret, user,
};
use crate::database::error::DatabaseError;
use crate::database::models::casbin_rule::ValidateError;
use crate::database::models::{
    CasbinName, CasbinRule, CasbinRuleGroup, Log, NamePtype, ObjectGroup, PermissionPolicy, Ptype,
    RecordingView, Role, Secret, SecretInfo, SessionRecording, Target, TargetInfo, TargetSecret,
    TargetSecretName, User, UserWithRole,
};
use crate::database::{DatabaseConfig, DatabaseRepository};
use crate::error::Error;

/// Matches the sqlx pool default. sea-orm defaults SQLite to a single
/// connection, which would serialise every database call.
const MAX_CONNECTIONS: u32 = 10;

pub struct SeaOrmRepository {
    pub(in crate::database) db: DatabaseConnection,
}

impl SeaOrmRepository {
    pub async fn new(config: &DatabaseConfig) -> Result<Self, Error> {
        info!("Connecting to database: {}", config);

        let mut options = ConnectOptions::new(config.connection_url());
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
            && exists!(casbin_names::Entity)
            && exists!(logs::Entity)
            && exists!(session_recordings::Entity)
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
            .register(casbin_names::Entity)
            .register(logs::Entity)
            .register(session_recordings::Entity)
            .sync(&self.db)
            .await?;

        info!("Database tables and indexes are up to date");
        Ok(())
    }

    // ---------------------------------------------------------------- users

    async fn create_user(&self, user: User) -> Result<User, Error> {
        debug!("Creating user: '{}({})'", user.username, user.id);
        let res = user.into_active_model().insert(&self.db).await?;
        debug!("User created successfully: '{}({})'", res.username, res.id);
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

    async fn update_user(&self, mut user: User) -> Result<User, Error> {
        debug!("Updating user: '{}({})'", user.username, user.id);
        user.updated_at = Utc::now().timestamp_millis();

        let res = user::Entity::update(user.into_active_model())
            .exec(&self.db)
            .await?;

        debug!("User updated successfully: '{}({})'", res.username, res.id);
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

    async fn search_users(&self, query: &str) -> Result<Vec<User>, Error> {
        let pattern = format!("%{}%", query);
        Ok(user::Entity::find()
            .filter(
                user::Column::Username
                    .like(&pattern)
                    .or(user::Column::Email.like(&pattern)),
            )
            .order_by_asc(user::Column::Username)
            .all(&self.db)
            .await?
            .into_iter()
            .map(User::from)
            .collect())
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

    async fn create_target(&self, target: Target) -> Result<Target, Error> {
        debug!("Creating target: '{}({})'", target.name, target.id);
        let res = target.into_active_model().insert(&self.db).await?;
        debug!("Target created successfully: '{}({})'", res.name, res.id);
        Ok(res.into())
    }

    async fn get_target_by_id(&self, id: Uuid, active_only: bool) -> Result<Option<Target>, Error> {
        let mut q = target::Entity::find_by_id(id);
        if active_only {
            q = q.filter(target::Column::IsActive.eq(true));
        }
        Ok(q.one(&self.db).await?.map(Target::from))
    }

    async fn get_targets_by_ids(&self, ids: &[&Uuid]) -> Result<Vec<Target>, Error> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        Ok(target::Entity::find()
            .filter(target::Column::Id.is_in(ids.iter().map(|i| **i)))
            .all(&self.db)
            .await?
            .into_iter()
            .map(Target::from)
            .collect())
    }

    async fn get_target_by_name(&self, name: &str) -> Result<Option<Target>, Error> {
        Ok(target::Entity::find()
            .filter(target::Column::Name.eq(name))
            .one(&self.db)
            .await?
            .map(Target::from))
    }

    async fn get_target_by_hostname(&self, hostname: &str) -> Result<Option<Target>, Error> {
        Ok(target::Entity::find()
            .filter(target::Column::Hostname.eq(hostname))
            .one(&self.db)
            .await?
            .map(Target::from))
    }

    async fn update_target(&self, mut target: Target) -> Result<Target, Error> {
        debug!("Updating target: '{}({})'", target.name, target.id);
        target.updated_at = Utc::now().timestamp_millis();

        let res = target::Entity::update(target.into_active_model())
            .exec(&self.db)
            .await?;

        debug!("Target updated successfully: '{}({})'", res.name, res.id);
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

    async fn search_targets(&self, query: &str) -> Result<Vec<Target>, Error> {
        let pattern = format!("%{}%", query);
        Ok(target::Entity::find()
            .filter(
                target::Column::Name
                    .like(&pattern)
                    .or(target::Column::Hostname.like(&pattern))
                    .or(target::Column::Description.like(&pattern)),
            )
            .order_by_asc(target::Column::Name)
            .all(&self.db)
            .await?
            .into_iter()
            .map(Target::from)
            .collect())
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

    async fn create_secret(&self, secret: Secret) -> Result<Secret, Error> {
        debug!("Creating secret: '{}({})'", secret.name, secret.id);
        let res = secret.into_active_model().insert(&self.db).await?;
        debug!("Secret created successfully: '{}({})'", res.name, res.id);
        Ok(res.into())
    }

    async fn update_secret(&self, mut secret: Secret) -> Result<Secret, Error> {
        debug!("Updating secret: '{}({})'", secret.name, secret.id);
        secret.updated_at = Utc::now().timestamp_millis();

        let res = secret::Entity::update(secret.into_active_model())
            .exec(&self.db)
            .await?;

        debug!("Secret updated successfully: '{}({})'", res.name, res.id);
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

    async fn get_secrets_by_ids(&self, ids: &[&Uuid]) -> Result<Vec<Secret>, Error> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        Ok(secret::Entity::find()
            .filter(secret::Column::Id.is_in(ids.iter().map(|i| **i)))
            .all(&self.db)
            .await?
            .into_iter()
            .map(Secret::from)
            .collect())
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
        target_secret: TargetSecret,
    ) -> Result<TargetSecret, Error> {
        let res = target_secret.into_active_model().insert(&self.db).await?;
        Ok(res.into())
    }

    async fn update_target_secret(
        &self,
        mut target_secret: TargetSecret,
    ) -> Result<TargetSecret, Error> {
        target_secret.updated_at = Utc::now().timestamp_millis();

        let res = target_secret::Entity::update(target_secret.into_active_model())
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
        debug!(
            "Upserting target_secret binding: target_id={}, secret_id={}, is_active={}",
            target_id, secret_id, is_active
        );

        let existing = target_secret::Entity::find()
            .filter(target_secret::Column::TargetId.eq(target_id))
            .filter(target_secret::Column::SecretId.eq(secret_id))
            .one(&self.db)
            .await?;

        match existing {
            Some(m) => {
                let mut ts = TargetSecret::from(m);
                ts.is_active = is_active;
                self.update_target_secret(ts).await?;
                debug!(
                    "Target_secret binding updated: target_id={}, secret_id={}",
                    target_id, secret_id
                );
            }
            None => {
                let mut ts = TargetSecret::new(target_id, secret_id, updated_by);
                ts.is_active = is_active;
                self.create_target_secret(ts).await?;
                debug!(
                    "Target_secret binding created: target_id={}, secret_id={}",
                    target_id, secret_id
                );
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

    async fn create_casbin_rule(&self, rule: CasbinRule) -> Result<CasbinRule, Error> {
        debug!("Creating casbin_rule: '({})'", rule.id);
        let res = rule.into_active_model().insert(&self.db).await?;
        debug!("Casbin_rule created successfully: '({})'", res.id);
        Ok(res.into())
    }

    async fn update_casbin_rule(&self, mut rule: CasbinRule) -> Result<CasbinRule, Error> {
        debug!("Updating casbin_rule: '({})'", rule.id);
        rule.updated_at = Utc::now().timestamp_millis();

        let res = casbin_rule::Entity::update(rule.into_active_model())
            .exec(&self.db)
            .await?;

        debug!("Casbin_rule updated successfully: '({})'", res.id);
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

    async fn delete_casbin_rule_by_v0_v1(
        &self,
        ptype: Ptype,
        v0: Uuid,
        v1: Uuid,
    ) -> Result<bool, Error> {
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

    async fn create_casbin_name(&self, name: CasbinName) -> Result<CasbinName, Error> {
        let res = name.into_active_model().insert(&self.db).await?;
        Ok(res.into())
    }

    async fn update_casbin_name(&self, mut name: CasbinName) -> Result<CasbinName, Error> {
        // Internal types may not be renamed or re-typed.
        if let Some(existing) = self.get_casbin_name_by_id(name.id).await?
            && existing.is_internal()
            && (existing.ptype != name.ptype || existing.name != name.name)
        {
            return Err(Error::Database(DatabaseError::CasbinNameValidation(
                ValidateError::InternalTypeModification,
            )));
        }

        name.updated_at = Utc::now().timestamp_millis();

        let res = casbin_names::Entity::update(name.into_active_model())
            .exec(&self.db)
            .await?;

        Ok(res.into())
    }

    async fn delete_casbin_name(&self, id: Uuid) -> Result<bool, Error> {
        debug!("Deleting casbin_name: id={}", id);

        if let Some(casbin_name) = self.get_casbin_name_by_id(id).await?
            && casbin_name.is_internal()
        {
            return Err(Error::Database(DatabaseError::CasbinNameValidation(
                ValidateError::InternalTypeModification,
            )));
        }

        let res = casbin_names::Entity::delete_by_id(id)
            .exec(&self.db)
            .await?;
        let deleted = res.rows_affected > 0;
        if deleted {
            debug!("Casbin_name deleted successfully: id={}", id);
        }
        Ok(deleted)
    }

    async fn get_casbin_name_by_name(&self, name: &str) -> Result<Option<CasbinName>, Error> {
        Ok(casbin_names::Entity::find()
            .filter(casbin_names::Column::Name.eq(name))
            .one(&self.db)
            .await?
            .map(CasbinName::from))
    }

    async fn get_casbin_name_by_id(&self, id: Uuid) -> Result<Option<CasbinName>, Error> {
        Ok(casbin_names::Entity::find_by_id(id)
            .one(&self.db)
            .await?
            .map(CasbinName::from))
    }

    async fn list_casbin_names_by_ptype(
        &self,
        ptype: NamePtype,
        active_only: bool,
    ) -> Result<Vec<CasbinName>, Error> {
        let mut q = casbin_names::Entity::find().filter(casbin_names::Column::Ptype.eq(ptype));
        if active_only {
            q = q.filter(casbin_names::Column::IsActive.eq(true));
        }
        Ok(q.all(&self.db)
            .await?
            .into_iter()
            .map(CasbinName::from)
            .collect())
    }

    async fn list_casbin_names(&self, active_only: bool) -> Result<Vec<CasbinName>, Error> {
        let mut q = casbin_names::Entity::find();
        if active_only {
            q = q.filter(casbin_names::Column::IsActive.eq(true));
        }
        Ok(q.order_by_asc(casbin_names::Column::Ptype)
            .order_by_asc(casbin_names::Column::Name)
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
        let mut q = casbin_names::Entity::find().filter(casbin_names::Column::Ptype.is_not_in([
            casbin_names::NamePtype::InternalActionType,
            casbin_names::NamePtype::InternalObjectType,
        ]));
        if active_only {
            q = q.filter(casbin_names::Column::IsActive.eq(true));
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
        let rows = casbin_names::Entity::insert_many(
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

    async fn insert_log(&self, log: Log) -> Result<(), Error> {
        log.into_active_model().insert(&self.db).await?;
        Ok(())
    }

    async fn list_logs(&self) -> Result<Vec<Log>, Error> {
        Ok(logs::Entity::find()
            .order_by_desc(logs::Column::CreatedAt)
            .all(&self.db)
            .await?
            .into_iter()
            .map(Log::from)
            .collect())
    }

    // ------------------------------------------------------ session records

    async fn create_session_recording(
        &self,
        recording: SessionRecording,
    ) -> Result<SessionRecording, Error> {
        debug!(
            "Creating session_recording: user_id={}, target_id={}",
            recording.user_id, recording.target_id
        );
        let res = recording.into_active_model().insert(&self.db).await?;
        Ok(res.into())
    }

    async fn update_session_recording(
        &self,
        recording: SessionRecording,
    ) -> Result<SessionRecording, Error> {
        debug!("Updating session_recording: id={}", recording.id);
        let res = session_recordings::Entity::update(recording.into_active_model())
            .exec(&self.db)
            .await?;
        Ok(res.into())
    }

    async fn get_session_recording_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<SessionRecording>, Error> {
        Ok(session_recordings::Entity::find_by_id(id)
            .one(&self.db)
            .await?
            .map(SessionRecording::from))
    }

    async fn list_session_recordings(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<SessionRecording>, Error> {
        let mut q =
            session_recordings::Entity::find().order_by_desc(session_recordings::Column::StartedAt);
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
        Ok(session_recordings::Entity::find()
            .filter(session_recordings::Column::UserId.eq(user_id))
            .order_by_desc(session_recordings::Column::StartedAt)
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
        Ok(session_recordings::Entity::find()
            .filter(session_recordings::Column::TargetId.eq(target_id))
            .order_by_desc(session_recordings::Column::StartedAt)
            .all(&self.db)
            .await?
            .into_iter()
            .map(SessionRecording::from)
            .collect())
    }

    // ------------------------------------------------------------ statistics

    async fn count_users(&self) -> Result<i64, Error> {
        Ok(user::Entity::find().count(&self.db).await? as i64)
    }

    async fn count_targets(&self) -> Result<i64, Error> {
        Ok(target::Entity::find().count(&self.db).await? as i64)
    }

    async fn count_active_users(&self) -> Result<i64, Error> {
        Ok(user::Entity::find()
            .filter(user::Column::IsActive.eq(true))
            .count(&self.db)
            .await? as i64)
    }

    async fn count_active_targets(&self) -> Result<i64, Error> {
        Ok(target::Entity::find()
            .filter(target::Column::IsActive.eq(true))
            .count(&self.db)
            .await? as i64)
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
        ids: &[Uuid],
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

    async fn list_secrets_for_target(&self, target_id: Uuid) -> Result<Vec<SecretInfo>, Error> {
        super::query::list_secrets_for_target(&self.db, target_id).await
    }

    async fn list_target_secrets_by_target_id(
        &self,
        target_id: Uuid,
        active_only: bool,
    ) -> Result<Vec<TargetSecret>, Error> {
        super::query::list_target_secrets_by_target_id(&self.db, target_id, active_only).await
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

    async fn get_policies_for_user(&self, user_id: Uuid) -> Result<Vec<CasbinRule>, Error> {
        super::query::get_policies_for_user(&self.db, user_id).await
    }

    async fn get_actions_for_policy(&self, policy_act: Uuid) -> Result<Vec<Uuid>, Error> {
        super::query::get_actions_for_policy(&self.db, policy_act).await
    }

    async fn list_targets_for_user(
        &self,
        user_id: Uuid,
        active_only: bool,
    ) -> Result<Vec<TargetSecretName>, Error> {
        super::query::list_targets_for_user(&self.db, user_id, active_only).await
    }

    async fn list_targets_by_ids(
        &self,
        ids: &[&Uuid],
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
    /// as JSON-in-TEXT, and the composite-PK `logs` table is queryable.
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

        // Composite primary key, and the widest legacy `detail` values.
        let logs = logs::Entity::find().all(&db).await.expect("read logs");

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

        session_recordings::Entity::find()
            .all(&db)
            .await
            .expect("read session_recordings");
        secret::Entity::find().all(&db).await.expect("read secrets");
        target_secret::Entity::find()
            .all(&db)
            .await
            .expect("read target_secrets");
        let names: Vec<(Uuid, String)> = casbin_names::Entity::find()
            .select_only()
            .columns([casbin_names::Column::Id, casbin_names::Column::Name])
            .into_tuple()
            .all(&db)
            .await
            .expect("read casbin_names");

        eprintln!(
            "legacy read OK: {} users ({} with keys), {} targets, {} logs, {} rules, {} names \
             (ptype excluded: needs migration to integer)",
            users.len(),
            keyed,
            targets.len(),
            logs.len(),
            rules.len(),
            names.len()
        );
    }
}
