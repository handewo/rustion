pub mod common;
pub(crate) mod models;
pub(crate) mod service;
pub(crate) mod sqlite;

use crate::error::Error;
use async_trait::async_trait;
use models::{
    CasbinName, CasbinRule, CasbinRuleGroup, InternalObject, Log, Secret, SecretInfo, Target,
    TargetInfo, TargetSecret, TargetSecretName, User,
};
pub use uuid::Uuid;

/// Database configuration enum to support multiple database backends
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum DatabaseConfig {
    Sqlite { path: String },
    // Future database support can be added here
    // Mysql { host: String, port: u16, database: String, username: String, password: String },
    // Postgresql { host: String, port: u16, database: String, username: String, password: String },
}

impl std::fmt::Display for DatabaseConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DatabaseConfig::Sqlite { path } => {
                write!(f, "sqlite({})", path)
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

/// Trait defining the database operations interface
/// This allows for easy extension to support multiple database backends
#[async_trait]
pub trait DatabaseRepository: Send + Sync {
    /// Initialize the database (create tables, run migrations, etc.)
    async fn initialize(&self) -> Result<(), Error>;

    /// User operations
    async fn create_user(&self, user: &User) -> Result<User, Error>;
    async fn get_user_by_id(&self, id: &Uuid) -> Result<Option<User>, Error>;
    async fn get_user_by_username(
        &self,
        username: &str,
        active_only: bool,
    ) -> Result<Option<User>, Error>;
    async fn update_user(&self, user: &User) -> Result<User, Error>;
    async fn delete_user(&self, id: &Uuid) -> Result<bool, Error>;
    async fn list_users(&self, active_only: bool) -> Result<Vec<User>, Error>;

    /// Target operations
    async fn create_target(&self, target: &Target) -> Result<Target, Error>;
    async fn get_target_by_id(&self, id: &Uuid, active_only: bool)
        -> Result<Option<Target>, Error>;
    async fn get_targets_by_ids(&self, ids: &[&Uuid]) -> Result<Vec<Target>, Error>;
    async fn get_targets_by_target_secret_ids(
        &self,
        ids: &[&Uuid],
        active_only: bool,
    ) -> Result<Vec<Target>, Error>;
    async fn get_target_by_name(&self, name: &str) -> Result<Option<Target>, Error>;
    async fn get_target_by_hostname(&self, hostname: &str) -> Result<Option<Target>, Error>;
    async fn update_target(&self, target: &Target) -> Result<Target, Error>;
    async fn delete_target(&self, id: &Uuid) -> Result<bool, Error>;
    async fn list_targets(&self, active_only: bool) -> Result<Vec<Target>, Error>;
    async fn list_targets_info(&self) -> Result<Vec<TargetInfo>, Error>;

    /// Secret operations
    async fn create_secret(&self, secret: &Secret) -> Result<Secret, Error>;
    async fn update_secret(&self, target: &Secret) -> Result<Secret, Error>;
    async fn list_secrets(&self, active_only: bool) -> Result<Vec<Secret>, Error>;
    async fn get_secret_by_id(&self, id: &Uuid) -> Result<Option<Secret>, Error>;
    async fn get_secret_by_target_secret_id(
        &self,
        id: &Uuid,
        active_only: bool,
    ) -> Result<Option<Secret>, Error>;
    async fn get_secrets_by_ids(&self, ids: &[&Uuid]) -> Result<Vec<Secret>, Error>;
    async fn delete_secret(&self, id: &Uuid) -> Result<bool, Error>;
    async fn list_secrets_for_target(&self, target_id: &Uuid) -> Result<Vec<SecretInfo>, Error>;

    /// TargetSecret operations
    async fn list_target_secrets(&self, active_only: bool) -> Result<Vec<TargetSecret>, Error>;
    async fn create_target_secret(
        &self,
        target_secret: &TargetSecret,
    ) -> Result<TargetSecret, Error>;
    async fn update_target_secret(&self, secret: &TargetSecret) -> Result<TargetSecret, Error>;
    async fn delete_target_secret(&self, id: &Uuid) -> Result<bool, Error>;
    async fn upsert_target_secret(
        &self,
        target_id: &Uuid,
        secret_id: &Uuid,
        is_active: bool,
        updated_by: &Uuid,
    ) -> Result<(), Error>;

    /// CasbinRule operations
    async fn list_casbin_rules(&self) -> Result<Vec<CasbinRule>, Error>;
    async fn list_casbin_rules_by_ptype(&self, ptype: &str) -> Result<Vec<CasbinRule>, Error>;
    async fn list_casbin_rule_group_by_ptype(
        &self,
        ptype: &str,
    ) -> Result<Vec<CasbinRuleGroup>, Error>;
    async fn list_roles_by_user_id(&self, user_id: &Uuid) -> Result<Vec<CasbinRule>, Error>;
    async fn create_casbin_rule(&self, rule: &CasbinRule) -> Result<CasbinRule, Error>;
    async fn update_casbin_rule(&self, rule: &CasbinRule) -> Result<CasbinRule, Error>;
    async fn delete_casbin_rule(&self, id: &Uuid) -> Result<bool, Error>;

    /// CasbinName operations - maps UUIDs to human-readable names
    async fn create_casbin_name(&self, name: &CasbinName) -> Result<CasbinName, Error>;
    async fn get_casbin_name_by_name(&self, name: &str) -> Result<Option<CasbinName>, Error>;
    async fn get_casbin_name_by_id(&self, id: &Uuid) -> Result<Option<CasbinName>, Error>;
    async fn list_casbin_names_by_ptype(&self, ptype: &str) -> Result<Vec<CasbinName>, Error>;

    /// InternalObject operations
    async fn list_internal_objects(&self, active_only: bool) -> Result<Vec<InternalObject>, Error>;
    async fn get_internal_object_by_name(
        &self,
        name: &str,
    ) -> Result<Option<InternalObject>, Error>;
    async fn update_internal_object(&self, obj: &InternalObject) -> Result<InternalObject, Error>;
    async fn create_internal_object(&self, obj: &InternalObject) -> Result<InternalObject, Error>;

    /// Log operations
    async fn insert_log(&self, log: &Log) -> Result<(), Error>;
    async fn list_logs(&self) -> Result<Vec<Log>, Error>;

    /// casbin operations
    async fn get_policies_for_user(&self, user_id: &Uuid) -> Result<Vec<CasbinRule>, Error>;
    async fn get_actions_for_policy(&self, policy_act: &Uuid) -> Result<Vec<Uuid>, Error>;

    /// Batch operations
    async fn create_users_batch(&self, users: &[User]) -> Result<Vec<User>, Error>;
    async fn create_targets_batch(&self, targets: &[Target]) -> Result<Vec<Target>, Error>;
    async fn create_secrets_batch(&self, targets: &[Secret]) -> Result<Vec<Secret>, Error>;
    async fn create_target_secrets_batch(
        &self,
        targets: &[TargetSecret],
    ) -> Result<Vec<TargetSecret>, Error>;
    async fn create_casbin_rules_batch(
        &self,
        rules: &[CasbinRule],
    ) -> Result<Vec<CasbinRule>, Error>;
    async fn create_internal_objects_batch(
        &self,
        objs: &[InternalObject],
    ) -> Result<Vec<InternalObject>, Error>;

    /// Search operations
    async fn search_users(&self, query: &str) -> Result<Vec<User>, Error>;
    async fn search_targets(&self, query: &str) -> Result<Vec<Target>, Error>;
    async fn list_targets_for_user(
        &self,
        user_id: &Uuid,
        active_only: bool,
    ) -> Result<Vec<TargetSecretName>, Error>;
    async fn list_targets_by_ids(
        &self,
        ids: &[&Uuid],
        pid: &Uuid,
        active_only: bool,
    ) -> Result<Vec<TargetSecretName>, Error>;

    async fn check_object_active(&self, id: &Uuid) -> Result<bool, Error>;

    /// Statistics
    async fn count_users(&self) -> Result<i64, Error>;
    async fn count_targets(&self) -> Result<i64, Error>;
    async fn count_active_users(&self) -> Result<i64, Error>;
    async fn count_active_targets(&self) -> Result<i64, Error>;
}

/// Database factory to create appropriate repository based on configuration
pub async fn create_repository(
    config: &DatabaseConfig,
) -> Result<Box<dyn DatabaseRepository>, Error> {
    match config {
        DatabaseConfig::Sqlite { path } => {
            let repo = sqlite::SqliteRepository::new(path).await?;
            Ok(Box::new(repo))
        } // Future database implementations can be added here
    }
}
