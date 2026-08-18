pub mod common;
pub(crate) mod entity;
pub mod error;
pub(crate) mod models;
pub(crate) mod query;
pub(crate) mod repository;
pub(crate) mod service;

use crate::{database::models::UserWithRole, error::Error};
use async_trait::async_trait;
use models::{
    CasbinName, CasbinRule, CasbinRuleGroup, Log, NamePtype, ObjectGroup, PermissionPolicy, Ptype,
    RecordingView, Role, Secret, SecretInfo, SessionRecording, Target, TargetInfo, TargetSecret,
    TargetSecretName, User,
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

/// Trait defining the database operations interface
/// This allows for easy extension to support multiple database backends
#[async_trait]
pub trait DatabaseRepository: Send + Sync {
    /// Initialize the database (create tables, run migrations, etc.)
    async fn initialize(&self) -> Result<(), Error>;

    /// User operations
    async fn create_user(&self, user: User) -> Result<User, Error>;
    async fn get_user_by_id(&self, id: Uuid) -> Result<Option<User>, Error>;
    async fn get_user_by_username(
        &self,
        username: &str,
        active_only: bool,
    ) -> Result<Option<User>, Error>;
    async fn update_user(&self, user: User) -> Result<User, Error>;
    async fn delete_user(&self, id: Uuid) -> Result<bool, Error>;
    async fn list_users(&self, active_only: bool) -> Result<Vec<User>, Error>;
    async fn list_users_with_role(&self, active_only: bool) -> Result<Vec<UserWithRole>, Error>;

    /// Target operations
    async fn create_target(&self, target: Target) -> Result<Target, Error>;
    async fn get_target_by_id(&self, id: Uuid, active_only: bool) -> Result<Option<Target>, Error>;
    async fn get_targets_by_ids(&self, ids: &[&Uuid]) -> Result<Vec<Target>, Error>;
    async fn get_target_by_target_secret_id(
        &self,
        id: Uuid,
        active_only: bool,
    ) -> Result<Option<Target>, Error>;
    async fn get_targets_by_target_secret_ids(
        &self,
        ids: &[Uuid],
        active_only: bool,
    ) -> Result<Vec<Target>, Error>;
    async fn get_target_by_name(&self, name: &str) -> Result<Option<Target>, Error>;
    async fn get_target_by_hostname(&self, hostname: &str) -> Result<Option<Target>, Error>;
    async fn update_target(&self, target: Target) -> Result<Target, Error>;
    async fn delete_target(&self, id: Uuid) -> Result<bool, Error>;
    async fn list_targets(&self, active_only: bool) -> Result<Vec<Target>, Error>;
    async fn list_targets_info(&self) -> Result<Vec<TargetInfo>, Error>;

    /// Secret operations
    async fn create_secret(&self, secret: Secret) -> Result<Secret, Error>;
    async fn update_secret(&self, secret: Secret) -> Result<Secret, Error>;
    async fn list_secrets(&self, active_only: bool) -> Result<Vec<Secret>, Error>;
    async fn get_secret_by_id(&self, id: Uuid) -> Result<Option<Secret>, Error>;
    async fn get_secret_by_target_secret_id(
        &self,
        id: Uuid,
        active_only: bool,
    ) -> Result<Option<Secret>, Error>;
    async fn get_secrets_by_ids(&self, ids: &[&Uuid]) -> Result<Vec<Secret>, Error>;
    async fn delete_secret(&self, id: Uuid) -> Result<bool, Error>;
    async fn list_secrets_for_target(&self, target_id: Uuid) -> Result<Vec<SecretInfo>, Error>;

    /// TargetSecret operations
    async fn list_target_secrets(&self, active_only: bool) -> Result<Vec<TargetSecret>, Error>;
    async fn list_target_secrets_by_target_id(
        &self,
        target_id: Uuid,
        active_only: bool,
    ) -> Result<Vec<TargetSecret>, Error>;
    async fn create_target_secret(
        &self,
        target_secret: TargetSecret,
    ) -> Result<TargetSecret, Error>;
    async fn update_target_secret(
        &self,
        target_secret: TargetSecret,
    ) -> Result<TargetSecret, Error>;
    async fn delete_target_secret(&self, id: Uuid) -> Result<bool, Error>;
    async fn upsert_target_secret(
        &self,
        target_id: Uuid,
        secret_id: Uuid,
        is_active: bool,
        updated_by: Uuid,
    ) -> Result<(), Error>;

    /// CasbinRule operations
    async fn list_casbin_rules(&self) -> Result<Vec<CasbinRule>, Error>;
    async fn list_casbin_rules_by_ptype(&self, ptype: Ptype) -> Result<Vec<CasbinRule>, Error>;
    async fn list_casbin_rule_group_by_ptype(
        &self,
        ptype: Ptype,
    ) -> Result<Vec<CasbinRuleGroup>, Error>;
    async fn list_roles_by_user_id(&self, user_id: Uuid) -> Result<Vec<Role>, Error>;
    async fn create_casbin_rule(&self, rule: CasbinRule) -> Result<CasbinRule, Error>;
    async fn update_casbin_rule(&self, rule: CasbinRule) -> Result<CasbinRule, Error>;
    async fn delete_casbin_rule(&self, id: Uuid) -> Result<bool, Error>;
    /// It's unsafe if ptype is not in [g1, g2, g3] — [`Ptype::Policy`] rows are
    /// identified by `v0`/`v1`/`v2` together, so this would delete too much.
    async fn delete_casbin_rule_by_v0_v1(
        &self,
        ptype: Ptype,
        v0: Uuid,
        v1: Uuid,
    ) -> Result<bool, Error>;

    /// CasbinName operations - maps UUIDs to human-readable names
    async fn create_casbin_name(&self, name: CasbinName) -> Result<CasbinName, Error>;
    async fn update_casbin_name(&self, name: CasbinName) -> Result<CasbinName, Error>;
    async fn delete_casbin_name(&self, id: Uuid) -> Result<bool, Error>;
    async fn get_casbin_name_by_name(&self, name: &str) -> Result<Option<CasbinName>, Error>;
    async fn get_casbin_name_by_id(&self, id: Uuid) -> Result<Option<CasbinName>, Error>;
    async fn list_casbin_names_by_ptype(
        &self,
        ptype: NamePtype,
        active_only: bool,
    ) -> Result<Vec<CasbinName>, Error>;
    async fn list_casbin_names(&self, active_only: bool) -> Result<Vec<CasbinName>, Error>;
    async fn list_casbin_names_user_visible(
        &self,
        active_only: bool,
    ) -> Result<Vec<CasbinName>, Error>;
    /// Returns the number of rows inserted.
    async fn create_casbin_names_batch(&self, names: Vec<CasbinName>) -> Result<u64, Error>;

    /// Log operations
    async fn insert_log(&self, log: Log) -> Result<(), Error>;
    async fn list_logs(&self) -> Result<Vec<Log>, Error>;

    /// Session recording operations
    async fn create_session_recording(
        &self,
        recording: SessionRecording,
    ) -> Result<SessionRecording, Error>;

    async fn update_session_recording(
        &self,
        recording: SessionRecording,
    ) -> Result<SessionRecording, Error>;

    async fn get_session_recording_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<SessionRecording>, Error>;

    async fn list_session_recordings(
        &self,
        limit: Option<i64>,
    ) -> Result<Vec<SessionRecording>, Error>;

    async fn list_recording_view_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<RecordingView>, Error>;

    async fn list_session_recordings_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<SessionRecording>, Error>;

    async fn list_session_recordings_for_target(
        &self,
        target_id: Uuid,
    ) -> Result<Vec<SessionRecording>, Error>;

    /// casbin operations
    async fn get_policies_for_user(&self, user_id: Uuid) -> Result<Vec<CasbinRule>, Error>;
    async fn get_actions_for_policy(&self, policy_act: Uuid) -> Result<Vec<Uuid>, Error>;

    /// Batch operations
    ///
    /// Each returns the number of rows inserted, as reported by the driver.
    async fn create_users_batch(&self, users: Vec<User>) -> Result<u64, Error>;
    async fn create_targets_batch(&self, targets: Vec<Target>) -> Result<u64, Error>;
    async fn create_secrets_batch(&self, secrets: Vec<Secret>) -> Result<u64, Error>;
    async fn create_target_secrets_batch(
        &self,
        target_secrets: Vec<TargetSecret>,
    ) -> Result<u64, Error>;
    async fn create_casbin_rules_batch(&self, rules: Vec<CasbinRule>) -> Result<u64, Error>;

    /// Search operations
    async fn search_users(&self, query: &str) -> Result<Vec<User>, Error>;
    async fn search_targets(&self, query: &str) -> Result<Vec<Target>, Error>;
    async fn list_targets_for_user(
        &self,
        user_id: Uuid,
        active_only: bool,
    ) -> Result<Vec<TargetSecretName>, Error>;
    async fn list_targets_by_ids(
        &self,
        ids: &[&Uuid],
        pid: Uuid,
        active_only: bool,
    ) -> Result<Vec<TargetSecretName>, Error>;

    async fn list_user_group(&self) -> Result<Vec<ObjectGroup>, Error>;
    async fn list_target_group(&self) -> Result<Vec<ObjectGroup>, Error>;
    async fn list_action_group(&self) -> Result<Vec<ObjectGroup>, Error>;

    async fn check_object_active(&self, id: Uuid) -> Result<bool, Error>;

    /// Statistics
    async fn count_users(&self) -> Result<i64, Error>;
    async fn count_targets(&self) -> Result<i64, Error>;
    async fn count_active_users(&self) -> Result<i64, Error>;
    async fn count_active_targets(&self) -> Result<i64, Error>;

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
