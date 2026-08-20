use log::info;
use std::sync::Arc;

use crate::database::{DatabaseConfig, DatabaseRepository, create_repository};
use crate::error::Error;

/// Database service that provides high-level operations
#[derive(Clone)]
pub struct DatabaseService {
    repository: Arc<Box<dyn DatabaseRepository>>,
}

impl DatabaseService {
    /// Create a new database service with the given configuration
    pub async fn new(config: &DatabaseConfig) -> Result<Self, Error> {
        info!("Initializing database service");
        let repository = create_repository(config).await?;
        Ok(Self {
            repository: Arc::new(repository),
        })
    }

    /// Get a reference to the repository for direct access
    pub fn repository(&self) -> &dyn DatabaseRepository {
        self.repository.as_ref().as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::{
        CasbinName, Target, User,
        entity::user,
        models::{CasbinRule, Secret, target_secret::TargetSecret},
    };
    use sea_orm::ActiveValue::Set;
    use serde::{Deserialize, Serialize};
    use serde_json;
    use std::{fs::File, io::Read};
    use tempfile::tempdir;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct RawData {
        users: Vec<User>,
        targets: Vec<Target>,
        secrets: Vec<Secret>,
        target_secrets: Vec<TargetSecret>,
        casbin_rule: Vec<CasbinRule>,
        casbin_names: Vec<CasbinName>,
    }

    async fn create_test_service() -> DatabaseService {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let _ = File::create(&db_path).unwrap();
        let config = DatabaseConfig::Sqlite {
            path: db_path.to_string_lossy().to_string(),
        };
        let db = DatabaseService::new(&config).await.unwrap();
        let mut test_data = File::open("mock_data.json").unwrap();
        let mut buffer = String::new();
        test_data.read_to_string(&mut buffer).unwrap();
        let mut raw_data: RawData = serde_json::from_str(&buffer).unwrap();
        let first_user = raw_data.users.pop().unwrap();
        let active_model: user::ActiveModel = user::ActiveModel {
            id: Set(first_user.id),
            username: Set(first_user.username),
            email: Set(first_user.email),
            authorized_keys: Set(first_user.authorized_keys.map(|v| v.into())),
            force_init_pass: Set(first_user.force_init_pass),
            is_active: Set(first_user.is_active),
            updated_by: Set(first_user.updated_by),
            updated_at: Set(first_user.updated_at),
            ..Default::default()
        };
        // Each batch insert reports the rows the driver actually wrote; assert it matches
        // the number of entities handed in.
        db.repository.create_user(active_model).await.unwrap();
        let n = raw_data.users.len() as u64;
        assert_eq!(
            db.repository
                .create_users_batch(raw_data.users)
                .await
                .unwrap(),
            n
        );

        db.repository
            .create_target(raw_data.targets.pop().unwrap())
            .await
            .unwrap();
        let n = raw_data.targets.len() as u64;
        assert_eq!(
            db.repository
                .create_targets_batch(raw_data.targets)
                .await
                .unwrap(),
            n
        );

        db.repository
            .create_casbin_rule(raw_data.casbin_rule.pop().unwrap())
            .await
            .unwrap();
        let n = raw_data.casbin_rule.len() as u64;
        assert_eq!(
            db.repository
                .create_casbin_rules_batch(raw_data.casbin_rule)
                .await
                .unwrap(),
            n
        );

        db.repository
            .create_secret(raw_data.secrets.pop().unwrap())
            .await
            .unwrap();
        let n = raw_data.secrets.len() as u64;
        assert_eq!(
            db.repository
                .create_secrets_batch(raw_data.secrets)
                .await
                .unwrap(),
            n
        );

        db.repository
            .create_target_secret(raw_data.target_secrets.pop().unwrap())
            .await
            .unwrap();
        let n = raw_data.target_secrets.len() as u64;
        assert_eq!(
            db.repository
                .create_target_secrets_batch(raw_data.target_secrets)
                .await
                .unwrap(),
            n
        );
        let n = raw_data.casbin_names.len() as u64;
        assert_eq!(
            db.repository
                .create_casbin_names_batch(raw_data.casbin_names)
                .await
                .unwrap(),
            n
        );

        db
    }

    #[tokio::test]
    async fn test_db_service() {
        let service = create_test_service().await;

        assert_eq!(service.repository.list_users(false).await.unwrap().len(), 5);
        assert_eq!(
            service.repository.list_targets(false).await.unwrap().len(),
            30
        );
        assert_eq!(
            service.repository.list_secrets(false).await.unwrap().len(),
            6
        );
        assert_eq!(
            service
                .repository
                .list_target_secrets(false)
                .await
                .unwrap()
                .len(),
            85
        );
        assert_eq!(
            service.repository.list_casbin_rules().await.unwrap().len(),
            108
        );
        assert_eq!(
            service
                .repository
                .list_casbin_names(false)
                .await
                .unwrap()
                .len(),
            21
        );
    }
}
