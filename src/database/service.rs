use log::info;
use std::sync::Arc;

use crate::database::{create_repository, DatabaseConfig, DatabaseRepository};
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
        models::{target_secret::TargetSecret, CasbinRule, Secret},
        InternalObject, Target, User,
    };
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
        internal_objects: Vec<InternalObject>,
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
        db.repository
            .create_user(&raw_data.users.pop().unwrap())
            .await
            .unwrap();
        db.repository
            .create_users_batch(&raw_data.users)
            .await
            .unwrap();

        db.repository
            .create_target(&raw_data.targets.pop().unwrap())
            .await
            .unwrap();
        db.repository
            .create_targets_batch(&raw_data.targets)
            .await
            .unwrap();

        db.repository
            .create_casbin_rule(&raw_data.casbin_rule.pop().unwrap())
            .await
            .unwrap();
        db.repository
            .create_casbin_rules_batch(&raw_data.casbin_rule)
            .await
            .unwrap();

        db.repository
            .create_secret(&raw_data.secrets.pop().unwrap())
            .await
            .unwrap();
        db.repository
            .create_secrets_batch(&raw_data.secrets)
            .await
            .unwrap();

        db.repository
            .create_target_secret(&raw_data.target_secrets.pop().unwrap())
            .await
            .unwrap();
        db.repository
            .create_target_secrets_batch(&raw_data.target_secrets)
            .await
            .unwrap();

        db.repository()
            .create_internal_object(&raw_data.internal_objects.pop().unwrap())
            .await
            .unwrap();
        db.repository()
            .create_internal_objects_batch(&raw_data.internal_objects)
            .await
            .unwrap();

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
                .list_internal_objects(false)
                .await
                .unwrap()
                .len(),
            1
        );

        assert_eq!(
            service
                .repository
                .list_objects_for_user("66ed2d9e-a51c-4765-966d-b77763232717", false)
                .await
                .unwrap()
                .len(),
            59
        );
        assert_eq!(
            service
                .repository
                .list_objects_for_user("a422db6f-c50e-48d3-bcfb-ddbf8989a974", false)
                .await
                .unwrap()
                .len(),
            53
        );
    }
}
