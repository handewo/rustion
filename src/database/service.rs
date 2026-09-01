use log::info;
use std::sync::Arc;

use crate::database::{DatabaseRepository, create_repository};
use crate::error::Error;

/// Database service that provides high-level operations
#[derive(Clone)]
pub struct DatabaseService {
    repository: Arc<Box<dyn DatabaseRepository>>,
}

impl DatabaseService {
    /// Create a new database service from a sea-orm connection URL
    pub async fn new(url: &str) -> Result<Self, Error> {
        info!("Initializing database service");
        let repository = create_repository(url).await?;
        Ok(Self {
            repository: Arc::new(repository),
        })
    }

    /// Get a reference to the repository for direct access
    pub fn repository(&self) -> &dyn DatabaseRepository {
        self.repository.as_ref().as_ref()
    }
}
