use crate::error::Error;
use chrono::Utc;
use log::warn;
use russh::client as ru_client;
use russh::keys::ssh_key;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// Target model for database storage
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Target {
    pub id: String,
    pub name: String,
    pub hostname: String,
    pub port: u16,
    pub server_public_key: String,
    pub description: Option<String>,
    pub is_active: bool,
    pub created_by: String, // User ID who created this target
    pub created_at: i64,
    pub updated_at: i64,
}

impl Target {
    pub fn new(
        name: String,
        hostname: String,
        port: u16,
        server_public_key: String,
        created_by: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            hostname,
            port,
            server_public_key,
            description: None,
            is_active: true,
            created_by,
            created_at: now.timestamp_millis(),
            updated_at: now.timestamp_millis(),
        }
    }

    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    pub fn set_active(mut self, active: bool) -> Self {
        self.is_active = active;
        self
    }

    pub(crate) async fn build_connect(self) -> Result<ru_client::Handle<Self>, Error> {
        let config = Arc::new(ru_client::Config::default());
        ru_client::connect(config, (self.hostname.clone(), self.port), self).await
    }
}

impl ru_client::Handler for Target {
    type Error = crate::error::Error;
    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        let target_public_key = ssh_key::PublicKey::from_openssh(self.server_public_key.as_str())
            .map_err(russh::keys::Error::from)?;
        if target_public_key.key_data() == server_public_key.key_data() {
            return Ok(true);
        }
        warn!(
            "The public key of target: {} doesn't match: {}",
            self.name,
            server_public_key.to_string()
        );
        Ok(false)
    }
}
