use crate::error::Error;
use chrono::Utc;
use log::warn;
use russh::client as ru_client;
use russh::keys::ssh_key::{self, PublicKey};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;

const MAX_NAME_LEN: usize = 50;

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
    pub updated_by: String, // User ID who last updated this target
    pub updated_at: i64,
}

impl Target {
    pub fn new(updated_by: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            name: String::default(),
            hostname: String::default(),
            port: 22,
            server_public_key: String::default(),
            description: None,
            is_active: true,
            updated_by,
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

    pub fn validate(&self) -> Result<(), ValidateError> {
        let name = self.name.trim();
        if name.is_empty() {
            return Err(ValidateError::NameEmpty);
        }
        if name.len() > MAX_NAME_LEN {
            return Err(ValidateError::NameTooLong);
        }
        let hostname = self.hostname.trim();
        if hostname.is_empty() {
            return Err(ValidateError::HostnameEmpty);
        }
        if hostname.len() > MAX_NAME_LEN {
            return Err(ValidateError::HostnameTooLong);
        }
        if PublicKey::from_str(&self.server_public_key).is_err() {
            return Err(ValidateError::ServerPublicKey);
        }
        Ok(())
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

#[derive(Debug, thiserror::Error)]
pub enum ValidateError {
    NameEmpty,
    NameTooLong,
    HostnameEmpty,
    HostnameTooLong,
    PortNotNumber,
    PortInvalid,
    ServerPublicKey,
}

impl std::fmt::Display for ValidateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ValidateError::*;
        match self {
            NameEmpty => {
                write!(f, "name cannot be empty")
            }
            NameTooLong => {
                write!(f, "name is too long, max: {}", MAX_NAME_LEN)
            }
            HostnameEmpty => {
                write!(f, "hostname cannot be empty")
            }
            HostnameTooLong => {
                write!(f, "hostname is too long, max: {}", MAX_NAME_LEN)
            }
            ServerPublicKey => {
                write!(f, "server public key is invalid")
            }
            PortNotNumber => {
                write!(f, "port is not a number")
            }
            PortInvalid => {
                write!(f, "port is not within the range of 1–65536")
            }
        }
    }
}
