use chrono::Utc;
use russh::keys::ssh_key::{PrivateKey, PublicKey};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct TargetSecret {
    pub id: String,
    pub target_id: String,
    pub secret_id: String,
    pub is_active: bool,
    pub updated_by: String,
    pub updated_at: i64,
}

/// For login to remote target
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Secret {
    pub id: String,
    pub name: String, //for display only
    pub user: String, //login user of target
    pub(in crate::database) password: Option<String>,
    pub(in crate::database) private_key: Option<String>,
    pub(in crate::database) public_key: Option<String>,
    pub is_active: bool,
    pub updated_by: String,
    pub updated_at: i64,
}

impl TargetSecret {
    pub fn new(target_id: String, secret_id: String, updated_by: String) -> Self {
        let now = Utc::now().timestamp_millis();
        Self {
            id: Uuid::new_v4().to_string(),
            target_id,
            secret_id,
            is_active: true,
            updated_by,
            updated_at: now,
        }
    }
}

impl Secret {
    pub fn new(updated_by: String) -> Self {
        let now = Utc::now().timestamp_millis();
        Self {
            id: Uuid::new_v4().to_string(),
            name: String::default(),
            user: String::default(),
            password: None,
            private_key: None,
            public_key: None,
            is_active: true,
            updated_by,
            updated_at: now,
        }
    }

    pub fn with_password(mut self, password: Option<String>) -> Self {
        self.password = password;
        self
    }

    pub fn print_password(&self) -> String {
        if self.password.is_some() {
            "********".to_string()
        } else {
            String::new()
        }
    }

    pub fn with_private_key(mut self, private_key: Option<String>) -> Self {
        self.private_key = private_key;
        self
    }

    pub fn print_private_key(&self) -> String {
        if self.private_key.is_some() {
            "********".to_string()
        } else {
            String::new()
        }
    }

    pub fn with_public_key(mut self, public_key: Option<String>) -> Self {
        self.public_key = public_key;
        self
    }

    pub fn print_public_key(&self) -> String {
        if self.public_key.is_some() {
            "********".to_string()
        } else {
            String::new()
        }
    }

    pub fn take_password(&mut self) -> Option<String> {
        self.password.take()
    }

    pub fn take_private_key(&mut self) -> Option<String> {
        self.private_key.take()
    }

    pub fn take_public_key(&mut self) -> Option<String> {
        self.public_key.take()
    }

    pub fn validate(&self) -> Result<(), ValidateError> {
        let name = self.name.trim();
        if name.is_empty() {
            return Err(ValidateError::NameEmpty);
        }

        let user = self.user.trim();
        if user.is_empty() {
            return Err(ValidateError::UserEmpty);
        }

        if let Some(private_key) = self.private_key.as_ref() {
            match PrivateKey::from_str(private_key) {
                Ok(key) => {
                    let ori_public_key = key.public_key();
                    if let Some(public_key) = self.public_key.as_ref() {
                        match PublicKey::from_str(public_key) {
                            Ok(pub_key) => {
                                if ori_public_key != &pub_key {
                                    return Err(ValidateError::UnmatchedKey);
                                }
                            }
                            Err(_) => return Err(ValidateError::PublicKeyInvalid),
                        }
                    }
                }
                Err(_) => return Err(ValidateError::PrivateKeyInvalid),
            }
        }

        if self.private_key.is_none() && self.public_key.is_some() {
            return Err(ValidateError::PublicKeyOnly);
        }

        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ValidateError {
    NameEmpty,
    UserEmpty,
    PrivateKeyInvalid,
    PublicKeyInvalid,
    UnmatchedKey,
    PublicKeyOnly,
}

impl std::fmt::Display for ValidateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ValidateError::*;
        match self {
            NameEmpty => {
                write!(f, "name cannot be empty")
            }
            UserEmpty => {
                write!(f, "user cannot be empty")
            }
            PrivateKeyInvalid => {
                write!(f, "invalid private key format")
            }
            PublicKeyInvalid => {
                write!(f, "invalid public key format")
            }
            UnmatchedKey => {
                write!(f, "private key and public key doesn't match")
            }
            PublicKeyOnly => {
                write!(f, "private key cannot be empty")
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct TargetSecretName {
    // policy id in casbin_rule
    pub pid: String,
    // target_secret id
    pub id: String,
    pub target_id: String,
    pub target_name: String,
    pub secret_id: String,
    pub secret_user: String,
}
