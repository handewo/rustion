use chrono::Utc;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct TargetSecret {
    pub id: Uuid,
    pub target_id: Uuid,
    pub secret_id: Uuid,
    pub is_active: bool,
    pub updated_by: Uuid,
    pub updated_at: i64,
}

/// For login to remote target
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Secret {
    pub id: Uuid,
    pub name: String, //for display only
    pub user: String, //login user of target
    pub(in crate::database) password: Option<String>,
    pub(in crate::database) private_key: Option<String>,
    pub(in crate::database) public_key: Option<String>,
    pub is_active: bool,
    pub updated_by: Uuid,
    pub updated_at: i64,
}

impl TargetSecret {
    pub fn new(target_id: Uuid, secret_id: Uuid, updated_by: Uuid) -> Self {
        let now = Utc::now().timestamp_millis();
        Self {
            id: Uuid::new_v4(),
            target_id,
            secret_id,
            is_active: true,
            updated_by,
            updated_at: now,
        }
    }
}

impl Secret {
    pub fn new(updated_by: Uuid) -> Self {
        let now = Utc::now().timestamp_millis();
        Self {
            id: Uuid::new_v4(),
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

    pub fn set_password(&mut self, password: Option<String>) {
        self.password = password;
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

    pub fn set_private_key(&mut self, private_key: Option<String>) {
        self.private_key = private_key;
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

    pub fn set_public_key(&mut self, public_key: Option<String>) {
        self.public_key = public_key
    }

    pub fn print_public_key(&self) -> String {
        if let Some(p) = self.public_key.as_ref() {
            crate::common::shorten_ssh_pubkey(p)
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

    pub fn encrypt_password(
        &mut self,
        f: crate::common::EncryptPlainText,
    ) -> Result<(), crate::error::Error> {
        if let Some(p) = self.password.take() {
            self.password = match f(&p) {
                Ok(enc) => Some(enc),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    pub fn encrypt_private_key(
        &mut self,
        f: crate::common::EncryptPlainText,
    ) -> Result<(), crate::error::Error> {
        self.public_key = match self.gen_public_key_from_text() {
            Ok(pub_key) => {
                if pub_key.is_some() {
                    match f(self.private_key.as_ref().unwrap()) {
                        Ok(key) => self.private_key = Some(key),
                        Err(e) => return Err(e),
                    }
                }
                pub_key
            }
            Err(e) => return Err(crate::error::Error::RusshKey(e)),
        };

        Ok(())
    }

    // Generate public key before `private_key` and `password` encrypted.
    pub fn gen_public_key_from_text(&self) -> Result<Option<String>, russh::keys::Error> {
        if let Some(private_key) = self.private_key.as_ref() {
            match russh::keys::decode_secret_key(private_key, None) {
                Ok(key) => return Ok(Some(key.public_key().to_openssh()?)),
                Err(e) => {
                    if matches!(e, russh::keys::Error::KeyIsEncrypted) {
                        match russh::keys::decode_secret_key(private_key, self.password.as_deref())
                        {
                            Ok(key) => return Ok(Some(key.public_key().to_openssh()?)),
                            Err(e) => return Err(e),
                        }
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        Ok(None)
    }

    pub fn validate(&self, verify_key: bool) -> Result<(), ValidateError> {
        let name = self.name.trim();
        if name.is_empty() {
            return Err(ValidateError::NameEmpty);
        }

        let user = self.user.trim();
        if user.is_empty() {
            return Err(ValidateError::UserEmpty);
        }

        if verify_key && self.gen_public_key_from_text().is_err() {
            return Err(ValidateError::PrivateKeyInvalid);
        }

        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ValidateError {
    NameEmpty,
    UserEmpty,
    PrivateKeyInvalid,
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
                write!(f, "invalid private key")
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct TargetSecretName {
    // policy id in casbin_rule
    pub pid: Uuid,
    // target_secret id
    pub id: Uuid,
    pub target_id: Uuid,
    pub target_name: String,
    pub secret_id: Uuid,
    pub secret_user: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SecretInfo {
    pub id: Uuid,
    pub name: String,
    pub user: String,
    pub is_bound: bool,
}
