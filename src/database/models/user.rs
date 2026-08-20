use serde::{Deserialize, Serialize};
use std::str::FromStr;
use uuid::Uuid;

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordVerifier},
};
use russh::keys::ssh_key::PublicKey;

/// User model for database storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub(in crate::database) password_hash: Option<String>, // For password authentication
    pub(in crate::database) authorized_keys: Option<Vec<String>>,
    pub force_init_pass: bool,
    pub is_active: bool,
    pub updated_by: Uuid,
    pub updated_at: i64,
}

impl User {
    pub fn new(updated_by: Uuid) -> Self {
        Self {
            id: Uuid::now_v7(),
            username: String::new(),
            email: None,
            password_hash: None,
            authorized_keys: None,
            force_init_pass: true,
            is_active: true,
            updated_by,
            updated_at: 0,
        }
    }

    pub fn with_email(mut self, email: String) -> Self {
        self.email = Some(email);
        self
    }

    pub fn with_password_hash(mut self, password_hash: Option<String>) -> Self {
        self.password_hash = password_hash;
        self
    }

    pub fn with_authorized_keys(mut self, authorized_keys: Vec<String>) -> Self {
        self.authorized_keys = Some(authorized_keys);
        self
    }

    pub fn set_authorized_keys(&mut self, authorized_keys: Option<Vec<String>>) {
        self.authorized_keys = authorized_keys
    }

    pub fn set_active(mut self, active: bool) -> Self {
        self.is_active = active;
        self
    }

    pub fn print_authorized_keys(&self) -> String {
        if self.authorized_keys.is_none() {
            return String::new();
        }
        "********".to_string()
    }

    pub fn take_authorized_keys(&mut self) -> Option<Vec<String>> {
        self.authorized_keys.take()
    }

    pub fn get_authorized_keys(&self) -> Option<&[String]> {
        self.authorized_keys.as_ref().map(|v| v.as_ref())
    }

    pub fn print_password(&self) -> String {
        if self.password_hash.is_some() {
            return "********".to_string();
        }
        String::new()
    }

    /// Verify a password against the stored hash
    pub(crate) fn verify_password(&self, password: &str) -> bool {
        let hash = match self.password_hash.as_ref() {
            Some(h) => h,
            None => return false,
        };
        let parsed_hash = match PasswordHash::new(hash) {
            Ok(h) => h,
            Err(_) => return false,
        };
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
    }

    pub(crate) fn verify_authorized_keys(&self, pub_key: &PublicKey) -> bool {
        if let Some(keys) = self.authorized_keys.as_ref() {
            for k_str in keys.iter() {
                match PublicKey::from_str(k_str) {
                    Ok(ref k) => {
                        if k.key_data() == pub_key.key_data() {
                            return true;
                        }
                    }
                    Err(_) => return false,
                };
            }
        }
        false
    }
}

pub struct UserWithRole {
    pub user: User,
    pub role: String,
}

impl UserWithRole {
    pub fn user(&self) -> User {
        self.user.clone()
    }
}

impl From<crate::database::entity::user::Model> for User {
    fn from(m: crate::database::entity::user::Model) -> Self {
        Self {
            id: m.id,
            username: m.username,
            email: m.email,
            password_hash: m.password_hash,
            authorized_keys: m.authorized_keys.map(|v| v.into()),
            force_init_pass: m.force_init_pass,
            is_active: m.is_active,
            updated_by: m.updated_by,
            updated_at: m.updated_at,
        }
    }
}

impl User {
    pub(in crate::database) fn into_active_model(
        self,
    ) -> crate::database::entity::user::ActiveModel {
        use sea_orm::ActiveValue::Set;
        crate::database::entity::user::ActiveModel {
            id: Set(self.id),
            username: Set(self.username),
            email: Set(self.email),
            password_hash: Set(self.password_hash),
            authorized_keys: Set(self.authorized_keys.map(|v| v.into())),
            force_init_pass: Set(self.force_init_pass),
            is_active: Set(self.is_active),
            updated_by: Set(self.updated_by),
            updated_at: Set(self.updated_at),
        }
    }
}
