use super::StringArray;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use uuid::Uuid;

use argon2::{
    password_hash::{PasswordHash, PasswordVerifier},
    Argon2,
};
use chrono::Utc;
use russh::keys::ssh_key::PublicKey;

/// User model for database storage
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, sqlx::Type)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    pub(in crate::database) password_hash: Option<String>, // For password authentication
    #[sqlx(json)]
    pub(in crate::database) authorized_keys: StringArray,
    pub force_init_pass: bool,
    pub is_active: bool,
    pub updated_by: String,
    pub updated_at: i64,
}

impl User {
    pub fn new(updated_by: String) -> Self {
        let now = Utc::now().timestamp_millis();
        Self {
            id: Uuid::new_v4().to_string(),
            username: String::new(),
            email: None,
            password_hash: None,
            authorized_keys: StringArray(Vec::new()),
            force_init_pass: true,
            is_active: true,
            updated_by,
            updated_at: now,
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
        self.authorized_keys = StringArray(authorized_keys);
        self
    }

    pub fn set_active(mut self, active: bool) -> Self {
        self.is_active = active;
        self
    }

    pub fn take_password_hash(&mut self) -> Option<String> {
        self.password_hash.take()
    }

    pub fn print_authorized_keys(&self) -> String {
        if self.authorized_keys.0.is_empty() {
            return String::new();
        }
        "********".to_string()
    }

    pub fn print_password(&self) -> String {
        if self.password_hash.is_some() {
            return "********".to_string();
        }
        String::new()
    }

    pub(crate) fn set_password_hash(&mut self, password: String) {
        self.password_hash = Some(password);
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
        for k_str in self.authorized_keys.0.iter() {
            match PublicKey::from_str(k_str) {
                Ok(ref k) => {
                    if k.key_data() == pub_key.key_data() {
                        return true;
                    }
                }
                Err(_) => return false,
            };
        }
        false
    }
}
