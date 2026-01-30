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

const MAX_USERNAME_LEN: usize = 40;

/// User model for database storage
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, sqlx::Type)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub(in crate::database) password_hash: Option<String>, // For password authentication
    pub(in crate::database) authorized_keys: Option<StringArray>,
    pub force_init_pass: bool,
    pub is_active: bool,
    pub updated_by: Uuid,
    pub updated_at: i64,
}

impl User {
    pub fn new(updated_by: Uuid) -> Self {
        let now = Utc::now().timestamp_millis();
        Self {
            id: Uuid::new_v4(),
            username: String::new(),
            email: None,
            password_hash: None,
            authorized_keys: None,
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
        self.authorized_keys = Some(StringArray(authorized_keys));
        self
    }

    pub fn set_authorized_keys(&mut self, authorized_keys: Option<Vec<String>>) {
        self.authorized_keys = authorized_keys.map(StringArray)
    }

    pub fn set_active(mut self, active: bool) -> Self {
        self.is_active = active;
        self
    }

    pub fn take_password_hash(&mut self) -> Option<String> {
        self.password_hash.take()
    }

    pub fn print_authorized_keys(&self) -> String {
        if self.authorized_keys.is_none() {
            return String::new();
        }
        "********".to_string()
    }

    pub fn get_authorized_keys(&self) -> Option<&[String]> {
        self.authorized_keys.as_ref().map(|v| v.0.as_ref())
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
        if let Some(keys) = self.authorized_keys.as_ref() {
            for k_str in keys.0.iter() {
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

    pub fn validate(&self) -> Result<(), ValidateError> {
        let username = self.username.trim();
        if username.is_empty() {
            return Err(ValidateError::UsernameEmpty);
        }
        if username.len() > MAX_USERNAME_LEN {
            return Err(ValidateError::UsernameTooLong);
        }
        if let Some(e) = self.email.as_ref() {
            if !crate::common::EMAIL_REGEX.is_match(e) {
                return Err(ValidateError::EmailInvalid);
            }
        }
        let mut invalid_keys = Vec::new();
        if let Some(keys) = self.authorized_keys.as_ref() {
            for (i, k_str) in keys.0.iter().enumerate() {
                if PublicKey::from_str(k_str).is_err() {
                    invalid_keys.push(i);
                }
            }
        }
        if !invalid_keys.is_empty() {
            return Err(ValidateError::AuthorizedKeyInvalid(invalid_keys));
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ValidateError {
    UsernameEmpty,
    UsernameTooLong,
    EmailInvalid,
    AuthorizedKeyInvalid(Vec<usize>),
}

impl std::fmt::Display for ValidateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ValidateError::*;
        match self {
            UsernameEmpty => {
                write!(f, "Username cannot be empty")
            }
            UsernameTooLong => {
                write!(f, "Username is too long, max: {}", MAX_USERNAME_LEN)
            }
            EmailInvalid => {
                write!(f, "Invalid email format")
            }
            AuthorizedKeyInvalid(v) => {
                write!(
                    f,
                    "Invalid authorized keys, line number: {}",
                    v.iter()
                        .map(|x| (x + 1).to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
        }
    }
}
