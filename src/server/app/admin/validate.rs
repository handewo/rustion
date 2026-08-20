use super::common;
use russh::keys::ssh_key::PublicKey;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error)]
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
                write!(
                    f,
                    "Username is too long, max: {}",
                    super::common::MAX_USERNAME_LEN
                )
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

pub fn varify_username(username: &str) -> Result<(), ValidateError> {
    if username.is_empty() {
        return Err(ValidateError::UsernameEmpty);
    }
    if username.len() > common::MAX_USERNAME_LEN {
        return Err(ValidateError::UsernameTooLong);
    }
    Ok(())
}

pub fn varify_email(email: &str) -> Result<(), ValidateError> {
    if !crate::common::EMAIL_REGEX.is_match(email) {
        Err(ValidateError::EmailInvalid)
    } else {
        Ok(())
    }
}

pub fn varify_authorized_keys(keys: &[String]) -> Result<(), ValidateError> {
    let mut invalid_keys = Vec::new();
    for (i, k_str) in keys.iter().enumerate() {
        if PublicKey::from_str(k_str).is_err() {
            invalid_keys.push(i);
        }
    }
    if !invalid_keys.is_empty() {
        Err(ValidateError::AuthorizedKeyInvalid(invalid_keys))
    } else {
        Ok(())
    }
}
