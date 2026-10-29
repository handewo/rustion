//! Field validators for the admin editors.
//!
//! These live here, not on the domain models, because they answer a UI question:
//! is what the operator just typed into this one field acceptable? The editors
//! call them per-field so an `ActiveModel` only ever receives values that have
//! already been checked, and the error goes straight back into the form.
//!
//! The database layer deliberately has no equivalent. It writes what it is
//! given — batch imports and the seeding path in `init_service` bypass all of
//! this, exactly as they did when `validate()` hung off the models.

use super::common;
use super::error::AdminError;
use crate::error::Error;
use crate::fill;
use crate::i18n::{Lang, Strings};
use crate::server::app::error::AppError;
use crate::server::error::ServerError;
use russh::keys::ssh_key::PublicKey;
use std::str::FromStr;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum ValidateError {
    UsernameEmpty,
    UsernameTooLong,
    EmailInvalid,
    AuthorizedKeyInvalid(Vec<usize>),
    NameEmpty,
    NameTooLong,
    NameStartsWithUnderscore,
    HostnameEmpty,
    HostnameTooLong,
    PortNotNumber,
    PortInvalid,
    ServerPublicKey,
    ProxyInvalid,
    SecretUserEmpty,
    SecretUserTooLong,
    SshKeyInvalid(russh::keys::Error),
    PtypeInvalid,
    UserRoleEmpty,
    TargetGroupEmpty,
    ActionGroupEmpty,
    MissingRuleId,
}

impl ValidateError {
    /// What is wrong, in `tr`'s language.
    pub fn message(&self, tr: &Strings) -> String {
        use ValidateError::*;
        let lines = |v: &[usize]| {
            v.iter()
                .map(|x| (x + 1).to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };
        match self {
            UsernameEmpty => tr.v_username_empty.to_string(),
            UsernameTooLong => fill!(tr.v_username_too_long, max = common::MAX_USERNAME_LEN),
            EmailInvalid => tr.v_email_invalid.to_string(),
            AuthorizedKeyInvalid(v) => fill!(tr.v_authorized_keys, lines = lines(v)),
            NameEmpty => tr.v_name_empty.to_string(),
            NameTooLong => fill!(tr.v_name_too_long, max = common::MAX_NAME_LEN),
            NameStartsWithUnderscore => tr.v_name_underscore.to_string(),
            HostnameEmpty => tr.v_hostname_empty.to_string(),
            HostnameTooLong => fill!(tr.v_hostname_too_long, max = common::MAX_NAME_LEN),
            PortNotNumber => tr.v_port_not_number.to_string(),
            PortInvalid => tr.v_port_range.to_string(),
            ServerPublicKey => tr.v_server_public_key.to_string(),
            ProxyInvalid => tr.v_proxy.to_string(),
            SecretUserEmpty => tr.v_secret_user_empty.to_string(),
            SecretUserTooLong => {
                fill!(tr.v_secret_user_too_long, max = common::MAX_USERNAME_LEN)
            }
            SshKeyInvalid(e) => fill!(tr.v_ssh_key, error = e),
            PtypeInvalid => tr.v_ptype.to_string(),
            UserRoleEmpty => tr.v_user_role_empty.to_string(),
            TargetGroupEmpty => tr.v_target_group_empty.to_string(),
            ActionGroupEmpty => tr.v_action_group_empty.to_string(),
            MissingRuleId => tr.v_missing_rule_id.to_string(),
        }
    }
}

/// English, for logs.
impl std::fmt::Display for ValidateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message(Lang::En.strings()))
    }
}

/// An editor's save error as the dialog says it, in `tr`'s language. What the
/// operator can fix is worded; anything else is an internal error, shown as it
/// is so it can be reported.
pub fn describe(e: &Error, tr: &Strings) -> String {
    match e {
        Error::App(AppError::Admin(AdminError::Validate(v))) => v.message(tr),
        Error::App(AppError::Admin(AdminError::DuplicateTargetUser { target, user })) => {
            fill!(tr.duplicate_target_user, target = target, user = user)
        }
        Error::Json(e) => fill!(tr.v_extend_policy, error = e),
        Error::Server(ServerError::ExtendPolicy(e)) => fill!(tr.v_extend_policy, error = e),
        e => e.to_string(),
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

pub fn varify_secret_user(name: &str) -> Result<(), ValidateError> {
    if name.is_empty() {
        return Err(ValidateError::SecretUserEmpty);
    }
    if name.len() > common::MAX_NAME_LEN {
        return Err(ValidateError::SecretUserTooLong);
    }
    Ok(())
}

/// Shared by targets and secrets: both are named by the operator and both are
/// unique-indexed as a bounded `varchar`.
pub fn varify_name(name: &str) -> Result<(), ValidateError> {
    if name.is_empty() {
        return Err(ValidateError::NameEmpty);
    }
    if name.len() > common::MAX_NAME_LEN {
        return Err(ValidateError::NameTooLong);
    }
    Ok(())
}

/// A casbin group name. Stricter than [`varify_name`]: the leading underscore is
/// reserved for the internal markers (`__internal_object_type` and friends), so
/// an operator must not be able to mint a name that collides with one.
pub fn varify_group_name(name: &str) -> Result<(), ValidateError> {
    varify_name(name)?;
    if name.starts_with('_') {
        return Err(ValidateError::NameStartsWithUnderscore);
    }
    Ok(())
}

pub fn varify_hostname(hostname: &str) -> Result<(), ValidateError> {
    if hostname.is_empty() {
        return Err(ValidateError::HostnameEmpty);
    }
    if hostname.len() > common::MAX_NAME_LEN {
        return Err(ValidateError::HostnameTooLong);
    }
    Ok(())
}

/// Returns the parsed port rather than `()`, so the caller cannot forget to
/// re-parse it — the range check and the conversion to `u16` happen together.
pub fn varify_port(port: &str) -> Result<u16, ValidateError> {
    let port: u32 = port.parse().map_err(|_| ValidateError::PortNotNumber)?;
    if !(1..=65535).contains(&port) {
        return Err(ValidateError::PortInvalid);
    }
    Ok(port as u16)
}

pub fn varify_server_public_key(key: &str) -> Result<(), ValidateError> {
    if PublicKey::from_str(key).is_err() {
        return Err(ValidateError::ServerPublicKey);
    }
    Ok(())
}

/// Accepted formats:
/// - `ssh://<uuid>`                                 → Ssh proxy via another target
/// - `http://proxy.example.com:8080`                → HTTP proxy
/// - `https://proxy.example.com:443`                → HTTPS proxy (verify TLS)
/// - `https://proxy.example.com:443?insecure=true`  → HTTPS proxy (skip TLS verification)
pub fn varify_proxy(proxy: &str) -> Result<(), ValidateError> {
    let uri = proxy
        .parse::<http::Uri>()
        .map_err(|_| ValidateError::ProxyInvalid)?;
    match uri.scheme_str() {
        Some("ssh") => {
            let host = uri.host().ok_or(ValidateError::ProxyInvalid)?;
            Uuid::parse_str(host).map_err(|_| ValidateError::ProxyInvalid)?;
            Ok(())
        }
        Some("http") | Some("https") => {
            let authority = uri.authority().ok_or(ValidateError::ProxyInvalid)?;
            if authority.host().is_empty() {
                return Err(ValidateError::ProxyInvalid);
            }
            Ok(())
        }
        _ => Err(ValidateError::ProxyInvalid),
    }
}

/// A permission policy names its three sides by picking from a table, so the
/// only way to get here is to have left one unpicked.
pub fn varify_permission_labels(
    user_role: &str,
    target_group: &str,
    action_group: &str,
) -> Result<(), ValidateError> {
    if user_role.is_empty() {
        return Err(ValidateError::UserRoleEmpty);
    }
    if target_group.is_empty() {
        return Err(ValidateError::TargetGroupEmpty);
    }
    if action_group.is_empty() {
        return Err(ValidateError::ActionGroupEmpty);
    }
    Ok(())
}

/// Checks a private key by deriving its public key, and hands that back: the
/// derivation has to happen before the key is encrypted, and the caller needs
/// the result to store alongside it.
///
/// `password` is the passphrase in plaintext, for an encrypted key. A stored
/// (already-encrypted) password is no use here, so changing the private key
/// means re-entering the passphrase — the same constraint the previous
/// `Secret::validate(verify_key)` imposed.
pub fn varify_private_key(
    private_key: &str,
    password: Option<&str>,
) -> Result<String, ValidateError> {
    let key = match russh::keys::decode_secret_key(private_key, None) {
        Ok(k) => k,
        Err(russh::keys::Error::KeyIsEncrypted) => {
            russh::keys::decode_secret_key(private_key, password)
                .map_err(ValidateError::SshKeyInvalid)?
        }
        Err(e) => return Err(ValidateError::SshKeyInvalid(e)),
    };
    key.public_key()
        .to_openssh()
        .map_err(|e| ValidateError::SshKeyInvalid(e.into()))
}
