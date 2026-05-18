use crate::error::Error;
use chrono::Utc;
use log::{debug, warn};
use russh::client as ru_client;
use russh::keys::ssh_key::{self, PublicKey};
use russh::{Preferred, SshId, keys::Algorithm};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use uuid::Uuid;

const MAX_NAME_LEN: usize = 50;

pub(crate) trait Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Stream for T {}

/// Target model for database storage
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Target {
    pub id: Uuid,
    pub name: String,
    pub hostname: String,
    pub port: u16,
    pub server_public_key: String,
    pub description: Option<String>,
    pub proxy: Option<String>,
    pub is_active: bool,
    pub updated_by: Uuid, // User ID who last updated this target
    pub updated_at: i64,
}

impl Target {
    pub fn new(updated_by: Uuid) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name: String::default(),
            hostname: String::default(),
            port: 22,
            server_public_key: String::default(),
            description: None,
            proxy: None,
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

    pub(crate) async fn build_connect(
        self,
        client_id: String,
        proxy: Option<Pin<Box<dyn Stream>>>,
    ) -> Result<ru_client::Handle<Self>, Error> {
        let pub_key = PublicKey::from_openssh(&self.server_public_key)?;
        let preferred = if let Ok(algo) = Algorithm::new(pub_key.algorithm().as_str()) {
            debug!(
                "Preferred key: {} from target: {}({})",
                algo, self.name, self.id
            );
            Preferred {
                key: Cow::Owned(vec![algo]),
                ..<_>::default()
            }
        } else {
            Preferred::default()
        };

        let config = Arc::new(russh::client::Config {
            client_id: SshId::Standard(Cow::Owned(client_id)),
            preferred,
            ..Default::default()
        });

        match proxy {
            Some(p) => ru_client::connect_stream(config, p, self).await,
            None => ru_client::connect(config, (self.hostname.clone(), self.port), self).await,
        }
    }

    pub fn print_server_key(&self) -> String {
        crate::common::shorten_ssh_pubkey(&self.server_public_key)
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
        if let Some(ref proxy) = self.proxy
            && SshProxy::from_str(proxy).is_err()
        {
            return Err(ValidateError::ProxyInvalid);
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
            "The public key of target: {}({}) doesn't match: {}",
            self.name,
            self.id,
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
    ProxyInvalid,
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
            ProxyInvalid => {
                write!(
                    f,
                    "proxy is invalid, expected format: ssh://<uuid>, http://<url>, or https://<url>[?insecure]"
                )
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

/// Proxy configuration for target connections.
///
/// Serialized format for storage in `Target.proxy` (String):
/// - `ssh://<uuid>`                          → Ssh proxy via another target
/// - `http://proxy.example.com:8080`         → HTTP proxy
/// - `https://proxy.example.com:443`          → HTTPS proxy (verify TLS)
/// - `https://proxy.example.com:443?insecure` → HTTPS proxy (skip TLS verification)
#[derive(Debug, Clone, PartialEq)]
pub enum SshProxy {
    Ssh(Uuid),
    Http(String),
    /// (url, verify_tls)
    Https(String, bool),
}

impl std::fmt::Display for SshProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshProxy::Ssh(uuid) => write!(f, "ssh://{uuid}"),
            SshProxy::Http(url) => write!(f, "http://{url}"),
            SshProxy::Https(url, verify_tls) => {
                if *verify_tls {
                    write!(f, "https://{url}")
                } else {
                    write!(f, "https://{url}?insecure")
                }
            }
        }
    }
}

impl FromStr for SshProxy {
    type Err = ProxyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(rest) = s.strip_prefix("ssh://") {
            let uuid = Uuid::parse_str(rest).map_err(|_| ProxyParseError::InvalidUuid)?;
            Ok(SshProxy::Ssh(uuid))
        } else if let Some(rest) = s.strip_prefix("https://") {
            if rest.is_empty() {
                return Err(ProxyParseError::EmptyUrl);
            }
            let verify_tls = !rest.contains("?insecure");
            let url = rest.replace("?insecure", "");
            if url.is_empty() {
                return Err(ProxyParseError::EmptyUrl);
            }
            Ok(SshProxy::Https(url, verify_tls))
        } else if let Some(rest) = s.strip_prefix("http://") {
            if rest.is_empty() {
                return Err(ProxyParseError::EmptyUrl);
            }
            Ok(SshProxy::Http(rest.to_string()))
        } else {
            Err(ProxyParseError::MissingScheme)
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyParseError {
    #[error("proxy string must start with ssh://, http://, or https://")]
    MissingScheme,
    #[error("invalid UUID in ssh proxy")]
    InvalidUuid,
    #[error("proxy URL cannot be empty")]
    EmptyUrl,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct TargetInfo {
    pub id: Uuid,
    pub name: String,
    pub hostname: String,
    pub port: u16,
}
