use crate::error::Error;
use log::{debug, warn};
use russh::client as ru_client;
use russh::keys::ssh_key::{self, PublicKey};
use russh::{Preferred, SshId, keys::Algorithm};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use uuid::Uuid;

pub(crate) trait Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Stream for T {}

/// Target model for database storage
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// A blank target for the editor to fill in. `updated_at` is left at 0
    /// because the repository stamps it on write; nothing reads it before then.
    pub fn new(updated_by: Uuid) -> Self {
        Self {
            id: Uuid::now_v7(),
            name: String::default(),
            hostname: String::default(),
            port: 22,
            server_public_key: String::default(),
            description: None,
            proxy: None,
            is_active: true,
            updated_by,
            updated_at: 0,
        }
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

#[derive(Debug, Clone, Serialize, Deserialize, sea_orm::FromQueryResult)]
pub struct TargetInfo {
    pub id: Uuid,
    pub name: String,
    pub hostname: String,
    /// `i32` rather than `u16`: sea-orm cannot read `u16` on PostgreSQL. This is
    /// a display-only projection (rendered via `to_string()` in the bind UI), so
    /// the wider type makes no difference to callers.
    pub port: i32,
}

impl From<crate::database::entity::target::Model> for Target {
    fn from(m: crate::database::entity::target::Model) -> Self {
        Self {
            id: m.id,
            name: m.name,
            hostname: m.hostname,
            // Narrowing is safe for anything the admin UI wrote:
            // `validate::varify_port` rejects the rest. A row seeded by a batch
            // import bypasses that, and would wrap here.
            port: m.port as u16,
            server_public_key: m.server_public_key,
            description: m.description,
            proxy: m.proxy,
            is_active: m.is_active,
            updated_by: m.updated_by,
            updated_at: m.updated_at,
        }
    }
}

impl Target {
    pub(in crate::database) fn into_active_model(
        self,
    ) -> crate::database::entity::target::ActiveModel {
        use sea_orm::ActiveValue::Set;
        crate::database::entity::target::ActiveModel {
            id: Set(self.id),
            name: Set(self.name),
            hostname: Set(self.hostname),
            port: Set(self.port as i32),
            server_public_key: Set(self.server_public_key),
            description: Set(self.description),
            proxy: Set(self.proxy),
            is_active: Set(self.is_active),
            updated_by: Set(self.updated_by),
            updated_at: Set(self.updated_at),
        }
    }
}
