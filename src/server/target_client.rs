//! Reaching a target as an SSH *client*: the stream the connection runs
//! over, the dial-up, and the host-key check.
//!
//! Connection dialect, so it lives in `server` beside its only caller,
//! [`BastionServer::connect_to_target`](super::bastion_server::BastionServer),
//! not in `database::models` with the storage type it dials for. The target's
//! row is data; connecting to it is server work.

use crate::database::models::Target;
use crate::server::error::ServerError;
use log::{debug, warn};
use russh::client as ru_client;
use russh::keys::PublicKeyOrCertificate;
use russh::keys::ssh_key::{self, PublicKey};
use russh::{Preferred, SshId, keys::Algorithm};
use std::borrow::Cow;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

/// Whatever a connection to a target — direct or through a proxy — runs over.
pub(crate) trait Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Stream for T {}

impl Target {
    pub(crate) async fn build_connect(
        self,
        client_id: String,
        proxy: Option<Pin<Box<dyn Stream>>>,
    ) -> Result<ru_client::Handle<Self>, ServerError> {
        let pub_key = PublicKey::from_openssh(&self.server_public_key)
            .map_err(russh::keys::Error::from)?;
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
}

impl ru_client::Handler for Target {
    type Error = ServerError;
    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let target_public_key = ssh_key::PublicKey::from_openssh(self.server_public_key.as_str())
            .map_err(russh::keys::Error::from)?;
        if target_public_key.key_data() == server_public_key.public_key().key_data() {
            return Ok(true);
        }
        warn!(
            "The public key of target: {}({}) doesn't match: {}",
            self.name,
            self.id,
            server_public_key.public_key().to_string()
        );
        Ok(false)
    }
}
