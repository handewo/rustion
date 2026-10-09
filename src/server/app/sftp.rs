use crate::database::models::TargetSecretName;
use crate::error::Error;
use crate::server::extend_policy;
use log::{debug, info};
use russh::Channel;
use russh::client as ru_client;
use russh::server as ru_server;
use russh_sftp::client::{RawSftpSession, error::Error as SftpError};
use russh_sftp::protocol::{
    Attrs, Data, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version,
};
use russh_sftp::server::StatusReply;
use std::sync::Arc;
use uuid::Uuid;

use std::collections::HashMap;

pub(crate) async fn sftp_subsystem<B>(
    handler_id: Uuid,
    user_id: Uuid,
    client_ip: Option<std::net::IpAddr>,
    backend: Arc<B>,
    target_secret_name: TargetSecretName,
    target_channel: Channel<ru_client::Msg>,
    session_channel: Channel<ru_server::Msg>,
) -> Result<(), SftpError>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    let session = RawSftpSession::new(target_channel.into_stream());
    session.init().await?;
    let proxy = SftpProxy {
        handler_id,
        user_id,
        client_ip,
        target_secret_name,
        session,
        backend,
    };

    russh_sftp::server::run(session_channel.into_stream(), proxy).await;
    Ok(())
}

struct SftpProxy<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    handler_id: Uuid,
    user_id: Uuid,
    session: RawSftpSession,
    client_ip: Option<std::net::IpAddr>,
    target_secret_name: TargetSecretName,
    backend: Arc<B>,
}

impl<B> SftpProxy<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    async fn check_permission(&self, action_uuid: Uuid) -> Result<bool, Error> {
        let ext_req = extend_policy::ExtendPolicyReq::new(self.client_ip);
        if !self
            .backend
            .enforce(
                self.user_id,
                self.target_secret_name.id,
                action_uuid,
                ext_req,
            )
            .await?
        {
            return Ok(false);
        }
        Ok(true)
    }
}

/// The backend numbers its own requests, so every reply arrives tagged with the
/// backend's id. Replies to the user must carry the id the *user* sent.
trait Retag {
    fn retag(self, id: u32) -> Self;
}

macro_rules! impl_retag {
    ($($packet:ty),*) => {
        $(impl Retag for $packet {
            fn retag(mut self, id: u32) -> Self {
                self.id = id;
                self
            }
        })*
    };
}

impl_retag!(Handle, Data, Name, Attrs, Status);

/// Wraps a client-side error so it can be returned as an `SSH_FXP_STATUS`.
struct ProxyError(StatusReply);

impl From<SftpError> for ProxyError {
    fn from(err: SftpError) -> Self {
        Self(match err {
            // The backend already said what went wrong (including `Eof`, which
            // ends a directory listing). Pass it through untouched.
            SftpError::Status(status) => StatusReply {
                status_code: status.status_code,
                error_message: Some(status.error_message),
                language_tag: Some(status.language_tag),
            },
            // Transport-level trouble between bastion and backend.
            other => StatusReply::new(StatusCode::Failure).with_message(other.to_string()),
        })
    }
}

impl From<ProxyError> for StatusReply {
    fn from(err: ProxyError) -> Self {
        err.0
    }
}

/// Every method is the same shape: forward, then re-tag the reply. Filtering or
/// auditing a particular operation means adding a check to its method.
impl<B> russh_sftp::server::Handler for SftpProxy<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    type Error = ProxyError;

    fn unimplemented(&self) -> Self::Error {
        ProxyError(StatusReply::new(StatusCode::OpUnsupported))
    }

    /// The backend session is already initialized by [`SftpProxy::connect`], so
    /// only the user's handshake is answered here. No extensions are advertised
    /// because this demo does not forward `SSH_FXP_EXTENDED`.
    async fn init(
        &mut self,
        version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        if !self
            .check_permission(crate::database::common::InternalUuids::get().act_sftp)
            .await
            .map_err(|_| ProxyError(StatusReply::new(StatusCode::Failure)))?
        {
            return Err(ProxyError(StatusReply::new(StatusCode::PermissionDenied)));
        };
        debug!(
            "[{}] sftp session started, client version {}",
            self.handler_id, version
        );
        Ok(Version::new())
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        info!("open {} ({:?})", filename, pflags);
        Ok(self.session.open(filename, pflags, attrs).await?.retag(id))
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        Ok(self.session.close(handle).await?.retag(id))
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        Ok(self.session.read(handle, offset, len).await?.retag(id))
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        Ok(self.session.write(handle, offset, data).await?.retag(id))
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        Ok(self.session.lstat(path).await?.retag(id))
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        Ok(self.session.fstat(handle).await?.retag(id))
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        Ok(self.session.setstat(path, attrs).await?.retag(id))
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        Ok(self.session.fsetstat(handle, attrs).await?.retag(id))
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        info!("opendir {}", path);
        Ok(self.session.opendir(path).await?.retag(id))
    }

    /// Returns the backend's `Eof` status once the listing is exhausted, which
    /// is exactly what the user's client expects.
    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        info!("readdir {}", handle);
        Ok(self.session.readdir(handle).await?.retag(id))
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        info!("remove {}", filename);
        Ok(self.session.remove(filename).await?.retag(id))
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        info!("mkdir {}", path);
        Ok(self.session.mkdir(path, attrs).await?.retag(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        info!("rmdir {}", path);
        Ok(self.session.rmdir(path).await?.retag(id))
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        info!("realpath {}", path);
        Ok(self.session.realpath(path).await?.retag(id))
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        info!("stat {}", path);
        Ok(self.session.stat(path).await?.retag(id))
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        info!("rename {} -> {}", oldpath, newpath);
        Ok(self.session.rename(oldpath, newpath).await?.retag(id))
    }

    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        Ok(self.session.readlink(path).await?.retag(id))
    }

    async fn symlink(
        &mut self,
        id: u32,
        linkpath: String,
        targetpath: String,
    ) -> Result<Status, Self::Error> {
        Ok(self.session.symlink(linkpath, targetpath).await?.retag(id))
    }
}
