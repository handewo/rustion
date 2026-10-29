//! SFTP between a user and a target, through the bastion.
//!
//! The user's client talks to [`SftpProxy`] (`russh_sftp::server::run`), which
//! talks to the target over a [`RawSftpSession`]. For every request the proxy
//! resolves the path against the target's home ([`path::resolve`]), asks
//! `enforce` whether this user may perform this operation on this path, and
//! forwards the *resolved* path, so the target acts on exactly what was checked.
//!
//! The session gate (`ACT_SFTP`) is checked by the caller before anything is
//! opened on the target ([`SftpContext::allow_session`]); the per-operation
//! actions are in [`SftpActions`]. Handle-only requests ride on the check made
//! at `open`/`opendir`, through [`handles::HandleTable`].
//!
//! Audited to `event_log` under [`EventKind::Sftp`]: session start and end,
//! one row per file, every mutation, every denial. Listings are not audited.
//!
//! The user's side is a stream fed by the handler's callbacks ([`client`]),
//! not the russh `Channel`.

mod audit;
pub(crate) mod client;
mod handles;
mod path;
#[cfg(test)]
mod test;

use crate::database::common::SftpActions;
use crate::server::HandlerBackend;
use crate::server::event_log::{Audit, EventLogger};
use crate::server::extend_policy::{ExtendPolicyReq, RequestKind};
use handles::{HandleKind, HandleTable, Use};
use log::{debug, info, trace, warn};
use russh_sftp::client::{RawSftpSession, error::Error as SftpError};
use russh_sftp::protocol::{
    Attrs, Data, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version,
};
use russh_sftp::server::StatusReply;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use uuid::Uuid;

/// Who is asking, for what, and where to report it. Built by the handler from
/// the connection and the `ConnectTarget` it replaces.
pub(crate) struct SftpContext<B> {
    pub handler_id: Uuid,
    pub user_id: Uuid,
    pub client_ip: Option<IpAddr>,
    /// The target-secret binding: the casbin object.
    pub object: Uuid,
    /// For log lines and audit rows: `web1(<uuid>) as deploy`.
    pub label: String,
    pub actions: SftpActions,
    pub backend: Arc<B>,
    /// Already scoped to `EventKind::Sftp`.
    pub log: EventLogger<B>,
}

impl<B> SftpContext<B>
where
    B: 'static + HandlerBackend + Send + Sync,
{
    /// `enforce`, with an error counted as a denial: a policy row that no
    /// longer parses must not grant anything, and must not end the session.
    ///
    /// `path` is `None` for the two SFTP requests that name no path — the
    /// subsystem gate and `realpath`. The kind still says SFTP, so a policy's
    /// `sftp_path` rule is skipped rather than failed: see
    /// [`verify_extend_policy`](crate::server::extend_policy::verify_extend_policy).
    async fn allows(&self, action: Uuid, path: Option<&str>) -> bool {
        let ext = ExtendPolicyReq::of(self.client_ip, RequestKind::Sftp(path.map(str::to_string)));
        match self
            .backend
            .enforce(self.user_id, self.object, action, ext)
            .await
        {
            Ok(allowed) => allowed,
            Err(e) => {
                debug!(
                    "[{}] sftp permission check failed, denying: {}",
                    self.handler_id, e
                );
                false
            }
        }
    }

    /// The session gate. Checked before anything is opened on the target.
    pub(crate) async fn allow_session(&self) -> bool {
        self.allows(self.actions.session, None).await
    }
}

pub(crate) struct SftpProxy<B>
where
    B: 'static + HandlerBackend + Send + Sync,
{
    ctx: SftpContext<B>,
    session: RawSftpSession,
    /// The target's `realpath(".")`: what relative paths resolve against.
    home: String,
    handles: HandleTable,
    /// Only the first transport failure in a session is worth a `warn!`;
    /// after it every request fails the same way.
    transport_failed: bool,
}

impl<B> SftpProxy<B>
where
    B: 'static + HandlerBackend + Send + Sync,
{
    /// Initialize the target session and learn its home directory. Nothing is
    /// sent to the user's client yet, so a failure here can still be reported
    /// as a failed subsystem request.
    pub(crate) async fn connect<S>(ctx: SftpContext<B>, target: S) -> Result<Self, SftpError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let session = RawSftpSession::new(target);
        session.init().await?;
        let home = session
            .realpath(".")
            .await?
            .files
            .into_iter()
            .next()
            .map(|f| f.filename)
            .ok_or(SftpError::UnexpectedPacket)?;
        info!(
            "[{}] sftp session on {} from {:?}, home {:?}",
            ctx.handler_id, ctx.label, ctx.client_ip, home
        );
        ctx.log
            .record(Audit::SftpStarted {
                target: ctx.label.clone(),
            })
            .await;
        Ok(Self {
            ctx,
            session,
            home,
            handles: HandleTable::default(),
            transport_failed: false,
        })
    }

    /// Serve the user's client. Returns at once; the loop runs on its own task
    /// and drops the proxy (writing the session-end rows) when the client's
    /// stream ends.
    pub(crate) async fn serve<S>(self, client: S)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        russh_sftp::server::run(client, self).await;
    }
}

/// Session-end rows. `russh_sftp::server::run` owns the proxy on a spawned
/// task and has no completion hook, so this is where the session is known to
/// be over; the async writes go on a task of their own.
impl<B> Drop for SftpProxy<B>
where
    B: 'static + HandlerBackend + Send + Sync,
{
    fn drop(&mut self) {
        let open = self.handles.drain_open();
        let t = self.handles.totals();
        let end = Audit::SftpEnded {
            files_read: t.files_read,
            bytes_read: t.bytes_read,
            files_written: t.files_written,
            bytes_written: t.bytes_written,
            not_closed: t.not_closed,
        };
        debug!("[{}] {:?}", self.ctx.handler_id, end);
        let rows: Vec<Audit> = open
            .iter()
            .filter_map(|h| match h.kind {
                HandleKind::File { read, write } => Some(Audit::SftpFile {
                    path: h.path.clone(),
                    read,
                    write,
                    bytes_read: h.bytes_read,
                    bytes_written: h.bytes_written,
                    closed: false,
                }),
                HandleKind::Dir => None,
            })
            .chain(std::iter::once(end))
            .collect();
        // No runtime means the process is shutting down; nothing can be written.
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            let log = self.ctx.log.clone();
            rt.spawn(async move {
                for row in rows {
                    log.record(row).await;
                }
            });
        }
    }
}

impl ProxyError {
    fn status(code: StatusCode) -> Self {
        Self(StatusReply::new(code))
    }
}

impl<B> SftpProxy<B>
where
    B: 'static + HandlerBackend + Send + Sync,
{
    /// Resolve and log one request. The client's string is shown too when it
    /// differs, since that is what the user typed.
    fn resolve(&self, op: &str, id: u32, path: &str) -> String {
        let resolved = path::resolve(&self.home, path);
        if resolved == path {
            debug!(
                "[{}] sftp {} #{} {:?}",
                self.ctx.handler_id, op, id, resolved
            );
        } else {
            debug!(
                "[{}] sftp {} #{} {:?} (client sent {:?})",
                self.ctx.handler_id, op, id, resolved, path
            );
        }
        resolved
    }

    /// Every path must be allowed. A denial is warned, audited, and answered
    /// with `PermissionDenied` without reaching the target.
    async fn check(&self, action: Uuid, op: &str, paths: &[&str]) -> Result<(), ProxyError> {
        for p in paths {
            if !self.ctx.allows(action, Some(*p)).await {
                let shown: Vec<String> = paths.iter().map(|p| audit::path(p)).collect();
                let shown = shown.join(" -> ");
                debug!(
                    "[{}] sftp denied {} {} on {}",
                    self.ctx.handler_id, op, shown, self.ctx.label
                );
                self.ctx
                    .log
                    .record(Audit::SftpDenied {
                        op: op.to_string(),
                        paths: paths.iter().map(|p| p.to_string()).collect(),
                    })
                    .await;
                return Err(ProxyError::status(StatusCode::PermissionDenied));
            }
        }
        Ok(())
    }

    /// A handle this proxy issued, opened for `u`.
    fn handle(&self, handle: &str, u: Use) -> Result<&handles::HandleInfo, ProxyError> {
        match self.handles.get(handle) {
            Some(h) if h.kind.allows(u) => Ok(h),
            found => {
                warn!(
                    "[{}] sftp refused handle {:?} for {:?}: {}",
                    self.ctx.handler_id,
                    handle,
                    u,
                    if found.is_some() {
                        "not opened for it"
                    } else {
                        "not issued"
                    }
                );
                Err(ProxyError::status(StatusCode::Failure))
            }
        }
    }

    /// Log a target-side failure at the level it deserves, then pass it on.
    /// A rejected mutation is worth a `warn!`; `NoSuchFile` from a `stat` or
    /// `Eof` from a `read` is how those operations normally end.
    fn target_err(&mut self, op: &str, e: SftpError, mutation: bool) -> ProxyError {
        let hid = self.ctx.handler_id;
        match &e {
            SftpError::Status(s) if mutation => {
                warn!(
                    "[{}] sftp {} rejected by target: {:?}",
                    hid, op, s.status_code
                )
            }
            SftpError::Status(s) => debug!("[{}] sftp {} -> {:?}", hid, op, s.status_code),
            other if !self.transport_failed => {
                self.transport_failed = true;
                warn!(
                    "[{}] sftp transport to target failed on {}: {}",
                    hid, op, other
                );
            }
            other => debug!("[{}] sftp {} failed: {}", hid, op, other),
        }
        e.into()
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
pub(crate) struct ProxyError(StatusReply);

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

/// Paths are resolved and checked before forwarding; handle-only requests are
/// checked against the handle table. `SSH_FXP_EXTENDED` is left unimplemented
/// (`OpUnsupported`): `posix-rename` and `hardlink` would otherwise sidestep
/// the rename and symlink checks.
impl<B> russh_sftp::server::Handler for SftpProxy<B>
where
    B: 'static + HandlerBackend + Send + Sync,
{
    type Error = ProxyError;

    fn unimplemented(&self) -> Self::Error {
        ProxyError::status(StatusCode::OpUnsupported)
    }

    /// The target session was initialized by [`SftpProxy::connect`]; this
    /// answers only the user's handshake, advertising no extensions.
    async fn init(
        &mut self,
        version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        debug!(
            "[{}] sftp client protocol version {}",
            self.ctx.handler_id, version
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
        let p = self.resolve("open", id, &filename);
        let write = pflags.intersects(
            OpenFlags::WRITE
                | OpenFlags::APPEND
                | OpenFlags::CREATE
                | OpenFlags::TRUNCATE
                | OpenFlags::EXCLUDE,
        );
        // No write flag means a read, whatever else is set, so no `open` skips
        // both checks.
        let read = pflags.contains(OpenFlags::READ) || !write;
        if read {
            self.check(self.ctx.actions.read, "read", &[p.as_str()])
                .await?;
        }
        if write {
            self.check(self.ctx.actions.write, "write", &[p.as_str()])
                .await?;
        }
        let res = self.session.open(p.as_str(), pflags, attrs).await;
        match res {
            Ok(h) => {
                self.handles
                    .insert(h.handle.clone(), p, HandleKind::File { read, write });
                Ok(h.retag(id))
            }
            Err(e) => Err(self.target_err("open", e, write)),
        }
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let p = self.resolve("opendir", id, &path);
        self.check(self.ctx.actions.list, "list", &[p.as_str()])
            .await?;
        let res = self.session.opendir(p.as_str()).await;
        match res {
            Ok(h) => {
                self.handles.insert(h.handle.clone(), p, HandleKind::Dir);
                Ok(h.retag(id))
            }
            Err(e) => Err(self.target_err("opendir", e, false)),
        }
    }

    /// Writes the file's row whether or not the target accepts the close: the
    /// bytes moved either way, and clients do not retry a close.
    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        self.handle(&handle, Use::Any)?;
        debug!("[{}] sftp close #{} {:?}", self.ctx.handler_id, id, handle);
        let res = self.session.close(handle.as_str()).await;
        if let Some(h) = self.handles.remove(&handle)
            && let HandleKind::File { read, write } = h.kind
        {
            self.ctx
                .log
                .record(Audit::SftpFile {
                    path: h.path.clone(),
                    read,
                    write,
                    bytes_read: h.bytes_read,
                    bytes_written: h.bytes_written,
                    closed: true,
                })
                .await;
        }
        res.map(|s| s.retag(id))
            .map_err(|e| self.target_err("close", e, false))
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        self.handle(&handle, Use::Read)?;
        trace!(
            "[{}] sftp read #{} {:?} @{} +{}",
            self.ctx.handler_id, id, handle, offset, len
        );
        let res = self.session.read(handle.as_str(), offset, len).await;
        match res {
            Ok(d) => {
                self.handles.add_read(&handle, d.data.len() as u64);
                Ok(d.retag(id))
            }
            Err(e) => Err(self.target_err("read", e, false)),
        }
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        self.handle(&handle, Use::Write)?;
        let n = data.len() as u64;
        trace!(
            "[{}] sftp write #{} {:?} @{} +{}",
            self.ctx.handler_id, id, handle, offset, n
        );
        let res = self.session.write(handle.as_str(), offset, data).await;
        match res {
            Ok(s) => {
                self.handles.add_written(&handle, n);
                Ok(s.retag(id))
            }
            Err(e) => Err(self.target_err("write", e, true)),
        }
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        self.handle(&handle, Use::Dir)?;
        debug!(
            "[{}] sftp readdir #{} {:?}",
            self.ctx.handler_id, id, handle
        );
        let res = self.session.readdir(handle.as_str()).await;
        res.map(|n| n.retag(id))
            .map_err(|e| self.target_err("readdir", e, false))
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        self.handle(&handle, Use::Any)?;
        debug!("[{}] sftp fstat #{} {:?}", self.ctx.handler_id, id, handle);
        let res = self.session.fstat(handle.as_str()).await;
        res.map(|a| a.retag(id))
            .map_err(|e| self.target_err("fstat", e, false))
    }

    /// Forwarded with the client's own string and never path-checked: every
    /// client calls `realpath(".")` before its prompt, and a path-restricted
    /// user's home is usually outside their patterns. It reveals whether a path
    /// exists and where a link points, not contents (see the spec).
    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        debug!("[{}] sftp realpath #{} {:?}", self.ctx.handler_id, id, path);
        let res = self.session.realpath(path).await;
        res.map(|n| n.retag(id))
            .map_err(|e| self.target_err("realpath", e, false))
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let p = self.resolve("stat", id, &path);
        self.check(self.ctx.actions.list, "list", &[p.as_str()])
            .await?;
        let res = self.session.stat(p).await;
        res.map(|a| a.retag(id))
            .map_err(|e| self.target_err("stat", e, false))
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let p = self.resolve("lstat", id, &path);
        self.check(self.ctx.actions.list, "list", &[p.as_str()])
            .await?;
        let res = self.session.lstat(p).await;
        res.map(|a| a.retag(id))
            .map_err(|e| self.target_err("lstat", e, false))
    }

    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let p = self.resolve("readlink", id, &path);
        self.check(self.ctx.actions.list, "list", &[p.as_str()])
            .await?;
        let res = self.session.readlink(p).await;
        res.map(|n| n.retag(id))
            .map_err(|e| self.target_err("readlink", e, false))
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let p = self.resolve("setstat", id, &path);
        self.check(self.ctx.actions.setstat, "setstat", &[p.as_str()])
            .await?;
        // Changing size rewrites contents, the same effect as opening with
        // TRUNCATE, so it needs write as well.
        if attrs.size.is_some() {
            self.check(self.ctx.actions.write, "write", &[p.as_str()])
                .await?;
        }
        let row = Audit::SftpSetstat {
            path: p.clone(),
            attrs: audit::attrs(&attrs),
            handle: false,
        };
        let res = self.session.setstat(p, attrs).await;
        self.mutated(id, "setstat", res, row).await
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let p = self.handle(&handle, Use::Any)?.path.clone();
        debug!("[{}] sftp fsetstat #{} {:?}", self.ctx.handler_id, id, p);
        self.check(self.ctx.actions.fsetstat, "fsetstat", &[p.as_str()])
            .await?;
        // Changing size rewrites contents, the same effect as opening with
        // TRUNCATE, so it needs write as well.
        if attrs.size.is_some() {
            self.check(self.ctx.actions.write, "write", &[p.as_str()])
                .await?;
        }
        let row = Audit::SftpSetstat {
            path: p.clone(),
            attrs: audit::attrs(&attrs),
            handle: true,
        };
        let res = self.session.fsetstat(handle, attrs).await;
        self.mutated(id, "fsetstat", res, row).await
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let p = self.resolve("mkdir", id, &path);
        self.check(self.ctx.actions.mkdir, "mkdir", &[p.as_str()])
            .await?;
        let row = Audit::SftpMkdir { path: p.clone() };
        let res = self.session.mkdir(p, attrs).await;
        self.mutated(id, "mkdir", res, row).await
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        let p = self.resolve("remove", id, &filename);
        self.check(self.ctx.actions.delete, "delete", &[p.as_str()])
            .await?;
        let row = Audit::SftpRemove { path: p.clone() };
        let res = self.session.remove(p).await;
        self.mutated(id, "remove", res, row).await
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        let p = self.resolve("rmdir", id, &path);
        self.check(self.ctx.actions.delete, "delete", &[p.as_str()])
            .await?;
        let row = Audit::SftpRmdir { path: p.clone() };
        let res = self.session.rmdir(p).await;
        self.mutated(id, "rmdir", res, row).await
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        let old = self.resolve("rename", id, &oldpath);
        let new = self.resolve("rename", id, &newpath);
        self.check(
            self.ctx.actions.rename,
            "rename",
            &[old.as_str(), new.as_str()],
        )
        .await?;
        let row = Audit::SftpRename {
            from: old.clone(),
            to: new.clone(),
        };
        let res = self.session.rename(old, new).await;
        self.mutated(id, "rename", res, row).await
    }

    /// Both fields are resolved, checked and forwarded resolved, regardless of
    /// which one the target's sftp-server treats as the link (OpenSSH swaps
    /// them). So a relative target is stored as the absolute path that was
    /// authorized, and a link made through the bastion never points elsewhere.
    async fn symlink(
        &mut self,
        id: u32,
        linkpath: String,
        targetpath: String,
    ) -> Result<Status, Self::Error> {
        let link = self.resolve("symlink", id, &linkpath);
        let target = self.resolve("symlink", id, &targetpath);
        self.check(
            self.ctx.actions.symlink,
            "symlink",
            &[link.as_str(), target.as_str()],
        )
        .await?;
        let row = Audit::SftpSymlink {
            link: link.clone(),
            target: target.clone(),
        };
        let res = self.session.symlink(link, target).await;
        self.mutated(id, "symlink", res, row).await
    }
}

impl<B> SftpProxy<B>
where
    B: 'static + HandlerBackend + Send + Sync,
{
    /// Finish a mutation: audit it if the target accepted it, otherwise warn.
    async fn mutated(
        &mut self,
        id: u32,
        op: &str,
        res: Result<Status, SftpError>,
        row: Audit,
    ) -> Result<Status, ProxyError> {
        match res {
            Ok(s) => {
                self.ctx.log.record(row).await;
                Ok(s.retag(id))
            }
            Err(e) => Err(self.target_err(op, e, true)),
        }
    }
}
