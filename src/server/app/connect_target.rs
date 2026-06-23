use crate::asciinema;
use crate::database::Uuid;
use crate::database::models::{SessionRecording, Target, TargetSecretName, User};
use crate::error::Error;
use crate::server::app::error::AppError;
use crate::server::{HandlerLog, error::ServerError, extend_policy};
use log::{debug, trace};
use russh::client as ru_client;
use russh::server as ru_server;
use russh::{Channel, ChannelId, ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Pty};
use std::fmt;
use std::sync::Arc;
use tokio::sync::Mutex;

static LOG_TYPE: &str = "target";

/// Wrapper for session recording that includes the database metadata ID
#[derive(Clone)]
struct RecordingSession {
    session: asciinema::Session,
    recording_id: Uuid,
}

#[derive(Clone, Copy)]
pub enum Request<'a> {
    Shell,
    Exec(&'a [u8]),
    OpenDirectTcpip((&'a str, u32, &'a str, u32)),
}

pub(crate) struct ConnectTarget<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    handler_id: Uuid,
    user_id: Uuid,
    client_ip: Option<std::net::IpAddr>,
    // selected target
    target: Target,

    // target bridge
    target_channel: Option<TargetChannel>,
    target_handle: Option<Arc<ru_client::Handle<Target>>>,
    target_secret_name: TargetSecretName,

    record_session: Option<Arc<Mutex<RecordingSession>>>,
    backend: Arc<B>,
    log: HandlerLog,
}

impl<B> ConnectTarget<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    pub(crate) async fn new(
        handler_id: Uuid,
        log: HandlerLog,
        user: &User,
        client_ip: Option<std::net::IpAddr>,
        backend: Arc<B>,
        target_user: &str,
        target_name: &str,
    ) -> Result<ConnectTarget<B>, Error>
    where
        B: 'static + crate::server::HandlerBackend + Send + Sync,
    {
        let target_secret_name = match backend
            .list_targets_for_user(&user.id, true)
            .await?
            .into_iter()
            .find(|t| t.target_name == target_name && t.secret_user == target_user)
        {
            Some(t) => t,
            None => {
                debug!(
                    "[{}] No target with secret user found for user: '{}({})', target: '{}@{}'",
                    handler_id, &user.username, user.id, target_user, target_name
                );
                return Err(AppError::ConnectTarget(
                    ConnectTargetError::TargetSecretNotFoundByUser,
                )
                .into());
            }
        };

        let target = if let Some(t) = backend
            .get_target_by_id(&target_secret_name.target_id, true)
            .await?
        {
            t
        } else {
            return Err(AppError::ConnectTarget(ConnectTargetError::TargetNotFoundById).into());
        };

        debug!(
            "[{}] Target initialized: user='{}({})' target: '{}@{}'",
            handler_id, user.username, user.id, target_user, target_name,
        );

        Ok(Self {
            handler_id,
            backend,
            user_id: user.id,
            client_ip,
            target,
            target_channel: None,
            target_handle: None,
            target_secret_name,
            record_session: None,
            log,
        })
    }

    pub(crate) fn new_with_target(
        handler_id: Uuid,
        user_id: Uuid,
        backend: Arc<B>,
        client_ip: Option<std::net::IpAddr>,
        log: HandlerLog,
        target: Target,
        target_secret_name: TargetSecretName,
    ) -> Result<ConnectTarget<B>, Error> {
        if target.id != target_secret_name.target_id {
            return Err(
                AppError::ConnectTarget(ConnectTargetError::NotMatchTargetAndTargetSecret).into(),
            );
        }
        Ok(Self {
            handler_id,
            backend,
            user_id,
            client_ip,
            target,
            target_channel: None,
            target_handle: None,
            target_secret_name,
            record_session: None,
            log,
        })
    }

    pub(crate) async fn data(&mut self, data: &[u8]) -> Result<(), Error> {
        self.target_channel
            .as_ref()
            .ok_or(AppError::ConnectTarget(
                ConnectTargetError::TargetChannelNotExist,
            ))?
            .data(data)
            .await?;

        if let Some(r) = self.record_session.as_ref() {
            r.lock().await.session.handle_input(data).await;
        }

        Ok(())
    }

    pub(crate) async fn channel_eof(&mut self) -> Result<(), Error> {
        self.target_channel
            .as_ref()
            .ok_or(AppError::ConnectTarget(
                ConnectTargetError::TargetChannelNotExist,
            ))?
            .eof()
            .await?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<ru_server::Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        session: &mut ru_server::Session,
    ) -> Result<bool, Error> {
        if !self
            .check_permission(
                crate::database::common::InternalUuids::get().act_direct_tcpip,
                Some((host_to_connect.to_string(), port_to_connect as u16)),
            )
            .await?
        {
            return Err(ServerError::PermissionDeny.into());
        };
        match self
            .do_channel_open_direct_tcpip(
                channel,
                host_to_connect,
                port_to_connect,
                originator_address,
                originator_port,
                session,
            )
            .await
        {
            Err(Error::Russh(russh::Error::ChannelOpenFailure(_))) => Ok(false),
            res => res,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut ru_server::Session,
        term: Option<&String>,
        window_size: Option<(u32, u32, u32, u32)>,
        modes: Option<&Vec<(Pty, u32)>>,
    ) -> Result<(), Error> {
        if !self
            .check_permission(crate::database::common::InternalUuids::get().act_exec, None)
            .await?
        {
            return Err(ServerError::PermissionDeny.into());
        };
        self.do_exec_request(data, term, window_size, modes, channel, session)
            .await
    }

    pub(crate) async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut ru_server::Session,
        term: &str,
        window_size: (u32, u32, u32, u32),
        modes: &[(Pty, u32)],
    ) -> Result<(), Error> {
        if !self
            .check_permission(
                crate::database::common::InternalUuids::get().act_shell,
                None,
            )
            .await?
        {
            return Err(ServerError::PermissionDeny.into());
        };
        self.connect_to_target_with_shell(term, window_size, modes, channel, session)
            .await
    }

    async fn connect_to_target_without_pty<'a>(
        &mut self,
        channel: ChannelId,
        session: &mut ru_server::Session,
        request: &Request<'a>,
    ) -> Result<bool, Error> {
        // TODO: print some info to client
        if !self.request_target_channel(request).await? {
            session.close(channel)?;
            return Ok(false);
        }

        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    async fn do_channel_open_direct_tcpip(
        &mut self,
        channel: Channel<ru_server::Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        session: &mut ru_server::Session,
    ) -> Result<bool, Error> {
        let request = Request::OpenDirectTcpip((
            host_to_connect,
            port_to_connect,
            originator_address,
            originator_port,
        ));
        if self
            .connect_to_target_without_pty(channel.id(), session, &request)
            .await?
        {
            self.bridge(session.handle(), channel.id(), request).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn connect_to_target_with_pty<'a>(
        &mut self,
        term: &str,
        window_size: (u32, u32, u32, u32),
        modes: &[(Pty, u32)],
        channel: ChannelId,
        session: &mut ru_server::Session,
        request: &Request<'a>,
    ) -> Result<bool, Error> {
        if !self
            .check_permission(crate::database::common::InternalUuids::get().act_pty, None)
            .await?
        {
            return Err(ServerError::PermissionDeny.into());
        };

        // TODO: print some info to client
        if !self.request_target_channel(request).await? {
            session.close(channel)?;
            return Ok(false);
        }

        let target_channel = self.target_channel.as_ref().ok_or(AppError::ConnectTarget(
            ConnectTargetError::TargetChannelNotExist,
        ))?;

        target_channel
            .request_pty(
                false,
                term,
                window_size.0,
                window_size.1,
                window_size.2,
                window_size.3,
                modes,
            )
            .await?;

        if self.backend.enable_record() {
            let recording = SessionRecording::new(
                self.user_id,
                self.target_secret_name.target_id,
                self.target_secret_name.secret_id,
                self.handler_id,
            );

            // Create the asciinema recorder
            if self.record_session.is_none() {
                let session = asciinema::new_recorder(
                    Some(term.to_string()),
                    std::path::PathBuf::from(self.backend.record_path()).join(&recording.file_path),
                    (window_size.0 as u16, window_size.1 as u16),
                    None,
                    self.backend.record_input(),
                )
                .await?;

                // Wrap session with recording metadata
                let recording_session = RecordingSession {
                    session,
                    recording_id: recording.id,
                };

                // Save to database
                if let Err(e) = self
                    .backend
                    .db_repository()
                    .create_session_recording(&recording)
                    .await
                {
                    log::error!(
                        "[{}] Failed to create session recording: {}",
                        self.handler_id,
                        e
                    );
                    return Err(AppError::ConnectTarget(ConnectTargetError::InitRecordError).into());
                }

                self.record_session = Some(Arc::new(Mutex::new(recording_session)));
            } else {
                return Err(AppError::ConnectTarget(ConnectTargetError::ReInitRecord).into());
            }
        }

        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    async fn do_exec_request(
        &mut self,
        data: &[u8],
        term: Option<&String>,
        window_size: Option<(u32, u32, u32, u32)>,
        modes: Option<&Vec<(Pty, u32)>>,
        channel: ChannelId,
        session: &mut ru_server::Session,
    ) -> Result<(), Error> {
        let request = Request::Exec(data);
        let res = match (term, window_size, modes) {
            (Some(t), Some(w), Some(m)) => {
                self.connect_to_target_with_pty(t, w, m, channel, session, &request)
                    .await?
            }
            _ => {
                self.connect_to_target_without_pty(channel, session, &request)
                    .await?
            }
        };

        if res {
            self.bridge(session.handle(), channel, request).await?;
        }
        Ok(())
    }

    async fn connect_to_target_with_shell(
        &mut self,
        term: &str,
        window_size: (u32, u32, u32, u32),
        modes: &[(Pty, u32)],
        channel: ChannelId,
        session: &mut ru_server::Session,
    ) -> Result<(), Error> {
        if self
            .connect_to_target_with_pty(term, window_size, modes, channel, session, &Request::Shell)
            .await?
        {
            self.bridge(session.handle(), channel, Request::Shell)
                .await?;
        }

        Ok(())
    }

    pub(crate) async fn window_change_request(
        &mut self,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
    ) -> Result<(), Error> {
        self.target_channel
            .as_ref()
            .ok_or(AppError::ConnectTarget(
                ConnectTargetError::TargetChannelNotExist,
            ))?
            .window_change(col_width, row_height, pix_width, pix_height)
            .await?;

        if let Some(r) = self.record_session.as_ref() {
            let mut rec = r.lock().await;
            rec.session.handle_marker("window change".to_string()).await;
            rec.session
                .handle_resize(asciinema::TtySize(col_width as u16, row_height as u16))
                .await;
        }
        Ok(())
    }

    async fn bridge<'a>(
        &mut self,
        handle: ru_server::Handle,
        channel: ChannelId,
        request: Request<'a>,
    ) -> Result<(), Error> {
        let target_channel = self.target_channel.take().ok_or(AppError::ConnectTarget(
            ConnectTargetError::TargetChannelNotExist,
        ))?;
        let (mut read_half, write_half) = target_channel.split();

        let move_target = self.target.clone();

        let request_str = request.to_string();
        match request {
            Request::Shell => write_half.request_shell(false).await?,
            Request::Exec(data) => write_half.exec(false, data).await?,
            Request::OpenDirectTcpip(_) => {}
        }
        self.target_channel = Some(write_half);
        let log = self.log.clone();

        let record = self.record_session.clone();

        let backend_for_task = self.backend.clone();
        let handler_id = self.handler_id;
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    msg = read_half.wait() => {
                        if let Some(msg) = msg {
                            match msg {
                                ChannelMsg::Data { data } => {
                                    if let Some(r) = &record {
                                        r.lock().await.session.handle_output(data.as_ref()).await;
                                    }
                                    let _ = handle.data(channel, data).await;
                                }
                                ChannelMsg::Eof => {
                                    let _ = handle.eof(channel).await;
                                }
                                ChannelMsg::ExtendedData { data, ext: 1 }  => {
                                    if let Some(r) = &record {
                                        r.lock().await.session.handle_output(data.as_ref()).await;
                                    }
                                    let _ = handle.extended_data(channel, 1, data).await;

                                }
                                ChannelMsg::ExitStatus { exit_status } => {
                                    if let Some(r) = &record {
                                        r.lock().await.session.handle_exit(exit_status as i32).await;
                                    }
                                    let _ = handle.exit_status_request(channel, exit_status).await;
                                }
                                _ => {}
                            }
                        } else {
                            break;
                        }
                    }
                }
            }
            // Update session recording as completed
            if let Some(r) = record
                && let Ok(Some(rec)) = backend_for_task
                    .db_repository()
                    .get_session_recording_by_id(&r.lock().await.recording_id)
                    .await
            {
                let mut updated = rec;
                updated.ended_at = Some(chrono::Utc::now().timestamp_millis());
                updated.status = "completed".to_string();
                if let Err(e) = backend_for_task
                    .db_repository()
                    .update_session_recording(&updated)
                    .await
                {
                    log::error!("[{}] Failed to update session recording: {}", handler_id, e);
                }
            }
            let _ = handle.close(channel).await;
            log(
                LOG_TYPE.into(),
                format!(
                    "target request: {} closed on {}({})",
                    request_str, move_target.name, move_target.id
                ),
            )
            .await;
        });

        (self.log)(
            LOG_TYPE.into(),
            format!(
                "target request: {} succeed on {}({})",
                request, self.target.name, self.target.id
            ),
        )
        .await;

        Ok(())
    }

    async fn check_permission(
        &self,
        action_uuid: Uuid,
        open_direct_tcpip: Option<(String, u16)>,
    ) -> Result<bool, Error> {
        let mut ext_req = extend_policy::ExtendPolicyReq::new(self.client_ip);
        ext_req.open_direct_tcpip = open_direct_tcpip;
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

    async fn do_connect_to_target(&mut self, force_build_connect: bool) -> Result<(), Error> {
        // NOTE: target_handle could be re-assigned.
        self.target_handle = self
            .backend
            .connect_to_target(
                self.target.clone(),
                self.target_secret_name.id,
                force_build_connect,
            )
            .await?;

        debug!(
            "[{}] Connected to target '{}({})' ({}:{})",
            self.handler_id,
            self.target.name,
            self.target.id,
            self.target.hostname,
            self.target.port
        );

        Ok(())
    }

    async fn request_target_channel<'a>(&mut self, request: &Request<'a>) -> Result<bool, Error> {
        self.do_connect_to_target(false).await?;
        let handle = if let Some(h) = self.target_handle.as_ref() {
            h
        } else {
            return Ok(false);
        };

        let channel = match request {
            Request::Shell | Request::Exec(_) => {
                match handle.channel_open_session().await {
                    Ok(ch) => ch,
                    Err(
                        russh::Error::ChannelOpenFailure(
                            russh::ChannelOpenFailure::AdministrativelyProhibited,
                        )
                        | russh::Error::SendError,
                    ) => {
                        // Try again if the cache of target connection is unavailable
                        self.do_connect_to_target(true).await?;
                        let handle = if let Some(h) = self.target_handle.as_ref() {
                            h
                        } else {
                            return Ok(false);
                        };
                        handle.channel_open_session().await?
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            Request::OpenDirectTcpip(d) => {
                match handle.channel_open_direct_tcpip(d.0, d.1, d.2, d.3).await {
                    Ok(ch) => ch,
                    Err(
                        russh::Error::ChannelOpenFailure(
                            russh::ChannelOpenFailure::AdministrativelyProhibited,
                        )
                        | russh::Error::SendError,
                    ) => {
                        // Try again if the cache of target connection is unavailable
                        self.do_connect_to_target(true).await?;
                        let handle = if let Some(h) = self.target_handle.as_ref() {
                            h
                        } else {
                            return Ok(false);
                        };
                        handle.channel_open_direct_tcpip(d.0, d.1, d.2, d.3).await?
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        };

        if self.target_channel.is_none() {
            self.target_channel = Some(TargetChannel::ChannelFull(channel));
            Ok(true)
        } else {
            Err(AppError::ConnectTarget(ConnectTargetError::ReInitTargetChannel).into())
        }
    }
}

impl<'a> fmt::Display for Request<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Request::Shell => write!(f, "shell"),
            Request::Exec(d) => write!(f, "exec: {}", String::from_utf8_lossy(d)),
            Request::OpenDirectTcpip(d) => {
                write!(
                    f,
                    "open_direct_tcpip: to_connect: {}:{} originator: {}:{}",
                    d.0, d.1, d.2, d.3
                )
            }
        }
    }
}

enum TargetChannel {
    ChannelFull(Channel<ru_client::Msg>),
    ChannelWriteHalf(ChannelWriteHalf<ru_client::Msg>),
}

impl TargetChannel {
    fn split(self) -> (ChannelReadHalf, Self) {
        if let TargetChannel::ChannelFull(ch) = self {
            let (r, w) = ch.split();
            (r, TargetChannel::ChannelWriteHalf(w))
        } else {
            unreachable!()
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn request_pty(
        &self,
        want_reply: bool,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        terminal_modes: &[(Pty, u32)],
    ) -> Result<(), Error> {
        match self {
            TargetChannel::ChannelFull(ch) => {
                ch.request_pty(
                    want_reply,
                    term,
                    col_width,
                    row_height,
                    pix_width,
                    pix_height,
                    terminal_modes,
                )
                .await?
            }
            TargetChannel::ChannelWriteHalf(ch) => {
                ch.request_pty(
                    want_reply,
                    term,
                    col_width,
                    row_height,
                    pix_width,
                    pix_height,
                    terminal_modes,
                )
                .await?
            }
        }
        Ok(())
    }

    async fn request_shell(&self, want_reply: bool) -> Result<(), Error> {
        match self {
            TargetChannel::ChannelFull(ch) => ch.request_shell(want_reply).await?,
            TargetChannel::ChannelWriteHalf(ch) => ch.request_shell(want_reply).await?,
        }
        Ok(())
    }

    async fn window_change(
        &self,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
    ) -> Result<(), Error> {
        match self {
            TargetChannel::ChannelFull(ch) => {
                ch.window_change(col_width, row_height, pix_width, pix_height)
                    .await?
            }
            TargetChannel::ChannelWriteHalf(ch) => {
                ch.window_change(col_width, row_height, pix_width, pix_height)
                    .await?
            }
        }
        Ok(())
    }

    async fn exec(&self, want_reply: bool, data: &[u8]) -> Result<(), Error> {
        match self {
            TargetChannel::ChannelFull(ch) => ch.exec(want_reply, data).await?,
            TargetChannel::ChannelWriteHalf(ch) => ch.exec(want_reply, data).await?,
        }
        Ok(())
    }

    async fn close(&self) -> Result<(), Error> {
        match self {
            TargetChannel::ChannelFull(ch) => ch.close().await?,
            TargetChannel::ChannelWriteHalf(ch) => ch.close().await?,
        }
        Ok(())
    }

    async fn eof(&self) -> Result<(), Error> {
        match self {
            TargetChannel::ChannelFull(ch) => ch.eof().await?,
            TargetChannel::ChannelWriteHalf(ch) => ch.eof().await?,
        }
        Ok(())
    }

    async fn data(&self, data: &[u8]) -> Result<(), Error> {
        match self {
            TargetChannel::ChannelFull(ch) => ch.data(data).await?,
            TargetChannel::ChannelWriteHalf(ch) => ch.data(data).await?,
        }
        Ok(())
    }
}

impl<B> Drop for ConnectTarget<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    fn drop(&mut self) {
        trace!("[{}] drop ConnectTarget", self.handler_id);
        let target_channel = self.target_channel.take();
        tokio::spawn(async move {
            if let Some(ch) = target_channel {
                let _ = ch.close().await;
            }
        });
    }
}

use thiserror::Error;
#[derive(Debug, Error)]
pub enum ConnectTargetError {
    #[error("Init record error")]
    InitRecordError,

    #[error("Re-initialize target_channel")]
    ReInitTargetChannel,

    #[error("Re-initialize record")]
    ReInitRecord,

    #[error("Target and TargetSecret doens't match")]
    NotMatchTargetAndTargetSecret,

    #[error("No target with secret user found for user")]
    TargetSecretNotFoundByUser,

    #[error("Target not found by ID")]
    TargetNotFoundById,

    #[error("Target channel not exist")]
    TargetChannelNotExist,
}
