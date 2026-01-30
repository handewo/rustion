use crate::asciinema;
use crate::database::models::{Target, TargetSecretName, User};
use crate::error::Error;
use crate::server::{casbin, HandlerLog};
use log::{debug, trace};
use russh::client as ru_client;
use russh::server as ru_server;
use russh::{Channel, ChannelId, ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Pty};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use tokio::sync::mpsc;
use crate::database::Uuid;

static LOG_TYPE: &str = "target";

#[derive(Clone, Copy)]
pub enum Request<'a> {
    Shell,
    Exec(&'a [u8]),
    OpenDirectTcpip((&'a str, u32, &'a str, u32)),
}

pub(crate) struct ConnectTarget {
    handler_id: Uuid,
    user: Option<User>,
    // selected target
    target: Option<Target>,

    // target bridge
    target_channel: HashMap<ChannelId, TargetChannel>,
    target_handle: Option<Arc<ru_client::Handle<Target>>>,
    target_sec_name: Option<TargetSecretName>,
    notify: HashMap<ChannelId, mpsc::Sender<()>>,

    record_session: HashMap<ChannelId, asciinema::Session>,
    log: HandlerLog,
}

impl ConnectTarget {
    pub(crate) fn new(id: Uuid, user: Option<User>, log: HandlerLog) -> Self {
        Self {
            handler_id: id,
            user,
            target: None,
            target_channel: HashMap::with_capacity(3),
            target_handle: None,
            target_sec_name: None,
            notify: HashMap::with_capacity(3),
            record_session: HashMap::with_capacity(3),
            log,
        }
    }

    pub(crate) fn with_target(mut self, val: Option<Target>) -> Self {
        self.target = val;
        self
    }

    pub(crate) fn with_target_sec_name(mut self, val: Option<TargetSecretName>) -> Self {
        self.target_sec_name = val;
        self
    }

    pub(crate) async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut ru_server::Session,
    ) -> Result<(), Error> {
        if let Some(w) = self.target_channel.get(&channel) {
            w.data(data).await?
        }
        if let Some(r) = self.record_session.get_mut(&channel) {
            r.handle_input(data).await;
        }

        Ok(())
    }

    pub(crate) async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut ru_server::Session,
    ) -> Result<(), Error> {
        if let Some(w) = self.target_channel.get(&channel) {
            w.eof().await?
        }

        Ok(())
    }

    pub(crate) async fn init_target<B: 'static + crate::server::HandlerBackend + Send + Sync>(
        &mut self,
        backend: Arc<B>,
        target_user: &str,
        target_name: &str,
    ) -> Result<bool, Error> {
        let user = if let Some(u) = self.user.as_ref() {
            u
        } else {
            return Ok(false);
        };

        let target_secret_name = match backend
            .list_targets_for_user(&user.id, true)
            .await?
            .into_iter()
            .find(|t| t.target_name == target_name && t.secret_user == target_user)
        {
            Some(t) => t,
            None => {
                debug!(
                    "[{}] No target with secret user found for user: {}",
                    self.handler_id, &user.username
                );
                return Ok(false);
            }
        };

        self.target = if let Some(t) = backend
            .get_target_by_id(&target_secret_name.target_id, true)
            .await?
        {
            Some(t)
        } else {
            return Ok(false);
        };

        self.target_sec_name = Some(target_secret_name);

        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn channel_open_direct_tcpip<B>(
        &mut self,
        backend: Arc<B>,
        channel: Channel<ru_server::Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        session: &mut ru_server::Session,
    ) -> Result<bool, Error>
    where
        B: 'static + crate::server::HandlerBackend + Send + Sync,
    {
        match self
            .do_channel_open_direct_tcpip(
                backend,
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
    pub(crate) async fn exec_request<B>(
        &mut self,
        backend: Arc<B>,
        channel: ChannelId,
        data: &[u8],
        session: &mut ru_server::Session,
        term: Option<&String>,
        window_size: Option<(u32, u32, u32, u32)>,
        modes: Option<&Vec<(Pty, u32)>>,
    ) -> Result<(), Error>
    where
        B: 'static + crate::server::HandlerBackend + Send + Sync,
    {
        match self
            .do_exec_request(backend, data, term, window_size, modes, channel, session)
            .await
        {
            Ok(_) => {
                session.channel_success(channel)?;
                Ok(())
            }
            Err(e) => {
                session.channel_failure(channel)?;
                Err(e)
            }
        }
    }

    pub(crate) async fn shell_request<B>(
        &mut self,
        backend: Arc<B>,
        channel: ChannelId,
        session: &mut ru_server::Session,
        term: &str,
        window_size: (u32, u32, u32, u32),
        modes: &[(Pty, u32)],
    ) -> Result<(), Error>
    where
        B: 'static + crate::server::HandlerBackend + Send + Sync,
    {
        match self
            .connect_to_target_with_shell(
                backend.clone(),
                term,
                window_size,
                modes,
                channel,
                session,
            )
            .await
        {
            Ok(_) => {
                session.channel_success(channel)?;
                Ok(())
            }
            Err(e) => {
                session.channel_failure(channel)?;
                Err(e)
            }
        }
    }

    async fn connect_to_target_without_pty<'a, B>(
        &mut self,
        backend: Arc<B>,
        channel: ChannelId,
        session: &mut ru_server::Session,
        request: &Request<'a>,
    ) -> Result<(), Error>
    where
        B: 'static + crate::server::HandlerBackend + Send + Sync,
    {
        // TODO: print some info to client
        if !self
            .request_target_channel(channel, backend, request)
            .await?
        {
            session.close(channel)?;
            return Ok(());
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn do_channel_open_direct_tcpip<B>(
        &mut self,
        backend: Arc<B>,
        channel: Channel<ru_server::Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        session: &mut ru_server::Session,
    ) -> Result<bool, Error>
    where
        B: 'static + crate::server::HandlerBackend + Send + Sync,
    {
        let request = Request::OpenDirectTcpip((
            host_to_connect,
            port_to_connect,
            originator_address,
            originator_port,
        ));
        self.connect_to_target_without_pty(backend, channel.id(), session, &request)
            .await?;

        self.bridge(session.handle(), channel.id(), request).await?;
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    async fn connect_to_target_with_pty<'a, B>(
        &mut self,
        backend: Arc<B>,
        term: &str,
        window_size: (u32, u32, u32, u32),
        modes: &[(Pty, u32)],
        channel: ChannelId,
        session: &mut ru_server::Session,
        request: &Request<'a>,
    ) -> Result<(), Error>
    where
        B: 'static + crate::server::HandlerBackend + Send + Sync,
    {
        // TODO: print some info to client
        if !self
            .request_target_channel(channel, backend.clone(), request)
            .await?
        {
            session.close(channel)?;
            return Ok(());
        }

        let target_channel = self
            .target_channel
            .get(&channel)
            .unwrap_or_else(|| panic!("[{}] target_channel should not be none", self.handler_id));

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

        if backend.enable_record() {
            let user = self
                .user
                .as_ref()
                .unwrap_or_else(|| panic!("[{}] user should not be none", self.handler_id))
                .username
                .as_str();
            let target_sec_name = self.target_sec_name.as_ref().unwrap_or_else(|| {
                panic!("[{}] target_sec_name should not be none", self.handler_id)
            });
            let path = format!(
                "{}/{}_{}@{}_{}_{}.cast",
                backend.record_path(),
                user,
                target_sec_name.secret_user,
                target_sec_name.target_name,
                self.handler_id,
                channel
            );
            if self
                .record_session
                .insert(
                    channel,
                    asciinema::new_recorder(
                        Some(term.to_string()),
                        &path,
                        (window_size.0 as u16, window_size.1 as u16),
                        None,
                        backend.record_input(),
                    )
                    .await?,
                )
                .is_some()
            {
                return Err(Error::App(format!(
                    "Channel: {} record already existed",
                    channel
                )));
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn do_exec_request<B>(
        &mut self,
        backend: Arc<B>,
        data: &[u8],
        term: Option<&String>,
        window_size: Option<(u32, u32, u32, u32)>,
        modes: Option<&Vec<(Pty, u32)>>,
        channel: ChannelId,
        session: &mut ru_server::Session,
    ) -> Result<(), Error>
    where
        B: 'static + crate::server::HandlerBackend + Send + Sync,
    {
        let request = Request::Exec(data);
        match (term, window_size, modes) {
            (Some(t), Some(w), Some(m)) => {
                self.connect_to_target_with_pty(backend, t, w, m, channel, session, &request)
                    .await?;
            }
            _ => {
                self.connect_to_target_without_pty(backend, channel, session, &request)
                    .await?;
            }
        }

        self.bridge(session.handle(), channel, request).await?;
        Ok(())
    }

    async fn connect_to_target_with_shell<B>(
        &mut self,
        backend: Arc<B>,
        term: &str,
        window_size: (u32, u32, u32, u32),
        modes: &[(Pty, u32)],
        channel: ChannelId,
        session: &mut ru_server::Session,
    ) -> Result<(), Error>
    where
        B: 'static + crate::server::HandlerBackend + Send + Sync,
    {
        self.connect_to_target_with_pty(
            backend,
            term,
            window_size,
            modes,
            channel,
            session,
            &Request::Shell,
        )
        .await?;

        self.bridge(session.handle(), channel, Request::Shell)
            .await?;
        Ok(())
    }

    pub(crate) async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: &mut ru_server::Session,
    ) -> Result<(), Error> {
        if let Some(ch) = self.target_channel.get(&channel) {
            ch.window_change(col_width, row_height, pix_width, pix_height)
                .await?;
            session.channel_success(channel)?;
        }

        if let Some(r) = self.record_session.get_mut(&channel) {
            r.handle_marker("window change".to_string()).await;
            r.handle_resize(asciinema::TtySize(col_width as u16, row_height as u16))
                .await;
        }

        session.channel_failure(channel)?;
        Ok(())
    }

    async fn bridge<'a>(
        &mut self,
        handle: ru_server::Handle,
        channel: ChannelId,
        request: Request<'a>,
    ) -> Result<(), Error> {
        let target_channel = self
            .target_channel
            .remove(&channel)
            .unwrap_or_else(|| panic!("[{}] target_channel should not be none", self.handler_id));
        let (mut read_half, write_half) = target_channel.split();
        self.target_channel.insert(channel, write_half);
        let write_half = self
            .target_channel
            .get(&channel)
            .unwrap_or_else(|| panic!("[{}] target_channel should not be none", self.handler_id));

        let target = self
            .target
            .as_ref()
            .unwrap_or_else(|| panic!("[{}] target should be assigned", self.handler_id));
        let move_target = target.clone();

        let request_str = request.to_string();
        match request {
            Request::Shell => write_half.request_shell(false).await?,
            Request::Exec(data) => write_half.exec(false, data).await?,
            Request::OpenDirectTcpip(_) => {}
        }
        let log = self.log.clone();

        let (send, mut recv) = mpsc::channel::<()>(1);
        if self.notify.insert(channel, send).is_some() {
            return Err(Error::App(format!(
                "Channel: {} notify already existed",
                channel
            )));
        };

        let mut record = self.record_session.get(&channel).cloned();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    msg = read_half.wait() => {
                        if let Some(msg) = msg {
                            match msg {
                                ChannelMsg::Data { data } => {
                                    if let Some(r) = record.as_mut() {
                                        r.handle_output(data.as_ref()).await;
                                    }
                                    let _ = handle.data(channel, data).await;
                                }
                                ChannelMsg::Eof => {
                                    let _ = handle.eof(channel).await;
                                }
                                ChannelMsg::ExtendedData { data, ext: 1 }  => {
                                    if let Some(r) = record.as_mut() {
                                        r.handle_output(data.as_ref()).await;
                                    }
                                    let _ = handle.extended_data(channel, 1, data).await;

                                }
                                ChannelMsg::ExitStatus { exit_status } => {
                                    if let Some(r) = record.as_mut() {
                                        r.handle_exit(exit_status as i32 ).await;
                                    }
                                    let _ = handle.exit_status_request(channel, exit_status).await;
                                }
                                _ => {}
                            }
                        } else {
                            break;
                        }
                    }
                    _ = recv.recv() => {
                        break;
                    }
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
                request, target.name, target.id
            ),
        )
        .await;

        Ok(())
    }

    pub async fn check_permission<B>(
        &mut self,
        backend: Arc<B>,
        action_uuid: Uuid,
        ip: Option<std::net::IpAddr>,
    ) -> Result<bool, Error>
    where
        B: 'static + crate::server::HandlerBackend + Send + Sync,
    {
        let user = if let Some(u) = self.user.as_ref() {
            u
        } else {
            return Ok(false);
        };

        let target_sec_id = if let Some(tsn) = self.target_sec_name.as_ref() {
            tsn.id
        } else {
            return Ok(false);
        };

        let target = if let Some(t) = self.target.as_ref() {
            t
        } else {
            return Ok(false);
        };

        if !backend
            .enforce(
                user.id,
                target_sec_id,
                action_uuid,
                casbin::ExtendPolicyReq::new(ip),
            )
            .await?
        {
            debug!(
                "[{}] User: {} doesn't have permission to access target: {}, action_uuid: {}",
                self.handler_id, &user.username, &target.name, action_uuid
            );
            return Ok(false);
        }
        Ok(true)
    }

    async fn do_connect_to_target<B>(&mut self, backend: Arc<B>) -> Result<(), Error>
    where
        B: 'static + crate::server::HandlerBackend + Send + Sync,
    {
        let target = if let Some(t) = self.target.as_ref() {
            t
        } else {
            return Ok(());
        };

        let target_sec_id = if let Some(tsn) = self.target_sec_name.as_ref() {
            &tsn.id
        } else {
            return Ok(());
        };

        // NOTE: target_handle could be re-assigned.
        self.target_handle = backend
            .connect_to_target(target.clone(), target_sec_id, false)
            .await?;

        Ok(())
    }

    async fn request_target_channel<'a, B>(
        &mut self,
        channel_id: ChannelId,
        backend: Arc<B>,
        request: &Request<'a>,
    ) -> Result<bool, Error>
    where
        B: 'static + crate::server::HandlerBackend + Send + Sync,
    {
        self.do_connect_to_target(backend.clone()).await?;
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
                        self.do_connect_to_target(backend).await?;
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
                        self.do_connect_to_target(backend).await?;
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

        self.target_channel
            .insert(channel_id, TargetChannel::ChannelFull(channel));
        Ok(true)
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

impl Drop for ConnectTarget {
    fn drop(&mut self) {
        for (_, send) in self.notify.drain() {
            tokio::spawn(async move {
                let _ = send.send(()).await;
            });
        }
        for (_, ch) in self.target_channel.drain() {
            tokio::spawn(async move {
                let _ = ch.close().await;
            });
        }
        trace!("[{}] drop ConnectTarget", self.handler_id);
    }
}
