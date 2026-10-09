use super::HandlerBackend;
use super::app::{self, Application, NextApplication};
use super::error::ServerError;
use super::event_log::{EventKind, EventLogger};
use super::tty;
use crate::database::Uuid;
use crate::database::models::User;
use crate::error::Error;
use crate::server::app::{ExecParams, PtyParams, connect_target::ConnectTarget};
use crate::server::extend_policy::ExtendPolicyReq;
use bytes::Bytes;
use log::{debug, info, trace, warn};
use russh::keys::ssh_key::PublicKey;
use russh::server as ru_server;
use russh::{Channel, ChannelId, Pty};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;
use tokio::sync::mpsc::{self, Receiver, Sender, channel};

pub struct BastionHandler<B: 'static + HandlerBackend + Send + Sync> {
    // Unique ID for each connection.
    id: Uuid,
    pub(super) user: Option<User>,
    login_parse: Option<LoginParse>,
    client_ip: Option<std::net::SocketAddr>,
    channel_session: HashMap<ChannelId, ChannelSession<B>>,
    backend: Arc<B>,
    /// `None` until authentication succeeds: an audit event needs a user to
    /// attribute it to. Unauthenticated connections audit nothing.
    log: Option<EventLogger<B>>,
    auth_attempts_per_conn: u32,
    max_auth_attempts_per_conn: u32,
    send_app_msg: Sender<(ChannelId, NextApplication)>,
    recv_app_msg: Receiver<(ChannelId, NextApplication)>,
}

impl<B: 'static + HandlerBackend + Send + Sync> ru_server::Handler for BastionHandler<B> {
    type Error = crate::error::Error;
    type Data = (ChannelId, NextApplication);

    async fn channel_open_session(
        &mut self,
        channel: Channel<ru_server::Msg>,
        reply: ru_server::ChannelOpenHandle,
        _session: &mut ru_server::Session,
    ) -> Result<(), Self::Error> {
        let user = self.user.as_ref().ok_or(ServerError::UserNotInit)?;
        let channel_id = channel.id();
        let mut channel_session = ChannelSession::new(Some(channel));
        if !self.init_session(user).await? {
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }

        let app = if !user.force_init_pass {
            match self
                .login_parse
                .as_ref()
                .ok_or(ServerError::InvalidLoginMode)?
                .parse_mode()
            {
                LoginMode::TargetSelector | LoginMode::Target(_) => Application::TargetSelector,
                LoginMode::TargetWithUser(target_user, target) => {
                    info!(
                        "[{}] Direct connection to '{}@{}' for user '{}({})'",
                        self.id, target_user, target, user.username, user.id
                    );
                    let app = Box::new(
                        app::connect_target::ConnectTarget::new(
                            self.id,
                            self.event_log()?,
                            user,
                            self.client_ip.map(|v| v.ip()),
                            self.backend.clone(),
                            &target_user,
                            &target,
                        )
                        .await?,
                    );
                    Application::ConnectTarget(app)
                }
                LoginMode::Admin => Application::Admin,
                LoginMode::Password => Application::Password,
                LoginMode::Player => Application::Player,
            }
        } else {
            debug!(
                "[{}] User '{}({})' requires password change",
                self.id, user.username, user.id
            );
            Application::Password
        };
        channel_session.app = app;
        match self.channel_session.entry(channel_id) {
            Entry::Occupied(_) => {
                return Err(ServerError::DuplicateChannelId.into());
            }
            Entry::Vacant(e) => {
                debug!("[{}] Create new channel: {}", self.id, channel_id);
                e.insert(channel_session);
            }
        };
        reply.accept().await;
        Ok(())
    }

    async fn auth_password(
        &mut self,
        login_name: &str,
        password: &str,
    ) -> Result<ru_server::Auth, Self::Error> {
        self.init_login(login_name).await?;

        if self.max_auth_attempts(login_name).await? {
            return Ok(ru_server::Auth::reject());
        }

        let Some(user) = self.user.as_ref() else {
            debug!("[{}] User {} doesn't exist", self.id, login_name);
            return Ok(ru_server::Auth::reject());
        };
        let log = self.init_event_log(user.id);

        if !user.is_active {
            return Ok(ru_server::Auth::reject());
        }
        if user.verify_password(password) {
            self.backend
                .clear_auth_attempts(self.client_ip, user.username.clone())
                .await;
            log.record("login successfully by password").await;
            self.log = Some(log);
            return Ok(ru_server::Auth::Accept);
        }
        Ok(ru_server::Auth::reject())
    }

    async fn auth_publickey(
        &mut self,
        login_name: &str,
        public_key: &PublicKey,
    ) -> Result<ru_server::Auth, Self::Error> {
        self.init_login(login_name).await?;

        if self.max_auth_attempts(login_name).await? {
            return Ok(ru_server::Auth::reject());
        }

        let Some(user) = self.user.as_ref() else {
            debug!("[{}] User {} doesn't exist", self.id, login_name);
            return Ok(ru_server::Auth::reject());
        };
        let log = self.init_event_log(user.id);

        if !user.is_active {
            return Ok(ru_server::Auth::reject());
        }
        if user.verify_authorized_keys(public_key) {
            self.backend
                .clear_auth_attempts(self.client_ip, user.username.clone())
                .await;
            log.record("login successfully by public key").await;
            self.log = Some(log);
            return Ok(ru_server::Auth::Accept);
        }
        Ok(ru_server::Auth::reject())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut ru_server::Session,
    ) -> Result<(), Self::Error> {
        let channel_session = self
            .channel_session
            .get_mut(&channel)
            .ok_or(ServerError::ChannelNotExist)?;
        match channel_session.app {
            Application::ConnectTarget(ref mut app) => app.channel_eof().await,
            _ => {
                session.close(channel)?;
                Ok(())
            }
        }
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut ru_server::Session,
    ) -> Result<(), Self::Error> {
        let channel_session = self
            .channel_session
            .get_mut(&channel)
            .ok_or(ServerError::ChannelNotExist)?;
        match channel_session.app {
            Application::ConnectTarget(ref mut app) => app.data(data).await,
            Application::Admin => match (
                channel_session.window_size.as_ref(),
                channel_session.pty_modes.as_ref(),
                channel_session.pty_term.as_ref(),
            ) {
                (Some(_), Some(_), Some(_)) => channel_session
                    .tty
                    .as_ref()
                    .ok_or(ServerError::TtyNotInit)?
                    .send_to_tty
                    .send(Bytes::copy_from_slice(data))
                    .await
                    .map_err(std::io::Error::other)
                    .map_err(Error::IO),
                _ => channel_session
                    .sender
                    .as_ref()
                    .ok_or(ServerError::ExecNotInit)?
                    .send(Bytes::copy_from_slice(data))
                    .await
                    .map_err(std::io::Error::other)
                    .map_err(Error::IO),
            },
            Application::TargetSelector | Application::Password | Application::Player => {
                channel_session
                    .tty
                    .as_ref()
                    .ok_or(ServerError::TtyNotInit)?
                    .send_to_tty
                    .send(Bytes::copy_from_slice(data))
                    .await
                    .map_err(std::io::Error::other)
                    .map_err(Error::IO)
            }
            Application::Sftp | Application::None => Ok(()),
        }
    }

    /// The client's window size has changed.
    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: &mut ru_server::Session,
    ) -> Result<(), Self::Error> {
        let channel_session = self
            .channel_session
            .get_mut(&channel)
            .ok_or(ServerError::ChannelNotExist)?;
        channel_session.window_size = Some((col_width, row_height, pix_width, pix_height));
        match channel_session.app {
            Application::ConnectTarget(ref mut app) => {
                if let Err(e) = app
                    .window_change_request(col_width, row_height, pix_width, pix_height)
                    .await
                {
                    session.channel_failure(channel)?;
                    Err(e)
                } else {
                    session.channel_success(channel)?;
                    Ok(())
                }
            }
            Application::TargetSelector
            | Application::Admin
            | Application::Password
            | Application::Player => {
                if let Some(tty) = channel_session.tty.as_mut() {
                    let win_raw = crate::terminal::window_change(
                        &mut tty.tty,
                        col_width,
                        row_height,
                        pix_width,
                        pix_height,
                    );

                    tty.send_to_tty
                        .send(win_raw.into())
                        .await
                        .map_err(std::io::Error::other)
                        .map_err(Error::IO)?;
                    session.channel_success(channel).map_err(Error::Russh)
                } else {
                    session.channel_failure(channel)?;
                    Err(ServerError::TtyNotInit.into())
                }
            }
            Application::Sftp | Application::None => Ok(()),
        }
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut ru_server::Session,
    ) -> Result<(), Self::Error> {
        let channel_session = self
            .channel_session
            .get_mut(&channel)
            .ok_or(ServerError::ChannelNotExist)?;
        match channel_session.app {
            Application::ConnectTarget(ref mut app) => {
                if let Err(e) = app
                    .exec_request(
                        channel,
                        data,
                        session,
                        channel_session.pty_term.as_ref(),
                        channel_session.window_size,
                        channel_session.pty_modes.as_ref(),
                    )
                    .await
                {
                    session.channel_failure(channel)?;
                    Err(e)
                } else {
                    session.channel_success(channel)?;
                    Ok(())
                }
            }
            Application::Admin => match (
                channel_session.window_size.as_ref(),
                channel_session.pty_modes.as_ref(),
                channel_session.pty_term.as_ref(),
            ) {
                (Some(_), Some(_), Some(_)) => {
                    let (tty, recv_from_tty) = channel_session.new_tty()?;
                    let app_params = self.wrap_pty_parameters(tty, recv_from_tty)?;
                    app::admin::exec_request_with_pty(app_params, channel, data, session).await?;
                    session.channel_failure(channel)?;
                    Ok(())
                }
                _ => {
                    let (tx, rx) = mpsc::channel(16);
                    channel_session.sender = Some(tx);
                    let params = self.wrap_exec_parameters(rx)?;
                    app::admin::exec_request_without_pty(params, channel, data, session).await?;
                    session.channel_success(channel)?;
                    Ok(())
                }
            },
            _ => {
                warn!("[{}] Unsupported exec request", self.id);
                session.channel_failure(channel)?;
                session.close(channel)?;
                Ok(())
            }
        }
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<ru_server::Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        reply: ru_server::ChannelOpenHandle,
        session: &mut ru_server::Session,
    ) -> Result<(), Self::Error> {
        let channel_id = channel.id();
        let mut channel_session = ChannelSession::new(None);
        let user = self.user.as_ref().ok_or(ServerError::UserNotInit)?;

        if user.force_init_pass {
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }

        if !self.init_session(user).await? {
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        match self
            .login_parse
            .as_ref()
            .ok_or(ServerError::InvalidLoginMode)?
            .parse_mode()
        {
            LoginMode::TargetWithUser(target_user, target) => {
                info!(
                    "[{}] Direct connection to '{}@{}' for user '{}({})'",
                    self.id, target_user, target, user.username, user.id
                );
                let mut app = Box::new(
                    app::connect_target::ConnectTarget::new(
                        self.id,
                        self.event_log()?,
                        user,
                        self.client_ip.map(|v| v.ip()),
                        self.backend.clone(),
                        &target_user,
                        &target,
                    )
                    .await?,
                );
                if !app
                    .channel_open_direct_tcpip(
                        channel_id,
                        host_to_connect,
                        port_to_connect,
                        originator_address,
                        originator_port,
                        session,
                    )
                    .await?
                {
                    reply
                        .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                        .await;
                    return Ok(());
                };
                channel_session.app = Application::ConnectTarget(app);
                match self.channel_session.entry(channel_id) {
                    Entry::Occupied(_) => {
                        return Err(ServerError::DuplicateChannelId.into());
                    }
                    Entry::Vacant(e) => {
                        debug!("[{}] Create new channel: {}", self.id, channel_id);
                        e.insert(channel_session);
                    }
                };
                reply.accept().await;
                Ok(())
            }
            _ => {
                reply
                    .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                    .await;
                Ok(())
            }
        }
    }

    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut ru_server::Session,
    ) -> Result<(), Self::Error> {
        // TODO:check permission
        let channel_session = self
            .channel_session
            .get_mut(&channel_id)
            .ok_or(ServerError::ChannelNotExist)?;

        let user = self.user.as_ref().ok_or(ServerError::UserNotInit)?;
        if name == "sftp"
            && let Application::ConnectTarget(ref mut app) = channel_session.app
        {
            if let Err(e) = app.request_subsystem(channel_id, name, session).await {
                session.channel_failure(channel_id)?;
                return Err(e);
            }
            if let (Some(target_channel), Some(session_channel)) =
                (app.take_target_channel(), channel_session.channel.take())
            {
                let target_secret_name = app.target_secret_name.clone();
                channel_session.app = Application::Sftp;
                session.channel_success(channel_id)?;
                app::sftp::sftp_subsystem(
                    self.id,
                    user.id,
                    self.client_ip.map(|v| v.ip()),
                    self.backend.clone(),
                    target_secret_name,
                    target_channel,
                    session_channel,
                )
                .await
                .map_err(app::error::AppError::Sftp)?;
                return Ok(());
            }
        }

        warn!("[{}] Unsupported subsystem request", self.id);
        session.channel_failure(channel_id)?;
        session.close(channel_id)?;

        Ok(())
    }

    /// The client requests a pseudo-terminal with the given
    /// specifications.
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
        session: &mut ru_server::Session,
    ) -> Result<(), Self::Error> {
        let channel_session = self
            .channel_session
            .get_mut(&channel)
            .ok_or(ServerError::ChannelNotExist)?;
        channel_session.pty_modes = Some(Vec::from(modes));
        channel_session.pty_term = Some(term.to_string());
        channel_session.window_size = Some((col_width, row_height, pix_width, pix_height));
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut ru_server::Session,
    ) -> Result<(), Self::Error> {
        let channel_session = self
            .channel_session
            .get_mut(&channel)
            .ok_or(ServerError::ChannelNotExist)?;
        match channel_session.app {
            Application::TargetSelector => {
                let (tty, recv_from_tty) = channel_session.new_tty()?;
                let app_params = self.wrap_pty_parameters(tty, recv_from_tty)?;
                let target_name = if let LoginMode::Target(t) = self
                    .login_parse
                    .as_ref()
                    .ok_or(ServerError::InvalidLoginMode)?
                    .parse_mode()
                {
                    Some(t.clone())
                } else {
                    None
                };

                app::target_selector::shell_request(target_name, app_params, channel, session)
                    .await?;

                session.channel_success(channel)?;
                Ok(())
            }
            Application::Admin => {
                let (tty, recv_from_tty) = channel_session.new_tty()?;
                let app_params = self.wrap_pty_parameters(tty, recv_from_tty)?;
                app::admin::shell_request(app_params, channel, session).await?;
                session.channel_success(channel)?;
                Ok(())
            }
            Application::Password => {
                let (tty, recv_from_tty) = channel_session.new_tty()?;
                let app_params = self.wrap_pty_parameters(tty, recv_from_tty)?;
                app::change_password::shell_request(
                    self.user.as_ref().ok_or(ServerError::UserNotInit)?.clone(),
                    app_params,
                    channel,
                    session,
                )
                .await?;
                session.channel_success(channel)?;
                Ok(())
            }
            Application::Player => {
                let (tty, recv_from_tty) = channel_session.new_tty()?;
                let app_params = self.wrap_pty_parameters(tty, recv_from_tty)?;
                app::player::shell_request(app_params, channel, session).await?;
                session.channel_success(channel)?;
                Ok(())
            }
            Application::ConnectTarget(ref mut app) => {
                if let Err(e) = app
                    .shell_request(
                        channel,
                        session,
                        channel_session
                            .pty_term
                            .as_ref()
                            .ok_or(ServerError::PtyTermNotExist)?,
                        channel_session
                            .window_size
                            .ok_or(ServerError::WindowSizeNotExist)?,
                        channel_session
                            .pty_modes
                            .as_ref()
                            .ok_or(ServerError::PtyModesNotExist)?,
                    )
                    .await
                {
                    session.channel_failure(channel)?;
                    Err(e)
                } else {
                    session.channel_success(channel)?;
                    Ok(())
                }
            }
            Application::Sftp | Application::None => {
                session.channel_failure(channel)?;
                Ok(())
            }
        }
    }

    fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut ru_server::Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        debug!("[{}] Channel: {} is closed", self.id, channel);
        self.channel_session.remove(&channel);
        async { Ok(()) }
    }

    async fn trigger(&mut self) -> Result<Self::Data, Self::Error> {
        match self.recv_app_msg.recv().await {
            Some(d) => {
                trace!("[{}] Receive app message", self.id);
                Ok(d)
            }
            None => std::future::pending().await,
        }
    }

    async fn process(
        &mut self,
        data: Self::Data,
        session: &mut ru_server::Session,
    ) -> Result<(), Self::Error> {
        // Taken before the `&mut` borrow of `channel_session` below.
        let log = self.event_log()?;
        let channel_session = self
            .channel_session
            .get_mut(&data.0)
            .ok_or(ServerError::ChannelNotExist)?;
        match data.1 {
            NextApplication::ConnectTargetShell(boxed) => {
                let (target, target_secret_name) = *boxed;
                trace!("[{}] Process connect_target message", self.id);
                let mut connect_target = Box::new(ConnectTarget::new_with_target(
                    self.id,
                    self.user.as_ref().ok_or(ServerError::UserNotInit)?.id,
                    self.backend.clone(),
                    self.client_ip.map(|v| v.ip()),
                    log,
                    target,
                    target_secret_name,
                )?);
                connect_target
                    .shell_request(
                        data.0,
                        session,
                        channel_session
                            .pty_term
                            .as_ref()
                            .ok_or(ServerError::PtyTermNotExist)?,
                        channel_session
                            .window_size
                            .ok_or(ServerError::WindowSizeNotExist)?,
                        channel_session
                            .pty_modes
                            .as_ref()
                            .ok_or(ServerError::PtyModesNotExist)?,
                    )
                    .await?;
                channel_session.app = Application::ConnectTarget(connect_target);
            }
            _ => todo!(),
        }
        Ok(())
    }
}

impl<B: 'static + HandlerBackend + Sync> BastionHandler<B> {
    pub(super) fn new(
        client_ip: Option<std::net::SocketAddr>,
        max_auth_attempts_per_conn: u32,
        backend: Arc<B>,
    ) -> Self {
        let (send_app_msg, recv_app_msg) = channel(1);
        let uuid = Uuid::new_v4();
        trace!("[{}] create new handler", uuid);
        BastionHandler {
            id: uuid,
            user: None,
            login_parse: None,
            client_ip,
            channel_session: HashMap::with_capacity(1),
            backend,
            log: None,
            auth_attempts_per_conn: 0,
            max_auth_attempts_per_conn,
            send_app_msg,
            recv_app_msg,
        }
    }

    /// The connection's audit logger. Errors before authentication, which is
    /// unreachable for anything downstream of a channel request.
    fn event_log(&self) -> Result<EventLogger<B>, Error> {
        self.log.clone().ok_or(ServerError::EventLogNotInit.into())
    }

    /// Bind the audit logger to the now-known user, and hand back a clone for
    /// the caller to log through.
    fn init_event_log(&self, user_id: Uuid) -> EventLogger<B> {
        EventLogger::new(self.backend.clone(), self.id, user_id, EventKind::Server)
    }

    async fn init_login(&mut self, login_name: &str) -> Result<(), Error> {
        if self.login_parse.is_none() {
            self.login_parse = LoginParse::parse_login_name(login_name);
        }

        match self.login_parse.as_ref() {
            Some(l) => {
                let user = l.0.clone();
                self.get_user(&user).await
            }
            None => Err(Error::Server(ServerError::InvalidLoginMode)),
        }
    }

    async fn init_session(&self, user: &User) -> Result<bool, Error> {
        let uuids = crate::database::common::InternalUuids::get();
        if !self
            .backend
            .enforce(
                user.id,
                uuids.obj_login,
                uuids.act_login,
                ExtendPolicyReq::new(self.client_ip.map(|v| v.ip())),
            )
            .await?
        {
            debug!(
                "[{}] User: '{}({})' has no permission to login",
                self.id, user.username, user.id
            );
            return Ok(false);
        };
        Ok(true)
    }

    fn wrap_exec_parameters(&self, recv: Receiver<Bytes>) -> Result<ExecParams<B>, Error> {
        Ok(ExecParams {
            handler_id: self.id,
            user_id: self.user.as_ref().ok_or(ServerError::UserNotInit)?.id,
            client_ip: self.client_ip.map(|v| v.ip()),
            backend: self.backend.clone(),
            recv,
            log: self.event_log()?,
        })
    }

    fn wrap_pty_parameters(
        &self,
        tty: tty::Tty,
        recv_from_tty: Receiver<Bytes>,
    ) -> Result<PtyParams<B>, Error> {
        Ok(PtyParams {
            handler_id: self.id,
            user_id: self.user.as_ref().ok_or(ServerError::UserNotInit)?.id,
            client_ip: self.client_ip.map(|v| v.ip()),
            backend: self.backend.clone(),
            tty,
            recv_from_tty,
            log: self.event_log()?,
            app_sender: self.send_app_msg.clone(),
        })
    }

    async fn get_user(&mut self, name: &str) -> Result<(), Error> {
        if self.user.is_none() {
            self.user = self.backend.get_user_by_username(name, true).await?
        }
        Ok(())
    }

    async fn max_auth_attempts(&mut self, login_name: &str) -> Result<bool, Error> {
        if self
            .backend
            .reject_auth_attempts(
                self.client_ip,
                self.login_parse
                    .as_ref()
                    .ok_or(ServerError::InvalidLoginMode)?
                    .0
                    .clone(),
            )
            .await
        {
            return Ok(true);
        }
        self.auth_attempts_per_conn += 1;

        if self.auth_attempts_per_conn > self.max_auth_attempts_per_conn {
            warn!(
                "[{}] Client {:?} exceeded max authentication attempts ({})",
                self.id, self.client_ip, self.max_auth_attempts_per_conn
            );
            return Ok(true);
        }

        debug!(
            "[{}] Authentication attempt {} for user '{}' from {:?}",
            self.id, self.auth_attempts_per_conn, login_name, self.client_ip
        );

        Ok(false)
    }
}

impl<B: 'static + HandlerBackend + Send + Sync> Drop for BastionHandler<B> {
    fn drop(&mut self) {
        // Only authenticated connections have a logout to record.
        if let Some(log) = self.log.clone() {
            tokio::spawn(async move {
                log.record("logout").await;
            });
        }
        trace!("[{}] drop BastionHandler", self.id);
    }
}

/// Parsing login name to which ssh client connect is used to
/// call different function.
///  - ssh user@root@target@rustion used to connect to target
///    with root directly.
///  - ssh user@target@rustion user to connect to target but doesn't
///    specify system user.
///  - ssh user@password@rustion used to change user's password.
///  - ssh user@rustion used to enter default mode.
#[derive(Clone)]
pub(super) struct LoginParse(String, String, String);

pub enum LoginMode {
    TargetSelector,
    Password,
    Player,
    Admin,
    Target(String),
    TargetWithUser(String, String),
}

impl LoginParse {
    fn parse_login_name(login: &str) -> Option<LoginParse> {
        let mut sp: Vec<_> = login.split('@').collect();
        match sp.len() {
            1 => Some(LoginParse(
                sp.pop().unwrap().into(),
                String::new(),
                String::new(),
            )),
            2 => {
                let second = sp.pop().unwrap().into();
                let first = sp.pop().unwrap().into();
                Some(LoginParse(first, second, String::new()))
            }
            3 => {
                let third = sp.pop().unwrap().into();
                let second = sp.pop().unwrap().into();
                let first = sp.pop().unwrap().into();
                Some(LoginParse(first, second, third))
            }
            _ => None,
        }
    }

    pub fn parse_mode(&self) -> LoginMode {
        if !self.1.is_empty() && !self.2.is_empty() {
            return LoginMode::TargetWithUser(self.1.clone(), self.2.clone());
        }
        if !self.1.is_empty() && self.2.is_empty() {
            match self.1.as_str() {
                "password" => return LoginMode::Password,
                "player" => return LoginMode::Player,
                "admin" => return LoginMode::Admin,
                _ => return LoginMode::Target(self.1.clone()),
            }
        }
        LoginMode::TargetSelector
    }
}

struct ChannelSession<B: 'static + HandlerBackend + Send + Sync> {
    pub app: Application<B>,
    pub channel: Option<Channel<ru_server::Msg>>,
    // shell request
    pub tty: Option<tty::Tty>,
    // exec request
    pub sender: Option<Sender<Bytes>>,
    // pty
    pub window_size: Option<(u32, u32, u32, u32)>,
    pub pty_modes: Option<Vec<(Pty, u32)>>,
    pub pty_term: Option<String>,
}

impl<B: 'static + HandlerBackend + Send + Sync> ChannelSession<B> {
    pub fn new(channel: Option<Channel<ru_server::Msg>>) -> Self {
        Self {
            app: Application::default(),
            channel,
            tty: None,
            sender: None,
            window_size: None,
            pty_modes: None,
            pty_term: None,
        }
    }

    fn new_tty(&mut self) -> Result<(tty::Tty, Receiver<Bytes>), Error> {
        let (mut tty, recv_from_tty) = tty::Tty::new();
        tty.window_size(self.window_size.ok_or(ServerError::WindowSizeNotExist)?);
        self.tty = Some(tty.clone());
        Ok((tty, recv_from_tty))
    }
}
