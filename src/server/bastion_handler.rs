use super::HandlerBackend;
use super::app::{self, Application, NextApplication};
use super::error::ServerError;
use super::event_log::{Audit, EventKind, EventLogger};
use super::tty;
use crate::database::Uuid;
use crate::database::models::User;
use crate::error::Error;
use crate::i18n::Lang;
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
        // Not kept: russh queues every message for `channel` before calling the
        // handler, and a full queue nobody reads stops the whole connection.
        // Every app, sftp included, is fed through the callbacks instead.
        drop(channel);
        let mut channel_session = ChannelSession::new();
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
            log.record(Audit::LoginPassword).await;
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
            log.record(Audit::LoginPublicKey).await;
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
            // End the proxy's input. It reads EOF, writes its last reply, and
            // closes the channel when it drops its stream. Closing here would
            // cut those replies off.
            Application::Sftp => {
                channel_session.sender = None;
                Ok(())
            }
            // An interactive app is still writing. EOF says the client will send
            // no more input — it does not say the app has finished its output,
            // and Ctrl+C arrives as EOF. Closing here discarded whatever the
            // prompt wrote on its way out: inquire's teardown comes from `Drop`,
            // which only buffers the bytes.
            //
            // So end the input instead. These are the last `send_to_tty` and
            // exec `Sender` clones — each app drops its own copy on the way in
            // (`let (tty, _) = tty.split()`) — so dropping them makes the app's
            // reader see end-of-input. Each app then runs its normal terminate
            // path, which drains the pending output before closing the channel.
            Application::TargetSelector
            | Application::Admin
            | Application::Password
            | Application::Player => {
                debug!("[{}] Client sent eof; ending input on {}", self.id, channel);
                channel_session.tty = None;
                channel_session.sender = None;
                Ok(())
            }
            // No app is running, so nothing else would ever close the channel.
            Application::None => {
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
            // A full queue holds the session loop here until the proxy reads,
            // exactly as russh's own channel queue did. Bytes after the proxy
            // has gone are dropped: the channel is closing.
            Application::Sftp => {
                if let Some(input) = channel_session.sender.as_ref()
                    && input.send(Bytes::copy_from_slice(data)).await.is_err()
                {
                    channel_session.sender = None;
                }
                Ok(())
            }
            Application::None => Ok(()),
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
                    let lang = channel_session.lang(self.backend.language());
                    let (tty, recv_from_tty) = channel_session.new_tty()?;
                    let app_params = self.wrap_pty_parameters(tty, recv_from_tty, lang)?;
                    app::admin::exec_request_with_pty(app_params, channel, data, session).await?;
                    session.channel_failure(channel)?;
                    Ok(())
                }
                _ => {
                    let lang = channel_session.lang(self.backend.language());
                    let (tx, rx) = mpsc::channel(16);
                    channel_session.sender = Some(tx);
                    let params = self.wrap_exec_parameters(rx, lang)?;
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
        let mut channel_session = ChannelSession::new();
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

    /// Only `sftp`, and only on a direct target connection. The gate is checked
    /// before anything is opened on the target, and the proxy is wired to the
    /// client only once the target session is up, so every failure before that
    /// is a plain failed request on a channel no app is using yet.
    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut ru_server::Session,
    ) -> Result<(), Self::Error> {
        let channel_session = self
            .channel_session
            .get_mut(&channel_id)
            .ok_or(ServerError::ChannelNotExist)?;
        let Application::ConnectTarget(ref mut app) = channel_session.app else {
            warn!(
                "[{}] Subsystem '{}' outside a target connection",
                self.id, name
            );
            return refuse(session, channel_id);
        };
        if name != "sftp" {
            warn!("[{}] Unsupported subsystem '{}'", self.id, name);
            return refuse(session, channel_id);
        }

        let ctx = app.sftp_context(crate::database::common::InternalUuids::get().sftp);
        if !ctx.allow_session().await {
            debug!("[{}] sftp denied on {}", self.id, ctx.label);
            ctx.log
                .record(Audit::SftpRefused {
                    target: ctx.label.clone(),
                })
                .await;
            return refuse(session, channel_id);
        }

        let target_channel = match app.request_subsystem(name).await {
            Ok(true) => app.take_target_channel(),
            Ok(false) => None,
            Err(e) => {
                debug!("[{}] sftp target subsystem request failed: {}", self.id, e);
                None
            }
        };
        let Some(target_channel) = target_channel else {
            return refuse(session, channel_id);
        };
        let proxy = match app::sftp::SftpProxy::connect(ctx, target_channel.into_stream()).await {
            Ok(p) => p,
            Err(e) => {
                warn!("[{}] sftp session with target failed: {}", self.id, e);
                return refuse(session, channel_id);
            }
        };
        let (input, client) = app::sftp::client::stream(
            session.handle(),
            channel_id,
            session.config().channel_buffer_size,
        );
        channel_session.sender = Some(input);
        channel_session.app = Application::Sftp;
        session.channel_success(channel_id)?;
        proxy.serve(client).await;
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

    /// Only the locale is kept, to pick the interface language; the rest is
    /// refused, as OpenSSH's `sshd` refuses what `AcceptEnv` does not list.
    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut ru_server::Session,
    ) -> Result<(), Self::Error> {
        let channel_session = self
            .channel_session
            .get_mut(&channel)
            .ok_or(ServerError::ChannelNotExist)?;
        if !LOCALE_VARS.contains(&variable_name) {
            session.channel_failure(channel)?;
            return Ok(());
        }
        let value: String = variable_value.chars().take(LOCALE_MAX).collect();
        let locale = &mut channel_session.locale;
        locale.retain(|(k, _)| k != variable_name);
        locale.push((variable_name.to_string(), value));
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
                let lang = channel_session.lang(self.backend.language());
                let (tty, recv_from_tty) = channel_session.new_tty()?;
                let app_params = self.wrap_pty_parameters(tty, recv_from_tty, lang)?;
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
                let lang = channel_session.lang(self.backend.language());
                let (tty, recv_from_tty) = channel_session.new_tty()?;
                let app_params = self.wrap_pty_parameters(tty, recv_from_tty, lang)?;
                app::admin::shell_request(app_params, channel, session).await?;
                session.channel_success(channel)?;
                Ok(())
            }
            Application::Password => {
                let lang = channel_session.lang(self.backend.language());
                let (tty, recv_from_tty) = channel_session.new_tty()?;
                let app_params = self.wrap_pty_parameters(tty, recv_from_tty, lang)?;
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
                let lang = channel_session.lang(self.backend.language());
                let (tty, recv_from_tty) = channel_session.new_tty()?;
                let app_params = self.wrap_pty_parameters(tty, recv_from_tty, lang)?;
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

    fn wrap_exec_parameters(
        &self,
        recv: Receiver<Bytes>,
        lang: Lang,
    ) -> Result<ExecParams<B>, Error> {
        Ok(ExecParams {
            lang,
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
        lang: Lang,
    ) -> Result<PtyParams<B>, Error> {
        Ok(PtyParams {
            lang,
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
                log.record(Audit::Logout).await;
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
    // shell request
    pub tty: Option<tty::Tty>,
    // exec request, or the sftp proxy's input
    pub sender: Option<Sender<Bytes>>,
    // pty
    pub window_size: Option<(u32, u32, u32, u32)>,
    pub pty_modes: Option<Vec<(Pty, u32)>>,
    pub pty_term: Option<String>,
    /// The client's `LC_ALL`, `LC_MESSAGES` and `LANG`, from env requests:
    /// the language of the interface. Nothing else the client sends is kept.
    pub locale: Vec<(String, String)>,
}

impl<B: 'static + HandlerBackend + Send + Sync> ChannelSession<B> {
    pub fn new() -> Self {
        Self {
            app: Application::default(),
            tty: None,
            sender: None,
            window_size: None,
            pty_modes: None,
            pty_term: None,
            locale: Vec::new(),
        }
    }

    /// The language the client's locale asks for, or `default`.
    fn lang(&self, default: Lang) -> Lang {
        Lang::from_env(|name| {
            self.locale
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        })
        .unwrap_or(default)
    }

    fn new_tty(&mut self) -> Result<(tty::Tty, Receiver<Bytes>), Error> {
        let (mut tty, recv_from_tty) = tty::Tty::new();
        tty.window_size(self.window_size.ok_or(ServerError::WindowSizeNotExist)?);
        self.tty = Some(tty.clone());
        Ok((tty, recv_from_tty))
    }
}

/// The environment a client may set: the variables that pick its language.
const LOCALE_VARS: [&str; 3] = ["LC_ALL", "LC_MESSAGES", "LANG"];
/// A locale name is short; anything longer is cut before it is kept.
const LOCALE_MAX: usize = 64;

/// Answer a subsystem request the bastion will not serve, and end the channel.
fn refuse(session: &mut ru_server::Session, channel: ChannelId) -> Result<(), Error> {
    session.channel_failure(channel)?;
    session.close(channel)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::config::Config;
    use crate::database::Uuid;
    use crate::database::common::{InternalUuids, OBJ_LOGIN};
    use crate::database::entity::{casbin_name, casbin_rule};
    use crate::database::fixture::{self, LUKA, PASSWORD};
    use crate::database::models::{NamePtype, Ptype};
    use crate::server::{BastionServer, HandlerBackend};
    use russh::keys::{Algorithm, PrivateKey, PublicKeyOrCertificate};
    use russh::{ChannelMsg, client as ru_client, server as ru_server};
    use sea_orm::ActiveValue::Set;
    use std::sync::Arc;
    use std::time::Duration;

    struct AnyHostKey;

    impl ru_client::Handler for AnyHostKey {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            _: &PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    /// Let `user` log in under the process-wide `InternalUuids`, which belong to
    /// whichever server in the test binary was built first and so need not be
    /// this database's.
    async fn grant_login(server: &BastionServer, f: &fixture::Fixture, user: Uuid) {
        let ids = InternalUuids::get();
        let repo = server.db_repository();
        if ids.obj_login != f.name(OBJ_LOGIN) {
            repo.create_casbin_name(casbin_name::ActiveModel {
                id: Set(ids.obj_login),
                ptype: Set(NamePtype::InternalObjectType),
                name: Set(format!("login-{}", ids.obj_login)),
                is_active: Set(true),
                updated_by: Set(f.admin_id),
                ..Default::default()
            })
            .await
            .expect("insert login object");
        }
        repo.create_casbin_rule(casbin_rule::ActiveModel {
            id: Set(Uuid::now_v7()),
            ptype: Set(Ptype::Policy),
            v0: Set(user),
            v1: Set(ids.obj_login),
            v2: Set(ids.act_login),
            v3: Set("{}".to_string()),
            v4: Set(String::new()),
            v5: Set(String::new()),
            updated_by: Set(f.admin_id),
            ..Default::default()
        })
        .await
        .expect("insert login policy");
    }

    /// russh queues every channel message for the `Channel` handed to
    /// `channel_open_session` before it calls the handler, in a queue of
    /// `channel_buffer_size` (100). A handler that kept that `Channel` without
    /// reading it froze the whole connection on the 101st message. `env` is the
    /// cheapest message to send that needs no app behind it.
    #[tokio::test]
    async fn an_unread_session_channel_cannot_wedge_the_connection() {
        let db = fixture::seed().await;
        let mut config = Config::default().gen_secret_token();
        config.database = db.url.clone();
        let mut server = BastionServer::with_config(config).await.expect("server");
        grant_login(&server, &db.fixture, db.fixture.user(LUKA)).await;

        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("host key");
        let server_config = Arc::new(ru_server::Config {
            keys: vec![key],
            ..Default::default()
        });
        let handler = ru_server::Server::new_client(&mut server, None);
        let (server_io, client_io) = tokio::io::duplex(1 << 20);
        let mut running = tokio::spawn(async move {
            ru_server::run_stream(server_config, server_io, handler)
                .await?
                .await
        });

        let flow = async {
            let mut client = ru_client::connect_stream(
                Arc::new(ru_client::Config::default()),
                client_io,
                AnyHostKey,
            )
            .await
            .expect("connect");
            let auth = client
                .authenticate_password(LUKA, PASSWORD)
                .await
                .expect("authenticate");
            assert!(auth.success(), "fixture password rejected");
            let mut channel = match client.channel_open_session().await {
                Ok(c) => c,
                Err(e) => panic!("open session: {e:?}; server: {:?}", (&mut running).await),
            };

            for i in 0..150 {
                channel
                    .set_env(false, format!("V{i}"), "x")
                    .await
                    .expect("send env");
            }
            channel
                .request_pty(true, "xterm", 80, 24, 0, 0, &[])
                .await
                .expect("send pty-req");
            loop {
                match channel.wait().await {
                    Some(ChannelMsg::Success) => break,
                    Some(ChannelMsg::Failure) | None => panic!("pty-req refused"),
                    Some(_) => {}
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(10), flow)
            .await
            .expect("the connection stopped answering after 150 channel requests");
        running.abort();
    }

    /// Only the locale variables are kept, and they decide the language; the
    /// rest of the environment is refused, as `sshd` refuses what `AcceptEnv`
    /// does not list.
    #[tokio::test]
    async fn the_client_locale_is_kept_and_the_rest_of_its_environment_refused() {
        let db = fixture::seed().await;
        let mut config = Config::default().gen_secret_token();
        config.database = db.url.clone();
        let mut server = BastionServer::with_config(config).await.expect("server");
        grant_login(&server, &db.fixture, db.fixture.user(LUKA)).await;

        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("host key");
        let server_config = Arc::new(ru_server::Config {
            keys: vec![key],
            ..Default::default()
        });
        let handler = ru_server::Server::new_client(&mut server, None);
        let (server_io, client_io) = tokio::io::duplex(1 << 20);
        let running = tokio::spawn(async move {
            ru_server::run_stream(server_config, server_io, handler)
                .await?
                .await
        });

        let flow = async {
            let mut client = ru_client::connect_stream(
                Arc::new(ru_client::Config::default()),
                client_io,
                AnyHostKey,
            )
            .await
            .expect("connect");
            let auth = client
                .authenticate_password(LUKA, PASSWORD)
                .await
                .expect("authenticate");
            assert!(auth.success(), "fixture password rejected");
            let mut channel = client.channel_open_session().await.expect("open session");
            let mut answer = async |name: &str, value: &str| {
                channel.set_env(true, name, value).await.expect("send env");
                loop {
                    match channel.wait().await {
                        Some(ChannelMsg::Success) => return true,
                        Some(ChannelMsg::Failure) => return false,
                        None => panic!("channel closed"),
                        Some(_) => {}
                    }
                }
            };
            assert!(answer("LANG", "ja_JP.UTF-8").await);
            assert!(answer("LC_ALL", "C.UTF-8").await);
            assert!(!answer("PATH", "/tmp/evil").await);
            assert!(!answer("LD_PRELOAD", "/tmp/evil.so").await);
        };
        tokio::time::timeout(Duration::from_secs(10), flow)
            .await
            .expect("env requests went unanswered");
        running.abort();
    }

    #[test]
    fn a_session_speaks_the_language_its_locale_names() {
        use super::ChannelSession;
        use crate::i18n::Lang;
        let mut session = ChannelSession::<BastionServer>::new();
        assert_eq!(
            session.lang(Lang::Fr),
            Lang::Fr,
            "no locale: the configured one"
        );
        session.locale.push(("LANG".into(), "zh_TW.UTF-8".into()));
        assert_eq!(session.lang(Lang::Fr), Lang::ZhHant);
        // `C` names no language, so `LANG` behind it still counts.
        session.locale.push(("LC_ALL".into(), "C".into()));
        assert_eq!(session.lang(Lang::Fr), Lang::ZhHant);
        session.locale.push(("LC_MESSAGES".into(), "es_ES".into()));
        assert_eq!(session.lang(Lang::Fr), Lang::Es);
    }
}
