use super::app::{self, Application};
use super::HandlerBackend;
use crate::database::models::{self, User};
use crate::error::Error;
use crate::server::casbin::ExtendPolicyReq;
use futures::future::FutureExt;
use log::{debug, info, trace, warn};
use russh::keys::ssh_key::PublicKey;
use russh::server as ru_server;
use russh::{Channel, ChannelId, Pty};
use std::sync::Arc;
use tokio::sync::mpsc::{channel, Receiver, Sender};

static LOG_TYPE: &str = "server";

pub struct BastionHandler<B: HandlerBackend + Send + Clone> {
    // Unique ID for each connection.
    id: String,
    pub(super) user: Option<User>,
    login_parse: Option<LoginParse>,
    client_ip: Option<std::net::SocketAddr>,
    app: Application,
    backend: Arc<B>,
    log: super::HandlerLog,
    auth_attempts_per_conn: u32,
    max_auth_attempts_per_conn: u32,
    send_app_msg: Sender<(ChannelId, Application)>,
    recv_app_msg: Receiver<(ChannelId, Application)>,
    //pty
    window_size: Option<(u32, u32, u32, u32)>,
    pty_modes: Option<Vec<(Pty, u32)>>,
    pty_term: Option<String>,
}

impl<B: 'static + HandlerBackend + Send + Sync> ru_server::Handler for BastionHandler<B> {
    type Error = crate::error::Error;
    type Data = (ChannelId, Application);

    async fn channel_open_session(
        &mut self,
        channel: Channel<ru_server::Msg>,
        session: &mut ru_server::Session,
    ) -> Result<bool, Self::Error> {
        match self.app {
            Application::None => {
                if !self.init_session().await? {
                    return Ok(false);
                }

                let user = if let Some(u) = self.user.as_ref() {
                    u
                } else {
                    return Ok(false);
                };

                let login_parse = if let Some(l) = self.login_parse.as_ref() {
                    l
                } else {
                    return Ok(false);
                };

                if user.force_init_pass {
                    let app = Box::new(app::ChangePassword::new(
                        self.id.clone(),
                        self.user.take(),
                        self.log.clone(),
                    ));
                    self.app = Application::ChangePassword(app);
                    return Ok(true);
                }
                match login_parse.parse_mode() {
                    LoginMode::TargetSelector => {
                        let mut app = Box::new(app::TargetSelector::new(
                            self.id.clone(),
                            self.user.take(),
                            self.log.clone(),
                        ));
                        let res = app
                            .channel_open_session(self.backend.clone(), channel, session)
                            .await?;
                        self.app = Application::TargetSelector(app);
                        Ok(res)
                    }
                    LoginMode::Password => {
                        let app = Box::new(app::ChangePassword::new(
                            self.id.clone(),
                            self.user.take(),
                            self.log.clone(),
                        ));
                        self.app = Application::ChangePassword(app);
                        Ok(true)
                    }
                    LoginMode::Admin => {
                        let mut app = Box::new(app::Admin::new(
                            self.id.clone(),
                            self.user.take(),
                            self.log.clone(),
                        ));
                        let res = app
                            .channel_open_session(
                                self.backend.clone(),
                                channel,
                                session,
                                self.client_ip.map(|v| v.ip()),
                            )
                            .await?;
                        self.app = Application::Admin(app);
                        Ok(res)
                    }
                    LoginMode::TargetWithUser(user, target) => {
                        let mut app = Box::new(app::ConnectTarget::new(
                            self.id.clone(),
                            self.user.take(),
                            self.log.clone(),
                        ));
                        let res = app
                            .init_target(self.backend.clone(), &user, &target)
                            .await?;
                        self.app = Application::ConnectTarget(app);
                        Ok(res)
                    }
                    LoginMode::Target(name) => {
                        let mut app = Box::new(app::TargetSelector::new(
                            self.id.clone(),
                            self.user.take(),
                            self.log.clone(),
                        ));
                        let res = app
                            .channel_open_with_target_name(
                                self.backend.clone(),
                                name,
                                channel,
                                session,
                            )
                            .await?;
                        self.app = Application::TargetSelector(app);
                        Ok(res)
                    }
                }
            }
            Application::ConnectTarget(_) => Ok(true),
            _ => {
                unreachable!()
            }
        }
    }

    async fn auth_password(
        &mut self,
        login_name: &str,
        password: &str,
    ) -> Result<ru_server::Auth, Self::Error> {
        self.init_login(login_name).await?;

        if self.max_auth_attempts(login_name).await {
            return Ok(ru_server::Auth::reject());
        }

        match self.user.as_ref() {
            Some(u) => {
                self.log = self.handler_log(u.id.clone());
                if !u.is_active {
                    return Ok(ru_server::Auth::reject());
                }
                if u.verify_password(password) {
                    self.backend
                        .clear_auth_attempts(
                            self.client_ip,
                            self.login_parse
                                .as_ref()
                                .unwrap_or_else(|| panic!("[{}] should not be none", self.id))
                                .0
                                .clone(),
                        )
                        .await;
                    (self.log)(LOG_TYPE.into(), "login successfully by password".into()).await;
                    return Ok(ru_server::Auth::Accept);
                }
            }
            None => {
                debug!("[{}] User {} doesn't exist", self.id, login_name);
                return Ok(ru_server::Auth::reject());
            }
        }
        Ok(ru_server::Auth::reject())
    }

    async fn auth_publickey(
        &mut self,
        login_name: &str,
        public_key: &PublicKey,
    ) -> Result<ru_server::Auth, Self::Error> {
        self.init_login(login_name).await?;

        if self.max_auth_attempts(login_name).await {
            return Ok(ru_server::Auth::reject());
        }

        match self.user.as_ref() {
            Some(u) => {
                self.log = self.handler_log(u.id.clone());
                if !u.is_active {
                    return Ok(ru_server::Auth::reject());
                }
                if u.verify_authorized_keys(public_key) {
                    self.backend
                        .clear_auth_attempts(
                            self.client_ip,
                            self.login_parse
                                .as_ref()
                                .unwrap_or_else(|| panic!("[{}] should not be none", self.id))
                                .0
                                .clone(),
                        )
                        .await;
                    (self.log)(LOG_TYPE.into(), "login successfully by public key".into()).await;
                    return Ok(ru_server::Auth::Accept);
                }
            }
            None => {
                debug!("[{}] User {} doesn't exist", self.id, login_name);
                return Ok(ru_server::Auth::reject());
            }
        }
        Ok(ru_server::Auth::reject())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut ru_server::Session,
    ) -> Result<(), Self::Error> {
        match self.app {
            Application::ConnectTarget(ref mut app) => app.channel_eof(channel, session).await,
            _ => {
                warn!("[{}] Unsupported eof request", self.id);
                session.channel_failure(channel)?;
                session.close(channel)?;
                Ok(())
            }
        }
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut ru_server::Session,
    ) -> Result<(), Self::Error> {
        match self.app {
            Application::ConnectTarget(ref mut app) => app.data(channel, data, session).await,
            Application::ChangePassword(ref mut app) => app.data(channel, data, session).await,
            Application::TargetSelector(ref mut app) => app.data(channel, data, session).await,
            Application::Admin(ref mut app) => app.data(channel, data, session).await,
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
        self.window_size = Some((col_width, row_height, pix_width, pix_height));
        match self.app {
            Application::ConnectTarget(ref mut app) => {
                app.window_change_request(
                    channel, col_width, row_height, pix_width, pix_height, session,
                )
                .await
            }
            Application::ChangePassword(ref mut app) => {
                app.window_change_request(
                    channel, col_width, row_height, pix_width, pix_height, session,
                )
                .await
            }
            Application::TargetSelector(ref mut app) => {
                app.window_change_request(
                    channel, col_width, row_height, pix_width, pix_height, session,
                )
                .await
            }
            Application::Admin(ref mut app) => {
                app.window_change_request(
                    channel, col_width, row_height, pix_width, pix_height, session,
                )
                .await
            }
            Application::None => Ok(()),
        }
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut ru_server::Session,
    ) -> Result<(), Self::Error> {
        match self.app {
            Application::ConnectTarget(ref mut app) => {
                if app
                    .check_permission(
                        self.backend.clone(),
                        models::Action::Exec,
                        self.client_ip.map(|v| v.ip()),
                    )
                    .await?
                {
                    return app
                        .exec_request(
                            self.backend.clone(),
                            channel,
                            data,
                            session,
                            self.pty_term.as_ref(),
                            self.window_size,
                            self.pty_modes.as_ref(),
                        )
                        .await;
                }
                session.channel_failure(channel)?;
                session.close(channel)?;
                Ok(())
            }
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
        session: &mut ru_server::Session,
    ) -> Result<bool, Self::Error> {
        match self.app {
            Application::ConnectTarget(ref mut app) => {
                if app
                    .check_permission(
                        self.backend.clone(),
                        models::Action::OpenDirectTcpip,
                        self.client_ip.map(|v| v.ip()),
                    )
                    .await?
                {
                    return app
                        .channel_open_direct_tcpip(
                            self.backend.clone(),
                            channel,
                            host_to_connect,
                            port_to_connect,
                            originator_address,
                            originator_port,
                            session,
                        )
                        .await;
                }
                Ok(false)
            }
            Application::None => {
                if !self.init_session().await? {
                    return Ok(false);
                }

                let user = if let Some(u) = self.user.as_ref() {
                    u
                } else {
                    return Ok(false);
                };

                if user.force_init_pass {
                    return Ok(false);
                }

                let login_parse = if let Some(l) = self.login_parse.as_ref() {
                    l
                } else {
                    return Ok(false);
                };
                match login_parse.parse_mode() {
                    LoginMode::TargetWithUser(user, target) => {
                        let mut app = Box::new(app::ConnectTarget::new(
                            self.id.clone(),
                            self.user.take(),
                            self.log.clone(),
                        ));
                        if !app
                            .init_target(self.backend.clone(), &user, &target)
                            .await?
                        {
                            return Ok(false);
                        }
                        if app
                            .check_permission(
                                self.backend.clone(),
                                models::Action::OpenDirectTcpip,
                                self.client_ip.map(|v| v.ip()),
                            )
                            .await?
                            && app
                                .channel_open_direct_tcpip(
                                    self.backend.clone(),
                                    channel,
                                    host_to_connect,
                                    port_to_connect,
                                    originator_address,
                                    originator_port,
                                    session,
                                )
                                .await?
                        {
                            self.app = Application::ConnectTarget(app);
                            return Ok(true);
                        }
                        Ok(false)
                    }
                    _ => Ok(false),
                }
            }
            _ => {
                warn!("[{}] Unsupported open_direct_tcpip request", self.id);
                Ok(false)
            }
        }
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
        match self.app {
            Application::ConnectTarget(ref mut app) => {
                if !app
                    .check_permission(
                        self.backend.clone(),
                        models::Action::Pty,
                        self.client_ip.map(|v| v.ip()),
                    )
                    .await?
                {
                    session.channel_failure(channel)?;
                    session.close(channel)?;
                    return Ok(());
                }
            }
            Application::Admin(ref mut app) => {
                app.pty_request(
                    channel, term, col_width, row_height, pix_width, pix_height, modes, session,
                )
                .await?;
            }
            Application::ChangePassword(ref mut app) => {
                app.pty_request(
                    channel, term, col_width, row_height, pix_width, pix_height, modes, session,
                )
                .await?;
            }
            _ => {}
        }
        self.pty_modes = Some(Vec::from(modes));
        self.pty_term = Some(term.to_string());
        self.window_size = Some((col_width, row_height, pix_width, pix_height));
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut ru_server::Session,
    ) -> Result<(), Self::Error> {
        if self.pty_term.is_none() || self.pty_modes.is_none() || self.window_size.is_none() {
            warn!(
                "[{}] user doesn't request pty before request shell",
                self.id
            );
            session.channel_failure(channel)?;
            session.close(channel)?;
            return Ok(());
        }

        match self.app {
            Application::TargetSelector(ref mut app) => {
                app.shell_request(
                    self.backend.clone(),
                    channel,
                    session,
                    self.send_app_msg.clone(),
                    self.window_size
                        .unwrap_or_else(|| panic!("[{}] window_size should not be none", self.id)),
                )
                .await
            }
            Application::ConnectTarget(ref mut app) => {
                if app
                    .check_permission(
                        self.backend.clone(),
                        models::Action::Shell,
                        self.client_ip.map(|v| v.ip()),
                    )
                    .await?
                {
                    return app
                        .shell_request(
                            self.backend.clone(),
                            channel,
                            session,
                            self.pty_term.as_ref().unwrap_or_else(|| {
                                panic!("[{}] pty_term should not be none", self.id)
                            }),
                            self.window_size.unwrap_or_else(|| {
                                panic!("[{}] window_size should not be none", self.id)
                            }),
                            self.pty_modes.as_ref().unwrap_or_else(|| {
                                panic!("[{}] pty_modes should not be none", self.id)
                            }),
                        )
                        .await;
                }
                session.channel_failure(channel)?;
                session.close(channel)?;
                Ok(())
            }
            Application::ChangePassword(ref mut app) => {
                app.shell_request(self.backend.clone(), channel, session)
                    .await
            }
            Application::Admin(ref mut app) => {
                app.shell_request(self.backend.clone(), channel, session)
                    .await
            }
            Application::None => Ok(()),
        }
    }

    async fn trigger(&mut self) -> Result<Self::Data, Self::Error> {
        match self.recv_app_msg.recv().await {
            Some(d) => Ok(d),
            None => std::future::pending().await,
        }
    }

    async fn process(
        &mut self,
        data: Self::Data,
        session: &mut ru_server::Session,
    ) -> Result<(), Self::Error> {
        self.app = data.1;
        match self.app {
            Application::ConnectTarget(ref mut app) => {
                if app
                    .check_permission(
                        self.backend.clone(),
                        models::Action::Pty,
                        self.client_ip.map(|v| v.ip()),
                    )
                    .await?
                    && app
                        .check_permission(
                            self.backend.clone(),
                            models::Action::Shell,
                            self.client_ip.map(|v| v.ip()),
                        )
                        .await?
                {
                    app.shell_request(
                        self.backend.clone(),
                        data.0,
                        session,
                        self.pty_term
                            .as_ref()
                            .unwrap_or_else(|| panic!("[{}] pty_term should not be none", self.id)),
                        self.window_size.unwrap_or_else(|| {
                            panic!("[{}] window_size should not be none", self.id)
                        }),
                        self.pty_modes.as_ref().unwrap_or_else(|| {
                            panic!("[{}] pty_modes should not be none", self.id)
                        }),
                    )
                    .await?;
                } else {
                    session.close(data.0)?
                }
            }
            Application::None => {}
            Application::TargetSelector(_) => {}
            _ => {}
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
        let uuid = uuid::Uuid::new_v4().to_string();
        trace!("[{}] create new handler", uuid);
        let uuid_log = uuid.clone();
        let log = Arc::new(move |_, _| {
            let uuid = uuid_log.clone();
            async move {
                warn!("[{}] handler log hasn't initialized", uuid);
            }
            .boxed()
        });
        BastionHandler {
            id: uuid.clone(),
            user: None,
            login_parse: None,
            client_ip,
            app: Application::None,
            backend,
            log,
            auth_attempts_per_conn: 0,
            max_auth_attempts_per_conn,
            send_app_msg,
            recv_app_msg,
            pty_modes: None,
            pty_term: None,
            window_size: None,
        }
    }

    fn handler_log(&self, user_id: String) -> super::HandlerLog {
        let cid = self.id.clone();
        let backend = self.backend.clone();

        Arc::new(move |log_type: String, detail: String| {
            let cid = cid.clone();
            let uid = user_id.clone();
            let backend = backend.clone();
            async move {
                backend.insert_log(cid, uid, log_type, detail).await;
            }
            .boxed()
        })
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
            None => Err(Error::Handler("invalid login name".into())),
        }
    }

    async fn init_session(&self) -> Result<bool, Error> {
        let user = if let Some(u) = self.user.as_ref() {
            u
        } else {
            return Ok(false);
        };

        if !self
            .backend
            .enforce(
                &user.id,
                crate::database::common::OBJ_LOGIN,
                models::Action::Login,
                ExtendPolicyReq::new(self.client_ip.map(|v| v.ip())),
            )
            .await?
        {
            debug!(
                "[{}] User: {} has no permission to login",
                self.id, user.username
            );
            return Ok(false);
        };
        Ok(true)
    }

    async fn get_user(&mut self, name: &str) -> Result<(), Error> {
        if self.user.is_none() {
            self.user = self.backend.get_user_by_username(name, true).await?
        }
        Ok(())
    }

    async fn max_auth_attempts(&mut self, login_name: &str) -> bool {
        if self
            .backend
            .reject_auth_attempts(
                self.client_ip,
                self.login_parse
                    .as_ref()
                    .unwrap_or_else(|| panic!("[{}] should not be none", self.id))
                    .0
                    .clone(),
            )
            .await
        {
            return true;
        }
        self.auth_attempts_per_conn += 1;

        if self.auth_attempts_per_conn > self.max_auth_attempts_per_conn {
            warn!(
                "[{}] Client {:?} exceeded max authentication attempts ({})",
                self.id, self.client_ip, self.max_auth_attempts_per_conn
            );
            return true;
        }

        info!(
            "[{}] Authentication attempt {} for user '{}' from {:?}",
            self.id, self.auth_attempts_per_conn, login_name, self.client_ip
        );

        false
    }
}

impl<B: HandlerBackend + Send + Clone> Drop for BastionHandler<B> {
    fn drop(&mut self) {
        let log = self.log.clone();
        tokio::spawn(async move {
            log(LOG_TYPE.into(), "logout".into()).await;
        });
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
                "admin" => return LoginMode::Admin,
                _ => return LoginMode::Target(self.1.clone()),
            }
        }
        LoginMode::TargetSelector
    }
}
