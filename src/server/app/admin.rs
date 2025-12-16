use crate::database::models::{Action, User};
use crate::error::Error;
use crate::server::HandlerLog;
use crate::server::{casbin, common as srv_common};

use crossbeam_channel::{unbounded, Receiver, Sender};
use crossterm::event::NoTtyEvent;
use log::{debug, trace, warn};
use tokio::sync::mpsc;

use russh::server as ru_server;
use russh::{Channel, ChannelId, Pty};

use std::sync::Arc;

mod common;
mod database;
mod manage;
mod shell;
mod widgets;

const LOG_TYPE: &str = "admin";

pub(crate) struct Admin {
    handler_id: String,
    user: Option<User>,

    // shell
    tty: Option<NoTtyEvent>,
    send_to_tty: Option<Sender<Vec<u8>>>,
    recv_from_tty: Option<Receiver<Vec<u8>>>,

    log: HandlerLog,
}

impl Admin {
    pub(crate) fn new(handler_id: String, user: Option<User>, log: HandlerLog) -> Self {
        Self {
            handler_id,
            user,
            tty: None,
            send_to_tty: None,
            recv_from_tty: None,
            log,
        }
    }

    pub(crate) async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut ru_server::Session,
    ) -> Result<(), Error> {
        if let Some(sender) = self.send_to_tty.as_ref() {
            sender.send(data.into()).map_err(std::io::Error::other)?;
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn pty_request(
        &mut self,
        _channel: ChannelId,
        _term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _modes: &[(Pty, u32)],
        _session: &mut ru_server::Session,
    ) -> Result<(), Error> {
        let (send_to_tty, recv_from_session) = unbounded();
        let (mut tty, recv_from_tty) = NoTtyEvent::new(recv_from_session);
        let _ =
            crate::terminal::window_change(&mut tty, col_width, row_height, pix_width, pix_height);

        self.tty = Some(tty);
        self.send_to_tty = Some(send_to_tty);
        self.recv_from_tty = Some(recv_from_tty);

        Ok(())
    }

    pub(crate) async fn channel_open_session<
        B: 'static + crate::server::HandlerBackend + Send + Sync,
    >(
        &mut self,
        backend: Arc<B>,
        _channel: Channel<ru_server::Msg>,
        _session: &mut ru_server::Session,
        ip: Option<std::net::IpAddr>,
    ) -> Result<bool, Error> {
        if !self
            .check_permission(backend, srv_common::OBJ_ADMIN, Action::Login, ip)
            .await?
        {
            debug!(
                "[{}] User: {} doesn't have permission to access admin",
                self.handler_id,
                self.user
                    .as_ref()
                    .unwrap_or_else(|| panic!("[{}] user should not be none", self.handler_id))
                    .username
            );
            return Ok(false);
        };

        Ok(true)
    }

    pub async fn check_permission<B>(
        &mut self,
        backend: Arc<B>,
        object: &str,
        action: Action,
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

        backend
            .enforce(&user.id, object, action, casbin::ExtendPolicyReq::new(ip))
            .await
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
        if let Some(tty) = self.tty.as_mut() {
            let win_raw =
                crate::terminal::window_change(tty, col_width, row_height, pix_width, pix_height);
            if let Some(sender) = self.send_to_tty.as_ref() {
                sender.send(win_raw).map_err(std::io::Error::other)?;
            }
            session.channel_success(channel)?;
        }

        session.channel_failure(channel)?;

        Ok(())
    }

    pub(crate) async fn shell_request<B>(
        &mut self,
        backend: Arc<B>,
        channel: ChannelId,
        session: &mut ru_server::Session,
    ) -> Result<(), Error>
    where
        B: 'static + crate::server::HandlerBackend + Send + Sync,
    {
        let user = self
            .user
            .take()
            .unwrap_or_else(|| panic!("[{}] user should not be none", self.handler_id));
        let username = user.username.clone();
        let user_id = user.id.clone();
        let handle_session = session.handle();
        let (send_to_session, mut recv_from_shell) = mpsc::channel::<Vec<u8>>(1);
        let (send_status, mut recv_status) = mpsc::channel(1);
        let send_to_session_from_tty = send_to_session.clone();
        let handler_id = self.handler_id.clone();

        let tty = if let Some(tty) = self.tty.clone() {
            tty
        } else {
            session.request_failure();
            return Ok(());
        };

        let recv_from_tty = if let Some(recv) = self.recv_from_tty.clone() {
            recv
        } else {
            session.request_failure();
            return Ok(());
        };

        tokio::task::spawn_blocking(move || {
            while let Ok(data) = recv_from_tty.recv() {
                if send_to_session_from_tty.blocking_send(data).is_err() {
                    debug!("[{}] Fail to send data to session from tty", handler_id);
                    break;
                }
            }
        });

        let handler_id = self.handler_id.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    data = recv_from_shell.recv() => {
                        if let Some(d) = data {
                            if handle_session.data(channel, d.into()).await.is_err() {
                                warn!("[{}] Fail to send data to session from prompt",handler_id);
                                break;
                            }
                        };
                    }
                    status = recv_status.recv() => {
                        if let Some(Status::Terminate(exit)) = status {
                            let _ = handle_session.exit_status_request(channel, exit).await;
                            let _ = handle_session.close(channel).await;
                            break;
                        }
                    }
                }
            }
        });

        let handler_id = self.handler_id.clone();
        let tokio_handle = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            shell::shell(
                tty,
                send_to_session,
                send_status,
                user_id,
                handler_id,
                backend,
                tokio_handle,
            )
        });

        session.channel_success(channel)?;
        (self.log)(
            LOG_TYPE.into(),
            format!("User: {} login to admin system", username),
        )
        .await;
        Ok(())
    }
}

impl Drop for Admin {
    fn drop(&mut self) {
        trace!("[{}] drop Admin", self.handler_id);
    }
}

pub enum Status {
    Terminate(u32),
}
