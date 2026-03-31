use crate::database::common as db_common;
use crate::database::models::{RecordingView, User};
use crate::error::Error;
use crate::server::casbin;
use crate::server::widgets::{AdminTable, Message};
use crate::server::HandlerLog;
use crossterm::event::{NoTtyEvent, SenderWriter};
use ratatui::backend::NottyBackend;
use ratatui::{Frame, Terminal};
use std::io::Write;
use tokio::runtime::Handle;

use crate::database::Uuid;
use crossbeam_channel::{unbounded, Receiver, Sender};
use log::{debug, trace, warn};
use ratatui::style::palette::tailwind;
use tokio::sync::mpsc;

use russh::server as ru_server;
use russh::{Channel, ChannelId, Pty};

use std::sync::Arc;

const LOG_TYPE: &str = "record_play";
const HELP_TEXT: [&str; 2] = [
    "(Enter) play | (d) delete | (Esc) quit | (↑↓←→) move around",
    "(+/-) zoom in/out | (PgUp/PgDn) page up/down",
];

pub(crate) struct RecordPlay {
    handler_id: Uuid,
    user: Option<User>,

    // shell
    tty: Option<NoTtyEvent>,
    send_to_tty: Option<Sender<Vec<u8>>>,
    recv_from_tty: Option<Receiver<Vec<u8>>>,

    log: HandlerLog,
}

impl RecordPlay {
    pub(crate) fn new(handler_id: Uuid, user: Option<User>, log: HandlerLog) -> Self {
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
        let uuids = db_common::InternalUuids::get();
        if !self
            .check_permission(backend, uuids.obj_record_play, uuids.act_login, ip)
            .await?
        {
            debug!(
                "[{}] User: {} doesn't have permission to access record_play",
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
        object: Uuid,
        action: Uuid,
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
            .enforce(user.id, object, action, casbin::ExtendPolicyReq::new(ip))
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
        let user_id = user.id;
        let handle_session = session.handle();
        let (send_to_session, mut recv_from_shell) = mpsc::channel::<Vec<u8>>(1);
        let (send_status, mut recv_status) = mpsc::channel(1);
        let send_to_session_from_tty = send_to_session.clone();
        let handler_id = self.handler_id;

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

        let handler_id = self.handler_id;
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    data = recv_from_shell.recv() => {
                        if let Some(d) = data {
                            if handle_session.data(channel, d).await.is_err() {
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

        let handler_id = self.handler_id;
        let tokio_handle = tokio::runtime::Handle::current();
        let app = App::new(backend, tokio_handle, handler_id, user_id);
        let w = SenderWriter::new(send_to_session.clone());
        let tty_backend = NottyBackend::new(tty.clone(), w);
        let mut terminal = Terminal::new(tty_backend)?;
        terminal.hide_cursor()?;
        terminal.flush()?;
        tokio::task::spawn_blocking(move || app.run(tty, &mut terminal));

        session.channel_success(channel)?;
        (self.log)(
            LOG_TYPE.into(),
            format!("User: {} login to record_play", username),
        )
        .await;
        Ok(())
    }
}

impl Drop for RecordPlay {
    fn drop(&mut self) {
        trace!("[{}] drop RecordPlay", self.handler_id);
    }
}

pub enum Status {
    Terminate(u32),
}

struct App<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    table: AdminTable,
    items: Vec<RecordingView>,
    backend: Arc<B>,
    t_handle: Handle,
    handler_id: Uuid,
    user_id: Uuid,
    message: Option<Message>,
    pub help_text: [&'static str; 2],
}

impl<B> App<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    fn new(backend: Arc<B>, t_handle: Handle, handler_id: Uuid, user_id: Uuid) -> Self {
        let mut message = None;
        let items = match t_handle.block_on(
            backend
                .db_repository()
                .list_recording_view_for_user(&user_id),
        ) {
            Ok(items) => items,
            Err(e) => {
                warn!(
                    "[{}] List recording view for user: ({}) failed: {}",
                    handler_id, user_id, e
                );
                message = Some(Message::Error(vec!["Internal error".into()]));
                Vec::new()
            }
        };

        App {
            table: AdminTable::new(&items, &tailwind::BLUE),
            items,
            backend,
            t_handle,
            handler_id,
            user_id,
            message,
            help_text: HELP_TEXT,
        }
    }
    fn run<W: Write>(&self, tty: NoTtyEvent, terminal: &mut Terminal<NottyBackend<W>>) {}

    fn render(&mut self, frame: &mut Frame) {}
}
