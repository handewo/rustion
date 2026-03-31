use crate::database::common as db_common;
use crate::database::models::{RecordingView, User};
use crate::error::Error;
use crate::server::casbin;
use crate::server::widgets::{
    common::DATETIME_LENGTH, render_message_popup, AdminTable, DisplayMode, Message,
};
use crate::server::HandlerLog;
use crossterm::event::{self, KeyCode, KeyModifiers, NoTtyEvent, SenderWriter};
use ratatui::backend::NottyBackend;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{palette::tailwind, Style};
use ratatui::text::Text;
use ratatui::widgets::{Block, BorderType, Paragraph};
use ratatui::{Frame, Terminal};
use std::io::Write;
use tokio::runtime::Handle;
use unicode_width::UnicodeWidthStr;

use crate::database::Uuid;
use crossbeam_channel::{unbounded, Receiver, Sender};
use log::{debug, trace, warn};
use tokio::sync::mpsc;

use russh::server as ru_server;
use russh::{Channel, ChannelId, Pty};

use std::sync::Arc;

const LOG_TYPE: &str = "tape";
const HELP_TEXT: [&str; 2] = [
    "(Enter) play | (Esc) quit | (↑↓) select",
    "(+/-) zoom in/out | (PgUp/PgDn) page up/down",
];

pub(crate) struct Tape {
    handler_id: Uuid,
    user: Option<User>,

    // shell
    tty: Option<NoTtyEvent>,
    send_to_tty: Option<Sender<Vec<u8>>>,
    recv_from_tty: Option<Receiver<Vec<u8>>>,

    log: HandlerLog,
}

impl Tape {
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
                "[{}] User: {} doesn't have permission to access tape",
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
        let app = App::new(backend, tokio_handle, handler_id, user_id).await;
        let w = SenderWriter::new(send_to_session.clone());
        let tty_backend = NottyBackend::new(tty.clone(), w);
        tokio::task::spawn_blocking(move || {
            let mut terminal = Terminal::new(tty_backend)?;
            terminal.hide_cursor()?;
            terminal.flush()?;
            app.run(tty, &mut terminal, send_status)
        });

        session.channel_success(channel)?;
        (self.log)(
            LOG_TYPE.into(),
            format!("User: {} login to record_play", username),
        )
        .await;
        Ok(())
    }
}

impl Drop for Tape {
    fn drop(&mut self) {
        trace!("[{}] drop Tape", self.handler_id);
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
    longest_item_lens: Vec<Constraint>,
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
    async fn new(backend: Arc<B>, t_handle: Handle, handler_id: Uuid, user_id: Uuid) -> Self {
        let mut message = None;
        let items = match backend
            .db_repository()
            .list_recording_view_for_user(&user_id)
            .await
        {
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

        let longest_item_lens = Self::constraint_len_calculator(&items);

        App {
            table: AdminTable::new(&items, &tailwind::BLUE),
            items,
            longest_item_lens,
            backend,
            t_handle,
            handler_id,
            user_id,
            message,
            help_text: HELP_TEXT,
        }
    }

    fn constraint_len_calculator(items: &[RecordingView]) -> Vec<Constraint> {
        let target_len = items
            .iter()
            .map(|v| v.target_secret.as_str())
            .map(UnicodeWidthStr::width)
            .max()
            .unwrap_or(0)
            .max(6);

        let status_len = items
            .iter()
            .map(|v| v.status.as_str())
            .map(UnicodeWidthStr::width)
            .max()
            .unwrap_or(0)
            .max(6);

        vec![
            Constraint::Length(target_len as u16),
            Constraint::Length(DATETIME_LENGTH),
            Constraint::Length(DATETIME_LENGTH),
            Constraint::Length(status_len as u16),
        ]
    }

    fn refresh_data(&mut self) {
        let items = match self.t_handle.block_on(
            self.backend
                .db_repository()
                .list_recording_view_for_user(&self.user_id),
        ) {
            Ok(items) => items,
            Err(e) => {
                warn!(
                    "[{}] List recording view for user: ({}) failed: {}",
                    self.handler_id, self.user_id, e
                );
                self.message = Some(Message::Error(vec!["Internal error".into()]));
                return;
            }
        };
        self.items = items;
        self.longest_item_lens = Self::constraint_len_calculator(&self.items);
        self.table = AdminTable::new(&self.items, &tailwind::BLUE);
    }

    fn do_play(&mut self, idx: usize) {
        // TODO: Implement recording playback
        if let Some(rec) = self.items.get(idx) {
            self.message = Some(Message::Info(vec![format!(
                "Playing recording: {}",
                rec.target_secret
            )]));
        }
    }

    fn run<W: Write>(
        mut self,
        tty: NoTtyEvent,
        terminal: &mut Terminal<NottyBackend<W>>,
        send_status: mpsc::Sender<Status>,
    ) -> Result<(), Error> {
        loop {
            terminal.draw(|frame| self.render(frame))?;
            let event = event::read(&tty)?;

            if let Some(key) = event.as_key_press_event() {
                if self.message.is_some() {
                    match key.code {
                        KeyCode::Enter => {
                            self.message = None;
                            continue;
                        }
                        _ => continue,
                    }
                }

                let ctrl_pressed = key.modifiers.contains(KeyModifiers::CONTROL);

                let items_len = self.items.len();
                match key.code {
                    KeyCode::PageUp => self.table.previous_page(),
                    KeyCode::PageDown => self.table.next_page(items_len),
                    KeyCode::Char('f') if ctrl_pressed => self.table.next_page(items_len),
                    KeyCode::Char('b') if ctrl_pressed => self.table.previous_page(),
                    KeyCode::Char('+') => self.table.zoom_in(),
                    KeyCode::Char('-') => self.table.zoom_out(),
                    KeyCode::Char('r') => {
                        self.refresh_data();
                    }
                    KeyCode::Char('q') => break,
                    KeyCode::Char('c') if ctrl_pressed => break,
                    KeyCode::Char('j') | KeyCode::Down => self.table.next_row(items_len),
                    KeyCode::Char('k') | KeyCode::Up => self.table.previous_row(items_len),
                    KeyCode::Enter => {
                        let idx = self.table.state.selected().unwrap_or(0);
                        self.do_play(idx);
                    }
                    _ => {}
                }
            }
        }
        let _ = send_status.blocking_send(Status::Terminate(0));
        let _ = terminal.show_cursor();
        Ok(())
    }

    fn render(&mut self, frame: &mut Frame) {
        let area = frame.area();

        let layout = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(5),
            Constraint::Length(4),
        ]);
        let [header_area, table_area, footer_area] = layout.areas(area);

        self.table.size = (table_area.width, table_area.height);

        self.render_header(frame, header_area);
        self.table.render(
            frame.buffer_mut(),
            table_area,
            &self.items,
            &self.longest_item_lens,
            DisplayMode::Full,
        );
        if let Some(ref msg) = self.message {
            render_message_popup(table_area, frame.buffer_mut(), msg);
        }
        self.render_footer(frame, footer_area);
    }

    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let header = Paragraph::new("Tape")
            .style(
                Style::new()
                    .bold()
                    .fg(tailwind::SLATE.c200)
                    .bg(tailwind::BLUE.c900),
            )
            .centered();
        frame.render_widget(header, area);
    }

    fn render_footer(&self, frame: &mut Frame, area: Rect) {
        let info_footer = Paragraph::new(Text::from_iter(self.help_text))
            .style(
                Style::new()
                    .fg(self.table.colors.row_fg)
                    .bg(self.table.colors.buffer_bg),
            )
            .centered()
            .block(
                Block::bordered()
                    .border_type(BorderType::Double)
                    .border_style(Style::new().fg(self.table.colors.footer_border_color)),
            );

        frame.render_widget(info_footer, area);
    }
}
