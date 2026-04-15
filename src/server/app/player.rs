use crate::database::common as db_common;
use crate::database::models::{RecordingView, User};
use crate::error::Error;
use crate::server::widgets::{
    AdminTable, Colors, DisplayMode, FormEditor, FormEvent, FormField, Message, centered_area,
    common::{DATETIME_LENGTH, MAX_POPUP_WINDOW_COL, MAX_POPUP_WINDOW_ROW},
    render_message_popup,
};
use crate::server::{HandlerLog, casbin};
use crossterm::event::{
    self, Event, KeyCode, KeyEventKind, KeyModifiers, NoTtyEvent, SenderWriter,
};
use ratatui::backend::NottyBackend;
use ratatui::buffer::Buffer;
use tui_term::widget::PseudoTerminal;

use ratatui::layout::{Constraint, Layout, Rect, Size};
use ratatui::style::{Modifier, Style, palette::tailwind};
use ratatui::text::{Line, Text};
use ratatui::widgets::{
    Block, BorderType, Borders, Clear, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState,
    Widget,
};
use ratatui::{Frame, Terminal};
use std::io::Write;
use tokio::runtime::Handle;
use unicode_width::UnicodeWidthStr;
use vt100::Screen;

use crate::asciinema::{
    asciicast::{self, EventData},
    player,
};
use crate::database::Uuid;
use crossbeam_channel::{Receiver, Sender, unbounded};
use log::{debug, trace, warn};
use tokio::sync::mpsc;

use russh::server as ru_server;
use russh::{Channel, ChannelId, Pty};

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

const SCROLLBACK_LEN: usize = 1000;
const LOG_TYPE: &str = "player";
const HELP_TEXT: [&str; 2] = [
    "(Enter) play | (Esc) quit | (↑↓) select | (s) setting",
    "(+/-) zoom in/out | (PgUp/PgDn) page up/down",
];

pub(crate) struct Player {
    handler_id: Uuid,
    user: Option<User>,

    // shell
    tty: Option<NoTtyEvent>,
    send_to_tty: Option<Sender<Vec<u8>>>,
    recv_from_tty: Option<Receiver<Vec<u8>>>,

    log: HandlerLog,
}

impl Player {
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
            .check_permission(backend, uuids.obj_player, uuids.act_login, ip)
            .await?
        {
            debug!(
                "[{}] User: {} doesn't have permission to access player",
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
                        if let Some(d) = data && handle_session.data(channel, d).await.is_err() {
                            warn!("[{}] Fail to send data to session from prompt",handler_id);
                            break;
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
            format!("User: {} login to player", username),
        )
        .await;
        Ok(())
    }
}

impl Drop for Player {
    fn drop(&mut self) {
        trace!("[{}] drop Player", self.handler_id);
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
    horizontal_scroll_offset: usize,
    vertical_scroll_offset: usize,
    max_vertical_scroll_offset: usize,
    max_horizontal_scroll_offset: usize,
    scroll_size: usize,
    scroll_position: usize,

    is_playing: bool,
    pause: bool,

    setting: Setting,

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
            horizontal_scroll_offset: 0,
            vertical_scroll_offset: 0,
            max_vertical_scroll_offset: 0,
            max_horizontal_scroll_offset: 0,
            scroll_size: 0,
            scroll_position: 0,

            is_playing: false,
            pause: false,

            setting: Setting::new(),

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

    fn do_play<W: Write>(
        &mut self,
        tty: &NoTtyEvent,
        terminal: &mut Terminal<NottyBackend<W>>,
    ) -> Result<(), Error> {
        let idx = self.table.state.selected().unwrap();
        let file_path = std::path::PathBuf::from(self.backend.record_path())
            .join(self.items.get(idx).unwrap().generate_path());
        let recording = asciicast::open_from_path(std::path::Path::new(&file_path))?;

        let initial_cols = recording.header.term_cols;
        let initial_rows = recording.header.term_rows;
        let mut events = player::emit_session_events(
            recording,
            self.setting.speed,
            self.setting.idle_time_limit,
        )?;

        let mut size = Size {
            width: initial_cols,
            height: initial_rows,
        };
        self.scroll_size = initial_rows as usize;
        let parser = Arc::new(RwLock::new(vt100::Parser::new(
            initial_rows,
            initial_cols,
            SCROLLBACK_LEN,
        )));

        let mut epoch = Instant::now();
        let mut next_event = self.t_handle.block_on(events.recv()).transpose()?;
        let mut processed_buf = Vec::new();
        let pause_on_markers = self.setting.pause_on_markers;
        let mut pause_elapsed_time: Option<u64> = None;

        while let Some(asciicast::Event { time, data }) = &next_event {
            if let Some(pet) = pause_elapsed_time {
                if let Event::Key(key) = event::read(tty)?
                    && key.kind == KeyEventKind::Press
                {
                    let ctrl_pressed = key.modifiers.contains(KeyModifiers::CONTROL);
                    match key.code {
                        KeyCode::Char('q') => return Ok(()),
                        KeyCode::Char('c') if ctrl_pressed => return Ok(()),
                        KeyCode::Char(' ') => {
                            self.pause = false;
                            epoch = Instant::now() - Duration::from_micros(pet);
                            pause_elapsed_time = None;
                        }
                        KeyCode::Char('.') => {
                            pause_elapsed_time = Some(time.as_micros() as u64);
                            match data {
                                EventData::Output(data) => {
                                    let mut parser = parser.write().unwrap();
                                    parser.process(data.as_bytes());
                                }

                                EventData::Resize(cols, rows) => {
                                    size.width = *cols;
                                    size.height = *rows;
                                    self.scroll_size = *rows as usize;
                                    parser.write().unwrap().screen_mut().set_size(*rows, *cols);
                                }

                                _ => {}
                            }
                            terminal.draw(|f| {
                                self.player_ui(f, parser.read().unwrap().screen(), size)
                            })?;

                            next_event = self.t_handle.block_on(events.recv()).transpose()?;
                        }
                        KeyCode::Char(']') => {
                            while let Some(asciicast::Event { time, data }) = next_event {
                                terminal.draw(|f| {
                                    self.player_ui(f, parser.read().unwrap().screen(), size)
                                })?;
                                next_event = self.t_handle.block_on(events.recv()).transpose()?;

                                match data {
                                    EventData::Output(data) => {
                                        let mut parser = parser.write().unwrap();
                                        parser.process(data.as_bytes());
                                    }

                                    EventData::Marker(_) => {
                                        pause_elapsed_time = Some(time.as_micros() as u64);
                                        break;
                                    }

                                    EventData::Resize(cols, rows) => {
                                        size.width = cols;
                                        size.height = rows;
                                        self.scroll_size = rows as usize;
                                        parser.write().unwrap().screen_mut().set_size(rows, cols);
                                    }

                                    _ => {}
                                }
                            }
                        }
                        KeyCode::Char('l') | KeyCode::Right => {
                            self.horizontal_scroll_offset = if self.horizontal_scroll_offset
                                == self.max_horizontal_scroll_offset
                            {
                                0
                            } else {
                                self.horizontal_scroll_offset.saturating_add(1)
                            };
                        }
                        KeyCode::Char('h') | KeyCode::Left => {
                            self.horizontal_scroll_offset = if self.horizontal_scroll_offset == 0 {
                                self.max_horizontal_scroll_offset
                            } else {
                                self.horizontal_scroll_offset.saturating_sub(1)
                            };
                        }
                        KeyCode::Char('f') if ctrl_pressed => {
                            self.decrease_scroll_position(&parser);
                        }
                        KeyCode::PageDown => {
                            self.decrease_scroll_position(&parser);
                        }
                        KeyCode::Char('b') if ctrl_pressed => {
                            self.increase_scroll_position(&parser);
                        }
                        KeyCode::PageUp => {
                            self.increase_scroll_position(&parser);
                        }
                        KeyCode::Char('j') | KeyCode::Down => {
                            self.vertical_scroll_offset =
                                if self.vertical_scroll_offset == self.max_vertical_scroll_offset {
                                    0
                                } else {
                                    self.vertical_scroll_offset.saturating_add(1)
                                };
                        }
                        KeyCode::Char('k') | KeyCode::Up => {
                            self.vertical_scroll_offset = if self.vertical_scroll_offset == 0 {
                                self.max_vertical_scroll_offset
                            } else {
                                self.vertical_scroll_offset.saturating_sub(1)
                            };
                        }
                        _ => continue,
                    }
                    terminal.draw(|f| self.player_ui(f, parser.read().unwrap().screen(), size))?;
                }
            } else {
                parser.write().unwrap().screen_mut().set_scrollback(0);
                self.scroll_position = 0;
                while let Some(asciicast::Event { time, data }) = &next_event {
                    terminal.draw(|f| self.player_ui(f, parser.read().unwrap().screen(), size))?;
                    let delay = time.as_micros() as i64 - epoch.elapsed().as_micros() as i64;

                    if delay > 0 && event::poll(tty, Duration::from_micros(delay as u64))? {
                        // It's guaranteed that the `read()` won't block when the `poll()`
                        // function returns `true`
                        if let Event::Key(key) = event::read(tty)?
                            && key.kind == KeyEventKind::Press
                        {
                            let ctrl_pressed = key.modifiers.contains(KeyModifiers::CONTROL);
                            match key.code {
                                KeyCode::Char('q') => return Ok(()),
                                KeyCode::Char('c') if ctrl_pressed => return Ok(()),
                                KeyCode::Char(' ') => {
                                    self.pause = true;
                                    terminal.draw(|f| {
                                        self.player_ui(f, parser.read().unwrap().screen(), size)
                                    })?;
                                    pause_elapsed_time = Some(epoch.elapsed().as_micros() as u64);
                                    break;
                                }
                                KeyCode::Char('l') | KeyCode::Right => {
                                    self.horizontal_scroll_offset = if self.horizontal_scroll_offset
                                        == self.max_horizontal_scroll_offset
                                    {
                                        0
                                    } else {
                                        self.horizontal_scroll_offset.saturating_add(1)
                                    }
                                }
                                KeyCode::Char('h') | KeyCode::Left => {
                                    self.horizontal_scroll_offset =
                                        if self.horizontal_scroll_offset == 0 {
                                            self.max_horizontal_scroll_offset
                                        } else {
                                            self.horizontal_scroll_offset.saturating_sub(1)
                                        };
                                }
                                KeyCode::Char('j') | KeyCode::Down => {
                                    self.vertical_scroll_offset = if self.vertical_scroll_offset
                                        == self.max_vertical_scroll_offset
                                    {
                                        0
                                    } else {
                                        self.vertical_scroll_offset.saturating_add(1)
                                    }
                                }
                                KeyCode::Char('k') | KeyCode::Up => {
                                    self.vertical_scroll_offset =
                                        if self.vertical_scroll_offset == 0 {
                                            self.max_vertical_scroll_offset
                                        } else {
                                            self.vertical_scroll_offset.saturating_sub(1)
                                        };
                                }

                                _ => {}
                            }
                        }
                        continue;
                    }

                    match data {
                        EventData::Output(data) => {
                            let size = data.len();
                            processed_buf.extend_from_slice(&data.as_bytes()[..size]);
                            let mut parser = parser.write().unwrap();
                            parser.process(&processed_buf);

                            // Clear the processed portion of the buffer
                            processed_buf.clear();
                        }

                        EventData::Resize(cols, rows) => {
                            size.width = *cols;
                            size.height = *rows;
                            self.scroll_size = *rows as usize;
                            parser.write().unwrap().screen_mut().set_size(*rows, *cols);
                        }

                        EventData::Marker(_) => {
                            if pause_on_markers {
                                pause_elapsed_time = Some(time.as_micros() as u64);
                                next_event = self.t_handle.block_on(events.recv()).transpose()?;
                                break;
                            }
                        }

                        _ => (),
                    }

                    next_event = self.t_handle.block_on(events.recv()).transpose()?;
                }
            }
        }
        Ok(())
    }

    fn run<W: Write>(
        mut self,
        tty: NoTtyEvent,
        terminal: &mut Terminal<NottyBackend<W>>,
        send_status: mpsc::Sender<Status>,
    ) -> Result<(), Error> {
        loop {
            if self.is_playing {
                if let Err(e) = self.do_play(&tty, terminal) {
                    warn!("[{}] Play record cast error: {}", self.handler_id, e);
                    self.message = Some(Message::Error(vec!["Internal error".into()]));
                };
                self.is_playing = false;
            }
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

                if self.setting.editing_mode {
                    match self.setting.form.handle_key_event(key.code, key.modifiers) {
                        FormEvent::Save => {
                            if let Err(e) = self.setting.verify() {
                                self.setting.form.set_save_error(vec![e.to_string()]);
                            } else {
                                self.setting.editing_mode = false;
                                self.setting.form.show_cancel_confirmation = false;
                                self.table.colors = Colors::new(&tailwind::BLUE);
                            }
                        }
                        FormEvent::Cancel => {
                            self.setting.editing_mode = false;
                            self.setting.form.show_cancel_confirmation = false;
                            self.table.colors = Colors::new(&tailwind::BLUE);
                        }
                        FormEvent::None => {}
                    }
                    continue;
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
                    KeyCode::Char('s') => {
                        self.setting.editing_mode = true;
                        self.table.colors.gray();
                    }
                    KeyCode::Char('q') => break,
                    KeyCode::Char('c') if ctrl_pressed => break,
                    KeyCode::Char('j') | KeyCode::Down => self.table.next_row(items_len),
                    KeyCode::Char('k') | KeyCode::Up => self.table.previous_row(items_len),
                    KeyCode::Enter => {
                        self.is_playing = true;
                    }
                    _ => {}
                }
            }
        }
        let _ = terminal.show_cursor();
        let _ = send_status.blocking_send(Status::Terminate(0));
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
        if self.setting.editing_mode {
            self.render_setting_popup(frame, table_area);
        }
        self.render_footer(frame, footer_area);
    }

    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let header = Paragraph::new("Player")
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
        let help_text = if self.setting.editing_mode {
            self.setting.form.help_text
        } else {
            self.help_text
        };
        let info_footer = Paragraph::new(Text::from_iter(help_text))
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

    fn render_setting_popup(&mut self, frame: &mut Frame, area: Rect) {
        let popup_area = if area.width <= MAX_POPUP_WINDOW_COL {
            area
        } else {
            centered_area(
                area,
                MAX_POPUP_WINDOW_COL,
                area.height.min(MAX_POPUP_WINDOW_ROW),
            )
        };
        let title = Line::styled("Setting", Style::default().bold());
        let popup = Block::bordered()
            .title(title)
            .title_style(Style::new().fg(self.table.colors.header_fg))
            .border_style(Style::new().fg(self.table.colors.footer_border_color))
            .border_type(BorderType::Double);
        frame.render_widget(Clear, popup_area);
        frame.render_widget(popup, popup_area);
        self.setting.form.render_ui(popup_area, frame.buffer_mut());
    }

    fn player_ui(&mut self, f: &mut Frame, screen: &Screen, size: Size) {
        let chunks = ratatui::layout::Layout::default()
            .direction(ratatui::layout::Direction::Vertical)
            .constraints(
                [
                    ratatui::layout::Constraint::Percentage(100),
                    ratatui::layout::Constraint::Length(1),
                ]
                .as_ref(),
            )
            .split(f.area());
        let block = Block::default().borders(Borders::ALL).style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(self.table.colors.footer_border_color),
        );
        let term_area = Rect::new(0, 0, size.width + 2, size.height + 2);
        let buf = f.buffer_mut();
        let mut term_buf = Buffer::empty(term_area);
        let vertical_bar_needed = term_area.height > chunks[0].height;
        let horizontal_bar_needed = term_area.width > chunks[0].width;
        let (visible_area, horizontal_bar_area, vertical_bar_area) =
            match (horizontal_bar_needed, vertical_bar_needed) {
                (true, true) => {
                    let ver_chunks = Layout::vertical([
                        ratatui::layout::Constraint::Percentage(100),
                        ratatui::layout::Constraint::Length(1),
                    ])
                    .split(chunks[0]);
                    let hor_chunks0 = Layout::horizontal([
                        ratatui::layout::Constraint::Percentage(100),
                        ratatui::layout::Constraint::Length(1),
                    ])
                    .split(ver_chunks[0]);
                    let hor_chunks1 = Layout::horizontal([
                        ratatui::layout::Constraint::Percentage(100),
                        ratatui::layout::Constraint::Length(1),
                    ])
                    .split(ver_chunks[1]);
                    (hor_chunks0[0], hor_chunks1[0], hor_chunks0[1])
                }
                (true, false) => {
                    let sub_chunks = Layout::vertical([
                        ratatui::layout::Constraint::Percentage(100),
                        ratatui::layout::Constraint::Length(1),
                    ])
                    .split(chunks[0]);
                    (sub_chunks[0], sub_chunks[1], Rect::default())
                }
                (false, true) => {
                    let sub_chunks = Layout::horizontal([
                        ratatui::layout::Constraint::Percentage(100),
                        ratatui::layout::Constraint::Length(1),
                    ])
                    .split(chunks[0]);
                    (sub_chunks[0], Rect::default(), sub_chunks[1])
                }
                (false, false) => (chunks[0], Rect::default(), Rect::default()),
            };

        if horizontal_bar_needed {
            use ratatui::widgets::StatefulWidget;
            let max_horizontal_scroll_offset = (term_area.width - visible_area.width) as usize;
            self.max_horizontal_scroll_offset = max_horizontal_scroll_offset;
            self.horizontal_scroll_offset =
                if self.horizontal_scroll_offset > max_horizontal_scroll_offset {
                    max_horizontal_scroll_offset
                } else {
                    self.horizontal_scroll_offset
                };
            // let area = visible_area.intersection(buf.area);
            let mut state = ScrollbarState::new(max_horizontal_scroll_offset)
                .position(self.horizontal_scroll_offset);
            Scrollbar::new(ScrollbarOrientation::HorizontalBottom)
                .thumb_symbol("🬋")
                .render(horizontal_bar_area, buf, &mut state);
        }

        if vertical_bar_needed {
            use ratatui::widgets::StatefulWidget;
            let max_vertical_scroll_offset = (term_area.height - visible_area.height) as usize;
            self.max_vertical_scroll_offset = max_vertical_scroll_offset;
            self.vertical_scroll_offset =
                if self.vertical_scroll_offset > max_vertical_scroll_offset {
                    max_vertical_scroll_offset
                } else {
                    self.vertical_scroll_offset
                };
            // let area = visible_area.intersection(buf.area);
            let mut state = ScrollbarState::new(max_vertical_scroll_offset)
                .position(self.vertical_scroll_offset);
            Scrollbar::new(ScrollbarOrientation::VerticalRight).render(
                vertical_bar_area,
                buf,
                &mut state,
            );
        }

        let pseudo_term = PseudoTerminal::new(screen).block(block);
        pseudo_term.render(term_area, &mut term_buf);
        match (horizontal_bar_needed, vertical_bar_needed) {
            (false, false) => {
                let width = term_area.width;
                for (i, cell) in term_buf.content.into_iter().enumerate() {
                    let x = i as u16 % width;
                    let y = i as u16 / width;
                    buf[(visible_area.x + x, visible_area.y + y)] = cell;
                }
            }
            (true, false) => {
                let drop_cell = term_area.width as usize
                    - visible_area.width as usize
                    - self.horizontal_scroll_offset;
                let iter = &mut term_buf.content.into_iter();
                for y in 0..term_area.height {
                    let line = iter
                        .skip(self.horizontal_scroll_offset)
                        .take(visible_area.width as usize);
                    for (x, cell) in line.enumerate() {
                        buf[(visible_area.x + x as u16, visible_area.y + y)] = cell;
                    }

                    if drop_cell > 0 {
                        let _ = iter.nth(drop_cell - 1);
                    }
                }
            }
            (false, true) => {
                let width = term_area.width;
                let visible_content = term_buf
                    .content
                    .into_iter()
                    .skip(width as usize * self.vertical_scroll_offset)
                    .take((width * visible_area.height) as usize);
                for (i, cell) in visible_content.enumerate() {
                    let x = i as u16 % width;
                    let y = i as u16 / width;
                    buf[(visible_area.x + x, visible_area.y + y)] = cell;
                }
            }
            (true, true) => {
                let drop_cell = term_area.width as usize
                    - visible_area.width as usize
                    - self.horizontal_scroll_offset;
                let iter = &mut term_buf.content.into_iter();
                let v_height = visible_area.height;
                let offset = self.vertical_scroll_offset * term_area.width as usize;
                if offset > 0 {
                    iter.nth(offset - 1);
                }
                for y in 0..v_height {
                    let line = iter
                        .skip(self.horizontal_scroll_offset)
                        .take(visible_area.width as usize);
                    for (x, cell) in line.enumerate() {
                        buf[(visible_area.x + x as u16, visible_area.y + y)] = cell;
                    }

                    if drop_cell > 0 {
                        let _ = iter.nth(drop_cell - 1);
                    }
                }
            }
        }

        let explanation = if self.pause {
            format!(
                "<space> play <.> step <]> next mark <PgUp/PgDn> scroll lines [{}*{}]",
                term_area.width, term_area.height
            )
        } else {
            format!(
                "<space> pause <q> exit [{}*{}]",
                term_area.width, term_area.height
            )
        };
        let explanation = Paragraph::new(explanation).style(
            Style::default()
                .add_modifier(Modifier::BOLD | Modifier::REVERSED)
                .fg(self.table.colors.footer_border_color),
        );
        f.render_widget(explanation, chunks[1]);
    }

    fn decrease_scroll_position(&mut self, parser: &RwLock<vt100::Parser>) {
        self.scroll_position = self.scroll_position.saturating_sub(self.scroll_size);
        parser
            .write()
            .unwrap()
            .screen_mut()
            .set_scrollback(self.scroll_position);
    }

    fn increase_scroll_position(&mut self, parser: &RwLock<vt100::Parser>) {
        self.scroll_position += self.scroll_size;
        if self.scroll_position > SCROLLBACK_LEN {
            self.scroll_position = SCROLLBACK_LEN
        }
        parser
            .write()
            .unwrap()
            .screen_mut()
            .set_scrollback(self.scroll_position);
    }
}

// Field indices
const F_SPEED: usize = 0;
const F_IDLE_TIME_LIMIT: usize = 1;
const F_PAUSE_ON_MARKERS: usize = 2;

#[derive(Debug)]
pub struct Setting {
    pub pause_on_markers: bool,
    pub speed: f64,
    pub idle_time_limit: Option<f64>,
    pub editing_mode: bool,
    pub form: FormEditor,
}

impl Setting {
    pub fn new() -> Self {
        let form = FormEditor::new(vec![
            FormField::text("Speed", Some(1.0f64.to_string())),
            FormField::text("Idle time limit", None),
            FormField::checkbox("Pause on markers", false),
        ]);

        Self {
            pause_on_markers: false,
            speed: 1.0,
            idle_time_limit: None,
            editing_mode: false,
            form,
        }
    }

    pub fn verify(&mut self) -> Result<(), std::num::ParseFloatError> {
        self.speed = self.form.get_text(F_SPEED).trim().parse()?;
        let idle_time_limit_text = self.form.get_text(F_IDLE_TIME_LIMIT);
        self.idle_time_limit = if idle_time_limit_text.trim().is_empty() {
            None
        } else {
            Some(idle_time_limit_text.trim().parse()?)
        };
        self.pause_on_markers = self.form.get_checkbox(F_PAUSE_ON_MARKERS);
        Ok(())
    }
}
