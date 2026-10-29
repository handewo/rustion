use crate::database::common::{
    TABLE_CASBIN_NAMES, TABLE_CASBIN_RULE, TABLE_LIST, TABLE_LOGS, TABLE_SECRETS,
    TABLE_SESSION_RECORDINGS, TABLE_TARGET_SECRETS, TABLE_TARGETS, TABLE_USERS,
};
use crate::database::models::*;
use crate::error::Error;
use crate::i18n::Lang;
use crate::server::event_log;
use crate::server::widgets::{
    AdminTable, DisplayMode, FieldsToArray, Help, TabBar, TableData as TD, Theme, footer_height,
    render_footer,
};
use crossterm::event::{self, KeyCode, KeyModifiers, NoTtyEvent, SenderWriter};
use crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::Frame;
use ratatui::backend::NottyBackend;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui_core::terminal::AsyncTerminal;
use std::sync::Arc;
use unicode_width::UnicodeWidthStr;

const INFO_TEXT: Help = |tr| [tr.help_database, tr.help_manage_nav];

const LENGTH_UUID: u16 = 36;
const LENGTH_SHORT_UUID: u16 = 19;
const LENGTH_TIMSTAMP: u16 = 14;

pub(super) async fn query_table<B>(
    tty: NoTtyEvent,
    writer: SenderWriter,
    backend: Arc<B>,
    theme: &mut &'static Theme,
    lang: &mut Lang,
) -> Result<(), Error>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    let tty_backend = NottyBackend::new(tty.clone(), writer.clone());
    let mut terminal = AsyncTerminal::new(tty_backend)?;
    crossterm::async_execute!(&writer, EnterAlternateScreen).await?;
    let mut app = App::new(backend, theme, *lang).await;
    let result = app.run(tty, &mut terminal).await;
    // The shell starts the next panel in the theme and language this one
    // ended with.
    *theme = app.theme;
    *lang = app.lang;
    result?;
    crossterm::async_execute!(&writer, LeaveAlternateScreen).await?;
    Ok(())
}

struct App<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    table: AdminTable,
    items: TableData,
    longest_item_lens: Vec<Constraint>,
    selected_tab: usize,
    last_selected_tab: usize,
    tabs: TabBar,
    theme: &'static Theme,
    lang: Lang,
    backend: Arc<B>,
}

impl<B> App<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    async fn new(backend: Arc<B>, theme: &'static Theme, lang: Lang) -> Self {
        let data = TableData::Users(
            backend
                .db_repository()
                .list_users(false)
                .await
                .unwrap_or_default(),
        );
        Self {
            table: AdminTable::new(&data),
            longest_item_lens: data.constraint_len_calculator(),
            selected_tab: 0,
            last_selected_tab: 0,
            tabs: TabBar::default(),
            theme,
            lang,
            backend,
            items: data,
        }
    }

    pub async fn next_tab(&mut self) {
        self.selected_tab = (self.selected_tab + 1) % TABLE_LIST.len();
        if self.selected_tab != self.last_selected_tab {
            self.refresh_data().await;
            self.last_selected_tab = self.selected_tab
        }
    }

    pub async fn previous_tab(&mut self) {
        if self.selected_tab == 0 {
            self.selected_tab = TABLE_LIST.len() - 1;
        } else {
            self.selected_tab = (self.selected_tab - 1) % TABLE_LIST.len();
        }
        if self.selected_tab != self.last_selected_tab {
            self.refresh_data().await;
            self.last_selected_tab = self.selected_tab
        }
    }

    async fn run(
        &mut self,
        tty: NoTtyEvent,
        terminal: &mut AsyncTerminal<NottyBackend>,
    ) -> Result<(), Error> {
        loop {
            terminal.draw(|frame| self.render(frame)).await?;

            if let Some(key) = event::read(&tty).await?.as_key_press_event() {
                let ctrl_pressed = key.modifiers.contains(KeyModifiers::CONTROL);
                let items_len = self.items.len();
                match key.code {
                    KeyCode::PageUp => self.table.previous_page(),
                    KeyCode::PageDown => self.table.next_page(items_len),
                    KeyCode::Char('f') if ctrl_pressed => self.table.next_page(items_len),
                    KeyCode::Char('b') if ctrl_pressed => self.table.previous_page(),
                    KeyCode::Char('+') => self.table.zoom_in(),
                    KeyCode::Char('-') => self.table.zoom_out(),
                    KeyCode::Char('t') => self.theme = self.theme.next(),
                    KeyCode::Char('L') => {
                        self.lang = self.lang.next();
                        // The log's details are worded as they are loaded.
                        if TABLE_LIST[self.selected_tab] == TABLE_LOGS {
                            self.refresh_data().await;
                        }
                    }
                    KeyCode::Tab => self.next_tab().await,
                    KeyCode::BackTab => self.previous_tab().await,
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Char('j') | KeyCode::Down => self.table.next_row(items_len),
                    KeyCode::Char('k') | KeyCode::Up => self.table.previous_row(items_len),
                    KeyCode::Char('l') | KeyCode::Right => self.table.next_column(),
                    KeyCode::Char('h') | KeyCode::Left => self.table.previous_column(),
                    _ => {}
                }
            }
        }
    }

    fn render(&mut self, frame: &mut Frame) {
        let tr = self.lang.strings();
        self.theme.paint(frame.area(), frame.buffer_mut());
        let layout = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(5),
            Constraint::Length(footer_height(INFO_TEXT(tr), frame.area().width)),
        ]);
        let [header_area, table_area, footer_area] = layout.areas(frame.area());

        self.table.size = (table_area.width, table_area.height);

        self.render_tabs(frame, header_area);
        self.table.render(
            frame.buffer_mut(),
            table_area,
            &self.items,
            &self.longest_item_lens,
            DisplayMode::Full,
            self.theme,
            tr,
        );
        self.render_footer(frame, footer_area);
    }

    async fn refresh_data(&mut self) {
        match TABLE_LIST[self.selected_tab] {
            TABLE_USERS => {
                self.items = TableData::Users(
                    self.backend
                        .db_repository()
                        .list_users(false)
                        .await
                        .unwrap_or_default(),
                );
            }
            TABLE_TARGETS => {
                self.items = TableData::Targets(
                    self.backend
                        .db_repository()
                        .list_targets(false)
                        .await
                        .unwrap_or_default(),
                );
            }
            TABLE_TARGET_SECRETS => {
                self.items = TableData::TargetSecrets(
                    self.backend
                        .db_repository()
                        .list_target_secrets(false)
                        .await
                        .unwrap_or_default(),
                );
            }
            TABLE_SECRETS => {
                self.items = TableData::Secrets(
                    self.backend
                        .db_repository()
                        .list_secrets(false)
                        .await
                        .unwrap_or_default(),
                );
            }
            TABLE_CASBIN_NAMES => {
                self.items = TableData::CasbinNames(
                    self.backend
                        .db_repository()
                        .list_casbin_names(false)
                        .await
                        .unwrap_or_default(),
                );
            }
            TABLE_CASBIN_RULE => {
                self.items = TableData::CasbinRule(
                    self.backend
                        .db_repository()
                        .list_casbin_rules()
                        .await
                        .unwrap_or_default(),
                );
            }
            TABLE_LOGS => {
                let tr = self.lang.strings();
                let mut logs = self
                    .backend
                    .db_repository()
                    .list_logs()
                    .await
                    .unwrap_or_default();
                // Stored as events in no language; worded here, in the reader's.
                for l in &mut logs {
                    l.detail = event_log::render(&l.detail, tr);
                }
                self.items = TableData::Logs(logs);
            }
            TABLE_SESSION_RECORDINGS => {
                self.items = TableData::SessionRecordings(
                    self.backend
                        .db_repository()
                        .list_session_recordings(None)
                        .await
                        .unwrap_or_default(),
                );
            }
            _ => {
                unreachable!()
            }
        };
        self.longest_item_lens = self.items.constraint_len_calculator();
        self.table.state.select(Some(0));
    }

    fn render_tabs(&mut self, frame: &mut Frame, area: Rect) {
        self.tabs.render(
            area,
            frame.buffer_mut(),
            &TABLE_LIST,
            self.selected_tab,
            self.theme,
        );
    }

    fn render_footer(&self, frame: &mut Frame, area: Rect) {
        let tr = self.lang.strings();
        render_footer(area, frame.buffer_mut(), INFO_TEXT(tr), self.theme, tr);
    }
}

enum TableData {
    Users(Vec<User>),
    Targets(Vec<Target>),
    Secrets(Vec<Secret>),
    TargetSecrets(Vec<TargetSecret>),
    CasbinNames(Vec<CasbinName>),
    CasbinRule(Vec<CasbinRule>),
    Logs(Vec<EventLog>),
    SessionRecordings(Vec<SessionRecording>),
}

// TODO: Support switching uuid format, long or short
impl TableData {
    fn constraint_len_calculator(&self) -> Vec<Constraint> {
        match self {
            Self::Users(data) => {
                let username_len = data
                    .iter()
                    .map(|v| v.username.as_str())
                    .map(UnicodeWidthStr::width)
                    .max()
                    .unwrap_or(0)
                    .max(8);
                let email_len = data
                    .iter()
                    .map(|v| v.email.as_deref().unwrap_or(""))
                    .map(UnicodeWidthStr::width)
                    .max()
                    .unwrap_or(0)
                    .max(5);

                vec![
                    Constraint::Length(LENGTH_UUID),
                    Constraint::Length(username_len as u16),
                    Constraint::Length(email_len as u16),
                    Constraint::Length(13),
                    Constraint::Length(15),
                    Constraint::Length(15),
                    Constraint::Length(9),
                    Constraint::Length(LENGTH_UUID),
                    Constraint::Length(LENGTH_TIMSTAMP),
                ]
            }
            Self::Targets(data) => {
                let name_len = data
                    .iter()
                    .map(|v| v.name.as_str())
                    .map(UnicodeWidthStr::width)
                    .max()
                    .unwrap_or(0)
                    .max(4);
                let hostname_len = data
                    .iter()
                    .map(|v| v.hostname.as_str())
                    .map(UnicodeWidthStr::width)
                    .max()
                    .unwrap_or(0)
                    .max(8);
                let proxy_len = data
                    .iter()
                    .map(|v| v.proxy.as_deref().map(|s| s.len()).unwrap_or(0))
                    .max()
                    .unwrap_or(0)
                    .max(5);
                let server_public_key_len = data
                    .iter()
                    .map(|v| v.print_server_key().len())
                    .max()
                    .unwrap_or(0)
                    .max(17);
                let desc_len = data
                    .iter()
                    .map(|v| v.description.as_deref().unwrap_or(""))
                    .map(UnicodeWidthStr::width)
                    .max()
                    .unwrap_or(0)
                    .max(11);

                vec![
                    Constraint::Length(LENGTH_UUID),
                    Constraint::Length(name_len as u16),
                    Constraint::Length(hostname_len as u16),
                    Constraint::Length(5),
                    Constraint::Length(server_public_key_len as u16),
                    Constraint::Length(desc_len as u16),
                    Constraint::Length(proxy_len as u16),
                    Constraint::Length(9), // is_active
                    Constraint::Length(LENGTH_UUID),
                    Constraint::Length(LENGTH_TIMSTAMP),
                ]
            }

            Self::TargetSecrets(_) => {
                vec![
                    Constraint::Length(LENGTH_UUID), // id
                    Constraint::Length(LENGTH_UUID), // target_id
                    Constraint::Length(LENGTH_UUID), // secret_id
                    Constraint::Length(9),           // is_active
                    Constraint::Length(LENGTH_UUID), // created_by
                    Constraint::Length(LENGTH_TIMSTAMP),
                ]
            }
            Self::Secrets(data) => {
                let name_len = data
                    .iter()
                    .map(|v| v.name.as_str())
                    .map(UnicodeWidthStr::width)
                    .max()
                    .unwrap_or(0)
                    .max(4);

                let user_len = data
                    .iter()
                    .map(|v| v.user.as_str())
                    .map(UnicodeWidthStr::width)
                    .max()
                    .unwrap_or(0)
                    .max(4);

                let public_key_len = data
                    .iter()
                    .map(|v| v.print_public_key().len())
                    .max()
                    .unwrap_or(0)
                    .max(10);

                vec![
                    Constraint::Length(LENGTH_UUID), // id
                    Constraint::Length(name_len as u16),
                    Constraint::Length(user_len as u16),
                    Constraint::Length(8),  // password (shown as <hidden>)
                    Constraint::Length(11), // private_key (shown as <hidden>)
                    Constraint::Length(public_key_len as u16),
                    Constraint::Length(9),           // is_active
                    Constraint::Length(LENGTH_UUID), // created_by
                    Constraint::Length(LENGTH_TIMSTAMP),
                ]
            }
            Self::CasbinNames(data) => {
                let name_len = data
                    .iter()
                    .map(|v| v.name.as_str())
                    .map(UnicodeWidthStr::width)
                    .max()
                    .unwrap_or(0)
                    .max(4);

                let ptype_len = data
                    .iter()
                    .map(|v| v.ptype.as_str().len())
                    .max()
                    .unwrap_or(0)
                    .max(5);

                vec![
                    Constraint::Length(LENGTH_UUID), // id
                    Constraint::Length(ptype_len as u16),
                    Constraint::Length(name_len as u16),
                    Constraint::Length(9), // is_active
                    Constraint::Length(LENGTH_UUID),
                    Constraint::Length(LENGTH_TIMSTAMP),
                ]
            }
            Self::CasbinRule(data) => {
                let v3_len = data
                    .iter()
                    .map(|v| v.v3.as_str())
                    .map(UnicodeWidthStr::width)
                    .max()
                    .unwrap_or(0)
                    .max(2);
                let v4_len = data
                    .iter()
                    .map(|v| v.v4.as_str())
                    .map(UnicodeWidthStr::width)
                    .max()
                    .unwrap_or(0)
                    .max(2);
                let v5_len = data
                    .iter()
                    .map(|v| v.v5.as_str())
                    .map(UnicodeWidthStr::width)
                    .max()
                    .unwrap_or(0)
                    .max(2);

                vec![
                    Constraint::Length(LENGTH_UUID),
                    Constraint::Length(5),
                    Constraint::Length(LENGTH_UUID),
                    Constraint::Length(LENGTH_UUID),
                    Constraint::Length(LENGTH_UUID),
                    Constraint::Length(v3_len as u16),
                    Constraint::Length(v4_len as u16),
                    Constraint::Length(v5_len as u16),
                    Constraint::Length(LENGTH_UUID),
                    Constraint::Length(LENGTH_TIMSTAMP),
                ]
            }
            Self::Logs(data) => {
                let id_len = data
                    .iter()
                    .map(|v| v.id.to_string().len())
                    .max()
                    .unwrap_or(0)
                    .max(2);
                let log_type_len = data
                    .iter()
                    .map(|v| v.log_type.as_str())
                    .map(UnicodeWidthStr::width)
                    .max()
                    .unwrap_or(0)
                    .max(8);
                let detail_len = data
                    .iter()
                    .map(|v| v.detail.as_str())
                    .map(UnicodeWidthStr::width)
                    .max()
                    .unwrap_or(0)
                    .max(6);
                vec![
                    Constraint::Length(id_len as u16),
                    Constraint::Length(LENGTH_SHORT_UUID),
                    Constraint::Length(log_type_len as u16),
                    Constraint::Length(LENGTH_SHORT_UUID),
                    Constraint::Length(detail_len as u16),
                    Constraint::Length(LENGTH_TIMSTAMP),
                ]
            }
            Self::SessionRecordings(data) => {
                let target_label_len = data
                    .iter()
                    .map(|v| v.target_label.as_str())
                    .map(UnicodeWidthStr::width)
                    .max()
                    .unwrap_or(0)
                    .max(12);
                let file_path_len = data
                    .iter()
                    .map(|v| v.file_path.as_str())
                    .map(UnicodeWidthStr::width)
                    .max()
                    .unwrap_or(0)
                    .max(9);
                let status_len = data
                    .iter()
                    .map(|v| v.status.as_str())
                    .map(UnicodeWidthStr::width)
                    .max()
                    .unwrap_or(0)
                    .max(6);
                vec![
                    Constraint::Length(LENGTH_SHORT_UUID), // id
                    Constraint::Length(LENGTH_SHORT_UUID), // user_id
                    Constraint::Length(LENGTH_SHORT_UUID), // target_id
                    Constraint::Length(LENGTH_SHORT_UUID), // secret_id
                    Constraint::Length(target_label_len as u16),
                    Constraint::Length(file_path_len as u16),
                    Constraint::Length(LENGTH_TIMSTAMP), // started_at
                    Constraint::Length(LENGTH_TIMSTAMP), // ended_at
                    Constraint::Length(LENGTH_SHORT_UUID), // connection_id
                    Constraint::Length(status_len as u16),
                ]
            }
        }
    }
}

impl crate::server::widgets::TableData for TableData {
    fn len(&self) -> usize {
        match self {
            Self::Users(data) => data.len(),
            Self::Targets(data) => data.len(),
            Self::Secrets(data) => data.len(),
            Self::TargetSecrets(data) => data.len(),
            Self::CasbinNames(data) => data.len(),
            Self::CasbinRule(data) => data.len(),
            Self::Logs(data) => data.len(),
            Self::SessionRecordings(data) => data.len(),
        }
    }

    fn as_vec(&self) -> Vec<&dyn FieldsToArray> {
        match self {
            Self::Users(data) => data
                .iter()
                .map(|v| v as &dyn FieldsToArray)
                .collect::<Vec<_>>(),
            Self::Targets(data) => data
                .iter()
                .map(|v| v as &dyn FieldsToArray)
                .collect::<Vec<_>>(),
            Self::Secrets(data) => data
                .iter()
                .map(|v| v as &dyn FieldsToArray)
                .collect::<Vec<_>>(),
            Self::TargetSecrets(data) => data
                .iter()
                .map(|v| v as &dyn FieldsToArray)
                .collect::<Vec<_>>(),
            Self::CasbinNames(data) => data
                .iter()
                .map(|v| v as &dyn FieldsToArray)
                .collect::<Vec<_>>(),
            Self::CasbinRule(data) => data
                .iter()
                .map(|v| v as &dyn FieldsToArray)
                .collect::<Vec<_>>(),
            Self::Logs(data) => data
                .iter()
                .map(|v| v as &dyn FieldsToArray)
                .collect::<Vec<_>>(),
            Self::SessionRecordings(data) => data
                .iter()
                .map(|v| v as &dyn FieldsToArray)
                .collect::<Vec<_>>(),
        }
    }

    /// The database's own column names, in every language: this panel shows
    /// the tables as stored.
    fn header(&self, _tr: &'static crate::i18n::Strings) -> Vec<&'static str> {
        match self {
            Self::Users(_) => {
                vec![
                    "id",
                    "username",
                    "email",
                    "password_hash",
                    "authorized_keys",
                    "force_init_pass",
                    "is_active",
                    "updated_by",
                    "updated_at",
                ]
            }
            Self::Targets(_) => {
                vec![
                    "id",
                    "name",
                    "hostname",
                    "port",
                    "server_public_key",
                    "description",
                    "proxy",
                    "is_active",
                    "updated_by",
                    "updated_at",
                ]
            }
            Self::TargetSecrets(_) => {
                vec![
                    "id",
                    "target_id",
                    "secret_id",
                    "is_active",
                    "updated_by",
                    "updated_at",
                ]
            }
            Self::Secrets(_) => {
                vec![
                    "id",
                    "name",
                    "user",
                    "password",
                    "private_key",
                    "public_key",
                    "is_active",
                    "updated_by",
                    "updated_at",
                ]
            }
            Self::CasbinNames(_) => {
                vec![
                    "id",
                    "ptype",
                    "name",
                    "is_active",
                    "updated_by",
                    "updated_at",
                ]
            }
            Self::CasbinRule(_) => {
                vec![
                    "id",
                    "ptype",
                    "v0",
                    "v1",
                    "v2",
                    "v3",
                    "v4",
                    "v5",
                    "updated_by",
                    "updated_at",
                ]
            }
            Self::Logs(_) => {
                vec![
                    "id",
                    "connection_id",
                    "log_type",
                    "user_id",
                    "detail",
                    "created_at",
                ]
            }
            Self::SessionRecordings(_) => {
                vec![
                    "id",
                    "user_id",
                    "target_id",
                    "secret_id",
                    "target_label",
                    "file_path",
                    "started_at",
                    "ended_at",
                    "connection_id",
                    "status",
                ]
            }
        }
    }
}
