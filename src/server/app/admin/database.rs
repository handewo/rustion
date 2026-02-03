use super::table::{AdminTable, DisplayMode, FieldsToArray, TableData as TD};
use crate::database::common::{
    TABLE_CASBIN_NAMES, TABLE_CASBIN_RULE, TABLE_LIST, TABLE_LOGS, TABLE_SECRETS, TABLE_TARGETS,
    TABLE_TARGET_SECRETS, TABLE_USERS,
};
use crate::database::models::*;
use crate::error::Error;
use crossterm::event::{self, KeyCode, KeyModifiers, NoTtyEvent};
use ratatui::backend::NottyBackend;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{self, Color, Style, Stylize};
use ratatui::text::Text;
use ratatui::widgets::{Block, BorderType, Paragraph, Tabs};
use ratatui::{Frame, Terminal};
use std::io::Write;
use std::sync::Arc;
use style::palette::tailwind;
use tokio::runtime::Handle;
use unicode_width::UnicodeWidthStr;

const INFO_TEXT: [&str; 2] = [
    "(Esc) quit | (↑) move up | (↓) move down | (←) move left | (→) move right",
    "(Tab) next tab | (Shift Tab) previous tab | (+) zoom in | (-) zoom out | (PgUp) page up | (PgDn) page down",
];

const LENGTH_UUID: u16 = 36;
const LENGTH_TIMSTAMP: u16 = 14;

pub(super) fn query_table<B, W: Write>(
    tty: NoTtyEvent,
    w: W,
    backend: Arc<B>,
    t_handle: Handle,
) -> Result<(), Error>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    let tty_backend = NottyBackend::new(tty.clone(), w);
    let mut terminal = Terminal::new(tty_backend)?;
    terminal.hide_cursor()?;
    terminal.flush()?;
    App::new(backend, t_handle).run(tty, &mut terminal)?;
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
    backend: Arc<B>,
    t_handle: Handle,
}

impl<B> App<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    fn new(backend: Arc<B>, t_handle: Handle) -> Self {
        let data = TableData::Users(
            t_handle
                .block_on(backend.db_repository().list_users(false))
                .unwrap_or_default(),
        );
        Self {
            table: AdminTable::new(&data, &tailwind::BLUE),
            longest_item_lens: data.constraint_len_calculator(),
            selected_tab: 0,
            last_selected_tab: 1,
            backend,
            t_handle,
            items: data,
        }
    }

    pub fn next_tab(&mut self) {
        self.selected_tab = (self.selected_tab + 1) % TABLE_LIST.len();
    }

    pub fn previous_tab(&mut self) {
        if self.selected_tab == 0 {
            self.selected_tab = TABLE_LIST.len() - 1;
        } else {
            self.selected_tab = (self.selected_tab - 1) % TABLE_LIST.len();
        }
    }

    fn run<W: Write>(
        mut self,
        tty: NoTtyEvent,
        terminal: &mut Terminal<NottyBackend<W>>,
    ) -> Result<(), Error> {
        loop {
            terminal.draw(|frame| self.render(frame))?;

            if let Some(key) = event::read(&tty)?.as_key_press_event() {
                let ctrl_pressed = key.modifiers.contains(KeyModifiers::CONTROL);
                let items_len = self.items.len();
                match key.code {
                    KeyCode::PageUp => self.table.previous_page(),
                    KeyCode::PageDown => self.table.next_page(items_len),
                    KeyCode::Char('f') if ctrl_pressed => self.table.next_page(items_len),
                    KeyCode::Char('b') if ctrl_pressed => self.table.previous_page(),
                    KeyCode::Char('+') => self.table.zoom_in(),
                    KeyCode::Char('-') => self.table.zoom_out(),
                    KeyCode::Tab => self.next_tab(),
                    KeyCode::BackTab => self.previous_tab(),
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
        let layout = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(5),
            Constraint::Length(4),
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
        );
        self.render_footer(frame, footer_area);
    }

    fn refresh_data(&mut self) {
        match TABLE_LIST[self.selected_tab] {
            TABLE_USERS => {
                self.items = TableData::Users(
                    self.t_handle
                        .block_on(self.backend.db_repository().list_users(false))
                        .unwrap_or_default(),
                );
            }
            TABLE_TARGETS => {
                self.items = TableData::Targets(
                    self.t_handle
                        .block_on(self.backend.db_repository().list_targets(false))
                        .unwrap_or_default(),
                );
            }
            TABLE_TARGET_SECRETS => {
                self.items = TableData::TargetSecrets(
                    self.t_handle
                        .block_on(self.backend.db_repository().list_target_secrets(false))
                        .unwrap_or_default(),
                );
            }
            TABLE_SECRETS => {
                self.items = TableData::Secrets(
                    self.t_handle
                        .block_on(self.backend.db_repository().list_secrets(false))
                        .unwrap_or_default(),
                );
            }
            TABLE_CASBIN_NAMES => {
                self.items = TableData::CasbinNames(
                    self.t_handle
                        .block_on(self.backend.db_repository().list_casbin_names(false))
                        .unwrap_or_default(),
                );
            }
            TABLE_CASBIN_RULE => {
                self.items = TableData::CasbinRule(
                    self.t_handle
                        .block_on(self.backend.db_repository().list_casbin_rules())
                        .unwrap_or_default(),
                );
            }
            TABLE_LOGS => {
                self.items = TableData::Logs(
                    self.t_handle
                        .block_on(self.backend.db_repository().list_logs())
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
        if self.selected_tab != self.last_selected_tab {
            self.refresh_data();
            self.last_selected_tab = self.selected_tab
        }

        let tabs = Tabs::new(
            TABLE_LIST
                .iter()
                .map(|v| format!("{v:^17}").fg(tailwind::SLATE.c400)),
        )
        .style(Color::White)
        .highlight_style(
            Style::default()
                .magenta()
                .on_black()
                .bold()
                .fg(self.table.colors.header_fg)
                .bg(self.table.colors.header_bg),
        )
        .select(self.selected_tab)
        .divider(" ")
        .padding("", "");
        frame.render_widget(tabs, area);
    }

    fn render_footer(&self, frame: &mut Frame, area: Rect) {
        let info_footer = Paragraph::new(Text::from_iter(INFO_TEXT))
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

enum TableData {
    Users(Vec<User>),
    Targets(Vec<Target>),
    Secrets(Vec<Secret>),
    TargetSecrets(Vec<TargetSecret>),
    CasbinNames(Vec<CasbinName>),
    CasbinRule(Vec<CasbinRule>),
    Logs(Vec<Log>),
}

impl TableData {
    fn constraint_len_calculator(&self) -> Vec<Constraint> {
        match self {
            Self::Users(ref data) => {
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
            Self::Targets(ref data) => {
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
            Self::Secrets(ref data) => {
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
            Self::CasbinNames(ref data) => {
                let name_len = data
                    .iter()
                    .map(|v| v.name.as_str())
                    .map(UnicodeWidthStr::width)
                    .max()
                    .unwrap_or(0)
                    .max(4);

                let ptype_len = data.iter().map(|v| v.ptype.len()).max().unwrap_or(0).max(5);

                vec![
                    Constraint::Length(LENGTH_UUID), // id
                    Constraint::Length(ptype_len as u16),
                    Constraint::Length(name_len as u16),
                    Constraint::Length(9), // is_active
                    Constraint::Length(LENGTH_UUID),
                    Constraint::Length(LENGTH_TIMSTAMP),
                ]
            }
            Self::CasbinRule(ref data) => {
                // UUIDs have fixed width of 36 characters
                let uuid_len = 36;
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
                    Constraint::Length(uuid_len as u16),
                    Constraint::Length(uuid_len as u16),
                    Constraint::Length(uuid_len as u16),
                    Constraint::Length(v3_len as u16),
                    Constraint::Length(v4_len as u16),
                    Constraint::Length(v5_len as u16),
                    Constraint::Length(LENGTH_UUID),
                    Constraint::Length(LENGTH_TIMSTAMP),
                ]
            }
            Self::Logs(ref data) => {
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
                    Constraint::Length(LENGTH_UUID),
                    Constraint::Length(log_type_len as u16),
                    Constraint::Length(LENGTH_UUID),
                    Constraint::Length(detail_len as u16),
                    Constraint::Length(LENGTH_TIMSTAMP),
                ]
            }
        }
    }
}

impl super::table::TableData for TableData {
    fn len(&self) -> usize {
        match self {
            Self::Users(ref data) => data.len(),
            Self::Targets(ref data) => data.len(),
            Self::Secrets(ref data) => data.len(),
            Self::TargetSecrets(ref data) => data.len(),
            Self::CasbinNames(ref data) => data.len(),
            Self::CasbinRule(ref data) => data.len(),
            Self::Logs(ref data) => data.len(),
        }
    }

    fn as_vec(&self) -> Vec<&dyn FieldsToArray> {
        match self {
            Self::Users(ref data) => data
                .iter()
                .map(|v| v as &dyn FieldsToArray)
                .collect::<Vec<_>>(),
            Self::Targets(ref data) => data
                .iter()
                .map(|v| v as &dyn FieldsToArray)
                .collect::<Vec<_>>(),
            Self::Secrets(ref data) => data
                .iter()
                .map(|v| v as &dyn FieldsToArray)
                .collect::<Vec<_>>(),
            Self::TargetSecrets(ref data) => data
                .iter()
                .map(|v| v as &dyn FieldsToArray)
                .collect::<Vec<_>>(),
            Self::CasbinNames(ref data) => data
                .iter()
                .map(|v| v as &dyn FieldsToArray)
                .collect::<Vec<_>>(),
            Self::CasbinRule(ref data) => data
                .iter()
                .map(|v| v as &dyn FieldsToArray)
                .collect::<Vec<_>>(),
            Self::Logs(ref data) => data
                .iter()
                .map(|v| v as &dyn FieldsToArray)
                .collect::<Vec<_>>(),
        }
    }

    fn header(&self) -> Vec<&str> {
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
                    "connection_id",
                    "log_type",
                    "user_id",
                    "detail",
                    "created_at",
                ]
            }
        }
    }
}
