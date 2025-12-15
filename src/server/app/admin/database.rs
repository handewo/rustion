use crate::database::models::*;
use crate::error::Error;
use crate::server::common::{
    TABLE_CASBIN_RULE, TABLE_INTERNAL_OBJECTS, TABLE_LIST, TABLE_LOGS, TABLE_SECRETS,
    TABLE_TARGETS, TABLE_TARGET_SECRETS, TABLE_USERS,
};
use crossterm::event::{self, KeyCode, KeyModifiers, NoTtyEvent};
use ratatui::backend::NottyBackend;
use ratatui::layout::{Constraint, Layout, Margin, Rect};
use ratatui::style::{self, Color, Modifier, Style, Stylize};
use ratatui::text::Text;
use ratatui::widgets::{
    Block, BorderType, Cell, HighlightSpacing, Paragraph, Row, Scrollbar, ScrollbarOrientation,
    ScrollbarState, Table, TableState, Tabs,
};
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

struct TableColors {
    buffer_bg: Color,
    header_bg: Color,
    header_fg: Color,
    row_fg: Color,
    selected_row_style_fg: Color,
    selected_column_style_fg: Color,
    selected_cell_style_fg: Color,
    normal_row_color: Color,
    alt_row_color: Color,
    footer_border_color: Color,
}

impl TableColors {
    const fn new(color: &tailwind::Palette) -> Self {
        Self {
            buffer_bg: tailwind::SLATE.c950,
            header_bg: color.c900,
            header_fg: tailwind::SLATE.c200,
            row_fg: tailwind::SLATE.c200,
            selected_row_style_fg: color.c400,
            selected_column_style_fg: color.c400,
            selected_cell_style_fg: color.c600,
            normal_row_color: tailwind::SLATE.c950,
            alt_row_color: tailwind::SLATE.c900,
            footer_border_color: color.c400,
        }
    }
}

struct App<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    state: TableState,
    items: TableData,
    longest_item_lens: Vec<Constraint>,
    scroll_state: ScrollbarState,
    row_height: usize,
    selected_tab: usize,
    last_selected_tab: usize,
    colors: TableColors,
    table_size: (u16, u16),
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
            state: TableState::default().with_selected(0),
            longest_item_lens: data.constraint_len_calculator(),
            scroll_state: ScrollbarState::new(((data.len() - 1) * 2).max(0)),
            colors: TableColors::new(&tailwind::BLUE),
            row_height: 2,
            selected_tab: 0,
            last_selected_tab: 1,
            table_size: (0, 0),
            backend,
            t_handle,
            items: data,
        }
    }

    pub fn previous_page(&mut self) {
        let rows = (self.table_size.1 as usize - 1) / self.row_height;
        *self.state.offset_mut() = if self.state.offset() < rows {
            0
        } else {
            self.state.offset() - rows
        };
        let i = match self.state.selected() {
            Some(i) => {
                if i < rows {
                    i
                } else {
                    i - rows
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
        self.scroll_state = self.scroll_state.position(i * self.row_height);
    }

    pub fn next_page(&mut self) {
        let rows = (self.table_size.1 as usize - 1) / self.row_height;
        let mut is_offset = false;
        if self.state.offset() + rows <= self.items.len() {
            *self.state.offset_mut() = self.state.offset() + rows;
        } else {
            is_offset = true;
        }
        let i = match self.state.selected() {
            Some(i) => {
                if is_offset {
                    i
                } else if i >= self.items.len() - rows {
                    self.state.offset()
                } else {
                    i + rows
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
        self.scroll_state = self.scroll_state.position(i * self.row_height);
    }

    pub fn next_row(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.items.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
        self.scroll_state = self.scroll_state.position(i * self.row_height);
    }

    pub fn previous_row(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.items.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
        self.scroll_state = self.scroll_state.position(i * self.row_height);
    }

    pub fn next_column(&mut self) {
        self.state.select_next_column();
    }

    pub fn previous_column(&mut self) {
        self.state.select_previous_column();
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

    pub fn zoom_in(&mut self) {
        self.row_height = self.row_height.saturating_add(1).min(20);
    }

    pub fn zoom_out(&mut self) {
        self.row_height = self.row_height.saturating_sub(1).max(1);
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
                match key.code {
                    KeyCode::PageUp => self.previous_page(),
                    KeyCode::PageDown => self.next_page(),
                    KeyCode::Char('f') if ctrl_pressed => self.next_page(),
                    KeyCode::Char('b') if ctrl_pressed => self.previous_page(),
                    KeyCode::Char('+') => self.zoom_in(),
                    KeyCode::Char('-') => self.zoom_out(),
                    KeyCode::Tab => self.next_tab(),
                    KeyCode::BackTab => self.previous_tab(),
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Char('j') | KeyCode::Down => self.next_row(),
                    KeyCode::Char('k') | KeyCode::Up => self.previous_row(),
                    KeyCode::Char('l') | KeyCode::Right => self.next_column(),
                    KeyCode::Char('h') | KeyCode::Left => self.previous_column(),
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

        self.table_size = (table_area.width, table_area.height);

        self.render_tabs(frame, header_area);
        self.render_table(frame, table_area);
        self.render_scrollbar(frame, table_area);
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
            TABLE_INTERNAL_OBJECTS => {
                self.items = TableData::InternalObjects(
                    self.t_handle
                        .block_on(self.backend.db_repository().list_internal_objects(false))
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
        self.state.select(Some(0));
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
                .fg(self.colors.header_fg)
                .bg(self.colors.header_bg),
        )
        .select(self.selected_tab)
        .divider(" ")
        .padding("", "");
        frame.render_widget(tabs, area);
    }

    fn render_table(&mut self, frame: &mut Frame, area: Rect) {
        let header_style = Style::default()
            .fg(self.colors.header_fg)
            .bg(self.colors.header_bg);
        let selected_row_style = Style::default()
            .add_modifier(Modifier::REVERSED)
            .fg(self.colors.selected_row_style_fg);
        let selected_col_style = Style::default().fg(self.colors.selected_column_style_fg);
        let selected_cell_style = Style::default()
            .add_modifier(Modifier::REVERSED)
            .fg(self.colors.selected_cell_style_fg);

        let header = self
            .items
            .header()
            .into_iter()
            .map(Cell::from)
            .collect::<Row>()
            .style(header_style)
            .height(1);
        let items = self.items.as_vec();
        let rows = items.iter().enumerate().map(|(i, data)| {
            let color = match i % 2 {
                0 => self.colors.normal_row_color,
                _ => self.colors.alt_row_color,
            };
            let item = data.ref_array();
            item.into_iter()
                .map(|content| Cell::from(Text::from(content.to_string())))
                .collect::<Row>()
                .style(Style::new().fg(self.colors.row_fg).bg(color))
                .height(self.row_height as u16)
        });
        let bar = vec!["   ".into(); self.row_height];
        let t = Table::new(rows, self.longest_item_lens.clone())
            .header(header)
            .row_highlight_style(selected_row_style)
            .column_highlight_style(selected_col_style)
            .cell_highlight_style(selected_cell_style)
            .highlight_symbol(Text::from(bar))
            .bg(self.colors.buffer_bg)
            .highlight_spacing(HighlightSpacing::Always);
        frame.render_stateful_widget(t, area, &mut self.state);
    }

    fn render_scrollbar(&mut self, frame: &mut Frame, area: Rect) {
        self.scroll_state = self
            .scroll_state
            .content_length((self.items.len() - 1) * self.row_height)
            .position(self.state.selected().unwrap_or(0) * self.row_height);
        frame.render_stateful_widget(
            Scrollbar::default()
                .orientation(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None),
            area.inner(Margin {
                vertical: 1,
                horizontal: 1,
            }),
            &mut self.scroll_state,
        );
    }

    fn render_footer(&self, frame: &mut Frame, area: Rect) {
        let info_footer = Paragraph::new(Text::from_iter(INFO_TEXT))
            .style(
                Style::new()
                    .fg(self.colors.row_fg)
                    .bg(self.colors.buffer_bg),
            )
            .centered()
            .block(
                Block::bordered()
                    .border_type(BorderType::Double)
                    .border_style(Style::new().fg(self.colors.footer_border_color)),
            );
        frame.render_widget(info_footer, area);
    }
}

enum TableData {
    Users(Vec<User>),
    Targets(Vec<Target>),
    Secrets(Vec<Secret>),
    TargetSecrets(Vec<TargetSecret>),
    InternalObjects(Vec<InternalObject>),
    CasbinRule(Vec<CasbinRule>),
    Logs(Vec<Log>),
}

impl TableData {
    fn len(&self) -> usize {
        match self {
            Self::Users(ref data) => data.len(),
            Self::Targets(ref data) => data.len(),
            Self::Secrets(ref data) => data.len(),
            Self::TargetSecrets(ref data) => data.len(),
            Self::InternalObjects(ref data) => data.len(),
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
            Self::InternalObjects(ref data) => data
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
                    .map(|v| v.server_public_key.as_str())
                    .map(UnicodeWidthStr::width)
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

                vec![
                    Constraint::Length(LENGTH_UUID), // id
                    Constraint::Length(name_len as u16),
                    Constraint::Length(user_len as u16),
                    Constraint::Length(8),  // password (shown as <hidden>)
                    Constraint::Length(11), // private_key (shown as <hidden>)
                    Constraint::Length(10), // public_key (shown as <hidden>)
                    Constraint::Length(9),  // is_active
                    Constraint::Length(LENGTH_UUID), // created_by
                    Constraint::Length(LENGTH_TIMSTAMP),
                ]
            }
            Self::InternalObjects(ref data) => {
                let name_len = data
                    .iter()
                    .map(|v| v.name.as_str())
                    .map(UnicodeWidthStr::width)
                    .max()
                    .unwrap_or(0)
                    .max(4);

                vec![
                    Constraint::Length(name_len as u16),
                    Constraint::Length(9), // is_active
                    Constraint::Length(LENGTH_UUID),
                    Constraint::Length(LENGTH_TIMSTAMP),
                ]
            }
            Self::CasbinRule(ref data) => {
                let v0_len = data
                    .iter()
                    .map(|v| v.v0.as_str())
                    .map(UnicodeWidthStr::width)
                    .max()
                    .unwrap_or(0)
                    .max(2);
                let v1_len = data
                    .iter()
                    .map(|v| v.v1.as_str())
                    .map(UnicodeWidthStr::width)
                    .max()
                    .unwrap_or(0)
                    .max(2);
                let v2_len = data
                    .iter()
                    .map(|v| v.v2.as_str())
                    .map(UnicodeWidthStr::width)
                    .max()
                    .unwrap_or(0)
                    .max(2);
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
                    Constraint::Length(v0_len as u16),
                    Constraint::Length(v1_len as u16),
                    Constraint::Length(v2_len as u16),
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
            Self::InternalObjects(_) => {
                vec!["name", "is_active", "updated_by", "updated_at"]
            }
            Self::CasbinRule(_) => {
                vec![
                    "id",
                    "ptype",
                    "p0",
                    "p1",
                    "p2",
                    "p3",
                    "p4",
                    "p5",
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

trait FieldsToArray {
    fn ref_array(&self) -> Vec<String>;
}

impl FieldsToArray for User {
    fn ref_array(&self) -> Vec<String> {
        vec![
            self.id.clone(),
            self.username.clone(),
            self.email.clone().unwrap_or_default(),
            self.print_password(),
            self.print_authorized_keys(),
            self.force_init_pass.to_string(),
            self.is_active.to_string(),
            self.updated_by.clone(),
            self.updated_at.to_string(),
        ]
    }
}

impl FieldsToArray for Target {
    fn ref_array(&self) -> Vec<String> {
        vec![
            self.id.clone(),
            self.name.clone(),
            self.hostname.clone(),
            self.port.to_string(),
            self.server_public_key.clone(),
            self.description.clone().unwrap_or_default(),
            self.is_active.to_string(),
            self.updated_by.clone(),
            self.updated_at.to_string(),
        ]
    }
}

impl FieldsToArray for TargetSecret {
    fn ref_array(&self) -> Vec<String> {
        vec![
            self.id.clone(),
            self.target_id.clone(),
            self.secret_id.clone(),
            self.is_active.to_string(),
            self.updated_by.clone(),
            self.updated_at.to_string(),
        ]
    }
}

impl FieldsToArray for Secret {
    fn ref_array(&self) -> Vec<String> {
        vec![
            self.id.clone(),
            self.name.clone(),
            self.user.clone(),
            self.print_password(),
            self.print_private_key(),
            self.print_public_key(),
            self.is_active.to_string(),
            self.updated_by.clone(),
            self.updated_at.to_string(),
        ]
    }
}

impl FieldsToArray for InternalObject {
    fn ref_array(&self) -> Vec<String> {
        vec![
            self.name.clone(),
            self.is_active.to_string(),
            self.updated_by.clone(),
            self.updated_at.to_string(),
        ]
    }
}

impl FieldsToArray for CasbinRule {
    fn ref_array(&self) -> Vec<String> {
        vec![
            self.id.clone(),
            self.ptype.clone(),
            self.v0.clone(),
            self.v1.clone(),
            self.v2.clone(),
            self.v3.clone(),
            self.v4.clone(),
            self.v5.clone(),
            self.updated_by.clone(),
            self.updated_at.to_string(),
        ]
    }
}

impl FieldsToArray for Log {
    fn ref_array(&self) -> Vec<String> {
        vec![
            self.connection_id.clone(),
            self.log_type.clone(),
            self.user_id.clone(),
            self.detail.clone(),
            self.created_at.to_string(),
        ]
    }
}
