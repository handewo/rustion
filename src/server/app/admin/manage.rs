use super::common::*;
use super::widgets::{centered_area, render_message_dialog, Message};
use crate::database::models::*;
use crate::error::Error;
use crate::server::app::admin::widgets::render_confirm_dialog;
use ::log::{error, warn};
use crossterm::event::{self, KeyCode, KeyModifiers, NoTtyEvent};
use ratatui::backend::NottyBackend;
use ratatui::layout::{Constraint, Layout, Margin, Rect};
use ratatui::style::{self, Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Text};
use ratatui::widgets::{
    Block, BorderType, Cell, Clear, HighlightSpacing, Paragraph, Row, Scrollbar,
    ScrollbarOrientation, ScrollbarState, Table, TableState, Tabs, Widget,
};
use ratatui::{Frame, Terminal};
use std::fmt;
use std::io::Write;
use std::sync::Arc;
use style::palette::tailwind;
use tokio::runtime::Handle;
use unicode_width::UnicodeWidthStr;

mod target;
mod user;

const HELP_TEXT: [&str; 2] = [
    "(a) add | (e) edit | (d) delete | (Esc) quit | (↑) move up | (↓) move down | (←) move left | (→) move right",
    "(Tab) next tab | (Shift Tab) previous tab | (+) zoom in | (-) zoom out | (PgUp) page up | (PgDn) page down",
];

const LENGTH_UUID: u16 = 32;
const LENGTH_TIMESTAMP: u16 = 14;
const MAX_POPUP_WINDOW_COL: u16 = 60;
const MAX_POPUP_WINDOW_ROW: u16 = 40;
const MIN_WINDOW_COL: u16 = 20;
const MIN_WINDOW_ROW: u16 = 15;

pub(super) fn manage<B, W: Write>(
    tty: NoTtyEvent,
    w: W,
    user_id: String,
    handler_id: String,
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
    App::new(backend, t_handle, user_id, handler_id).run(tty, &mut terminal)?;
    Ok(())
}

struct EditorColors {
    border_color: Color,
    title_color: Color,
}

impl EditorColors {
    const fn new(color: &tailwind::Palette) -> Self {
        Self {
            border_color: color.c400,
            title_color: tailwind::SLATE.c200,
        }
    }
}

struct TableColors {
    buffer_bg: Color,
    header_bg: Color,
    header_fg: Color,
    row_fg: Color,
    tab_font: Color,
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
            tab_font: tailwind::SLATE.c400,
            selected_row_style_fg: color.c400,
            selected_column_style_fg: color.c400,
            selected_cell_style_fg: color.c600,
            normal_row_color: tailwind::SLATE.c950,
            alt_row_color: tailwind::SLATE.c900,
            footer_border_color: color.c400,
        }
    }

    pub fn grep(&mut self) {
        self.header_bg = tailwind::GRAY.c900;
        self.selected_row_style_fg = tailwind::GRAY.c400;
        self.selected_column_style_fg = tailwind::GRAY.c400;
        self.selected_cell_style_fg = tailwind::GRAY.c600;
    }
}

enum Popup {
    None,
    Add,
    Edit,
    Delete(usize),
}

#[repr(usize)]
#[derive(Debug, PartialEq, PartialOrd, Clone, Copy)]
enum SelectedTab {
    Users = 0,
    Targets = 1,
    Secrets = 2,
}

impl fmt::Display for SelectedTab {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SelectedTab::Users => write!(f, "Users"),
            SelectedTab::Targets => write!(f, "Targets"),
            SelectedTab::Secrets => write!(f, "Secrets"),
        }
    }
}

impl SelectedTab {
    fn next(&self) -> Self {
        match self {
            SelectedTab::Users => SelectedTab::Targets,
            SelectedTab::Targets => SelectedTab::Secrets,
            SelectedTab::Secrets => SelectedTab::Users,
        }
    }

    fn previous(&self) -> Self {
        match self {
            SelectedTab::Users => SelectedTab::Secrets,
            SelectedTab::Targets => SelectedTab::Users,
            SelectedTab::Secrets => SelectedTab::Targets,
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
    selected_tab: SelectedTab,
    last_selected_tab: SelectedTab,
    popup: Popup,
    table_colors: TableColors,
    editor_colors: EditorColors,
    table_size: (u16, u16),
    backend: Arc<B>,
    t_handle: Handle,
    handler_id: String,
    user_id: String,
    editor: Editor,
    message: Option<Message>,
}

impl<B> App<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    fn new(backend: Arc<B>, t_handle: Handle, user_id: String, handler_id: String) -> Self {
        let data = TableData::Users(
            match t_handle.block_on(backend.db_repository().list_users(false)) {
                Ok(d) => d,
                Err(e) => {
                    error!("Failed to list users: {}", e);
                    Vec::new()
                }
            },
        );
        Self {
            state: TableState::default().with_selected(0),
            longest_item_lens: data.constraint_len_calculator(),
            scroll_state: ScrollbarState::new((data.len().max(1) - 1) * 2),
            table_colors: TableColors::new(&tailwind::BLUE),
            editor_colors: EditorColors::new(&tailwind::BLUE),
            row_height: 2,
            selected_tab: SelectedTab::Users,
            last_selected_tab: SelectedTab::Users.next(),
            popup: Popup::None,
            table_size: (0, 0),
            backend,
            t_handle,
            handler_id,
            items: data,
            user_id,
            editor: Editor::None,
            message: None,
        }
    }

    fn previous_page(&mut self) {
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

    fn next_page(&mut self) {
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

    fn next_row(&mut self) {
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

    fn previous_row(&mut self) {
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

    fn next_column(&mut self) {
        self.state.select_next_column();
    }

    fn previous_column(&mut self) {
        self.state.select_previous_column();
    }

    fn next_tab(&mut self) {
        self.selected_tab = self.selected_tab.next();
    }

    fn previous_tab(&mut self) {
        self.selected_tab = self.selected_tab.previous();
    }

    fn zoom_in(&mut self) {
        self.row_height = self.row_height.saturating_add(1).min(20);
    }

    fn zoom_out(&mut self) {
        self.row_height = self.row_height.saturating_sub(1).max(1);
    }

    fn add_form(&mut self) {
        self.popup = Popup::Add;
        match self.selected_tab {
            SelectedTab::Users => {
                self.editor = Editor::User(Box::new(user::UserEditor::new(User::new(
                    self.user_id.clone(),
                ))))
            }
            SelectedTab::Targets => {
                self.editor = Editor::Target(Box::new(target::TargetEditor::new(User::new(
                    self.user_id.clone(),
                ))))
            }
            _ => {
                todo!()
            }
        }
    }

    fn edit_form(&mut self) -> bool {
        self.popup = Popup::Edit;
        match self.selected_tab {
            SelectedTab::Users => {
                let idx = self.state.selected().unwrap();
                let user = match self.items.get_user(idx) {
                    Some(u) => u,
                    None => {
                        return false;
                    }
                };
                self.editor = Editor::User(Box::new(user::UserEditor::new(user)));
            }
            _ => {
                todo!()
            }
        }
        true
    }

    fn do_delete(&mut self, idx: usize) {
        match self.selected_tab {
            SelectedTab::Users => {
                self.popup = Popup::None;
                self.clear_form();
                if let Some(u) = self.items.get_user(idx) {
                    let result = self
                        .t_handle
                        .block_on(self.backend.db_repository().delete_user(&u.id));

                    if let Err(e) = result {
                        self.message = Some(Message::Error(vec!["Internal error".into()]));
                        warn!(
                            "[{}] Delete user: {} failed, {}",
                            self.handler_id, u.username, e
                        );
                        return;
                    }
                    self.message = Some(Message::Success(vec!["User deleted".into()]));
                    self.refresh_data();
                }
            }
            _ => {
                todo!()
            }
        }
    }

    fn could_delete(&mut self, idx: usize) -> bool {
        match self.selected_tab {
            SelectedTab::Users => {
                if self.items.get_user(idx).is_some() {
                    return true;
                }
            }
            _ => {
                todo!()
            }
        }
        false
    }

    fn clear_form(&mut self) {
        self.popup = Popup::None;
        self.editor = Editor::None;
        self.table_colors = TableColors::new(&tailwind::BLUE);
    }

    fn run<W: Write>(
        mut self,
        tty: NoTtyEvent,
        terminal: &mut Terminal<NottyBackend<W>>,
    ) -> Result<(), Error> {
        loop {
            terminal.draw(|frame| self.render(frame))?;

            if let Some(key) = event::read(&tty)?.as_key_press_event() {
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
                match self.popup {
                    Popup::None => match key.code {
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
                        KeyCode::Char('d') => {
                            self.table_colors.grep();

                            let idx = self.state.selected().unwrap();
                            if self.could_delete(idx) {
                                self.popup = Popup::Delete(idx);
                            } else {
                                self.clear_form();
                            }
                        }
                        KeyCode::Char('a') => {
                            self.table_colors.grep();
                            self.add_form()
                        }
                        KeyCode::Char('e') => {
                            self.table_colors.grep();
                            if !self.edit_form() {
                                self.clear_form();
                            }
                        }
                        _ => {}
                    },
                    Popup::Add => match self.editor {
                        Editor::User(ref mut e) => {
                            if e.as_mut().handle_key_event(key.code, key.modifiers) {
                                if !e.show_cancel_confirmation {
                                    let mut user = e.user.to_owned();
                                    if e.generate_password {
                                        let password = crate::common::gen_password(12);
                                        self.backend.set_password(&mut user, &password)?;
                                    }
                                    let result = self
                                        .t_handle
                                        .block_on(self.backend.db_repository().create_user(&user));

                                    if let Err(err) = result {
                                        let msg = match err {
                                            Error::Sqlx(sqlx::Error::Database(db_err))
                                                if db_err.kind()
                                                    == sqlx::error::ErrorKind::UniqueViolation =>
                                            {
                                                "Username already exists"
                                            }
                                            _ => "Internal error",
                                        };

                                        self.message = Some(Message::Error(vec![msg.into()]));
                                        continue;
                                    }
                                    self.message = Some(Message::Success(vec!["User added".into()]))
                                };
                                self.clear_form();
                                self.refresh_data();
                            }
                        }
                        Editor::Target(ref mut e) => {
                            if e.as_mut().handle_key_event(key.code, key.modifiers) {
                                self.clear_form();
                            }
                        }
                        _ => {
                            todo!()
                        }
                    },
                    Popup::Edit => match self.editor {
                        Editor::User(ref mut e) => {
                            if e.as_mut().handle_key_event(key.code, key.modifiers) {
                                if !e.show_cancel_confirmation {
                                    let mut user = e.user.to_owned();
                                    if e.generate_password {
                                        let password = crate::common::gen_password(12);
                                        self.backend.set_password(&mut user, &password)?;
                                    }
                                    let result = self
                                        .t_handle
                                        .block_on(self.backend.db_repository().update_user(&user));

                                    if result.is_err() {
                                        self.message =
                                            Some(Message::Error(vec!["Internal error".into()]));
                                        continue;
                                    }
                                    self.message =
                                        Some(Message::Success(vec!["User updated".into()]))
                                };
                                self.clear_form();
                                self.refresh_data();
                            }
                        }
                        _ => {
                            todo!()
                        }
                    },
                    Popup::Delete(i) => match key.code {
                        KeyCode::Char('y') | KeyCode::Char('Y') => {
                            self.do_delete(i);
                        }
                        KeyCode::Char('n') | KeyCode::Char('N') => {
                            self.popup = Popup::None;
                            self.clear_form()
                        }
                        _ => {}
                    },
                }
            }
        }
    }

    fn render(&mut self, frame: &mut Frame) {
        let area = frame.area();
        if area.width < MIN_WINDOW_COL || area.height < MIN_WINDOW_ROW {
            self.render_notice(frame, area, "window is too small");
            return;
        }
        let layout = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(5),
            Constraint::Length(4),
        ]);
        let [header_area, table_area, footer_area] = layout.areas(area);

        self.table_size = (table_area.width, table_area.height);

        self.render_tabs(frame, header_area);
        self.render_table(frame, table_area);
        self.render_scrollbar(frame, table_area);
        self.render_popup(frame, table_area);
        self.render_message(frame, table_area);
        self.render_footer(frame, footer_area);
    }

    fn refresh_data(&mut self) {
        match self.selected_tab {
            SelectedTab::Users => {
                self.items = TableData::Users(
                    self.t_handle
                        .block_on(self.backend.db_repository().list_users(false))
                        .unwrap_or_default(),
                );
            }
            SelectedTab::Targets => {
                self.items = TableData::Targets(
                    self.t_handle
                        .block_on(self.backend.db_repository().list_targets(false))
                        .unwrap_or_default(),
                );
            }
            SelectedTab::Secrets => {
                self.items = TableData::Secrets(
                    self.t_handle
                        .block_on(self.backend.db_repository().list_secrets(false))
                        .unwrap_or_default(),
                );
            }
        };
        self.longest_item_lens = self.items.constraint_len_calculator();
    }

    fn render_tabs(&mut self, frame: &mut Frame, area: Rect) {
        if self.selected_tab != self.last_selected_tab {
            self.refresh_data();
            self.state.select(Some(0));
            self.last_selected_tab = self.selected_tab
        }

        let tabs = Tabs::new(
            MANAGE_LIST
                .iter()
                .map(|v| format!("{v:^17}").fg(self.table_colors.tab_font)),
        )
        .style(self.table_colors.header_bg)
        .highlight_style(
            Style::default()
                .magenta()
                .on_black()
                .bold()
                .fg(self.table_colors.header_fg)
                .bg(self.table_colors.header_bg),
        )
        .select(self.selected_tab as usize)
        .divider(" ")
        .padding("", "");
        frame.render_widget(tabs, area);
    }

    fn render_notice(&mut self, frame: &mut Frame, area: Rect, msg: &str) {
        let paragraph = Paragraph::new(msg);
        frame.render_widget(paragraph, area);
    }

    fn render_table(&mut self, frame: &mut Frame, area: Rect) {
        let header_style = Style::default()
            .fg(self.table_colors.header_fg)
            .bg(self.table_colors.header_bg);
        let selected_row_style = Style::default()
            .add_modifier(Modifier::REVERSED)
            .fg(self.table_colors.selected_row_style_fg);
        let selected_col_style = Style::default().fg(self.table_colors.selected_column_style_fg);
        let selected_cell_style = Style::default()
            .add_modifier(Modifier::REVERSED)
            .fg(self.table_colors.selected_cell_style_fg);

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
                0 => self.table_colors.normal_row_color,
                _ => self.table_colors.alt_row_color,
            };
            let item = data.ref_array();
            item.into_iter()
                .map(|content| Cell::from(Text::from(content.to_string())))
                .collect::<Row>()
                .style(Style::new().fg(self.table_colors.row_fg).bg(color))
                .height(self.row_height as u16)
        });
        let bar = vec!["   ".into(); self.row_height];
        let t = Table::new(rows, self.longest_item_lens.clone())
            .header(header)
            .row_highlight_style(selected_row_style)
            .column_highlight_style(selected_col_style)
            .cell_highlight_style(selected_cell_style)
            .highlight_symbol(Text::from(bar))
            .bg(self.table_colors.buffer_bg)
            .highlight_spacing(HighlightSpacing::Always);
        frame.render_stateful_widget(t, area, &mut self.state);
    }

    fn render_scrollbar(&mut self, frame: &mut Frame, area: Rect) {
        self.scroll_state = self
            .scroll_state
            .content_length((self.items.len().max(1) - 1) * self.row_height)
            .position(self.state.selected().unwrap_or(0) * self.row_height);
        frame.render_stateful_widget(
            Scrollbar::default().orientation(ScrollbarOrientation::VerticalRight),
            area.inner(Margin {
                vertical: 1,
                horizontal: 1,
            }),
            &mut self.scroll_state,
        );
    }

    fn render_message(&mut self, frame: &mut Frame, area: Rect) {
        if let Some(ref msg) = self.message {
            let popup_area = if area.width <= MAX_POPUP_WINDOW_COL {
                area
            } else {
                centered_area(
                    area,
                    MAX_POPUP_WINDOW_COL,
                    area.height.min(MAX_POPUP_WINDOW_ROW),
                )
            };
            render_message_dialog(popup_area, frame.buffer_mut(), msg);
        }
    }

    fn render_popup(&mut self, frame: &mut Frame, area: Rect) {
        if let Popup::None = self.popup {
            return;
        }

        let popup_area = if area.width <= MAX_POPUP_WINDOW_COL {
            area
        } else {
            centered_area(
                area,
                MAX_POPUP_WINDOW_COL,
                area.height.min(MAX_POPUP_WINDOW_ROW),
            )
        };

        let title = match self.popup {
            Popup::Add => match self.editor {
                Editor::User(_) => Line::styled("Add New User", Style::default().bold()),
                Editor::Target(_) => Line::styled("Add New Target", Style::default().bold()),
                _ => todo!(),
            },
            Popup::Edit => match self.editor {
                Editor::User(_) => Line::styled("Edit User", Style::default().bold()),
                Editor::Target(_) => Line::styled("Edit Target", Style::default().bold()),
                _ => todo!(),
            },
            Popup::Delete(_) => {
                match self.selected_tab {
                    SelectedTab::Users => {
                        render_confirm_dialog(
                            popup_area,
                            frame.buffer_mut(),
                            &["Delete selected user?".to_string()],
                        );
                    }
                    _ => todo!(),
                };
                return;
            }
            _ => unreachable!(),
        };
        let popup = Block::bordered()
            .title(title)
            .title_style(Style::new().fg(self.editor_colors.title_color))
            .border_style(Style::new().fg(self.editor_colors.border_color))
            .border_type(BorderType::Double);

        frame.render_widget(Clear, popup_area);
        frame.render_widget(popup, popup_area);
        frame.render_widget(&mut self.editor, popup_area);
    }

    fn render_footer(&self, frame: &mut Frame, area: Rect) {
        let text = match self.editor {
            Editor::User(ref e) => e.as_ref().help_text,
            Editor::Target(ref e) => e.as_ref().help_text,
            Editor::None => HELP_TEXT,
        };
        let info_footer = Paragraph::new(Text::from_iter(text))
            .style(
                Style::new()
                    .fg(self.table_colors.row_fg)
                    .bg(self.table_colors.buffer_bg),
            )
            .centered()
            .block(
                Block::bordered()
                    .border_type(BorderType::Double)
                    .border_style(Style::new().fg(self.table_colors.footer_border_color)),
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
    fn get_user(&self, i: usize) -> Option<User> {
        if let TableData::Users(data) = self {
            data.get(i).cloned()
        } else {
            None
        }
    }

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
                    Constraint::Length(LENGTH_TIMESTAMP),
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
                    Constraint::Length(LENGTH_TIMESTAMP),
                ]
            }

            Self::TargetSecrets(_) => {
                vec![
                    Constraint::Length(LENGTH_UUID), // id
                    Constraint::Length(LENGTH_UUID), // target_id
                    Constraint::Length(LENGTH_UUID), // secret_id
                    Constraint::Length(9),           // is_active
                    Constraint::Length(LENGTH_UUID), // created_by
                    Constraint::Length(LENGTH_TIMESTAMP),
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
                    Constraint::Length(LENGTH_TIMESTAMP),
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
                    Constraint::Length(LENGTH_TIMESTAMP),
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
                    Constraint::Length(LENGTH_TIMESTAMP),
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
                    Constraint::Length(LENGTH_TIMESTAMP),
                ]
            }
        }
    }

    fn header(&self) -> Vec<&str> {
        match self {
            Self::Users(_) => {
                vec![
                    "username",
                    "email",
                    "password_hash",
                    "authorized_keys",
                    "force_init_pass",
                    "is_active",
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
            self.username.clone(),
            self.email.clone().unwrap_or_default(),
            self.print_password(),
            self.print_authorized_keys(),
            self.force_init_pass.to_string(),
            self.is_active.to_string(),
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

enum Editor {
    User(Box<user::UserEditor>),
    Target(Box<target::TargetEditor>),
    None,
}

impl Widget for &mut Editor {
    fn render(self, area: Rect, buf: &mut ratatui::prelude::Buffer)
    where
        Self: Sized,
    {
        match self {
            Editor::User(ref mut e) => {
                e.render(area, buf);
            }
            Editor::Target(ref e) => {
                e.render(area, buf);
            }
            _ => {
                unreachable!()
            }
        }
    }
}
