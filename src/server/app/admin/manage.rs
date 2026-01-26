use super::common::*;
use super::table::{AdminTable, Colors, DisplayMode, FieldsToArray, TableData as TD};
use super::widgets::{centered_area, render_confirm_dialog, render_message_popup, Message};
use crate::database::models::*;
use crate::error::Error;
use ::log::{error, warn};
use crossterm::event::{self, KeyCode, KeyEvent, KeyModifiers, NoTtyEvent};
use ratatui::backend::NottyBackend;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{self, Color, Style, Stylize};
use ratatui::text::{Line, Text};
use ratatui::widgets::{Block, BorderType, Clear, Paragraph, Tabs, Widget};
use ratatui::{Frame, Terminal};
use russh::keys::ssh_key::PrivateKey;
use std::fmt;
use std::io::Write;
use std::str::FromStr;
use std::sync::Arc;
use style::palette::tailwind;
use tokio::runtime::Handle;
use unicode_width::UnicodeWidthStr;

mod bind;
mod role;
mod secret;
mod target;
mod user;

const HELP_TEXT: [&str; 2] = [
    "(a) add | (e) edit | (d) delete | (Esc) quit | (↑↓←→) move around",
    "(Tab) next tab | (Shift Tab) previous tab | (+/-) zoom in/out | (PgUp/PgDn) page up/down",
];

const LENGTH_UUID: u16 = 32;
const LENGTH_TIMESTAMP: u16 = 14;
pub const MAX_POPUP_WINDOW_COL: u16 = 60;
pub const MAX_POPUP_WINDOW_ROW: u16 = 40;
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
    Bind = 3,
    Role = 4,
}

impl fmt::Display for SelectedTab {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SelectedTab::Users => write!(f, "Users"),
            SelectedTab::Targets => write!(f, "Targets"),
            SelectedTab::Secrets => write!(f, "Secrets"),
            SelectedTab::Bind => write!(f, "Bind"),
            SelectedTab::Role => write!(f, "Role"),
        }
    }
}

impl SelectedTab {
    fn next(&self) -> Self {
        match self {
            SelectedTab::Users => SelectedTab::Targets,
            SelectedTab::Targets => SelectedTab::Secrets,
            SelectedTab::Secrets => SelectedTab::Bind,
            SelectedTab::Bind => SelectedTab::Role,
            SelectedTab::Role => SelectedTab::Users,
        }
    }

    fn previous(&self) -> Self {
        match self {
            SelectedTab::Users => SelectedTab::Role,
            SelectedTab::Targets => SelectedTab::Users,
            SelectedTab::Secrets => SelectedTab::Targets,
            SelectedTab::Bind => SelectedTab::Secrets,
            SelectedTab::Role => SelectedTab::Bind,
        }
    }
}

struct App<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    table: AdminTable,
    items: TableData,
    longest_item_lens: Vec<Constraint>,
    selected_tab: SelectedTab,
    last_selected_tab: SelectedTab,
    popup: Popup,
    editor_colors: EditorColors,
    backend: Arc<B>,
    t_handle: Handle,
    handler_id: String,
    user_id: String,
    editor: Editor<B>,
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
            table: AdminTable::new(&data, &tailwind::BLUE),
            longest_item_lens: data.constraint_len_calculator(),
            editor_colors: EditorColors::new(&tailwind::BLUE),
            selected_tab: SelectedTab::Users,
            last_selected_tab: SelectedTab::Users.next(),
            popup: Popup::None,
            backend,
            t_handle,
            handler_id,
            items: data,
            user_id,
            editor: Editor::None,
            message: None,
        }
    }

    fn next_tab(&mut self) {
        self.selected_tab = self.selected_tab.next();
    }

    fn previous_tab(&mut self) {
        self.selected_tab = self.selected_tab.previous();
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
                self.editor = Editor::Target(Box::new(target::TargetEditor::new(Target::new(
                    self.user_id.clone(),
                ))))
            }
            SelectedTab::Secrets => {
                self.editor = Editor::Secret(Box::new(secret::SecretEditor::new(Secret::new(
                    self.user_id.clone(),
                ))))
            }
            SelectedTab::Bind => unreachable!(),
            SelectedTab::Role => unreachable!(),
        }
    }

    fn edit_form(&mut self) -> bool {
        self.popup = Popup::Edit;

        match self.selected_tab {
            SelectedTab::Users => {
                let idx = self.table.state.selected().unwrap();
                let user = match self.items.get_user(idx) {
                    Some(u) => u,
                    None => {
                        return false;
                    }
                };
                self.editor = Editor::User(Box::new(user::UserEditor::new(user)));
            }
            SelectedTab::Targets => {
                let idx = self.table.state.selected().unwrap();
                let target = match self.items.get_target(idx) {
                    Some(u) => u,
                    None => {
                        return false;
                    }
                };
                self.editor = Editor::Target(Box::new(target::TargetEditor::new(target)));
            }
            SelectedTab::Secrets => {
                let idx = self.table.state.selected().unwrap();
                let secret = match self.items.get_secret(idx) {
                    Some(s) => s,
                    None => {
                        return false;
                    }
                };
                self.editor = Editor::Secret(Box::new(secret::SecretEditor::new(secret)));
            }
            SelectedTab::Bind => unreachable!(),
            SelectedTab::Role => unreachable!(),
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
            SelectedTab::Targets => {
                self.popup = Popup::None;
                self.clear_form();

                if let Some(t) = self.items.get_target(idx) {
                    let result = self
                        .t_handle
                        .block_on(self.backend.db_repository().delete_target(&t.id));

                    if let Err(e) = result {
                        self.message = Some(Message::Error(vec!["Internal error".into()]));
                        warn!(
                            "[{}] Delete target: {} failed, {}",
                            self.handler_id, t.name, e
                        );
                        return;
                    }

                    self.message = Some(Message::Success(vec!["Target deleted".into()]));
                    self.refresh_data();
                }
            }
            SelectedTab::Secrets => {
                self.popup = Popup::None;
                self.clear_form();

                if let Some(s) = self.items.get_secret(idx) {
                    let result = self
                        .t_handle
                        .block_on(self.backend.db_repository().delete_secret(&s.id));

                    if let Err(e) = result {
                        self.message = Some(Message::Error(vec!["Internal error".into()]));
                        warn!(
                            "[{}] Delete secret: {} failed, {}",
                            self.handler_id, s.name, e
                        );
                        return;
                    }

                    self.message = Some(Message::Success(vec!["Secret deleted".into()]));
                    self.refresh_data();
                }
            }
            SelectedTab::Bind => unreachable!(),
            SelectedTab::Role => unreachable!(),
        }
    }

    fn could_delete(&mut self, idx: usize) -> bool {
        match self.selected_tab {
            SelectedTab::Users => {
                if self.items.get_user(idx).is_some() {
                    return true;
                }
            }
            SelectedTab::Targets => {
                if self.items.get_target(idx).is_some() {
                    return true;
                }
            }
            SelectedTab::Secrets => {
                if self.items.get_secret(idx).is_some() {
                    return true;
                }
            }
            SelectedTab::Bind => unreachable!(),
            SelectedTab::Role => unreachable!(),
        }

        false
    }

    fn clear_form(&mut self) {
        self.popup = Popup::None;
        self.editor = Editor::None;
        self.table.colors = Colors::new(&tailwind::BLUE);
    }

    fn run<W: Write>(
        mut self,
        tty: NoTtyEvent,
        terminal: &mut Terminal<NottyBackend<W>>,
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

                match self.editor {
                    Editor::Bind(ref mut e) => {
                        if e.handle_key_event(key.code, key.modifiers) {
                            self.editor = Editor::None;
                        } else {
                            continue;
                        }
                    }
                    Editor::Role(ref mut e) => {
                        if e.handle_key_event(key.code, key.modifiers) {
                            self.editor = Editor::None;
                        } else {
                            continue;
                        }
                    }
                    _ => {}
                }
                let ctrl_pressed = key.modifiers.contains(KeyModifiers::CONTROL);

                match self.popup {
                    Popup::None => {
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
                            KeyCode::Char('d') => {
                                self.table.colors.gray();
                                let idx = self.table.state.selected().unwrap();

                                if self.could_delete(idx) {
                                    self.popup = Popup::Delete(idx);
                                } else {
                                    self.clear_form();
                                }
                            }
                            KeyCode::Char('a') => {
                                self.table.colors.gray();
                                self.add_form()
                            }
                            KeyCode::Char('e') => {
                                self.table.colors.gray();
                                if !self.edit_form() {
                                    self.clear_form();
                                }
                            }
                            _ => {}
                        }
                    }
                    Popup::Add | Popup::Edit => self.do_edit(key)?,
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
            if let Some(paste) = event.as_paste_event() {
                match self.editor {
                    Editor::User(ref mut e) => {
                        let _ = e.as_mut().handle_paste_event(paste);
                    }
                    Editor::Target(ref mut e) => {
                        let _ = e.as_mut().handle_paste_event(paste);
                    }
                    Editor::Secret(ref mut e) => {
                        let _ = e.as_mut().handle_paste_event(paste);
                    }
                    Editor::Bind(_) => unreachable!(),
                    Editor::Role(_) => unreachable!(),
                    Editor::None => {}
                }
            }
        }
    }

    fn do_edit(&mut self, key: KeyEvent) -> Result<(), Error> {
        match self.editor {
            Editor::User(ref mut e) => {
                if e.as_mut().handle_key_event(key.code, key.modifiers) {
                    if !e.show_cancel_confirmation {
                        let mut password = String::new();
                        let mut user = e.user.to_owned();

                        if e.generate_password {
                            password = crate::common::gen_password(12);
                            self.backend.set_password(&mut user, &password)?;
                        }

                        let (action, result) = match self.popup {
                            Popup::Add => (
                                "added",
                                self.t_handle
                                    .block_on(self.backend.db_repository().create_user(&user)),
                            ),
                            Popup::Edit => (
                                "updated",
                                self.t_handle
                                    .block_on(self.backend.db_repository().update_user(&user)),
                            ),
                            _ => unreachable!(),
                        };

                        if let Err(err) = result {
                            let msg = match err {
                                Error::Sqlx(sqlx::Error::Database(db_err))
                                    if db_err.kind() == sqlx::error::ErrorKind::UniqueViolation =>
                                {
                                    "Username already exists"
                                }
                                _ => "Internal error",
                            };

                            self.message = Some(Message::Error(vec![msg.into()]));
                            return Ok(());
                        }

                        let mut msg = vec![format!("User {}", action)];
                        if !password.is_empty() {
                            msg.push(format!("New password: {}", password));
                        }
                        self.message = Some(Message::Success(msg));
                    }

                    self.clear_form();
                    self.refresh_data();
                }
            }
            Editor::Target(ref mut e) => {
                if e.as_mut().handle_key_event(key.code, key.modifiers) {
                    if !e.show_cancel_confirmation {
                        let target = e.target.to_owned();

                        let (action, result) = match self.popup {
                            Popup::Add => (
                                "added",
                                self.t_handle
                                    .block_on(self.backend.db_repository().create_target(&target)),
                            ),
                            Popup::Edit => (
                                "updated",
                                self.t_handle
                                    .block_on(self.backend.db_repository().update_target(&target)),
                            ),
                            _ => unreachable!(),
                        };

                        if let Err(err) = result {
                            let msg = match err {
                                Error::Sqlx(sqlx::Error::Database(db_err))
                                    if db_err.kind() == sqlx::error::ErrorKind::UniqueViolation =>
                                {
                                    "Target already exists"
                                }
                                _ => "Internal error",
                            };

                            self.message = Some(Message::Error(vec![msg.into()]));
                            return Ok(());
                        }

                        let msg = vec![format!("Target {}", action)];
                        self.message = Some(Message::Success(msg));
                    }

                    self.clear_form();
                    self.refresh_data();
                }
            }
            Editor::Secret(ref mut e) => {
                if e.as_mut().handle_key_event(key.code, key.modifiers) {
                    if !e.show_cancel_confirmation {
                        let mut secret = e.secret.to_owned();
                        if e.password_updated {
                            if let Some(p) = secret.take_password() {
                                secret.set_password(Some(self.backend.encrypt_plain_text(&p)?));
                            };
                        };
                        if e.private_key_updated {
                            if let Some(p) = secret.take_private_key() {
                                secret.set_private_key(Some(self.backend.encrypt_plain_text(&p)?));
                                secret.set_public_key(Some(
                                    PrivateKey::from_str(&p)?.public_key().to_openssh()?,
                                ));
                            }
                        }
                        let (action, result) = match self.popup {
                            Popup::Add => (
                                "added",
                                self.t_handle
                                    .block_on(self.backend.db_repository().create_secret(&secret)),
                            ),
                            Popup::Edit => (
                                "updated",
                                self.t_handle
                                    .block_on(self.backend.db_repository().update_secret(&secret)),
                            ),
                            _ => unreachable!(),
                        };
                        if let Err(err) = result {
                            let msg = match err {
                                Error::Sqlx(sqlx::Error::Database(db_err))
                                    if db_err.kind() == sqlx::error::ErrorKind::UniqueViolation =>
                                {
                                    "Secret already exists"
                                }
                                _ => "Internal error",
                            };
                            self.message = Some(Message::Error(vec![msg.into()]));
                            return Ok(());
                        }
                        let msg = vec![format!("Secret {}", action)];
                        self.message = Some(Message::Success(msg));
                    }
                    self.clear_form();
                    self.refresh_data();
                }
            }
            Editor::Bind(_) => unreachable!(),
            Editor::Role(_) => unreachable!(),
            Editor::None => unreachable!(),
        }
        Ok(())
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

        self.table.size = (table_area.width, table_area.height);

        self.render_tabs(frame, header_area);
        match self.selected_tab {
            SelectedTab::Bind => {
                if let Editor::Bind(_) = self.editor {
                    frame.render_widget(&mut self.editor, table_area);
                } else {
                    unreachable!()
                }
            }
            SelectedTab::Role => {
                if let Editor::Role(ref mut e) = self.editor {
                    e.draw(table_area, frame.buffer_mut());
                } else {
                    unreachable!()
                }
            }
            _ => {
                self.table.render(
                    frame.buffer_mut(),
                    table_area,
                    &self.items,
                    &self.longest_item_lens,
                    DisplayMode::Manage,
                );
            }
        }
        self.render_popup(frame, table_area);
        if let Some(ref msg) = self.message {
            render_message_popup(table_area, frame.buffer_mut(), msg);
        }
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
            SelectedTab::Bind => {
                // For Bind tab, we need to load targets and secrets
                let targets = self
                    .t_handle
                    .block_on(self.backend.db_repository().list_targets_info())
                    .unwrap_or_default();
                let secrets = if !targets.is_empty() {
                    // Get secrets for the first target as default
                    self.t_handle
                        .block_on(
                            self.backend
                                .db_repository()
                                .list_secrets_for_target(&targets[0].id),
                        )
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };
                self.editor = Editor::Bind(Box::new(bind::BindEditor::new(
                    targets,
                    secrets,
                    self.backend.clone(),
                    self.t_handle.clone(),
                    self.handler_id.clone(),
                    self.user_id.clone(),
                )));
            }
            SelectedTab::Role => {
                self.editor = Editor::Role(Box::new(role::RoleEditor::new(
                    self.backend.clone(),
                    self.t_handle.clone(),
                    self.handler_id.clone(),
                    self.user_id.clone(),
                )));
            }
        };

        self.longest_item_lens = self.items.constraint_len_calculator();
    }

    fn render_tabs(&mut self, frame: &mut Frame, area: Rect) {
        if self.selected_tab != self.last_selected_tab {
            self.refresh_data();
            self.table.state.select(Some(0));
            self.last_selected_tab = self.selected_tab
        }

        let tabs = Tabs::new(
            MANAGE_LIST
                .iter()
                .map(|v| format!("{v:^17}").fg(self.table.colors.tab_font)),
        )
        .style(self.table.colors.header_bg)
        .highlight_style(
            Style::default()
                .magenta()
                .on_black()
                .bold()
                .fg(self.table.colors.header_fg)
                .bg(self.table.colors.header_bg),
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
                Editor::Secret(_) => Line::styled("Add New Secret", Style::default().bold()),
                Editor::Bind(_) => unreachable!(),
                Editor::Role(_) => unreachable!(),
                Editor::None => unreachable!(),
            },
            Popup::Edit => match self.editor {
                Editor::User(_) => Line::styled("Edit User", Style::default().bold()),
                Editor::Target(_) => Line::styled("Edit Target", Style::default().bold()),
                Editor::Secret(_) => Line::styled("Edit Secret", Style::default().bold()),
                Editor::Bind(_) => unreachable!(),
                Editor::Role(_) => unreachable!(),
                Editor::None => unreachable!(),
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
                    SelectedTab::Targets => {
                        render_confirm_dialog(
                            popup_area,
                            frame.buffer_mut(),
                            &["Delete selected target?".to_string()],
                        );
                    }
                    SelectedTab::Secrets => {
                        render_confirm_dialog(
                            popup_area,
                            frame.buffer_mut(),
                            &["Delete selected secret?".to_string()],
                        );
                    }
                    SelectedTab::Bind => unreachable!(),
                    SelectedTab::Role => unreachable!(),
                }
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
            Editor::Secret(ref e) => e.as_ref().help_text,
            Editor::Bind(ref e) => e.as_ref().help_text,
            Editor::Role(ref e) => e.as_ref().help_text,
            Editor::None => HELP_TEXT,
        };

        let info_footer = Paragraph::new(Text::from_iter(text))
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
    InternalObjects(Vec<InternalObject>),
    CasbinRule(Vec<CasbinRule>),
    Logs(Vec<Log>),
}

impl TableData {
    fn get_target(&self, i: usize) -> Option<Target> {
        if let TableData::Targets(data) = self {
            data.get(i).cloned()
        } else {
            None
        }
    }

    fn get_user(&self, i: usize) -> Option<User> {
        if let TableData::Users(data) = self {
            data.get(i).cloned()
        } else {
            None
        }
    }

    fn get_secret(&self, i: usize) -> Option<Secret> {
        if let TableData::Secrets(data) = self {
            data.get(i).cloned()
        } else {
            None
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
                    Constraint::Length(username_len as u16),
                    Constraint::Length(email_len as u16),
                    Constraint::Length(13),
                    Constraint::Length(15),
                    Constraint::Length(15),
                    Constraint::Length(9),
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
                    Constraint::Length(name_len as u16),
                    Constraint::Length(hostname_len as u16),
                    Constraint::Length(5),
                    Constraint::Length(server_public_key_len as u16),
                    Constraint::Length(desc_len as u16),
                    Constraint::Length(9), // is_active
                ]
            }
            Self::TargetSecrets(_) => vec![
                Constraint::Length(LENGTH_UUID), // id
                Constraint::Length(LENGTH_UUID), // target_id
                Constraint::Length(LENGTH_UUID), // secret_id
                Constraint::Length(9),           // is_active
                Constraint::Length(LENGTH_UUID), // created_by
                Constraint::Length(LENGTH_TIMESTAMP),
            ],
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
                    Constraint::Length(name_len as u16),
                    Constraint::Length(user_len as u16),
                    Constraint::Length(8),  // password (shown as <hidden>)
                    Constraint::Length(11), // private_key (shown as <hidden>)
                    Constraint::Length(public_key_len as u16), // public_key (shown as <hidden>)
                    Constraint::Length(9),  // is_active
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
}

impl super::table::TableData for TableData {
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

    fn header(&self) -> Vec<&str> {
        match self {
            Self::Users(_) => vec![
                "username",
                "email",
                "password_hash",
                "authorized_keys",
                "force_init_pass",
                "is_active",
            ],
            Self::Targets(_) => vec![
                "name",
                "hostname",
                "port",
                "server_public_key",
                "description",
                "is_active",
            ],
            Self::TargetSecrets(_) => vec![
                "id",
                "target_id",
                "secret_id",
                "is_active",
                "updated_by",
                "updated_at",
            ],
            Self::Secrets(_) => vec![
                "name",
                "user",
                "password",
                "private_key",
                "public_key",
                "is_active",
            ],
            Self::InternalObjects(_) => vec!["name", "is_active", "updated_by", "updated_at"],
            Self::CasbinRule(_) => vec![
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
            ],
            Self::Logs(_) => vec![
                "connection_id",
                "log_type",
                "user_id",
                "detail",
                "created_at",
            ],
        }
    }
}

enum Editor<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    User(Box<user::UserEditor>),
    Target(Box<target::TargetEditor>),
    Secret(Box<secret::SecretEditor>),
    Bind(Box<bind::BindEditor<B>>),
    Role(Box<role::RoleEditor<B>>),
    None,
}

impl<B> Widget for &mut Editor<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    fn render(self, area: Rect, buf: &mut ratatui::prelude::Buffer)
    where
        Self: Sized,
    {
        match self {
            Editor::User(ref mut e) => {
                e.render(area, buf);
            }
            Editor::Target(ref mut e) => {
                e.render(area, buf);
            }
            Editor::Secret(ref mut e) => {
                e.render(area, buf);
            }
            Editor::Bind(ref mut e) => {
                e.render(area, buf);
            }
            Editor::Role(_) => {
                unreachable!();
            }
            Editor::None => {}
        }
    }
}
