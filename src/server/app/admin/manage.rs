use super::common::*;
use crate::database::Uuid;
use crate::database::models::*;
use crate::error::Error;
use crate::server::HandlerLog;
use crate::server::casbin::GroupType;
use crate::server::widgets::{
    AdminTable, Colors, DisplayMode, FieldsToArray, Message, TableData as TD, centered_area,
    common::*, render_confirm_dialog, render_message_popup,
};
use ::log::{error, info, warn};
use crossterm::event::{self, KeyCode, KeyEvent, KeyModifiers, NoTtyEvent};
use ratatui::backend::NottyBackend;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{self, Color, Style, Stylize};
use ratatui::text::{Line, Text};
use ratatui::widgets::{Block, BorderType, Clear, Paragraph, Tabs, Widget};
use ratatui::{Frame, Terminal};
use std::fmt;
use std::io::Write;
use std::sync::Arc;
use style::palette::tailwind;
use tokio::runtime::Handle;
use unicode_width::UnicodeWidthStr;

mod bind;
mod casbin_group;
mod casbin_name;
mod grant_role;
mod permission;
mod secret;
mod target;
mod user;

const LOG_TYPE: &str = "manage";
const HELP_TEXT: [&str; 2] = [
    "(a) add | (e) edit | (d) delete | (Esc) quit | (↑↓←→) move around",
    "(Tab) next tab | (Shift Tab) previous tab | (+/-) zoom in/out | (PgUp/PgDn) page up/down",
];

const USER_HELP_TEXT: [&str; 2] = [
    "(a) add | (e) edit | (d) delete | (r) grant role | (Esc) quit | (↑↓←→) move around",
    "(Tab) next tab | (Shift Tab) previous tab | (+/-) zoom in/out | (PgUp/PgDn) page up/down",
];

pub(super) fn manage<B, W: Write>(
    tty: NoTtyEvent,
    w: W,
    user_id: Uuid,
    handler_id: Uuid,
    backend: Arc<B>,
    t_handle: Handle,
    log: HandlerLog,
) -> Result<(), Error>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    let tty_backend = NottyBackend::new(tty.clone(), w);
    let mut terminal = Terminal::new(tty_backend)?;
    terminal.hide_cursor()?;
    terminal.flush()?;
    App::new(backend, t_handle, user_id, handler_id, log).run(tty, &mut terminal)?;
    Ok(())
}

struct EditorColors {
    border_color: Color,
    title_color: Color,
    tab_font: Color,
    tab_fg: Color,
    tab_bg: Color,
}

impl EditorColors {
    const fn new(color: &tailwind::Palette) -> Self {
        Self {
            border_color: color.c400,
            title_color: tailwind::SLATE.c200,
            tab_font: tailwind::SLATE.c400,
            tab_fg: tailwind::SLATE.c200,
            tab_bg: color.c900,
        }
    }
}

#[derive(PartialEq)]
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
    Permissions = 4,
    CasbinNames = 5,
    RoleHierarchy = 6,
    TargetGroup = 7,
    ActionGroup = 8,
}

impl fmt::Display for SelectedTab {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SelectedTab::Users => write!(f, "{}", MANAGE_USERS),
            SelectedTab::Targets => write!(f, "{}", MANAGE_TARGETS),
            SelectedTab::Secrets => write!(f, "{}", MANAGE_SECRETS),
            SelectedTab::Bind => write!(f, "{}", MANAGE_BIND),
            SelectedTab::Permissions => write!(f, "{}", MANAGE_PERMISSIONS),
            SelectedTab::CasbinNames => write!(f, "{}", MANAGE_CASBIN_NAMES),
            SelectedTab::RoleHierarchy => write!(f, "{}", MANAGE_ROLE_HIERARCHY),
            SelectedTab::TargetGroup => write!(f, "{}", MANAGE_TARGET_GROUP),
            SelectedTab::ActionGroup => write!(f, "{}", MANAGE_ACTION_GROUP),
        }
    }
}

impl SelectedTab {
    fn next(&self) -> Self {
        match self {
            SelectedTab::Users => SelectedTab::Targets,
            SelectedTab::Targets => SelectedTab::Secrets,
            SelectedTab::Secrets => SelectedTab::Bind,
            SelectedTab::Bind => SelectedTab::Permissions,
            SelectedTab::Permissions => SelectedTab::CasbinNames,
            SelectedTab::CasbinNames => SelectedTab::RoleHierarchy,
            SelectedTab::RoleHierarchy => SelectedTab::TargetGroup,
            SelectedTab::TargetGroup => SelectedTab::ActionGroup,
            SelectedTab::ActionGroup => SelectedTab::Users,
        }
    }

    fn previous(&self) -> Self {
        match self {
            SelectedTab::Users => SelectedTab::ActionGroup,
            SelectedTab::Targets => SelectedTab::Users,
            SelectedTab::Secrets => SelectedTab::Targets,
            SelectedTab::Bind => SelectedTab::Secrets,
            SelectedTab::Permissions => SelectedTab::Bind,
            SelectedTab::CasbinNames => SelectedTab::Permissions,
            SelectedTab::RoleHierarchy => SelectedTab::CasbinNames,
            SelectedTab::TargetGroup => SelectedTab::RoleHierarchy,
            SelectedTab::ActionGroup => SelectedTab::TargetGroup,
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
    handler_id: Uuid,
    admin_id: Uuid,
    editor: Editor<B>,
    message: Option<Message>,
    log: HandlerLog,
}

impl<B> App<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    fn new(
        backend: Arc<B>,
        t_handle: Handle,
        admin_id: Uuid,
        handler_id: Uuid,
        log: HandlerLog,
    ) -> Self {
        let data = TableData::Users(
            match t_handle.block_on(backend.db_repository().list_users_with_role(false)) {
                Ok(d) => d,
                Err(e) => {
                    error!("[{}] Failed to list users: {}", handler_id, e);
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
            admin_id,
            editor: Editor::None,
            message: None,
            log,
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
                self.editor =
                    Editor::User(Box::new(user::UserEditor::new(User::new(self.admin_id))))
            }
            SelectedTab::Targets => {
                self.editor = Editor::Target(Box::new(target::TargetEditor::new(Target::new(
                    self.admin_id,
                ))))
            }
            SelectedTab::Secrets => {
                self.editor = Editor::Secret(Box::new(secret::SecretEditor::new(Secret::new(
                    self.admin_id,
                ))))
            }
            SelectedTab::Permissions => {
                let mut perm = PermissionPolicy::new(self.admin_id);
                perm.rule.ptype = "p".to_string();
                self.editor = Editor::Permission(Box::new(permission::PermissionEditor::new(
                    perm,
                    self.backend.clone(),
                    self.t_handle.clone(),
                )))
            }
            SelectedTab::CasbinNames => {
                self.editor = Editor::CasbinName(Box::new(casbin_name::CasbinNameEditor::new(
                    CasbinName::new(String::new(), String::new(), true, self.admin_id),
                )))
            }
            SelectedTab::Bind => unreachable!(),
            SelectedTab::RoleHierarchy => unreachable!(),
            SelectedTab::TargetGroup => unreachable!(),
            SelectedTab::ActionGroup => unreachable!(),
        }
    }

    fn grant_role_form(&mut self) -> bool {
        self.popup = Popup::Edit;
        let idx = self.table.state.selected().unwrap();
        let user = match self.items.get_user(idx) {
            Some(u) => u,
            None => {
                return false;
            }
        };
        self.editor = Editor::GrantRole(Box::new(grant_role::GrantRoleEditor::new(
            user.id,
            self.backend.clone(),
            self.t_handle.clone(),
            self.handler_id,
            self.admin_id,
            self.log.clone(),
        )));
        true
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
            SelectedTab::Permissions => {
                let idx = self.table.state.selected().unwrap();
                let permission = match self.items.get_permission(idx) {
                    Some(s) => s,
                    None => {
                        return false;
                    }
                };
                self.editor = Editor::Permission(Box::new(permission::PermissionEditor::new(
                    permission,
                    self.backend.clone(),
                    self.t_handle.clone(),
                )));
            }
            SelectedTab::CasbinNames => {
                let idx = self.table.state.selected().unwrap();
                let casbin_name = match self.items.get_casbin_name(idx) {
                    Some(c) => c,
                    None => {
                        return false;
                    }
                };
                self.editor =
                    Editor::CasbinName(Box::new(casbin_name::CasbinNameEditor::new(casbin_name)));
            }
            SelectedTab::Bind => unreachable!(),
            SelectedTab::RoleHierarchy => unreachable!(),
            SelectedTab::TargetGroup => unreachable!(),
            SelectedTab::ActionGroup => unreachable!(),
        }

        true
    }

    fn do_delete(&mut self, idx: usize) {
        self.popup = Popup::None;
        match self.selected_tab {
            SelectedTab::Users => {
                if let Some(u) = self.items.get_user(idx) {
                    let result = self
                        .t_handle
                        .block_on(self.backend.db_repository().delete_user(&u.id));

                    if let Err(e) = result {
                        self.message = Some(Message::Error(vec!["Internal error".into()]));
                        warn!(
                            "[{}] Delete user '{}({})' failed by admin_id={}: {}",
                            self.handler_id, u.username, u.id, self.admin_id, e
                        );
                        return;
                    }

                    info!(
                        "[{}] User '{}({})' deleted by admin_id={}",
                        self.handler_id, u.username, u.id, self.admin_id
                    );
                    self.t_handle.block_on((self.log)(
                        LOG_TYPE.into(),
                        format!("User '{}({})' deleted", u.username, u.id),
                    ));
                    self.message = Some(Message::Success(vec!["User deleted".into()]));
                    self.refresh_data();
                }
            }
            SelectedTab::Targets => {
                if let Some(t) = self.items.get_target(idx) {
                    let result = self
                        .t_handle
                        .block_on(self.backend.db_repository().delete_target(&t.id));

                    if let Err(e) = result {
                        self.message = Some(Message::Error(vec!["Internal error".into()]));
                        warn!(
                            "[{}] Delete target '{}({})' failed by admin_id={}: {}",
                            self.handler_id, t.name, t.id, self.admin_id, e
                        );
                        return;
                    }

                    info!(
                        "[{}] Target '{}({})' deleted by admin_id={}",
                        self.handler_id, t.name, t.id, self.admin_id
                    );
                    self.t_handle.block_on((self.log)(
                        LOG_TYPE.into(),
                        format!("Target '{}({})' deleted", t.name, t.id),
                    ));
                    self.message = Some(Message::Success(vec!["Target deleted".into()]));
                    self.refresh_data();
                }
            }
            SelectedTab::Secrets => {
                if let Some(s) = self.items.get_secret(idx) {
                    let result = self
                        .t_handle
                        .block_on(self.backend.db_repository().delete_secret(&s.id));

                    if let Err(e) = result {
                        self.message = Some(Message::Error(vec!["Internal error".into()]));
                        warn!(
                            "[{}] Delete secret '{}({})' failed by admin_id={}: {}",
                            self.handler_id, s.name, s.id, self.admin_id, e
                        );
                        return;
                    }

                    info!(
                        "[{}] Secret '{}({})' deleted by admin_id={}",
                        self.handler_id, s.name, s.id, self.admin_id
                    );
                    self.t_handle.block_on((self.log)(
                        LOG_TYPE.into(),
                        format!("Secret '{}({})' deleted", s.name, s.id),
                    ));
                    self.message = Some(Message::Success(vec!["Secret deleted".into()]));
                    self.refresh_data();
                }
            }
            SelectedTab::Permissions => {
                if let Some(p) = self.items.get_permission(idx) {
                    let result = self
                        .t_handle
                        .block_on(self.backend.db_repository().delete_casbin_rule(&p.rule.id));

                    if let Err(e) = result {
                        self.message = Some(Message::Error(vec!["Internal error".into()]));
                        warn!(
                            "[{}] Delete permission '({})' failed by admin_id={}: {}",
                            self.handler_id, p.rule.id, self.admin_id, e
                        );
                        return;
                    }

                    info!(
                        "[{}] Permission '({})' deleted by admin_id={}",
                        self.handler_id, p.rule.id, self.admin_id
                    );
                    self.t_handle.block_on((self.log)(
                        LOG_TYPE.into(),
                        format!("Permission '({})' deleted", p.rule.id),
                    ));
                    self.message = Some(Message::Success(vec!["Permission deleted".into()]));
                    self.refresh_data();
                }
            }
            SelectedTab::CasbinNames => {
                if let Some(c) = self.items.get_casbin_name(idx) {
                    let result = self
                        .t_handle
                        .block_on(self.backend.db_repository().delete_casbin_name(&c.id));

                    if let Err(e) = result {
                        self.message = Some(Message::Error(vec!["Internal error".into()]));
                        warn!(
                            "[{}] Delete casbin name '{}({})' failed by admin_id={}: {}",
                            self.handler_id, c.name, c.id, self.admin_id, e
                        );
                        return;
                    }

                    info!(
                        "[{}] Casbin name '{}({})' deleted by admin_id={}",
                        self.handler_id, c.name, c.id, self.admin_id
                    );
                    self.t_handle.block_on((self.log)(
                        LOG_TYPE.into(),
                        format!("Casbin name '{}({})' deleted", c.name, c.id),
                    ));
                    self.message = Some(Message::Success(vec!["Group deleted".into()]));
                    self.refresh_data();
                }
            }
            SelectedTab::Bind => unreachable!(),
            SelectedTab::RoleHierarchy => unreachable!(),
            SelectedTab::TargetGroup => unreachable!(),
            SelectedTab::ActionGroup => unreachable!(),
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
            SelectedTab::Permissions => {
                if self.items.get_permission(idx).is_some() {
                    return true;
                }
            }
            SelectedTab::CasbinNames => {
                if self.items.get_casbin_name(idx).is_some() {
                    return true;
                }
            }
            SelectedTab::Bind => unreachable!(),
            SelectedTab::RoleHierarchy => unreachable!(),
            SelectedTab::TargetGroup => unreachable!(),
            SelectedTab::ActionGroup => unreachable!(),
        }

        false
    }

    fn clear_form(&mut self) {
        self.popup = Popup::None;
        self.editor = Editor::None;
    }

    fn restore_color(&mut self) {
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
                            if self.popup == Popup::None {
                                self.restore_color();
                            }
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
                    Editor::CasbinGroup(ref mut e) => {
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
                            KeyCode::Char('c') if ctrl_pressed => return Ok(()),
                            KeyCode::Char('j') | KeyCode::Down => self.table.next_row(items_len),
                            KeyCode::Char('k') | KeyCode::Up => self.table.previous_row(items_len),
                            KeyCode::Char('l') | KeyCode::Right => self.table.next_column(),
                            KeyCode::Char('h') | KeyCode::Left => self.table.previous_column(),
                            KeyCode::Char('d') if !ctrl_pressed => {
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
                            KeyCode::Char('r') => {
                                self.table.colors.gray();
                                if !self.grant_role_form() {
                                    self.clear_form();
                                }
                            }
                            _ => {}
                        }
                    }
                    Popup::Add | Popup::Edit => {
                        if let Err(e) = self.do_edit(key) {
                            self.message = Some(Message::Error(vec!["Internal error".into()]));
                            warn!("[{}] Failed to edit: {}", self.handler_id, e);
                        }
                    }
                    Popup::Delete(i) => match key.code {
                        KeyCode::Char('y') | KeyCode::Char('Y') => {
                            self.do_delete(i);
                        }
                        KeyCode::Char('n') | KeyCode::Char('N') => {
                            self.popup = Popup::None;
                            self.clear_form();
                            self.restore_color();
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
                    Editor::CasbinName(ref mut e) => {
                        let _ = e.as_mut().handle_paste_event(paste);
                    }
                    Editor::GrantRole(_) => {}
                    Editor::Permission(_) => {}
                    Editor::Bind(_) => unreachable!(),
                    Editor::CasbinGroup(_) => unreachable!(),
                    Editor::None => {}
                }
            }
        }
    }

    fn do_edit(&mut self, key: KeyEvent) -> Result<(), Error> {
        match self.editor {
            Editor::User(ref mut e) => {
                if e.as_mut().handle_key_event(key.code, key.modifiers) {
                    if !e.form.show_cancel_confirmation {
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

                        if let Err(ref err) = result {
                            let msg = match err {
                                Error::Sqlx(sqlx::Error::Database(db_err))
                                    if db_err.kind() == sqlx::error::ErrorKind::UniqueViolation =>
                                {
                                    "Username already exists"
                                }
                                _ => "Internal error",
                            };
                            warn!(
                                "[{}] Failed to {} user '{}({})': {}",
                                self.handler_id, action, user.username, user.id, err
                            );
                            self.message = Some(Message::Error(vec![msg.into()]));
                            return Ok(());
                        }

                        info!(
                            "[{}] User '{}({})' {} by admin_id={}",
                            self.handler_id, user.username, user.id, action, self.admin_id
                        );
                        self.t_handle.block_on((self.log)(
                            LOG_TYPE.into(),
                            format!("User '{}({})' {}", user.username, user.id, action),
                        ));
                        let mut msg = vec![format!("User {}", action)];
                        if !password.is_empty() {
                            msg.push(format!("New password: {}", password));
                        }
                        self.message = Some(Message::Success(msg));
                    }

                    self.clear_form();
                    self.refresh_data();
                    self.restore_color();
                }
            }
            Editor::Target(ref mut e) => {
                if e.as_mut().handle_key_event(key.code, key.modifiers) {
                    if !e.form.show_cancel_confirmation {
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

                        if let Err(ref err) = result {
                            let msg = match err {
                                Error::Sqlx(sqlx::Error::Database(db_err))
                                    if db_err.kind() == sqlx::error::ErrorKind::UniqueViolation =>
                                {
                                    "Target already exists"
                                }
                                _ => "Internal error",
                            };
                            warn!(
                                "[{}] Failed to {} target '{}({})': {}",
                                self.handler_id, action, target.name, target.id, err
                            );
                            self.message = Some(Message::Error(vec![msg.into()]));
                            return Ok(());
                        }

                        info!(
                            "[{}] Target '{}({})' {} by admin_id={}",
                            self.handler_id, target.name, target.id, action, self.admin_id
                        );
                        self.t_handle.block_on((self.log)(
                            LOG_TYPE.into(),
                            format!("Target '{}({})' {}", target.name, target.id, action),
                        ));
                        let msg = vec![format!("Target {}", action)];
                        self.message = Some(Message::Success(msg));
                    }

                    self.clear_form();
                    self.refresh_data();
                    self.restore_color();
                }
            }
            Editor::Secret(ref mut e) => {
                if e.as_mut().handle_key_event(key.code, key.modifiers) {
                    if !e.form.show_cancel_confirmation {
                        let mut secret = e.secret.to_owned();
                        if e.private_key_updated {
                            secret.encrypt_private_key(self.backend.encrypt_plain_text())?;
                        }
                        if e.password_updated {
                            secret.encrypt_password(self.backend.encrypt_plain_text())?;
                        };
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
                        if let Err(ref err) = result {
                            let msg = match err {
                                Error::Sqlx(sqlx::Error::Database(db_err))
                                    if db_err.kind() == sqlx::error::ErrorKind::UniqueViolation =>
                                {
                                    "Secret already exists"
                                }
                                _ => "Internal error",
                            };
                            warn!(
                                "[{}] Failed to {} secret '{}({})': {}",
                                self.handler_id, action, secret.name, secret.id, err
                            );
                            self.message = Some(Message::Error(vec![msg.into()]));
                            return Ok(());
                        }
                        info!(
                            "[{}] Secret '{}({})' {} by admin_id={}",
                            self.handler_id, secret.name, secret.id, action, self.admin_id
                        );
                        self.t_handle.block_on((self.log)(
                            LOG_TYPE.into(),
                            format!("Secret '{}({})' {}", secret.name, secret.id, action),
                        ));
                        let msg = vec![format!("Secret {}", action)];
                        self.message = Some(Message::Success(msg));
                    }
                    self.clear_form();
                    self.refresh_data();
                    self.restore_color();
                }
            }
            Editor::Permission(ref mut e) => {
                if e.as_mut().handle_key_event(key.code, key.modifiers) {
                    if !e.show_cancel_confirmation {
                        let mut perm = e.perm.to_owned();
                        perm.rule.updated_by = self.admin_id;
                        let (action, result) = match self.popup {
                            Popup::Add => (
                                "added",
                                self.t_handle.block_on(
                                    self.backend.db_repository().create_casbin_rule(&perm.rule),
                                ),
                            ),
                            Popup::Edit => (
                                "updated",
                                self.t_handle.block_on(
                                    self.backend.db_repository().update_casbin_rule(&perm.rule),
                                ),
                            ),
                            _ => unreachable!(),
                        };
                        if let Err(ref err) = result {
                            let msg = match err {
                                Error::Sqlx(sqlx::Error::Database(db_err))
                                    if db_err.kind() == sqlx::error::ErrorKind::UniqueViolation =>
                                {
                                    "Permission already exists"
                                }
                                _ => "Internal error",
                            };
                            warn!(
                                "[{}] Failed to {} permission '({})': {}",
                                self.handler_id, action, perm.rule.id, err
                            );
                            self.message = Some(Message::Error(vec![msg.into()]));
                            return Ok(());
                        }
                        info!(
                            "[{}] Permission '({})' {} by admin_id={}",
                            self.handler_id, perm.rule.id, action, self.admin_id
                        );
                        self.t_handle.block_on((self.log)(
                            LOG_TYPE.into(),
                            format!("Permission '({})' {}", perm.rule.id, action),
                        ));
                        let msg = vec![format!("Permission {}", action)];
                        self.message = Some(Message::Success(msg));
                    }
                    self.clear_form();
                    self.refresh_data();
                    self.restore_color();
                }
            }
            Editor::GrantRole(ref mut e) => {
                if e.as_mut().handle_key_event(key.code, key.modifiers) {
                    self.clear_form();
                    self.refresh_data();
                    self.restore_color();
                }
            }
            Editor::CasbinName(ref mut e) => {
                if e.as_mut().handle_key_event(key.code, key.modifiers) {
                    if !e.form.show_cancel_confirmation {
                        let casbin_name = e.casbin_name.to_owned();

                        let (action, result) = match self.popup {
                            Popup::Add => (
                                "added",
                                self.t_handle.block_on(
                                    self.backend
                                        .db_repository()
                                        .create_casbin_name(&casbin_name),
                                ),
                            ),
                            Popup::Edit => (
                                "updated",
                                self.t_handle.block_on(
                                    self.backend
                                        .db_repository()
                                        .update_casbin_name(&casbin_name),
                                ),
                            ),
                            _ => unreachable!(),
                        };

                        if let Err(ref err) = result {
                            let msg = match err {
                                Error::Sqlx(sqlx::Error::Database(db_err))
                                    if db_err.kind() == sqlx::error::ErrorKind::UniqueViolation =>
                                {
                                    "Group already exists"
                                }
                                _ => "Internal error",
                            };
                            warn!(
                                "[{}] Failed to {} casbin name '{}({})': {}",
                                self.handler_id, action, casbin_name.name, casbin_name.id, err
                            );
                            self.message = Some(Message::Error(vec![msg.into()]));
                            return Ok(());
                        }

                        info!(
                            "[{}] Casbin name '{}({})' {} by admin_id={}",
                            self.handler_id,
                            casbin_name.name,
                            casbin_name.id,
                            action,
                            self.admin_id
                        );
                        self.t_handle.block_on((self.log)(
                            LOG_TYPE.into(),
                            format!(
                                "Casbin name '{}({})' {}",
                                casbin_name.name, casbin_name.id, action
                            ),
                        ));
                        let msg = vec![format!("Group {}", action)];
                        self.message = Some(Message::Success(msg));
                    }
                    self.clear_form();
                    self.refresh_data();
                    self.restore_color();
                }
            }
            Editor::Bind(_) => unreachable!(),
            Editor::CasbinGroup(_) => unreachable!(),
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
            SelectedTab::RoleHierarchy => {
                if let Editor::CasbinGroup(ref mut e) = self.editor {
                    e.draw(table_area, frame.buffer_mut());
                } else {
                    unreachable!()
                }
            }
            SelectedTab::TargetGroup => {
                if let Editor::CasbinGroup(ref mut e) = self.editor {
                    e.draw(table_area, frame.buffer_mut());
                } else {
                    unreachable!()
                }
            }
            SelectedTab::ActionGroup => {
                if let Editor::CasbinGroup(ref mut e) = self.editor {
                    e.draw(table_area, frame.buffer_mut());
                } else {
                    unreachable!()
                }
            }
            SelectedTab::Users
            | SelectedTab::Targets
            | SelectedTab::Secrets
            | SelectedTab::Permissions
            | SelectedTab::CasbinNames => {
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
                        .block_on(self.backend.db_repository().list_users_with_role(false))
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
                    self.handler_id,
                    self.admin_id,
                    self.log.clone(),
                )));
            }
            SelectedTab::Permissions => {
                self.items = TableData::Permissions(
                    self.t_handle
                        .block_on(self.backend.db_repository().list_permission_polices())
                        .unwrap_or_default(),
                );
            }
            SelectedTab::CasbinNames => {
                self.items = TableData::CasbinNames(
                    self.t_handle
                        .block_on(
                            self.backend
                                .db_repository()
                                .list_casbin_names_user_visible(false),
                        )
                        .unwrap_or_default(),
                );
            }
            SelectedTab::RoleHierarchy => {
                self.editor = Editor::CasbinGroup(Box::new(casbin_group::CasbinGroupEditor::new(
                    self.backend.clone(),
                    self.t_handle.clone(),
                    self.handler_id,
                    self.admin_id,
                    GroupType::Subject,
                    self.log.clone(),
                )));
            }
            SelectedTab::TargetGroup => {
                self.editor = Editor::CasbinGroup(Box::new(casbin_group::CasbinGroupEditor::new(
                    self.backend.clone(),
                    self.t_handle.clone(),
                    self.handler_id,
                    self.admin_id,
                    GroupType::Object,
                    self.log.clone(),
                )));
            }
            SelectedTab::ActionGroup => {
                self.editor = Editor::CasbinGroup(Box::new(casbin_group::CasbinGroupEditor::new(
                    self.backend.clone(),
                    self.t_handle.clone(),
                    self.handler_id,
                    self.admin_id,
                    GroupType::Action,
                    self.log.clone(),
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
                .map(|v| format!("{v:^17}").fg(self.editor_colors.tab_font)),
        )
        .style(self.editor_colors.tab_bg)
        .highlight_style(
            Style::default()
                .magenta()
                .on_black()
                .bold()
                .fg(self.editor_colors.tab_fg)
                .bg(self.editor_colors.tab_bg),
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
                Editor::Permission(_) => {
                    Line::styled("Add New Permission", Style::default().bold())
                }
                Editor::CasbinName(_) => Line::styled("Add New Group", Style::default().bold()),
                Editor::GrantRole(_) => unreachable!(),
                Editor::Bind(_) => unreachable!(),
                Editor::CasbinGroup(_) => unreachable!(),
                Editor::None => unreachable!(),
            },
            Popup::Edit => match self.editor {
                Editor::User(_) => Line::styled("Edit User", Style::default().bold()),
                Editor::Target(_) => Line::styled("Edit Target", Style::default().bold()),
                Editor::Secret(_) => Line::styled("Edit Secret", Style::default().bold()),
                Editor::Permission(_) => Line::styled("Edit Permission", Style::default().bold()),
                Editor::GrantRole(_) => Line::styled("Grant Role", Style::default().bold()),
                Editor::CasbinName(_) => Line::styled("Edit Group", Style::default().bold()),
                Editor::Bind(_) => unreachable!(),
                Editor::CasbinGroup(_) => unreachable!(),
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
                    SelectedTab::Permissions => {
                        render_confirm_dialog(
                            popup_area,
                            frame.buffer_mut(),
                            &["Delete selected permission?".to_string()],
                        );
                    }
                    SelectedTab::CasbinNames => {
                        render_confirm_dialog(
                            popup_area,
                            frame.buffer_mut(),
                            &["Delete selected group?".to_string()],
                        );
                    }
                    SelectedTab::Bind => unreachable!(),
                    SelectedTab::RoleHierarchy => unreachable!(),
                    SelectedTab::TargetGroup => unreachable!(),
                    SelectedTab::ActionGroup => unreachable!(),
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
            Editor::User(ref e) => e.as_ref().form.help_text,
            Editor::Target(ref e) => e.as_ref().form.help_text,
            Editor::Secret(ref e) => e.as_ref().form.help_text,
            Editor::Bind(ref e) => e.as_ref().help_text,
            Editor::CasbinGroup(ref e) => e.as_ref().help_text,
            Editor::Permission(ref e) => e.as_ref().help_text,
            Editor::GrantRole(ref e) => e.as_ref().help_text,
            Editor::CasbinName(ref e) => e.as_ref().form.help_text,
            Editor::None => {
                if self.selected_tab == SelectedTab::Users {
                    USER_HELP_TEXT
                } else {
                    HELP_TEXT
                }
            }
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
    Users(Vec<UserWithRole>),
    Targets(Vec<Target>),
    Secrets(Vec<Secret>),
    CasbinNames(Vec<CasbinName>),
    Permissions(Vec<PermissionPolicy>),
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
            data.get(i).map(|u| u.user())
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

    fn get_permission(&self, i: usize) -> Option<PermissionPolicy> {
        if let TableData::Permissions(data) = self {
            data.get(i).cloned()
        } else {
            None
        }
    }

    fn get_casbin_name(&self, i: usize) -> Option<CasbinName> {
        if let TableData::CasbinNames(data) = self {
            data.get(i).cloned()
        } else {
            None
        }
    }

    fn constraint_len_calculator(&self) -> Vec<Constraint> {
        match self {
            Self::Users(data) => {
                let username_len = data
                    .iter()
                    .map(|v| v.user.username.as_str())
                    .map(UnicodeWidthStr::width)
                    .max()
                    .unwrap_or(0)
                    .max(8);

                let email_len = data
                    .iter()
                    .map(|v| v.user.email.as_deref().unwrap_or(""))
                    .map(UnicodeWidthStr::width)
                    .max()
                    .unwrap_or(0)
                    .max(5);

                let role_len = data
                    .iter()
                    .map(|v| v.role.as_str())
                    .map(UnicodeWidthStr::width)
                    .max()
                    .unwrap_or(0)
                    .max(4);

                vec![
                    Constraint::Length(username_len as u16),
                    Constraint::Length(email_len as u16),
                    Constraint::Length(13),
                    Constraint::Length(15),
                    Constraint::Length(15),
                    Constraint::Length(9),
                    Constraint::Length(role_len as u16),
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
                    Constraint::Length(name_len as u16),
                    Constraint::Length(user_len as u16),
                    Constraint::Length(8),  // password (shown as <hidden>)
                    Constraint::Length(11), // private_key (shown as <hidden>)
                    Constraint::Length(public_key_len as u16), // public_key (shown as <hidden>)
                    Constraint::Length(9),  // is_active
                ]
            }
            Self::CasbinNames(data) => {
                let ptype_len = data.iter().map(|v| v.ptype.len()).max().unwrap_or(0).max(6);

                let name_len = data
                    .iter()
                    .map(|v| v.name.as_str())
                    .map(UnicodeWidthStr::width)
                    .max()
                    .unwrap_or(0)
                    .max(4);

                vec![
                    Constraint::Length(ptype_len as u16),
                    Constraint::Length(name_len as u16),
                    Constraint::Length(9), // is_active
                ]
            }
            Self::Permissions(data) => {
                let user_role_len = data
                    .iter()
                    .map(|v| v.user_role.as_str())
                    .map(UnicodeWidthStr::width)
                    .max()
                    .unwrap_or(0)
                    .max(9);

                let target_group_len = data
                    .iter()
                    .map(|v| v.target_group.as_str())
                    .map(UnicodeWidthStr::width)
                    .max()
                    .unwrap_or(0)
                    .max(12);

                let action_group_len = data
                    .iter()
                    .map(|v| v.action_group.as_str())
                    .map(UnicodeWidthStr::width)
                    .max()
                    .unwrap_or(0)
                    .max(12);

                let ext_len = data
                    .iter()
                    .map(|v| v.rule.v3.len())
                    .max()
                    .unwrap_or(0)
                    .max(13);

                vec![
                    Constraint::Length(user_role_len as u16),
                    Constraint::Length(target_group_len as u16),
                    Constraint::Length(action_group_len as u16),
                    Constraint::Length(ext_len as u16),
                ]
            }
        }
    }
}

impl crate::server::widgets::TableData for TableData {
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
            Self::CasbinNames(data) => data
                .iter()
                .map(|v| v as &dyn FieldsToArray)
                .collect::<Vec<_>>(),
            Self::Permissions(data) => data
                .iter()
                .map(|v| v as &dyn FieldsToArray)
                .collect::<Vec<_>>(),
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Users(data) => data.len(),
            Self::Targets(data) => data.len(),
            Self::Secrets(data) => data.len(),
            Self::CasbinNames(data) => data.len(),
            Self::Permissions(data) => data.len(),
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
                "role",
            ],
            Self::Targets(_) => vec![
                "name",
                "hostname",
                "port",
                "server_public_key",
                "description",
                "is_active",
            ],
            Self::Secrets(_) => vec![
                "name",
                "user",
                "password",
                "private_key",
                "public_key",
                "is_active",
            ],
            Self::CasbinNames(_) => vec!["Type", "name", "is_active"],
            Self::Permissions(_) => {
                vec!["user/role", "target/group", "action/group", "extend policy"]
            }
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
    Permission(Box<permission::PermissionEditor>),
    CasbinGroup(Box<casbin_group::CasbinGroupEditor<B>>),
    GrantRole(Box<grant_role::GrantRoleEditor<B>>),
    CasbinName(Box<casbin_name::CasbinNameEditor>),
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
            Editor::User(e) => {
                e.render(area, buf);
            }
            Editor::Target(e) => {
                e.render(area, buf);
            }
            Editor::Secret(e) => {
                e.render(area, buf);
            }
            Editor::GrantRole(e) => {
                e.render(area, buf);
            }
            Editor::Bind(e) => {
                e.render(area, buf);
            }
            Editor::Permission(e) => {
                e.render(area, buf);
            }
            Editor::CasbinName(e) => {
                e.render(area, buf);
            }
            Editor::CasbinGroup(_) => {
                unreachable!();
            }
            Editor::None => {}
        }
    }
}
