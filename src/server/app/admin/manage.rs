use crate::database::Uuid;
use crate::database::models::*;
use crate::error::Error;
use crate::fill;
use crate::i18n::{Lang, Strings};
use crate::server::event_log::{Audit, Change, EventKind, EventLogger, Object, dependents_items};
use crate::server::widgets::{
    AdminTable, DisplayMode, FieldsToArray, Help, Message, TabBar, TableData as TD, Theme,
    centered_area, common::*, footer_height, popup_block, render_confirm_dialog, render_footer,
    render_message_popup,
};
use ::log::{error, info, warn};
use crossterm::event::{self, KeyCode, KeyEvent, KeyModifiers, NoTtyEvent, SenderWriter};
use crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::Frame;
use ratatui::backend::NottyBackend;
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::widgets::Paragraph;
use ratatui_core::terminal::AsyncTerminal;
use std::sync::Arc;
use unicode_width::UnicodeWidthStr;

mod bind;
mod casbin_group;
mod casbin_name;
mod grant_role;
mod permission;
mod secret;
mod target;
mod user;

const HELP_TEXT: Help = |tr| [tr.help_manage, tr.help_manage_nav];

const USER_HELP_TEXT: Help = |tr| [tr.help_manage_user, tr.help_manage_nav];

#[allow(clippy::too_many_arguments)]
pub(super) async fn manage<B>(
    tty: NoTtyEvent,
    writer: SenderWriter,
    user_id: Uuid,
    handler_id: Uuid,
    backend: Arc<B>,
    log: EventLogger<B>,
    theme: &mut &'static Theme,
    lang: &mut Lang,
) -> Result<(), Error>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    let tty_backend = NottyBackend::new(tty.clone(), writer.clone());
    let mut terminal = AsyncTerminal::new(tty_backend)?;
    crossterm::async_execute!(&writer, EnterAlternateScreen).await?;
    let mut app = App::new(backend, user_id, handler_id, log, theme, *lang).await;
    let result = app.run(tty, &mut terminal).await;
    // The shell starts the next panel in the theme and language this one
    // ended with.
    *theme = app.theme;
    *lang = app.lang;
    result?;
    crossterm::async_execute!(&writer, LeaveAlternateScreen).await?;
    Ok(())
}

#[derive(PartialEq)]
enum Popup {
    None,
    Add,
    Edit,
    /// The row, and what deleting it would take along, for the dialog.
    Delete(usize, Dependents),
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

impl SelectedTab {
    /// The tab's label, in the order of the tabs.
    fn labels(tr: &Strings) -> [&'static str; 9] {
        [
            tr.tab_users,
            tr.tab_targets,
            tr.tab_secrets,
            tr.tab_bind,
            tr.tab_permissions,
            tr.tab_groups,
            tr.tab_role_hierarchy,
            tr.tab_target_group,
            tr.tab_action_group,
        ]
    }

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
    theme: &'static Theme,
    lang: Lang,
    backend: Arc<B>,
    handler_id: Uuid,
    admin_id: Uuid,
    editor: Editor<B>,
    message: Option<Message>,
    log: EventLogger<B>,
    tabs: TabBar,
}

impl<B> App<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    async fn new(
        backend: Arc<B>,
        admin_id: Uuid,
        handler_id: Uuid,
        log: EventLogger<B>,
        theme: &'static Theme,
        lang: Lang,
    ) -> Self {
        let data = TableData::Users(
            match backend.db_repository().list_users_with_role(false).await {
                Ok(d) => d,
                Err(e) => {
                    error!("[{}] Failed to list users: {}", handler_id, e);
                    Vec::new()
                }
            },
        );

        Self {
            table: AdminTable::new(&data),
            longest_item_lens: data.constraint_len_calculator(),
            theme,
            lang,
            selected_tab: SelectedTab::Users,
            last_selected_tab: SelectedTab::Users,
            popup: Popup::None,
            backend,
            handler_id,
            items: data,
            admin_id,
            editor: Editor::None,
            message: None,
            log: log.scoped(EventKind::Manage),
            tabs: TabBar::default(),
        }
    }

    async fn next_tab(&mut self) {
        self.selected_tab = self.selected_tab.next();
        if self.selected_tab != self.last_selected_tab {
            self.refresh_data().await;
            self.table.state.select(Some(0));
            self.last_selected_tab = self.selected_tab
        }
    }

    async fn previous_tab(&mut self) {
        self.selected_tab = self.selected_tab.previous();
        if self.selected_tab != self.last_selected_tab {
            self.refresh_data().await;
            self.table.state.select(Some(0));
            self.last_selected_tab = self.selected_tab
        }
    }

    async fn add_form(&mut self) {
        self.popup = Popup::Add;

        match self.selected_tab {
            SelectedTab::Users => {
                self.editor = Editor::User(Box::new(user::UserEditor::new(
                    User::new(self.admin_id),
                    true,
                    self.lang.strings(),
                )))
            }
            SelectedTab::Targets => {
                self.editor = Editor::Target(Box::new(target::TargetEditor::new(
                    Target::new(self.admin_id),
                    true,
                    self.lang.strings(),
                )))
            }
            SelectedTab::Secrets => {
                self.editor = Editor::Secret(Box::new(secret::SecretEditor::new(
                    Secret::new(self.admin_id),
                    true,
                    self.backend.clone(),
                    self.lang.strings(),
                )))
            }
            SelectedTab::Permissions => {
                let perm = PermissionPolicy::new(self.admin_id);
                self.editor = Editor::Permission(Box::new(
                    permission::PermissionEditor::new(
                        perm,
                        true,
                        self.backend.clone(),
                        self.lang.strings(),
                    )
                    .await,
                ))
            }
            SelectedTab::CasbinNames => {
                self.editor = Editor::CasbinName(Box::new(casbin_name::CasbinNameEditor::new(
                    // `G1` matches the radio's first option in `casbin_name.rs`.
                    CasbinName::new(NamePtype::G1, String::new(), true, self.admin_id),
                    true,
                    self.lang.strings(),
                )))
            }
            SelectedTab::Bind => unreachable!(),
            SelectedTab::RoleHierarchy => unreachable!(),
            SelectedTab::TargetGroup => unreachable!(),
            SelectedTab::ActionGroup => unreachable!(),
        }
    }

    async fn grant_role_form(&mut self) -> bool {
        self.popup = Popup::Edit;
        let idx = self.table.state.selected().unwrap();
        let user = match self.items.get_user(idx) {
            Some(u) => u,
            None => {
                return false;
            }
        };
        self.editor = Editor::GrantRole(Box::new(
            grant_role::GrantRoleEditor::new(
                user.id,
                self.backend.clone(),
                self.handler_id,
                self.admin_id,
                self.log.clone(),
                self.lang.strings(),
            )
            .await,
        ));
        true
    }

    async fn edit_form(&mut self) -> bool {
        self.popup = Popup::Edit;

        match self.selected_tab {
            SelectedTab::Users => {
                let idx = self.table.state.selected().unwrap();
                let mut user = match self.items.get_user(idx) {
                    Some(u) => u,
                    None => {
                        return false;
                    }
                };
                user.updated_by = self.admin_id;
                self.editor = Editor::User(Box::new(user::UserEditor::new(
                    user,
                    false,
                    self.lang.strings(),
                )));
            }
            SelectedTab::Targets => {
                let idx = self.table.state.selected().unwrap();
                let mut target = match self.items.get_target(idx) {
                    Some(u) => u,
                    None => {
                        return false;
                    }
                };
                target.updated_by = self.admin_id;
                self.editor = Editor::Target(Box::new(target::TargetEditor::new(
                    target,
                    false,
                    self.lang.strings(),
                )));
            }
            SelectedTab::Secrets => {
                let idx = self.table.state.selected().unwrap();
                let mut secret = match self.items.get_secret(idx) {
                    Some(s) => s,
                    None => {
                        return false;
                    }
                };
                secret.updated_by = self.admin_id;
                self.editor = Editor::Secret(Box::new(secret::SecretEditor::new(
                    secret,
                    false,
                    self.backend.clone(),
                    self.lang.strings(),
                )));
            }
            SelectedTab::Permissions => {
                let idx = self.table.state.selected().unwrap();
                let mut permission = match self.items.get_permission(idx) {
                    Some(s) => s,
                    None => {
                        return false;
                    }
                };
                permission.rule.updated_by = self.admin_id;
                self.editor = Editor::Permission(Box::new(
                    permission::PermissionEditor::new(
                        permission,
                        false,
                        self.backend.clone(),
                        self.lang.strings(),
                    )
                    .await,
                ));
            }
            SelectedTab::CasbinNames => {
                let idx = self.table.state.selected().unwrap();
                let mut casbin_name = match self.items.get_casbin_name(idx) {
                    Some(c) => c,
                    None => {
                        return false;
                    }
                };
                casbin_name.updated_by = self.admin_id;
                self.editor = Editor::CasbinName(Box::new(casbin_name::CasbinNameEditor::new(
                    casbin_name,
                    false,
                    self.lang.strings(),
                )));
            }
            SelectedTab::Bind => unreachable!(),
            SelectedTab::RoleHierarchy => unreachable!(),
            SelectedTab::TargetGroup => unreachable!(),
            SelectedTab::ActionGroup => unreachable!(),
        }

        true
    }

    async fn do_delete(&mut self, idx: usize) {
        self.popup = Popup::None;
        match self.selected_tab {
            SelectedTab::Users => {
                if let Some(u) = self.items.get_user(idx) {
                    let result = self.backend.db_repository().delete_user(u.id).await;

                    let removed = match result {
                        Ok(removed) => removed.unwrap_or_default(),
                        Err(e) => {
                            self.message = Some(Message::Error(vec![
                                self.lang.strings().internal_error.into(),
                            ]));
                            warn!(
                                "[{}] Delete user '{}({})' failed by admin_id={}: {}",
                                self.handler_id, u.username, u.id, self.admin_id, e
                            );
                            return;
                        }
                    };

                    info!(
                        "[{}] User '{}({})' deleted by admin_id={}, with {:?}",
                        self.handler_id, u.username, u.id, self.admin_id, removed
                    );
                    let event = Audit::deleted(Object::User, &u.username, u.id, removed);
                    self.message = Some(Message::Success(vec![event.notice(self.lang.strings())]));
                    self.log.record(event).await;
                    self.refresh_data().await;
                }
            }
            SelectedTab::Targets => {
                if let Some(t) = self.items.get_target(idx) {
                    let result = self.backend.db_repository().delete_target(t.id).await;

                    let removed = match result {
                        Ok(removed) => removed.unwrap_or_default(),
                        Err(e) => {
                            self.message = Some(Message::Error(vec![
                                self.lang.strings().internal_error.into(),
                            ]));
                            warn!(
                                "[{}] Delete target '{}({})' failed by admin_id={}: {}",
                                self.handler_id, t.name, t.id, self.admin_id, e
                            );
                            return;
                        }
                    };

                    info!(
                        "[{}] Target '{}({})' deleted by admin_id={}, with {:?}",
                        self.handler_id, t.name, t.id, self.admin_id, removed
                    );
                    let event = Audit::deleted(Object::Target, &t.name, t.id, removed);
                    self.message = Some(Message::Success(vec![event.notice(self.lang.strings())]));
                    self.log.record(event).await;
                    self.refresh_data().await;
                }
            }
            SelectedTab::Secrets => {
                if let Some(s) = self.items.get_secret(idx) {
                    let result = self.backend.db_repository().delete_secret(s.id).await;

                    let removed = match result {
                        Ok(removed) => removed.unwrap_or_default(),
                        Err(e) => {
                            self.message = Some(Message::Error(vec![
                                self.lang.strings().internal_error.into(),
                            ]));
                            warn!(
                                "[{}] Delete secret '{}({})' failed by admin_id={}: {}",
                                self.handler_id, s.name, s.id, self.admin_id, e
                            );
                            return;
                        }
                    };

                    info!(
                        "[{}] Secret '{}({})' deleted by admin_id={}, with {:?}",
                        self.handler_id, s.name, s.id, self.admin_id, removed
                    );
                    let event = Audit::deleted(Object::Secret, &s.name, s.id, removed);
                    self.message = Some(Message::Success(vec![event.notice(self.lang.strings())]));
                    self.log.record(event).await;
                    self.refresh_data().await;
                }
            }
            SelectedTab::Permissions => {
                if let Some(p) = self.items.get_permission(idx) {
                    let result = self
                        .backend
                        .db_repository()
                        .delete_casbin_rule(p.rule.id)
                        .await;

                    if let Err(e) = result {
                        self.message = Some(Message::Error(vec![
                            self.lang.strings().internal_error.into(),
                        ]));
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
                    let event = Audit::saved(Object::Permission, Change::Deleted, "", p.rule.id);
                    self.message = Some(Message::Success(vec![event.notice(self.lang.strings())]));
                    self.log.record(event).await;
                    self.refresh_data().await;
                }
            }
            SelectedTab::CasbinNames => {
                if let Some(c) = self.items.get_casbin_name(idx) {
                    let result = self.backend.db_repository().delete_casbin_name(c.id).await;

                    let removed = match result {
                        Ok(removed) => removed.unwrap_or_default(),
                        Err(e) => {
                            self.message = Some(Message::Error(vec![
                                self.lang.strings().internal_error.into(),
                            ]));
                            warn!(
                                "[{}] Delete casbin name '{}({})' failed by admin_id={}: {}",
                                self.handler_id, c.name, c.id, self.admin_id, e
                            );
                            return;
                        }
                    };

                    info!(
                        "[{}] Casbin name '{}({})' deleted by admin_id={}, with {:?}",
                        self.handler_id, c.name, c.id, self.admin_id, removed
                    );
                    let event = Audit::deleted(Object::Group, &c.name, c.id, removed);
                    self.message = Some(Message::Success(vec![event.notice(self.lang.strings())]));
                    self.log.record(event).await;
                    self.refresh_data().await;
                }
            }
            SelectedTab::Bind => unreachable!(),
            SelectedTab::RoleHierarchy => unreachable!(),
            SelectedTab::TargetGroup => unreachable!(),
            SelectedTab::ActionGroup => unreachable!(),
        }
    }

    /// What deleting the row at `idx` would take along. A permission is a
    /// rule itself, and nothing names it.
    async fn dependents(&self, idx: usize) -> Result<Dependents, Error> {
        let id = match self.selected_tab {
            SelectedTab::Users => self.items.get_user(idx).map(|u| u.id),
            SelectedTab::Targets => self.items.get_target(idx).map(|t| t.id),
            SelectedTab::Secrets => self.items.get_secret(idx).map(|s| s.id),
            SelectedTab::CasbinNames => self.items.get_casbin_name(idx).map(|c| c.id),
            _ => None,
        };
        match id {
            Some(id) => self.backend.db_repository().dependents(id).await,
            None => Ok(Dependents::default()),
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
        self.table.dim(false);
    }

    async fn run(
        &mut self,
        tty: NoTtyEvent,
        terminal: &mut AsyncTerminal<NottyBackend>,
    ) -> Result<(), Error> {
        loop {
            terminal.draw(|frame| self.render(frame)).await?;
            let event = event::read(&tty).await?;

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
                        if e.handle_key_event(key.code, key.modifiers).await {
                            self.editor = Editor::None;
                        } else {
                            continue;
                        }
                    }
                    Editor::CasbinGroup(ref mut e) => {
                        if e.handle_key_event(key.code, key.modifiers).await {
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
                            KeyCode::Char('t') => self.theme = self.theme.next(),
                            KeyCode::Char('L') => self.lang = self.lang.next(),
                            KeyCode::Tab => self.next_tab().await,
                            KeyCode::BackTab => self.previous_tab().await,
                            KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                            KeyCode::Char('c') if ctrl_pressed => return Ok(()),
                            KeyCode::Char('j') | KeyCode::Down => self.table.next_row(items_len),
                            KeyCode::Char('k') | KeyCode::Up => self.table.previous_row(items_len),
                            KeyCode::Char('l') | KeyCode::Right => self.table.next_column(),
                            KeyCode::Char('h') | KeyCode::Left => self.table.previous_column(),
                            KeyCode::Char('d') if !ctrl_pressed => {
                                self.table.dim(true);
                                let idx = self.table.state.selected().unwrap();

                                if self.could_delete(idx) {
                                    match self.dependents(idx).await {
                                        Ok(d) => self.popup = Popup::Delete(idx, d),
                                        Err(e) => {
                                            self.message = Some(Message::Error(vec![
                                                self.lang.strings().internal_error.into(),
                                            ]));
                                            warn!(
                                                "[{}] Counting what a delete takes failed: {}",
                                                self.handler_id, e
                                            );
                                            self.clear_form();
                                        }
                                    }
                                } else {
                                    self.clear_form();
                                }
                            }
                            KeyCode::Char('a') => {
                                self.table.dim(true);
                                self.add_form().await
                            }
                            KeyCode::Char('e') => {
                                self.table.dim(true);
                                if !self.edit_form().await {
                                    self.clear_form();
                                }
                            }
                            KeyCode::Char('r') => {
                                self.table.dim(true);
                                if !self.grant_role_form().await {
                                    self.clear_form();
                                }
                            }
                            _ => {}
                        }
                    }
                    Popup::Add | Popup::Edit => {
                        if let Err(e) = self.do_edit(key).await {
                            self.message = Some(Message::Error(vec![
                                self.lang.strings().internal_error.into(),
                            ]));
                            warn!("[{}] Failed to edit: {}", self.handler_id, e);
                        }
                    }
                    Popup::Delete(i, _) => match key.code {
                        KeyCode::Char('y') | KeyCode::Char('Y') => {
                            self.do_delete(i).await;
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
                    Editor::Permission(ref mut e) => {
                        let _ = e.as_mut().handle_paste_event(paste);
                    }
                    Editor::GrantRole(_) => {}
                    Editor::Bind(_) => unreachable!(),
                    Editor::CasbinGroup(_) => unreachable!(),
                    Editor::None => {}
                }
            }
        }
    }

    async fn do_edit(&mut self, key: KeyEvent) -> Result<(), Error> {
        match self.editor {
            Editor::User(ref mut e) => {
                if e.as_mut().handle_key_event(key.code, key.modifiers) {
                    if !e.form.show_cancel_confirmation {
                        let mut password = String::new();
                        let mut active_model = e.active_model.to_owned();

                        if e.generate_password {
                            password = crate::common::gen_password(12);
                            self.backend.set_password(&mut active_model, &password)?;
                        }

                        let (action, result) = match self.popup {
                            Popup::Add => (
                                Change::Added,
                                self.backend.db_repository().create_user(active_model).await,
                            ),
                            Popup::Edit => (
                                Change::Updated,
                                self.backend.db_repository().update_user(active_model).await,
                            ),
                            _ => unreachable!(),
                        };

                        let user = match result {
                            Ok(u) => u,
                            Err(ref err) => {
                                let msg = match err {
                                    e if e.is_unique_violation() => self.lang.strings().user_exists,
                                    _ => self.lang.strings().internal_error,
                                };
                                warn!("[{}] Failed to {} user: {}", self.handler_id, action, err);
                                self.message = Some(Message::Error(vec![msg.into()]));
                                return Ok(());
                            }
                        };

                        info!(
                            "[{}] User '{}({})' {} by admin_id={}",
                            self.handler_id, user.username, user.id, action, self.admin_id
                        );
                        let event = Audit::saved(Object::User, action, &user.username, user.id);
                        let tr = self.lang.strings();
                        let mut msg = vec![event.notice(tr)];
                        if !password.is_empty() {
                            msg.push(fill!(tr.new_password, password = password));
                        }
                        self.log.record(event).await;
                        self.message = Some(Message::Success(msg));
                    }

                    self.clear_form();
                    self.refresh_data().await;
                    self.restore_color();
                }
            }
            Editor::Target(ref mut e) => {
                if e.as_mut().handle_key_event(key.code, key.modifiers) {
                    if !e.form.show_cancel_confirmation {
                        let active_model = e.active_model.to_owned();

                        let (action, result) = match self.popup {
                            Popup::Add => (
                                Change::Added,
                                self.backend
                                    .db_repository()
                                    .create_target(active_model)
                                    .await,
                            ),
                            Popup::Edit => (
                                Change::Updated,
                                self.backend
                                    .db_repository()
                                    .update_target(active_model)
                                    .await,
                            ),
                            _ => unreachable!(),
                        };

                        let target = match result {
                            Ok(t) => t,
                            Err(ref err) => {
                                let msg = match err {
                                    e if e.is_unique_violation() => {
                                        self.lang.strings().target_exists
                                    }
                                    _ => self.lang.strings().internal_error,
                                };
                                warn!("[{}] Failed to {} target: {}", self.handler_id, action, err);
                                self.message = Some(Message::Error(vec![msg.into()]));
                                return Ok(());
                            }
                        };

                        info!(
                            "[{}] Target '{}({})' {} by admin_id={}",
                            self.handler_id, target.name, target.id, action, self.admin_id
                        );
                        let event = Audit::saved(Object::Target, action, &target.name, target.id);
                        let msg = vec![event.notice(self.lang.strings())];
                        self.log.record(event).await;
                        self.message = Some(Message::Success(msg));
                    }

                    self.clear_form();
                    self.refresh_data().await;
                    self.restore_color();
                }
            }
            Editor::Secret(ref mut e) => {
                if e.as_mut().handle_key_event(key.code, key.modifiers) {
                    if !e.form.show_cancel_confirmation {
                        let active_model = e.active_model.to_owned();
                        let (action, result) = match self.popup {
                            Popup::Add => (
                                Change::Added,
                                self.backend
                                    .db_repository()
                                    .create_secret(active_model)
                                    .await,
                            ),
                            Popup::Edit => (
                                Change::Updated,
                                self.backend
                                    .db_repository()
                                    .update_secret(active_model)
                                    .await,
                            ),
                            _ => unreachable!(),
                        };

                        let secret = match result {
                            Ok(s) => s,
                            Err(ref err) => {
                                let msg = match err {
                                    e if e.is_unique_violation() => {
                                        self.lang.strings().secret_exists
                                    }
                                    _ => self.lang.strings().internal_error,
                                };
                                warn!("[{}] Failed to {} secret: {}", self.handler_id, action, err);
                                self.message = Some(Message::Error(vec![msg.into()]));
                                return Ok(());
                            }
                        };

                        info!(
                            "[{}] Secret '{}({})' {} by admin_id={}",
                            self.handler_id, secret.name, secret.id, action, self.admin_id
                        );
                        let event = Audit::saved(Object::Secret, action, &secret.name, secret.id);
                        let msg = vec![event.notice(self.lang.strings())];
                        self.log.record(event).await;
                        self.message = Some(Message::Success(msg));
                    }
                    self.clear_form();
                    self.refresh_data().await;
                    self.restore_color();
                }
            }
            Editor::Permission(ref mut e) => {
                if e.as_mut().handle_key_event(key.code, key.modifiers) {
                    if !e.show_cancel_confirmation {
                        let active_model = e.active_model.to_owned();
                        let (action, result) = match self.popup {
                            Popup::Add => (
                                Change::Added,
                                self.backend
                                    .db_repository()
                                    .create_casbin_rule(active_model)
                                    .await,
                            ),
                            Popup::Edit => (
                                Change::Updated,
                                self.backend
                                    .db_repository()
                                    .update_casbin_rule(active_model)
                                    .await,
                            ),
                            _ => unreachable!(),
                        };

                        let rule = match result {
                            Ok(s) => s,
                            Err(ref err) => {
                                let msg = match err {
                                    e if e.is_unique_violation() => {
                                        self.lang.strings().permission_exists
                                    }
                                    _ => self.lang.strings().internal_error,
                                };
                                warn!(
                                    "[{}] Failed to {} permission: {}",
                                    self.handler_id, action, err
                                );
                                self.message = Some(Message::Error(vec![msg.into()]));
                                return Ok(());
                            }
                        };

                        info!(
                            "[{}] Permission '({})' {} by admin_id={}",
                            self.handler_id, rule.id, action, self.admin_id
                        );
                        let event = Audit::saved(Object::Permission, action, "", rule.id);
                        let msg = vec![event.notice(self.lang.strings())];
                        self.log.record(event).await;
                        self.message = Some(Message::Success(msg));
                    }
                    self.clear_form();
                    self.refresh_data().await;
                    self.restore_color();
                }
            }
            Editor::GrantRole(ref mut e) => {
                if e.as_mut().handle_key_event(key.code, key.modifiers).await {
                    self.clear_form();
                    self.refresh_data().await;
                    self.restore_color();
                }
            }
            Editor::CasbinName(ref mut e) => {
                if e.as_mut().handle_key_event(key.code, key.modifiers) {
                    if !e.form.show_cancel_confirmation {
                        let active_model = e.active_model.to_owned();

                        let (action, result) = match self.popup {
                            Popup::Add => (
                                Change::Added,
                                self.backend
                                    .db_repository()
                                    .create_casbin_name(active_model)
                                    .await,
                            ),
                            Popup::Edit => (
                                Change::Updated,
                                self.backend
                                    .db_repository()
                                    .update_casbin_name(active_model)
                                    .await,
                            ),
                            _ => unreachable!(),
                        };

                        let casbin_name = match result {
                            Ok(s) => s,
                            Err(ref err) => {
                                let msg = match err {
                                    e if e.is_unique_violation() => {
                                        self.lang.strings().group_exists
                                    }
                                    _ => self.lang.strings().internal_error,
                                };
                                warn!(
                                    "[{}] Failed to {} casbin name: {}",
                                    self.handler_id, action, err
                                );
                                self.message = Some(Message::Error(vec![msg.into()]));
                                return Ok(());
                            }
                        };

                        info!(
                            "[{}] Casbin name '{}({})' {} by admin_id={}",
                            self.handler_id,
                            casbin_name.name,
                            casbin_name.id,
                            action,
                            self.admin_id
                        );
                        let event =
                            Audit::saved(Object::Group, action, &casbin_name.name, casbin_name.id);
                        let msg = vec![event.notice(self.lang.strings())];
                        self.log.record(event).await;
                        self.message = Some(Message::Success(msg));
                    }
                    self.clear_form();
                    self.refresh_data().await;
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
        let theme = self.theme;
        let tr = self.lang.strings();
        theme.paint(area, frame.buffer_mut());

        if area.width < MIN_WINDOW_COL || area.height < MIN_WINDOW_ROW {
            self.render_notice(frame, area, self.lang.strings().window_too_small);
            return;
        }

        let layout = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(5),
            Constraint::Length(footer_height(self.help_text(), area.width)),
        ]);
        let [header_area, table_area, footer_area] = layout.areas(area);

        self.table.size = (table_area.width, table_area.height);

        self.render_tabs(frame, header_area);
        match self.selected_tab {
            SelectedTab::Bind => {
                if let Editor::Bind(_) = self.editor {
                    self.editor.render(table_area, frame.buffer_mut(), theme);
                } else {
                    unreachable!()
                }
            }
            SelectedTab::RoleHierarchy => {
                if let Editor::CasbinGroup(ref mut e) = self.editor {
                    e.draw(table_area, frame.buffer_mut(), theme);
                } else {
                    unreachable!()
                }
            }
            SelectedTab::TargetGroup => {
                if let Editor::CasbinGroup(ref mut e) = self.editor {
                    e.draw(table_area, frame.buffer_mut(), theme);
                } else {
                    unreachable!()
                }
            }
            SelectedTab::ActionGroup => {
                if let Editor::CasbinGroup(ref mut e) = self.editor {
                    e.draw(table_area, frame.buffer_mut(), theme);
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
                    theme,
                    tr,
                );
            }
        }
        self.render_popup(frame, table_area);
        if let Some(ref msg) = self.message {
            render_message_popup(table_area, frame.buffer_mut(), msg, theme, tr);
        }
        self.render_footer(frame, footer_area);
    }

    async fn refresh_data(&mut self) {
        match self.selected_tab {
            SelectedTab::Users => {
                self.items = TableData::Users(
                    self.backend
                        .db_repository()
                        .list_users_with_role(false)
                        .await
                        .unwrap_or_default(),
                );
            }
            SelectedTab::Targets => {
                self.items = TableData::Targets(
                    self.backend
                        .db_repository()
                        .list_targets(false)
                        .await
                        .unwrap_or_default(),
                );
            }
            SelectedTab::Secrets => {
                self.items = TableData::Secrets(
                    self.backend
                        .db_repository()
                        .list_secrets(false)
                        .await
                        .unwrap_or_default(),
                );
            }
            SelectedTab::Bind => {
                // For Bind tab, we need to load targets and secrets
                let targets = self
                    .backend
                    .db_repository()
                    .list_targets_info()
                    .await
                    .unwrap_or_default();
                let secrets = if !targets.is_empty() {
                    // Get secrets for the first target as default

                    self.backend
                        .db_repository()
                        .list_secrets_by_target_id(targets[0].id)
                        .await
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };
                self.editor = Editor::Bind(Box::new(bind::BindEditor::new(
                    targets,
                    secrets,
                    self.backend.clone(),
                    self.handler_id,
                    self.admin_id,
                    self.log.clone(),
                    self.lang.strings(),
                )));
            }
            SelectedTab::Permissions => {
                self.items = TableData::Permissions(
                    self.backend
                        .db_repository()
                        .list_permission_polices()
                        .await
                        .unwrap_or_default(),
                );
            }
            SelectedTab::CasbinNames => {
                self.items = TableData::CasbinNames(
                    self.backend
                        .db_repository()
                        .list_casbin_names_user_visible(false)
                        .await
                        .unwrap_or_default(),
                );
            }
            SelectedTab::RoleHierarchy => {
                self.editor = Editor::CasbinGroup(Box::new(
                    casbin_group::CasbinGroupEditor::new(
                        self.backend.clone(),
                        self.handler_id,
                        self.admin_id,
                        GroupType::Subject,
                        self.log.clone(),
                        self.lang.strings(),
                    )
                    .await,
                ));
            }
            SelectedTab::TargetGroup => {
                self.editor = Editor::CasbinGroup(Box::new(
                    casbin_group::CasbinGroupEditor::new(
                        self.backend.clone(),
                        self.handler_id,
                        self.admin_id,
                        GroupType::Object,
                        self.log.clone(),
                        self.lang.strings(),
                    )
                    .await,
                ));
            }
            SelectedTab::ActionGroup => {
                self.editor = Editor::CasbinGroup(Box::new(
                    casbin_group::CasbinGroupEditor::new(
                        self.backend.clone(),
                        self.handler_id,
                        self.admin_id,
                        GroupType::Action,
                        self.log.clone(),
                        self.lang.strings(),
                    )
                    .await,
                ));
            }
        };

        self.longest_item_lens = self.items.constraint_len_calculator();
    }

    fn render_tabs(&mut self, frame: &mut Frame, area: Rect) {
        self.tabs.render(
            area,
            frame.buffer_mut(),
            &SelectedTab::labels(self.lang.strings()),
            self.selected_tab as usize,
            self.theme,
        );
    }

    fn render_notice(&mut self, frame: &mut Frame, area: Rect, msg: &str) {
        let paragraph = Paragraph::new(msg)
            .style(Style::new().fg(self.theme.warning).bold())
            .centered();
        let area = centered_area(area, area.width, 1);
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

        let tr = self.lang.strings();
        let title = match self.popup {
            Popup::Add => match self.editor {
                Editor::User(_) => tr.title_add_user,
                Editor::Target(_) => tr.title_add_target,
                Editor::Secret(_) => tr.title_add_secret,
                Editor::Permission(_) => tr.title_add_permission,
                Editor::CasbinName(_) => tr.title_add_group,
                Editor::GrantRole(_) => unreachable!(),
                Editor::Bind(_) => unreachable!(),
                Editor::CasbinGroup(_) => unreachable!(),
                Editor::None => unreachable!(),
            },
            Popup::Edit => match self.editor {
                Editor::User(_) => tr.title_edit_user,
                Editor::Target(_) => tr.title_edit_target,
                Editor::Secret(_) => tr.title_edit_secret,
                Editor::Permission(_) => tr.title_edit_permission,
                Editor::GrantRole(_) => tr.title_grant_role,
                Editor::CasbinName(_) => tr.title_edit_group,
                Editor::Bind(_) => unreachable!(),
                Editor::CasbinGroup(_) => unreachable!(),
                Editor::None => unreachable!(),
            },
            Popup::Delete(_, removes) => {
                let lines = |question: &str| {
                    let mut lines = vec![question.to_string()];
                    let items = dependents_items(&removes, tr);
                    if !items.is_empty() {
                        lines.push(String::new());
                        lines.push(tr.also_removes.to_string());
                        lines.extend(items);
                    }
                    lines
                };
                match self.selected_tab {
                    SelectedTab::Users => {
                        render_confirm_dialog(
                            popup_area,
                            frame.buffer_mut(),
                            &lines(tr.delete_user_q),
                            self.theme,
                            tr,
                        );
                    }
                    SelectedTab::Targets => {
                        render_confirm_dialog(
                            popup_area,
                            frame.buffer_mut(),
                            &lines(tr.delete_target_q),
                            self.theme,
                            tr,
                        );
                    }
                    SelectedTab::Secrets => {
                        render_confirm_dialog(
                            popup_area,
                            frame.buffer_mut(),
                            &lines(tr.delete_secret_q),
                            self.theme,
                            tr,
                        );
                    }
                    SelectedTab::Permissions => {
                        render_confirm_dialog(
                            popup_area,
                            frame.buffer_mut(),
                            &lines(tr.delete_permission_q),
                            self.theme,
                            tr,
                        );
                    }
                    SelectedTab::CasbinNames => {
                        render_confirm_dialog(
                            popup_area,
                            frame.buffer_mut(),
                            &lines(tr.delete_group_q),
                            self.theme,
                            tr,
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
        let theme = self.theme;
        theme.clear(popup_area, frame.buffer_mut());
        frame.render_widget(popup_block(title, theme), popup_area);
        self.editor.render(popup_area, frame.buffer_mut(), theme);
    }

    fn render_footer(&self, frame: &mut Frame, area: Rect) {
        let tr = self.lang.strings();
        render_footer(area, frame.buffer_mut(), self.help_text(), self.theme, tr);
    }

    /// The keys the footer lists: the open editor's, or the table's.
    fn help_text(&self) -> [&'static str; 2] {
        let help: Help = match self.editor {
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
        help(self.lang.strings())
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

                let proxy_len = data
                    .iter()
                    .map(|v| v.proxy.as_deref().map(|s| s.len()).unwrap_or(0))
                    .max()
                    .unwrap_or(0)
                    .max(5);

                vec![
                    Constraint::Length(name_len as u16),
                    Constraint::Length(hostname_len as u16),
                    Constraint::Length(5),
                    Constraint::Length(server_public_key_len as u16),
                    Constraint::Length(desc_len as u16),
                    Constraint::Length(proxy_len as u16),
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
                let ptype_len = data
                    .iter()
                    .map(|v| v.ptype.as_str().len())
                    .max()
                    .unwrap_or(0)
                    .max(6);

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

    fn header(&self, tr: &'static Strings) -> Vec<&'static str> {
        match self {
            Self::Users(_) => vec![
                tr.col_username,
                tr.col_email,
                tr.col_password_hash,
                tr.col_authorized_keys,
                tr.col_force_init_pass,
                tr.col_is_active,
                tr.col_role,
            ],
            Self::Targets(_) => vec![
                tr.col_name,
                tr.col_hostname,
                tr.col_port,
                tr.col_server_public_key,
                tr.col_description,
                tr.col_proxy,
                tr.col_is_active,
            ],
            Self::Secrets(_) => vec![
                tr.col_name,
                tr.col_user,
                tr.col_password,
                tr.col_private_key,
                tr.col_public_key,
                tr.col_is_active,
            ],
            Self::CasbinNames(_) => vec![tr.col_type, tr.col_name, tr.col_is_active],
            Self::Permissions(_) => vec![
                tr.col_user_role,
                tr.col_target_group,
                tr.col_action_group,
                tr.col_extend_policy,
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
    Secret(Box<secret::SecretEditor<B>>),
    Bind(Box<bind::BindEditor<B>>),
    Permission(Box<permission::PermissionEditor>),
    CasbinGroup(Box<casbin_group::CasbinGroupEditor<B>>),
    GrantRole(Box<grant_role::GrantRoleEditor<B>>),
    CasbinName(Box<casbin_name::CasbinNameEditor>),
    None,
}

impl<B> Editor<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    fn render(&mut self, area: Rect, buf: &mut Buffer, theme: &Theme) {
        match self {
            Editor::User(e) => e.render(area, buf, theme),
            Editor::Target(e) => e.render(area, buf, theme),
            Editor::Secret(e) => e.render(area, buf, theme),
            Editor::GrantRole(e) => e.render(area, buf, theme),
            Editor::Bind(e) => e.render(area, buf, theme),
            Editor::Permission(e) => e.render(area, buf, theme),
            Editor::CasbinName(e) => e.render(area, buf, theme),
            Editor::CasbinGroup(_) => {
                unreachable!();
            }
            Editor::None => {}
        }
    }
}
