use super::super::error::AdminError;
use super::super::validate;
use super::super::validate::describe;
use crate::database::entity::casbin_rule;
use crate::database::models::{ObjectGroup, PermissionPolicy};
use crate::error::Error;
use crate::server::app::error::AppError;
use crate::server::error::ServerError;
use crate::server::extend_policy::ExtendPolicy;
use crate::server::widgets::{
    AdminTable, COMMON_HELP, DisplayMode, Help, Message, SingleLineText, Strings, Theme,
    centered_area, render_cancel_dialog, render_message_popup, render_textarea,
    table_object_group_len_calculator, text_editing_style, text_input_position, theme,
};
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    widgets::{Scrollbar, ScrollbarOrientation, ScrollbarState, StatefulWidget},
};
use sea_orm::ActiveValue::{Set, Unchanged};
use std::sync::Arc;

pub const HELP_TABLE: Help = |tr| [tr.help_pick, tr.help_pick_nav];
pub const HELP_EDITOR: Help = |tr| [tr.help_permission, tr.help_form_nav];
#[derive(Debug, Clone, Copy, PartialEq)]
enum InputField {
    User,
    Target,
    Action,
    ExtendPolicy,
}

impl InputField {
    fn next(&self) -> Self {
        match self {
            Self::User => Self::Target,
            Self::Target => Self::Action,
            Self::Action => Self::ExtendPolicy,
            Self::ExtendPolicy => Self::User,
        }
    }

    fn previous(&self) -> Self {
        match self {
            Self::User => Self::ExtendPolicy,
            Self::Target => Self::User,
            Self::Action => Self::Target,
            Self::ExtendPolicy => Self::Action,
        }
    }
}

pub(super) struct PermissionEditor {
    pub perm: PermissionPolicy,
    pub active_model: casbin_rule::ActiveModel,
    user_items: Vec<ObjectGroup>,
    target_items: Vec<ObjectGroup>,
    action_items: Vec<ObjectGroup>,
    focused_field: InputField,
    user_table: AdminTable,
    target_table: AdminTable,
    action_table: AdminTable,
    longest_user_lens: Vec<Constraint>,
    longest_target_lens: Vec<Constraint>,
    longest_action_lens: Vec<Constraint>,
    extend_policy_text: SingleLineText,
    scroll_offset: usize,
    /// The theme's cursor colour as of the last render; see `FormEditor`.
    cursor_color: Color,
    pub show_cancel_confirmation: bool,
    editing_mode: bool,
    save_error: Option<Error>,
    tr: &'static Strings,
    pub help_text: Help,
}

impl PermissionEditor {
    pub async fn new<B>(
        perm: PermissionPolicy,
        is_new: bool,
        backend: Arc<B>,
        tr: &'static Strings,
    ) -> Self
    where
        B: 'static + crate::server::HandlerBackend + Send + Sync,
    {
        let mut save_error = None;
        let user_items = match backend.db_repository().list_user_group().await {
            Ok(items) => items,
            Err(e) => {
                save_error = Some(e);
                Vec::new()
            }
        };

        let target_items = match backend.db_repository().list_target_group().await {
            Ok(items) => items,
            Err(e) => {
                save_error = Some(e);
                Vec::new()
            }
        };

        let action_items = match backend.db_repository().list_action_group().await {
            Ok(items) => items,
            Err(e) => {
                save_error = Some(e);
                Vec::new()
            }
        };

        let longest_user_lens = table_object_group_len_calculator(&user_items);
        let longest_target_lens = table_object_group_len_calculator(&target_items);
        let longest_action_lens = table_object_group_len_calculator(&action_items);

        let extend_policy_text = SingleLineText::new(Some(perm.rule.v3.clone()));

        // Every column of a new rule is pre-seeded: an insert needs all of them,
        // and each `v*` is `NOT NULL`. Picking a row overwrites the placeholder,
        // and `varify_permission_labels` is what refuses to save while one of the
        // three is still unpicked.
        let active_model = if is_new {
            casbin_rule::ActiveModel {
                id: Set(perm.rule.id),
                // A permission policy is a `p` rule by definition.
                ptype: Set(perm.rule.ptype),
                v3: Set(perm.rule.v3.clone()),
                v4: Set(perm.rule.v4.clone()),
                v5: Set(perm.rule.v5.clone()),
                updated_by: Set(perm.rule.updated_by),
                ..Default::default()
            }
        } else {
            casbin_rule::ActiveModel {
                id: Unchanged(perm.rule.id),
                updated_by: Set(perm.rule.updated_by),
                ..Default::default()
            }
        };

        Self {
            perm,
            active_model,
            user_table: AdminTable::new(&user_items),
            target_table: AdminTable::new(&target_items),
            action_table: AdminTable::new(&action_items),
            user_items,
            target_items,
            action_items,
            longest_user_lens,
            longest_target_lens,
            longest_action_lens,
            extend_policy_text,
            focused_field: InputField::User,
            scroll_offset: 0,
            cursor_color: theme::DEFAULT.accent_dim,
            show_cancel_confirmation: false,
            editing_mode: false,
            save_error,
            tr,
            help_text: HELP_EDITOR,
        }
    }

    pub fn handle_paste_event(&mut self, paste: &str) -> bool {
        if self.focused_field == InputField::ExtendPolicy && self.editing_mode {
            self.extend_policy_text.handle_paste(paste)
        } else {
            false
        }
    }

    pub fn handle_key_event(&mut self, key: KeyCode, modifiers: KeyModifiers) -> bool {
        // Handle cancel confirmation dialog
        if self.show_cancel_confirmation {
            match key {
                KeyCode::Char('y') | KeyCode::Char('Y') => return true, // Exit
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.show_cancel_confirmation = false;
                }
                _ => {}
            }
            return false;
        }

        if self.save_error.is_some() {
            if key == KeyCode::Enter {
                self.save_error = None;
            }
            return false;
        }
        let ctrl_pressed = modifiers.contains(KeyModifiers::CONTROL);

        // Global shortcuts
        if ctrl_pressed {
            match key {
                KeyCode::Char('s') => {
                    if let Err(e) = self.verify_permission() {
                        self.save_error = Some(e);
                        return false;
                    }
                    return true;
                }
                KeyCode::Char('c') => {
                    self.show_cancel_confirmation = true;
                    return false;
                }
                _ => {}
            }
        }

        if self.editing_mode {
            let mut table = &mut self.user_table;
            let mut items_len = self.user_items.len();
            match self.focused_field {
                InputField::User => {}
                InputField::Target => {
                    table = &mut self.target_table;
                    items_len = self.target_items.len();
                }
                InputField::Action => {
                    table = &mut self.action_table;
                    items_len = self.action_items.len();
                }
                InputField::ExtendPolicy => {
                    if self.extend_policy_text.handle_input(key) {
                        self.editing_mode = false;
                        self.extend_policy_text.clear_style();
                    }
                }
            }
            if self.focused_field != InputField::ExtendPolicy {
                match key {
                    KeyCode::Esc | KeyCode::Char('q') | KeyCode::Tab | KeyCode::BackTab => {
                        self.editing_mode = false;
                        self.help_text = HELP_EDITOR
                    }
                    KeyCode::Char('+') => {
                        table.zoom_in();
                    }
                    KeyCode::Char('-') => {
                        table.zoom_out();
                    }
                    KeyCode::PageDown => {
                        table.next_page(items_len);
                    }
                    KeyCode::PageUp => {
                        table.previous_page();
                    }
                    KeyCode::Char('f') if ctrl_pressed => {
                        table.next_page(items_len);
                    }
                    KeyCode::Char('b') if ctrl_pressed => {
                        table.previous_page();
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        table.next_row(items_len);
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        table.previous_row(items_len);
                    }
                    KeyCode::Char(' ') | KeyCode::Enter => {
                        self.editing_mode = false;
                        self.help_text = HELP_EDITOR;
                        match self.focused_field {
                            InputField::User => {
                                let idx = self.user_table.state.selected().unwrap();
                                let t = self.user_items.get(idx).unwrap();
                                self.perm.user_role = t.name.clone();
                                if self.perm.rule.v0 != t.id {
                                    self.active_model.v0 = Set(t.id);
                                }
                            }
                            InputField::Target => {
                                let idx = self.target_table.state.selected().unwrap();
                                let t = self.target_items.get(idx).unwrap();
                                self.perm.target_group = t.name.clone();
                                if self.perm.rule.v1 != t.id {
                                    self.active_model.v1 = Set(t.id);
                                }
                            }
                            InputField::Action => {
                                let idx = self.action_table.state.selected().unwrap();
                                let t = self.action_items.get(idx).unwrap();
                                self.perm.action_group = t.name.clone();
                                if self.perm.rule.v2 != t.id {
                                    self.active_model.v2 = Set(t.id);
                                }
                            }
                            InputField::ExtendPolicy => {
                                unreachable!()
                            }
                        }
                    }
                    _ => {}
                }
            } else {
                match key {
                    KeyCode::Esc | KeyCode::Enter | KeyCode::Char(_) => {
                        return false;
                    }
                    _ => {}
                }
            }
        } else {
            match key {
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.show_cancel_confirmation = true;
                }
                KeyCode::Tab | KeyCode::Char('j') | KeyCode::Down => {
                    self.editing_mode = false;
                    self.next();
                    self.scroll_offset = if self.scroll_offset == self.max_scroll_offset() {
                        0
                    } else {
                        self.scroll_offset.saturating_add(1)
                    }
                }
                KeyCode::BackTab | KeyCode::Char('k') | KeyCode::Up => {
                    self.editing_mode = false;
                    self.previous();
                    self.scroll_offset = if self.scroll_offset == 0 {
                        self.max_scroll_offset()
                    } else {
                        self.scroll_offset.saturating_sub(1)
                    };
                }
                KeyCode::Char('d')
                    if !self.editing_mode && self.focused_field == InputField::ExtendPolicy =>
                {
                    self.extend_policy_text.clear_line();
                }
                KeyCode::Enter | KeyCode::Char('i') | KeyCode::Char('a')
                    if self.focused_field == InputField::ExtendPolicy =>
                {
                    self.editing_mode = true;
                    text_editing_style(self.cursor_color, &mut self.extend_policy_text.textarea);
                    text_input_position(key, &mut self.extend_policy_text.textarea);
                }
                KeyCode::Enter | KeyCode::Char('e') | KeyCode::Char('i') | KeyCode::Char('a')
                    if self.focused_field != InputField::ExtendPolicy =>
                {
                    self.editing_mode = true;
                    self.help_text = HELP_TABLE
                }
                _ => {}
            }
        }

        false
    }

    fn next(&mut self) {
        self.focused_field = self.focused_field.next();
        if self.focused_field == InputField::ExtendPolicy {
            self.help_text = COMMON_HELP;
        } else {
            self.help_text = HELP_EDITOR;
        }
    }

    fn previous(&mut self) {
        self.focused_field = self.focused_field.previous();
        if self.focused_field == InputField::ExtendPolicy {
            self.help_text = COMMON_HELP;
        } else {
            self.help_text = HELP_EDITOR;
        }
    }

    fn verify_permission(&mut self) -> Result<(), Error> {
        // Parsed on every save, not only when it changed: `verify_extend_policy`
        // parses `v3` again at enforcement time, so an unparseable one must never
        // reach the column — including the empty string a new rule starts with.
        let extend_policy = self.extend_policy_text.get_input().trim().to_string();
        let ext: ExtendPolicy = serde_json::from_str(&extend_policy)?;
        ext.validate().map_err(ServerError::ExtendPolicy)?;
        if self.perm.rule.v3 != extend_policy {
            self.active_model.v3 = Set(extend_policy.clone());
        }

        validate::varify_permission_labels(
            &self.perm.user_role,
            &self.perm.target_group,
            &self.perm.action_group,
        )
        .map_err(|e| AppError::Admin(AdminError::Validate(e)))?;
        Ok(())
    }

    fn max_scroll_offset(&self) -> usize {
        5
    }

    fn window_height(&self) -> u16 {
        12
    }

    fn render_textarea(&mut self, area: Rect, buf: &mut Buffer, theme: &Theme) {
        let height = self.window_height();
        let area = centered_area(area, area.width - 2, area.height - 2);
        let editor_area = Rect::new(0, 0, area.width, height);
        let mut editor_buf = theme.buffer(editor_area);
        let scrollbar_needed = height > area.height;
        let content_area = if scrollbar_needed {
            Rect {
                width: editor_area.width - 1,
                ..editor_area
            }
        } else {
            editor_area
        };

        // Create main layout
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Length(3),
            ])
            .split(content_area);

        // User field
        render_textarea(
            chunks[0],
            &mut editor_buf,
            self.tr.field_user_role,
            &SingleLineText::new(Some(self.perm.user_role.clone())),
            false,
            theme,
            self.focused_field == InputField::User,
        );

        // Target field
        render_textarea(
            chunks[1],
            &mut editor_buf,
            self.tr.field_target_group,
            &SingleLineText::new(Some(self.perm.target_group.clone())),
            false,
            theme,
            self.focused_field == InputField::Target,
        );

        // Action field
        render_textarea(
            chunks[2],
            &mut editor_buf,
            self.tr.field_action_group,
            &SingleLineText::new(Some(self.perm.action_group.clone())),
            false,
            theme,
            self.focused_field == InputField::Action,
        );

        // ExtendPolicy field
        render_textarea(
            chunks[3],
            &mut editor_buf,
            self.tr.field_extend_policy,
            &self.extend_policy_text,
            self.editing_mode,
            theme,
            self.focused_field == InputField::ExtendPolicy,
        );

        if scrollbar_needed {
            let visible_content = editor_buf
                .content
                .into_iter()
                .skip(area.width as usize * self.scroll_offset * 3)
                .take(area.area() as usize);
            for (i, cell) in visible_content.enumerate() {
                let x = i as u16 % area.width;
                let y = i as u16 / area.width;
                buf[(area.x + x, area.y + y)] = cell;
            }
        } else {
            for (i, cell) in editor_buf.content.into_iter().enumerate() {
                let x = i as u16 % area.width;
                let y = i as u16 / area.width;
                buf[(area.x + x, area.y + y)] = cell;
            }
        };

        if scrollbar_needed {
            let area = area.intersection(buf.area);
            let mut state =
                ScrollbarState::new(self.max_scroll_offset()).position(self.scroll_offset);
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .style(Style::new().fg(theme.muted))
                .render(area, buf, &mut state);
        }
    }

    pub fn render(&mut self, area: Rect, buf: &mut Buffer, theme: &Theme) {
        self.cursor_color = theme.accent_dim;
        if self.editing_mode && self.focused_field != InputField::ExtendPolicy {
            let area = centered_area(area, area.width - 2, area.height - 2);
            match self.focused_field {
                InputField::User => {
                    self.user_table.size = (area.width, area.height);
                    self.user_table.render(
                        buf,
                        area,
                        &self.user_items,
                        &self.longest_user_lens,
                        DisplayMode::Manage,
                        theme,
                        self.tr,
                    );
                }
                InputField::Target => {
                    self.target_table.size = (area.width, area.height);
                    self.target_table.render(
                        buf,
                        area,
                        &self.target_items,
                        &self.longest_target_lens,
                        DisplayMode::Manage,
                        theme,
                        self.tr,
                    );
                }
                InputField::Action => {
                    self.action_table.size = (area.width, area.height);
                    self.action_table.render(
                        buf,
                        area,
                        &self.action_items,
                        &self.longest_action_lens,
                        DisplayMode::Manage,
                        theme,
                        self.tr,
                    );
                }
                InputField::ExtendPolicy => unreachable!(),
            }
        } else {
            self.render_textarea(area, buf, theme);
        }

        // Render cancel confirmation dialog if needed
        if self.show_cancel_confirmation {
            render_cancel_dialog(area, buf, theme, self.tr);
        }

        if let Some(err) = self.save_error.as_ref() {
            let message = Message::Error(vec![describe(err, self.tr)]);
            render_message_popup(area, buf, &message, theme, self.tr);
        }
    }
}
