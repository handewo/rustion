use crate::server::widgets::{table_object_group_len_calculator, AdminTable, DisplayMode, EditorColors, SingleLineText, centered_area, render_cancel_dialog, render_message_popup, render_textarea, Message, COMMON_HELP, text_editing_style, text_input_position};
use crate::database::error::DatabaseError;
use crate::database::models::{ObjectGroup, PermissionPolicy};
use crate::error::Error;
use crate::server::casbin::ExtendPolicy;
use crate::server::error::ServerError;
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::palette::tailwind,
    widgets::{Scrollbar, ScrollbarOrientation, ScrollbarState, StatefulWidget, Widget},
};
use std::str::FromStr;
use std::sync::Arc;
use tokio::runtime::Handle;

pub const HELP_TABLE: [&str; 2] = [
    "(Space/Enter) select",
    "(↑↓) move around | (+/-) zoom in/out | (PgUp/PgDn) page up/down",
];
pub const HELP_EDITOR: [&str; 2] = [
    "(Enter/e) edit",
    "(Ctrl+s) save | (Esc) cancel | (Tab) next | (Shift Tab) previous",
];
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
    colors: EditorColors,
    pub show_cancel_confirmation: bool,
    editing_mode: bool,
    save_error: Option<Error>,
    pub help_text: [&'static str; 2],
}

impl PermissionEditor {
    pub fn new<B>(perm: PermissionPolicy, backend: Arc<B>, t_handle: Handle) -> Self
    where
        B: 'static + crate::server::HandlerBackend + Send + Sync,
    {
        let mut save_error = None;
        let user_items = match t_handle.block_on(backend.db_repository().list_user_group()) {
            Ok(items) => items,
            Err(e) => {
                save_error = Some(e);
                Vec::new()
            }
        };

        let target_items = match t_handle.block_on(backend.db_repository().list_target_group()) {
            Ok(items) => items,
            Err(e) => {
                save_error = Some(e);
                Vec::new()
            }
        };

        let action_items = match t_handle.block_on(backend.db_repository().list_action_group()) {
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
        Self {
            perm,
            user_table: AdminTable::new(&user_items, &tailwind::BLUE),
            target_table: AdminTable::new(&target_items, &tailwind::BLUE),
            action_table: AdminTable::new(&action_items, &tailwind::BLUE),
            user_items,
            target_items,
            action_items,
            longest_user_lens,
            longest_target_lens,
            longest_action_lens,
            extend_policy_text,
            focused_field: InputField::User,
            scroll_offset: 0,
            colors: EditorColors::new(&tailwind::BLUE),
            show_cancel_confirmation: false,
            editing_mode: false,
            save_error,
            help_text: HELP_EDITOR,
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
                                self.perm.rule.v0 = t.id;
                            }
                            InputField::Target => {
                                let idx = self.target_table.state.selected().unwrap();
                                let t = self.target_items.get(idx).unwrap();
                                self.perm.target_group = t.name.clone();
                                self.perm.rule.v1 = t.id;
                            }
                            InputField::Action => {
                                let idx = self.action_table.state.selected().unwrap();
                                let t = self.action_items.get(idx).unwrap();
                                self.perm.action_group = t.name.clone();
                                self.perm.rule.v2 = t.id;
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
                    text_editing_style(
                        self.colors.input_cursor,
                        &mut self.extend_policy_text.textarea,
                    );
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
        let extend_policy = self.extend_policy_text.get_input();
        self.perm.rule.v3 = extend_policy.trim().into();
        let _ =
            ExtendPolicy::from_str(&self.perm.rule.v3).map_err(ServerError::ExtendPolicyParse)?;
        self.perm
            .verify()
            .map_err(|e| Error::Database(DatabaseError::PermissionPolicyValidation(e)))?;
        Ok(())
    }

    fn max_scroll_offset(&self) -> usize {
        5
    }

    fn window_height(&self) -> u16 {
        12
    }

    fn render_textarea(&mut self, area: Rect, buf: &mut Buffer) {
        let height = self.window_height();
        let area = centered_area(area, area.width - 2, area.height - 2);
        let editor_area = Rect::new(0, 0, area.width, height);
        let mut editor_buf = Buffer::empty(editor_area);
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
            "*User/Role*",
            &SingleLineText::new(Some(self.perm.user_role.clone())),
            false,
            &self.colors,
            self.focused_field == InputField::User,
        );

        // Target field
        render_textarea(
            chunks[1],
            &mut editor_buf,
            "*Target/Group*",
            &SingleLineText::new(Some(self.perm.target_group.clone())),
            false,
            &self.colors,
            self.focused_field == InputField::Target,
        );

        // Action field
        render_textarea(
            chunks[2],
            &mut editor_buf,
            "*Action/Group*",
            &SingleLineText::new(Some(self.perm.action_group.clone())),
            false,
            &self.colors,
            self.focused_field == InputField::Action,
        );

        // ExtendPolicy field
        render_textarea(
            chunks[3],
            &mut editor_buf,
            "Extend Policy",
            &self.extend_policy_text,
            self.editing_mode,
            &self.colors,
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
            Scrollbar::new(ScrollbarOrientation::VerticalRight).render(area, buf, &mut state);
        }
    }

    fn render_ui(&mut self, area: Rect, buf: &mut Buffer) {
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
                    );
                }
                InputField::ExtendPolicy => unreachable!(),
            }
        } else {
            self.render_textarea(area, buf);
        }

        // Render cancel confirmation dialog if needed
        if self.show_cancel_confirmation {
            render_cancel_dialog(area, buf);
        }

        if let Some(err) = self.save_error.as_ref() {
            render_message_popup(area, buf, &Message::Error(vec![err.to_string()]));
        }
    }
}

impl Widget for &mut PermissionEditor {
    fn render(self, area: Rect, buf: &mut Buffer) {
        self.render_ui(area, buf);
    }
}
