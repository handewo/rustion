use crate::database::models::target_secret::Secret;
use crate::error::Error;
use crate::server::app::admin::widgets::*;
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::palette::tailwind,
    widgets::{Scrollbar, ScrollbarOrientation, ScrollbarState, StatefulWidget, Widget},
};

#[derive(Debug, Clone, Copy, PartialEq)]
enum InputField {
    Name,
    User,
    Password,
    PrivateKey,
    IsActive,
}

impl InputField {
    fn next(&self) -> Self {
        match self {
            Self::Name => Self::User,
            Self::User => Self::Password,
            Self::Password => Self::IsActive,
            Self::IsActive => Self::PrivateKey,
            Self::PrivateKey => Self::Name,
        }
    }

    fn previous(&self) -> Self {
        match self {
            Self::Name => Self::PrivateKey,
            Self::User => Self::Name,
            Self::Password => Self::User,
            Self::IsActive => Self::Password,
            Self::PrivateKey => Self::IsActive,
        }
    }
}

#[derive(Debug)]
pub struct SecretEditor {
    pub secret: Secret,
    focused_field: InputField,
    name_text: SingleLineText,
    user_text: SingleLineText,
    password_text: SingleLineText,
    private_key_text: MultiLineText,
    scroll_offset: usize,
    colors: EditorColors,
    pub show_cancel_confirmation: bool,
    pub private_key_updated: bool,
    pub password_updated: bool,
    editing_mode: bool,
    save_error: Option<Error>,
    pub help_text: [&'static str; 2],
}

impl SecretEditor {
    pub fn new(secret: Secret) -> Self {
        let name_text = SingleLineText::new(Some(secret.name.clone()));
        let user_text = SingleLineText::new(Some(secret.user.clone()));

        let mut password_text = SingleLineText::new(Some(secret.print_password()));
        password_text.textarea.set_mask_char('*');
        let private_key_text = MultiLineText::new(Some(&[secret.print_private_key()]));

        Self {
            secret,
            focused_field: InputField::Name,
            name_text,
            user_text,
            password_text,
            private_key_text,
            scroll_offset: 0,
            colors: EditorColors::new(&tailwind::BLUE),
            show_cancel_confirmation: false,
            private_key_updated: false,
            password_updated: false,
            editing_mode: false,
            save_error: None,
            help_text: COMMON_HELP,
        }
    }

    pub fn handle_paste_event(&mut self, paste: &str) -> bool {
        if self.editing_mode {
            match self.focused_field {
                InputField::Name => self.name_text.handle_paste(paste),
                InputField::User => self.user_text.handle_paste(paste),
                InputField::Password => self.password_text.handle_paste(paste),
                InputField::PrivateKey => self.private_key_text.handle_paste(paste),
                InputField::IsActive => false,
            }
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

        // Global shortcuts
        if modifiers.contains(KeyModifiers::CONTROL) {
            match key {
                KeyCode::Char('s') => {
                    if let Err(e) = self.save_secret() {
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
            match self.focused_field {
                InputField::Name => {
                    if self.name_text.handle_input(key) {
                        self.editing_mode = false;
                        self.name_text.clear_style();
                    }
                }
                InputField::User => {
                    if self.user_text.handle_input(key) {
                        self.editing_mode = false;
                        self.user_text.clear_style();
                    }
                }
                InputField::Password => {
                    if self.password_text.handle_input(key) {
                        self.editing_mode = false;
                        self.password_text.clear_style();
                    }
                }
                InputField::PrivateKey => {
                    if self.private_key_text.handle_input(key) {
                        self.editing_mode = false;
                        self.private_key_text.clear_style();
                        self.help_text = MULTILINES_HELP;
                    } else if self.private_key_text.editing_mode {
                        self.help_text = MULTILINES_INPUT_HELP;
                    } else {
                        self.help_text = MULTILINES_EDIT_HELP;
                    }
                    return false;
                }
                _ => {
                    unreachable!()
                }
            }

            match key {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char(_) => {
                    return false;
                }
                _ => {}
            }
        }

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
            KeyCode::Enter | KeyCode::Char('i') | KeyCode::Char('a') => match self.focused_field {
                InputField::IsActive => {
                    self.secret.is_active = !self.secret.is_active;
                }
                InputField::Name => {
                    self.editing_mode = true;
                    text_editing_style(self.colors.input_cursor, &mut self.name_text.textarea);
                    text_input_position(key, &mut self.name_text.textarea);
                }
                InputField::User => {
                    self.editing_mode = true;
                    text_editing_style(self.colors.input_cursor, &mut self.user_text.textarea);
                    text_input_position(key, &mut self.user_text.textarea);
                }
                InputField::Password => {
                    self.editing_mode = true;
                    text_editing_style(self.colors.input_cursor, &mut self.password_text.textarea);
                    text_input_position(key, &mut self.password_text.textarea);
                }
                InputField::PrivateKey => {
                    self.editing_mode = true;
                    self.private_key_text.cursor_color = self.colors.input_cursor;
                    self.private_key_text.highlight();
                    self.help_text = MULTILINES_EDIT_HELP;
                }
            },
            KeyCode::Char('d') if !self.editing_mode => match self.focused_field {
                InputField::Name => {
                    self.name_text.clear_line();
                }
                InputField::User => {
                    self.user_text.clear_line();
                }
                InputField::Password => {
                    self.password_text.clear_line();
                }
                InputField::PrivateKey => {
                    self.private_key_text = MultiLineText::new(None);
                }
                _ => {}
            },
            KeyCode::Char(' ') => {
                if let InputField::IsActive = self.focused_field {
                    self.secret.is_active = !self.secret.is_active;
                }
            }
            _ => {}
        }

        false
    }

    fn next(&mut self) {
        self.focused_field = self.focused_field.next();
        match self.focused_field {
            InputField::PrivateKey => {
                self.help_text = MULTILINES_HELP;
            }
            InputField::Name | InputField::Password | InputField::User => {
                self.help_text = COMMON_HELP;
            }
            InputField::IsActive => {
                self.help_text = CHECKBOX_HELP;
            }
        }
    }

    fn previous(&mut self) {
        self.focused_field = self.focused_field.previous();
        match self.focused_field {
            InputField::PrivateKey => {
                self.help_text = MULTILINES_HELP;
            }
            InputField::Name | InputField::User | InputField::Password => {
                self.help_text = COMMON_HELP;
            }
            InputField::IsActive => {
                self.help_text = CHECKBOX_HELP;
            }
        }
    }

    fn save_secret(&mut self) -> Result<(), Error> {
        let name = self.name_text.get_input();
        self.secret.name = name.trim().into();

        let user = self.user_text.get_input();
        self.secret.user = user.trim().into();

        let password = self.password_text.get_input().trim().to_string();

        // If the password field was modified (not the placeholder), update it
        // TODO: A better method is needed here.
        if password != self.secret.print_password() {
            if password.is_empty() {
                let _ = self.secret.take_password();
            } else {
                self.secret.set_password(Some(password));
            }
            self.password_updated = true;
        }

        let private_key = self
            .private_key_text
            .get_input()
            .join("\n")
            .trim()
            .to_string();
        // If the private key field was modified (not the placeholder), update it
        // TODO: A better method is needed here.
        if private_key != self.secret.print_private_key() {
            if private_key.is_empty() {
                let _ = self.secret.take_private_key();
                let _ = self.secret.take_public_key();
            } else {
                self.secret.set_private_key(Some(private_key));
            }
            self.private_key_updated = true;
        }

        self.secret
            .validate(self.private_key_updated)
            .map_err(Error::SecretValidator)
    }

    fn max_scroll_offset(&self) -> usize {
        4
    }

    fn window_height(&self) -> u16 {
        20
    }

    fn render_ui(&mut self, area: Rect, buf: &mut Buffer) {
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
                Constraint::Length(3), // Name
                Constraint::Length(3), // User
                Constraint::Length(3), // Password
                Constraint::Length(3), // Is Active
                Constraint::Length(8), // Private Key
            ])
            .split(content_area);

        // Name field
        render_textarea(
            chunks[0],
            &mut editor_buf,
            "*Name*",
            &self.name_text,
            self.editing_mode,
            &self.colors,
            self.focused_field == InputField::Name,
        );

        // User field
        render_textarea(
            chunks[1],
            &mut editor_buf,
            "*User*",
            &self.user_text,
            self.editing_mode,
            &self.colors,
            self.focused_field == InputField::User,
        );

        // Password field
        render_textarea(
            chunks[2],
            &mut editor_buf,
            "Password",
            &self.password_text,
            self.editing_mode,
            &self.colors,
            self.focused_field == InputField::Password,
        );

        // Is Active checkbox
        render_checkbox(
            chunks[3],
            &mut editor_buf,
            "Is Active",
            self.secret.is_active,
            &self.colors,
            self.focused_field == InputField::IsActive,
        );

        // Private Key field
        render_textarea(
            chunks[4],
            &mut editor_buf,
            "Private Key",
            &self.private_key_text,
            self.editing_mode,
            &self.colors,
            self.focused_field == InputField::PrivateKey,
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

        // Render cancel confirmation dialog if needed
        if self.show_cancel_confirmation {
            render_cancel_dialog(area, buf);
        }

        if let Some(err) = self.save_error.as_ref() {
            let e = vec![err.to_string()];
            render_message_dialog(area, buf, &Message::Error(e));
        }
    }
}

impl Widget for &mut SecretEditor {
    fn render(self, area: Rect, buf: &mut Buffer) {
        self.render_ui(area, buf);
    }
}
