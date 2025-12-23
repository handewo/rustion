use crate::database::models::target::ValidateError;
use crate::database::models::Target;
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
    Hostname,
    Port,
    ServerPublicKey,
    Description,
    IsActive,
}

impl InputField {
    fn next(&self) -> Self {
        match self {
            Self::Name => Self::Hostname,
            Self::Hostname => Self::Port,
            Self::Port => Self::ServerPublicKey,
            Self::ServerPublicKey => Self::Description,
            Self::Description => Self::IsActive,
            Self::IsActive => Self::Name,
        }
    }

    fn previous(&self) -> Self {
        match self {
            Self::Name => Self::IsActive,
            Self::Hostname => Self::Name,
            Self::Port => Self::Hostname,
            Self::ServerPublicKey => Self::Port,
            Self::Description => Self::ServerPublicKey,
            Self::IsActive => Self::Description,
        }
    }
}

#[derive(Debug)]
pub struct TargetEditor {
    pub target: Target,
    focused_field: InputField,
    name_text: SingleLineText,
    hostname_text: SingleLineText,
    port_text: SingleLineText,
    server_public_key_text: SingleLineText,
    description_text: SingleLineText,
    scroll_offset: usize,
    colors: EditorColors,
    pub show_cancel_confirmation: bool,
    editing_mode: bool,
    save_error: Option<Error>,
    pub help_text: [&'static str; 2],
}

impl TargetEditor {
    pub fn new(target: Target) -> Self {
        let name_text = SingleLineText::new(Some(target.name.clone()));
        let hostname_text = SingleLineText::new(Some(target.hostname.clone()));
        let port_text = SingleLineText::new(Some(target.port.to_string()));
        let server_public_key_text = SingleLineText::new(Some(target.server_public_key.clone()));
        let description_text = SingleLineText::new(target.description.clone());

        Self {
            target,
            focused_field: InputField::Name,
            name_text,
            hostname_text,
            port_text,
            server_public_key_text,
            description_text,
            scroll_offset: 0,
            colors: EditorColors::new(&tailwind::BLUE),
            show_cancel_confirmation: false,
            editing_mode: false,
            save_error: None,
            help_text: COMMON_HELP,
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
                    if let Err(e) = self.save_target() {
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
                InputField::Hostname => {
                    if self.hostname_text.handle_input(key) {
                        self.editing_mode = false;
                        self.hostname_text.clear_style();
                    }
                }
                InputField::Port => {
                    if self.port_text.handle_input(key) {
                        self.editing_mode = false;
                        self.port_text.clear_style();
                    }
                }
                InputField::ServerPublicKey => {
                    if self.server_public_key_text.handle_input(key) {
                        self.editing_mode = false;
                        self.server_public_key_text.clear_style();
                    }
                }
                InputField::Description => {
                    if self.description_text.handle_input(key) {
                        self.editing_mode = false;
                        self.description_text.clear_style();
                    }
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
                    self.target.is_active = !self.target.is_active;
                }
                InputField::Name => {
                    self.editing_mode = true;
                    text_editing_style(self.colors.input_cursor, &mut self.name_text.textarea);
                    text_input_position(key, &mut self.name_text.textarea);
                }
                InputField::Hostname => {
                    self.editing_mode = true;
                    text_editing_style(self.colors.input_cursor, &mut self.hostname_text.textarea);
                    text_input_position(key, &mut self.hostname_text.textarea);
                }
                InputField::Port => {
                    self.editing_mode = true;
                    text_editing_style(self.colors.input_cursor, &mut self.port_text.textarea);
                    text_input_position(key, &mut self.port_text.textarea);
                }
                InputField::ServerPublicKey => {
                    self.editing_mode = true;
                    text_editing_style(
                        self.colors.input_cursor,
                        &mut self.server_public_key_text.textarea,
                    );
                    text_input_position(key, &mut self.server_public_key_text.textarea);
                }
                InputField::Description => {
                    self.editing_mode = true;
                    text_editing_style(
                        self.colors.input_cursor,
                        &mut self.description_text.textarea,
                    );
                    text_input_position(key, &mut self.description_text.textarea);
                }
            },
            KeyCode::Char('d') if !self.editing_mode => match self.focused_field {
                InputField::Name => {
                    self.name_text.clear_line();
                }
                InputField::Hostname => {
                    self.hostname_text.clear_line();
                }
                InputField::Port => {
                    self.port_text.clear_line();
                }
                InputField::ServerPublicKey => {
                    self.server_public_key_text.clear_line();
                }
                InputField::Description => {
                    self.description_text.clear_line();
                }
                _ => {}
            },
            KeyCode::Char(' ') => {
                if let InputField::IsActive = self.focused_field {
                    self.target.is_active = !self.target.is_active;
                }
            }
            _ => {}
        }
        false
    }

    fn next(&mut self) {
        self.focused_field = self.focused_field.next();
        match self.focused_field {
            InputField::ServerPublicKey | InputField::Description => {
                self.help_text = COMMON_HELP;
            }
            InputField::Name | InputField::Hostname | InputField::Port => {
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
            InputField::ServerPublicKey | InputField::Description => {
                self.help_text = COMMON_HELP;
            }
            InputField::Name | InputField::Hostname | InputField::Port => {
                self.help_text = COMMON_HELP;
            }
            InputField::IsActive => {
                self.help_text = CHECKBOX_HELP;
            }
        }
    }

    fn save_target(&mut self) -> Result<(), Error> {
        let name = self.name_text.get_input();
        self.target.name = name.trim().into();

        let hostname = self.hostname_text.get_input();
        self.target.hostname = hostname.trim().into();

        let port_str = self.port_text.get_input().trim().to_string();
        let port: u64 = match port_str.parse() {
            Ok(p) => {
                if (1..=65535).contains(&p) {
                    p
                } else {
                    return Err(Error::TargetValidator(ValidateError::PortInvalid));
                }
            }
            Err(_) => return Err(Error::TargetValidator(ValidateError::PortNotNumber)),
        };
        self.target.port = port as u16;
        let server_public_key = self.server_public_key_text.get_input();
        self.target.server_public_key = server_public_key.trim().to_string();

        let description = (!self.description_text.get_input().trim().is_empty())
            .then(|| self.description_text.get_input().trim().to_string());
        self.target.description = description;

        self.target.validate().map_err(Error::TargetValidator)
    }

    fn max_scroll_offset(&self) -> usize {
        5
    }

    fn window_height(&self) -> u16 {
        21
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
                Constraint::Length(3), // Hostname
                Constraint::Length(3), // Port
                Constraint::Length(3), // Server Public Key
                Constraint::Length(3), // Description
                Constraint::Length(3), // Is Active
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

        // Hostname field
        render_textarea(
            chunks[1],
            &mut editor_buf,
            "*Hostname*",
            &self.hostname_text,
            self.editing_mode,
            &self.colors,
            self.focused_field == InputField::Hostname,
        );

        // Port field
        render_textarea(
            chunks[2],
            &mut editor_buf,
            "*Port*",
            &self.port_text,
            self.editing_mode,
            &self.colors,
            self.focused_field == InputField::Port,
        );

        // Server Public Key field
        render_textarea(
            chunks[3],
            &mut editor_buf,
            "*Server Public Key*",
            &self.server_public_key_text,
            self.editing_mode,
            &self.colors,
            self.focused_field == InputField::ServerPublicKey,
        );

        // Description field
        render_textarea(
            chunks[4],
            &mut editor_buf,
            "Description",
            &self.description_text,
            self.editing_mode,
            &self.colors,
            self.focused_field == InputField::Description,
        );

        // Is Active checkbox
        render_checkbox(
            chunks[5],
            &mut editor_buf,
            "Is Active",
            self.target.is_active,
            &self.colors,
            self.focused_field == InputField::IsActive,
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

impl Widget for &mut TargetEditor {
    fn render(self, area: Rect, buf: &mut Buffer) {
        self.render_ui(area, buf);
    }
}
