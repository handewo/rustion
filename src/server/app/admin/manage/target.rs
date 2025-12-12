use crate::database::models::User;
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    buffer::Buffer,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Widget, Wrap},
    Frame,
};

const COMMON_HELP: [&str; 2] = [
    "(Tab) next | (Shift Tab) previous | (Enter) Edit/Activate",
    "(Ctrl+S) Save | (Esc) Cancel",
];
const EDITOR_HELP: [&str; 2] = [
    "(Esc) quit | (↑) move up | (↓) move down | (←) move left | (→) move right",
    "(Tab) next tab | (Shift Tab) previous tab | (+) zoom in | (-) zoom out | (PgUp) page up | (PgDn) page down",
];

#[derive(Debug, Clone, Copy, PartialEq)]
enum InputField {
    Username,
    Email,
    Password,
    AuthorizedKeys,
    ForceInitPass,
    IsActive,
}

impl InputField {
    fn next(&self) -> Self {
        match self {
            Self::Username => Self::Email,
            Self::Email => Self::Password,
            Self::Password => Self::AuthorizedKeys,
            Self::AuthorizedKeys => Self::ForceInitPass,
            Self::ForceInitPass => Self::IsActive,
            Self::IsActive => Self::Username,
        }
    }

    fn previous(&self) -> Self {
        match self {
            Self::Username => Self::IsActive,
            Self::Email => Self::Username,
            Self::Password => Self::Email,
            Self::AuthorizedKeys => Self::Password,
            Self::ForceInitPass => Self::AuthorizedKeys,
            Self::IsActive => Self::ForceInitPass,
        }
    }
}

#[derive(Debug)]
pub struct TargetEditor {
    user: User,
    focused_field: InputField,
    username_input: String,
    email_input: String,
    password_input: String,
    authorized_keys_input: String,
    cursor_position: usize,
    show_cancel_confirmation: bool,
    editing_mode: bool,
    pub help_text: [&'static str; 2],
}

impl TargetEditor {
    pub fn new(user: User) -> Self {
        Self {
            user,
            focused_field: InputField::Username,
            username_input: String::new(),
            email_input: String::new(),
            password_input: String::new(),
            authorized_keys_input: String::new(),
            cursor_position: 0,
            show_cancel_confirmation: false,
            editing_mode: false,
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
                _ => {
                    unreachable!()
                }
            }
            return false;
        }

        // Global shortcuts
        if modifiers.contains(KeyModifiers::CONTROL) {
            match key {
                KeyCode::Char('s') => {
                    self.save_user();
                    return true;
                }
                KeyCode::Char('c') => {
                    self.show_cancel_confirmation = true;
                    return false;
                }
                _ => {}
            }
        }

        match key {
            KeyCode::Esc => {
                if self.editing_mode {
                    self.editing_mode = false;
                } else {
                    self.show_cancel_confirmation = true;
                }
            }
            KeyCode::Tab => {
                self.editing_mode = false;
                self.focused_field = self.focused_field.next();
                self.update_cursor_position();
            }
            KeyCode::BackTab => {
                self.editing_mode = false;
                self.focused_field = self.focused_field.previous();
                self.update_cursor_position();
            }
            KeyCode::Enter => match self.focused_field {
                InputField::ForceInitPass => {
                    self.user.force_init_pass = !self.user.force_init_pass;
                }
                InputField::IsActive => {
                    self.user.is_active = !self.user.is_active;
                }
                _ => {
                    self.editing_mode = true;
                    self.help_text = EDITOR_HELP;
                }
            },
            KeyCode::Char(' ') => {
                if matches!(
                    self.focused_field,
                    InputField::ForceInitPass | InputField::IsActive
                ) {
                    match self.focused_field {
                        InputField::ForceInitPass => {
                            self.user.force_init_pass = !self.user.force_init_pass;
                        }
                        InputField::IsActive => {
                            self.user.is_active = !self.user.is_active;
                        }
                        _ => {}
                    }
                } else if self.editing_mode {
                    self.handle_char_input(' ');
                }
            }
            KeyCode::Char(c) if self.editing_mode => {
                self.handle_char_input(c);
            }
            KeyCode::Backspace if self.editing_mode => {
                self.handle_backspace();
            }
            KeyCode::Delete if self.editing_mode => {
                self.handle_delete();
            }
            KeyCode::Left if self.editing_mode => {
                if self.cursor_position > 0 {
                    self.cursor_position -= 1;
                }
            }
            KeyCode::Right if self.editing_mode => {
                let current_input = self.get_current_input();
                if self.cursor_position < current_input.len() {
                    self.cursor_position += 1;
                }
            }
            KeyCode::Home if self.editing_mode => {
                self.cursor_position = 0;
            }
            KeyCode::End if self.editing_mode => {
                self.cursor_position = self.get_current_input().len();
            }
            _ => {}
        }

        false
    }

    fn handle_char_input(&mut self, c: char) {
        let cur_pos = self.cursor_position;
        let input = self.get_current_input_mut();
        input.insert(cur_pos, c);
        self.cursor_position += 1;
    }

    fn handle_backspace(&mut self) {
        let cur_pos = self.cursor_position;
        if self.cursor_position > 0 {
            let input = self.get_current_input_mut();
            input.remove(cur_pos - 1);
            self.cursor_position -= 1;
        }
    }

    fn handle_delete(&mut self) {
        let input_len = self.get_current_input().len();
        let cur_pos = self.cursor_position;
        if self.cursor_position < input_len {
            let input = self.get_current_input_mut();
            input.remove(cur_pos);
        }
    }

    fn get_current_input(&self) -> &str {
        match self.focused_field {
            InputField::Username => &self.username_input,
            InputField::Email => &self.email_input,
            InputField::Password => &self.password_input,
            InputField::AuthorizedKeys => &self.authorized_keys_input,
            _ => "",
        }
    }

    fn get_current_input_mut(&mut self) -> &mut String {
        match self.focused_field {
            InputField::Username => &mut self.username_input,
            InputField::Email => &mut self.email_input,
            InputField::Password => &mut self.password_input,
            InputField::AuthorizedKeys => &mut self.authorized_keys_input,
            _ => panic!("Invalid field for text input"),
        }
    }

    fn update_cursor_position(&mut self) {
        self.cursor_position = self.get_current_input().len();
    }

    fn save_user(&mut self) {
        self.user.username = self.username_input.clone();
        self.user.email = if self.email_input.is_empty() {
            None
        } else {
            Some(self.email_input.clone())
        };
    }

    fn render_ui(&self, area: Rect, buf: &mut Buffer) {
        // Create main layout
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(2)
            .constraints([
                Constraint::Length(3), // Username
                Constraint::Length(3), // Email
                Constraint::Length(3), // Password
                Constraint::Length(5), // Authorized Keys
                Constraint::Length(3), // Force Init Pass
                Constraint::Length(3), // Is Active
            ])
            .split(area);

        // Username field
        self.render_text_input(
            chunks[0],
            buf,
            "*Username*",
            &self.username_input,
            InputField::Username,
        );

        // Email field
        self.render_text_input(
            chunks[1],
            buf,
            "Email",
            &self.email_input,
            InputField::Email,
        );

        // Password field
        let masked_password = "*".repeat(self.password_input.len());
        self.render_text_input(
            chunks[2],
            buf,
            "Password",
            &masked_password,
            InputField::Password,
        );

        // Authorized Keys field
        self.render_textarea(
            chunks[3],
            buf,
            "Authorized Keys (one per line)",
            &self.authorized_keys_input,
            InputField::AuthorizedKeys,
        );

        // Force Init Pass checkbox
        self.render_checkbox(
            chunks[4],
            buf,
            "Force Init Password",
            self.user.force_init_pass,
            InputField::ForceInitPass,
        );

        // Is Active checkbox
        self.render_checkbox(
            chunks[5],
            buf,
            "Is Active",
            self.user.is_active,
            InputField::IsActive,
        );

        // Render cancel confirmation dialog if needed
        if self.show_cancel_confirmation {
            self.render_cancel_dialog(area, buf);
        }

        // Set cursor position if in editing mode
        if self.editing_mode {
            let chunk = match self.focused_field {
                InputField::Username => chunks[1],
                InputField::Email => chunks[2],
                InputField::Password => chunks[3],
                InputField::AuthorizedKeys => chunks[4],
                _ => return,
            };
            let x = chunk.x + self.cursor_position as u16 + 1;
            let y = chunk.y + 1;
            // TODO: cursor
            // area.set_cursor_position(ratatui::layout::Position::new(x, y));
        }
    }

    fn render_text_input(
        &self,
        area: Rect,
        buf: &mut Buffer,
        label: &str,
        value: &str,
        field: InputField,
    ) {
        let is_focused = self.focused_field == field;
        let style = if is_focused {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };

        let border_style = if is_focused && self.editing_mode {
            Style::default().fg(Color::Green)
        } else if is_focused {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .title(label)
            .border_style(border_style);

        let paragraph = Paragraph::new(value).style(style).block(block);
        paragraph.render(area, buf);
    }

    fn render_textarea(
        &self,
        area: Rect,
        buf: &mut Buffer,
        label: &str,
        value: &str,
        field: InputField,
    ) {
        let is_focused = self.focused_field == field;

        let border_style = if is_focused && self.editing_mode {
            Style::default().fg(Color::Green)
        } else if is_focused {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .title(label)
            .border_style(border_style);

        let paragraph = Paragraph::new(value)
            .block(block)
            .wrap(Wrap { trim: false });
        paragraph.render(area, buf);
    }

    fn render_checkbox(
        &self,
        area: Rect,
        buf: &mut Buffer,
        label: &str,
        checked: bool,
        field: InputField,
    ) {
        let is_focused = self.focused_field == field;
        let checkbox = if checked { "[X]" } else { "[ ]" };

        let style = if is_focused {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };

        let text = format!("{} {}", checkbox, label);
        let paragraph = Paragraph::new(text)
            .style(style)
            .block(Block::default().borders(Borders::ALL));
        paragraph.render(area, buf);
    }

    fn render_help(&self, frame: &mut Frame, area: Rect) {
        let help_text = if self.editing_mode {
            "Editing Mode | Esc: Exit Edit | Enter: Confirm | ←→: Move Cursor | Home/End: Jump"
        } else {
            "Tab/Shift+Tab: Navigate | Enter: Edit/Activate | Space: Toggle Checkbox | Ctrl+S: Save | Esc: Cancel"
        };

        let paragraph = Paragraph::new(help_text)
            .style(Style::default().fg(Color::DarkGray))
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true });
        frame.render_widget(paragraph, area);
    }

    fn render_cancel_dialog(&self, area: Rect, buf: &mut Buffer) {
        let dialog_width = 50;
        let dialog_height = 7;
        let x = (area.width.saturating_sub(dialog_width)) / 2;
        let y = (area.height.saturating_sub(dialog_height)) / 2;

        let dialog_area = Rect::new(x, y, dialog_width, dialog_height);

        // Clear the area
        Clear.render(dialog_area, buf);

        // Render dialog
        let block = Block::default()
            .borders(Borders::ALL)
            .title("Confirm Cancel")
            .border_style(Style::default().fg(Color::Red));

        let text = vec![
            Line::from(""),
            Line::from("Are you sure you want to cancel?"),
            Line::from("All unsaved changes will be lost."),
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    "Y",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("es / "),
                Span::styled(
                    "N",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Span::raw("o"),
            ]),
        ];

        let paragraph = Paragraph::new(text)
            .block(block)
            .alignment(Alignment::Center);
        paragraph.render(area, buf);
    }
}
impl Widget for &TargetEditor {
    fn render(self, area: Rect, buf: &mut Buffer) {
        self.render_ui(area, buf);
    }
}
