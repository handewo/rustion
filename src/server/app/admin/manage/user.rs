use crate::{database::models::User, server::app::admin::manage::centered_area};
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    buffer::Buffer,
    layout::{Alignment, Constraint, Direction, Flex, Layout, Rect},
    style::{palette::tailwind, Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Clear, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState,
        StatefulWidget, Widget, Wrap,
    },
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
            Self::Password => Self::ForceInitPass,
            Self::ForceInitPass => Self::IsActive,
            Self::IsActive => Self::AuthorizedKeys,
            Self::AuthorizedKeys => Self::Username,
        }
    }

    fn previous(&self) -> Self {
        match self {
            Self::Username => Self::AuthorizedKeys,
            Self::Email => Self::Username,
            Self::Password => Self::Email,
            Self::ForceInitPass => Self::Password,
            Self::IsActive => Self::ForceInitPass,
            Self::AuthorizedKeys => Self::IsActive,
        }
    }
}

#[derive(Debug)]
struct EditorColors {
    focus_color: Color,
    editor_color: Color,
}

impl EditorColors {
    const fn new(color: &tailwind::Palette) -> Self {
        Self {
            focus_color: color.c400,
            editor_color: color.c300,
        }
    }
}

#[derive(Debug)]
pub struct UserEditor {
    user: User,
    focused_field: InputField,
    username_input: String,
    email_input: String,
    password_input: String,
    authorized_keys_input: String,
    scroll_offset: usize,
    colors: EditorColors,
    input_position: usize,
    pub cursor_position: Option<(u16, u16)>,
    show_cancel_confirmation: bool,
    editing_mode: bool,
    pub help_text: [&'static str; 2],
}

impl UserEditor {
    pub fn new(user: User) -> Self {
        Self {
            user,
            focused_field: InputField::Username,
            username_input: String::new(),
            email_input: String::new(),
            password_input: String::new(),
            authorized_keys_input: String::new(),
            input_position: 0,
            cursor_position: None,
            scroll_offset: 0,
            colors: EditorColors::new(&tailwind::BLUE),
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
                _ => {}
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
            KeyCode::Char(c) if self.editing_mode => {
                self.handle_char_input(c);
            }
            KeyCode::Esc | KeyCode::Char('q') => {
                if self.editing_mode {
                    self.editing_mode = false;
                } else {
                    self.show_cancel_confirmation = true;
                }
            }
            KeyCode::Tab | KeyCode::Char('j') | KeyCode::Down => {
                self.editing_mode = false;
                self.focused_field = self.focused_field.next();
                self.scroll_offset = if self.scroll_offset == self.max_scroll_offset() {
                    0
                } else {
                    self.scroll_offset.saturating_add(1)
                }
            }
            KeyCode::BackTab | KeyCode::Char('k') | KeyCode::Up => {
                self.editing_mode = false;
                self.focused_field = self.focused_field.previous();
                self.scroll_offset = if self.scroll_offset == 0 {
                    self.max_scroll_offset()
                } else {
                    self.scroll_offset.saturating_sub(1)
                };
            }
            KeyCode::Enter | KeyCode::Char('i') | KeyCode::Char('a') => {
                if self.editing_mode {
                    self.editing_mode = false;
                } else {
                    match self.focused_field {
                        InputField::ForceInitPass => {
                            self.user.force_init_pass = !self.user.force_init_pass;
                        }
                        InputField::IsActive => {
                            self.user.is_active = !self.user.is_active;
                        }
                        _ => {
                            self.editing_mode = true;
                            if KeyCode::Char('i') == key {
                                self.input_position = 0;
                            } else {
                                self.update_cursor_position();
                            }
                            self.help_text = EDITOR_HELP;
                        }
                    }
                }
            }
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
            KeyCode::Backspace if self.editing_mode => {
                self.handle_backspace();
            }
            KeyCode::Delete if self.editing_mode => {
                self.handle_delete();
            }
            KeyCode::Left if self.editing_mode => {
                if self.input_position > 0 {
                    self.input_position -= 1;
                }
            }
            KeyCode::Right if self.editing_mode => {
                let current_input = self.get_current_input();
                if self.input_position < current_input.len() {
                    self.input_position += 1;
                }
            }
            KeyCode::Home if self.editing_mode => {
                self.input_position = 0;
            }
            KeyCode::End if self.editing_mode => {
                self.input_position = self.get_current_input().len();
            }
            _ => {}
        }

        false
    }

    fn handle_char_input(&mut self, c: char) {
        let cur_pos = self.input_position;
        let input = self.get_current_input_mut();
        input.insert(cur_pos, c);
        self.input_position += 1;
    }

    fn handle_backspace(&mut self) {
        let cur_pos = self.input_position;
        if self.input_position > 0 {
            let input = self.get_current_input_mut();
            input.remove(cur_pos - 1);
            self.input_position -= 1;
        }
    }

    fn handle_delete(&mut self) {
        let input_len = self.get_current_input().len();
        let cur_pos = self.input_position;
        if self.input_position < input_len {
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
        self.input_position = self.get_current_input().len();
    }

    fn save_user(&mut self) {
        self.user.username = self.username_input.clone();
        self.user.email = if self.email_input.is_empty() {
            None
        } else {
            Some(self.email_input.clone())
        };
    }

    fn max_scroll_offset(&self) -> usize {
        5
    }

    fn window_height(&self) -> u16 {
        20
    }

    fn render_ui(&mut self, area: Rect, buf: &mut Buffer) {
        let height = self.window_height();
        let area = super::centered_area(area, area.width - 2, area.height - 2);
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
                Constraint::Length(3), // Username
                Constraint::Length(3), // Email
                Constraint::Length(3), // Password
                Constraint::Length(3), // Force Init Pass
                Constraint::Length(3), // Is Active
                Constraint::Length(5), // Authorized Keys
            ])
            .split(content_area);

        // Username field
        self.render_text_input(
            chunks[0],
            &mut editor_buf,
            "*Username*",
            &self.username_input,
            InputField::Username,
        );

        // Email field
        self.render_text_input(
            chunks[1],
            &mut editor_buf,
            "Email",
            &self.email_input,
            InputField::Email,
        );

        // Password field
        let masked_password = "*".repeat(self.password_input.len());
        self.render_text_input(
            chunks[2],
            &mut editor_buf,
            "Password",
            &masked_password,
            InputField::Password,
        );

        // Authorized Keys field
        self.render_textarea(
            chunks[5],
            &mut editor_buf,
            "Authorized Keys (one per line)",
            &self.authorized_keys_input,
            InputField::AuthorizedKeys,
        );

        // Force Init Pass checkbox
        self.render_checkbox(
            chunks[3],
            &mut editor_buf,
            "Force Init Password",
            self.user.force_init_pass,
            InputField::ForceInitPass,
        );

        // Is Active checkbox
        self.render_checkbox(
            chunks[4],
            &mut editor_buf,
            "Is Active",
            self.user.is_active,
            InputField::IsActive,
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

        // Set cursor position if in editing mode
        if self.editing_mode {
            let chunk = match self.focused_field {
                InputField::Username => chunks[0],
                InputField::Email => chunks[1],
                InputField::Password => chunks[2],
                InputField::AuthorizedKeys => chunks[5],
                _ => return,
            };
            let x = chunk.x + self.input_position as u16 + 1;
            let y = chunk.y + 1;
            // TODO: cursor
            self.cursor_position = Some((x, y));
        } else {
            self.cursor_position = None;
        }

        // Render cancel confirmation dialog if needed
        if self.show_cancel_confirmation {
            self.render_cancel_dialog(area, buf);
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

        let title_style = if is_focused {
            Style::default()
                .fg(tailwind::SLATE.c200)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };

        let border_style = if is_focused && self.editing_mode {
            Style::default().fg(self.colors.editor_color)
        } else if is_focused {
            Style::default().fg(self.colors.focus_color)
        } else {
            Style::default()
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .title(label)
            .border_style(border_style)
            .title_style(title_style);

        let paragraph = Paragraph::new(value).style(Style::default()).block(block);
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
            Style::default().fg(self.colors.editor_color)
        } else if is_focused {
            Style::default().fg(self.colors.focus_color)
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
                .fg(self.colors.focus_color)
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

    fn render_cancel_dialog(&self, area: Rect, buf: &mut Buffer) {
        let dialog_area = centered_area(area, area.width, 7);

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
        paragraph.render(dialog_area, buf);
    }
}
impl Widget for &mut UserEditor {
    fn render(self, area: Rect, buf: &mut Buffer) {
        self.render_ui(area, buf);
    }
}
