use super::super::widgets::{
    text_editing_style, text_input_position, MultiLineText, SingleLineText,
};
use crate::error::Error;
use crate::{database::models::User, server::app::admin::manage::centered_area};
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    buffer::Buffer,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{palette::tailwind, Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Clear, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState,
        StatefulWidget, Widget,
    },
};

const COMMON_HELP: [&str; 2] = [
    "(Enter) edit | (i) insert | (a) append | (d) clear",
    "(Ctrl+S) save | (Esc) cancel | (Tab) next | (Shift Tab) previous",
];
const CHECKBOX_HELP: [&str; 2] = [
    "(Space) toggle",
    "(Ctrl+S) save | (Esc) cancel | (Tab) next | (Shift Tab) previous",
];
const AUTHORIZED_KEYS_HELP: [&str; 2] = [
    "(Enter) activate | (d) clear all",
    "(Ctrl+S) save | (Esc) cancel | (Tab) next | (Shift Tab) previous",
];
const AUTHORIZED_KEYS_EDIT_HELP: [&str; 2] = [
    "(Enter) edit | (i) insert | (a) append | (d) delete line | (o) newline",
    "(Esc) cancel | (Up) next line | (Down) previous line",
];
const AUTHORIZED_KEYS_INPUT_HELP: [&str; 2] = ["(Enter) newline", "(Esc) quit edit"];

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
    focus: Color,
    editor: Color,
    input_cursor: Color,
}

impl EditorColors {
    const fn new(color: &tailwind::Palette) -> Self {
        Self {
            focus: color.c400,
            editor: color.c300,
            input_cursor: color.c600,
        }
    }
}

#[derive(Debug)]
pub struct UserEditor {
    user: User,
    focused_field: InputField,
    username_text: SingleLineText,
    email_text: SingleLineText,
    authorized_keys_text: MultiLineText,
    scroll_offset: usize,
    colors: EditorColors,
    show_cancel_confirmation: bool,
    generate_password: bool,
    editing_mode: bool,
    pub help_text: [&'static str; 2],
}

impl UserEditor {
    pub fn new(user: User) -> Self {
        let username_text = SingleLineText::new(Some(user.username.clone()));
        let email_text = SingleLineText::new(user.email.clone());

        let authorized_keys_text = MultiLineText::new(Some(user.get_authorized_keys()));

        Self {
            user,
            focused_field: InputField::Username,
            username_text,
            email_text,
            generate_password: false,
            authorized_keys_text,
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

        if self.editing_mode {
            match self.focused_field {
                InputField::Username => {
                    if self.username_text.handle_input(key) {
                        self.editing_mode = false;
                        self.username_text.clear_style();
                    }
                }
                InputField::Email => {
                    if self.email_text.handle_input(key) {
                        self.editing_mode = false;
                        self.email_text.clear_style();
                    }
                }
                InputField::AuthorizedKeys => {
                    if self.authorized_keys_text.handle_input(key) {
                        self.editing_mode = false;
                        self.authorized_keys_text.clear_style();
                        self.help_text = AUTHORIZED_KEYS_HELP;
                    } else if self.authorized_keys_text.editing_mode {
                        self.help_text = AUTHORIZED_KEYS_INPUT_HELP;
                    } else {
                        self.help_text = AUTHORIZED_KEYS_EDIT_HELP;
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
                InputField::ForceInitPass => {
                    self.user.force_init_pass = !self.user.force_init_pass;
                }
                InputField::IsActive => {
                    self.user.is_active = !self.user.is_active;
                }
                InputField::Password => {
                    self.generate_password = !self.generate_password;
                }
                InputField::Username => {
                    self.editing_mode = true;
                    text_editing_style(self.colors.input_cursor, &mut self.username_text.textarea);
                    text_input_position(key, &mut self.username_text.textarea);
                }
                InputField::Email => {
                    self.editing_mode = true;
                    text_editing_style(self.colors.input_cursor, &mut self.email_text.textarea);
                    text_input_position(key, &mut self.email_text.textarea);
                }
                InputField::AuthorizedKeys => {
                    self.editing_mode = true;
                    self.authorized_keys_text.cursor_color = self.colors.input_cursor;
                    self.authorized_keys_text.highlight();
                    self.help_text = AUTHORIZED_KEYS_EDIT_HELP;
                }
            },
            KeyCode::Char('d') if !self.editing_mode => match self.focused_field {
                InputField::Username => {
                    self.username_text.clear_line();
                }
                InputField::Email => {
                    self.email_text.clear_line();
                }
                InputField::AuthorizedKeys => {
                    let authorized_keys_text = MultiLineText::new(None);
                    self.authorized_keys_text = authorized_keys_text
                }
                _ => {}
            },
            KeyCode::Char(' ') => match self.focused_field {
                InputField::ForceInitPass => {
                    self.user.force_init_pass = !self.user.force_init_pass;
                }
                InputField::IsActive => {
                    self.user.is_active = !self.user.is_active;
                }
                InputField::Password => {
                    self.generate_password = !self.generate_password;
                }
                _ => {}
            },
            _ => {}
        }

        false
    }

    fn next(&mut self) {
        self.focused_field = self.focused_field.next();
        match self.focused_field {
            InputField::AuthorizedKeys => {
                self.help_text = AUTHORIZED_KEYS_HELP;
            }
            InputField::Username | InputField::Email => {
                self.help_text = COMMON_HELP;
            }
            InputField::Password | InputField::ForceInitPass | InputField::IsActive => {
                self.help_text = CHECKBOX_HELP;
            }
        }
    }

    fn previous(&mut self) {
        self.focused_field = self.focused_field.previous();
        match self.focused_field {
            InputField::AuthorizedKeys => {
                self.help_text = AUTHORIZED_KEYS_HELP;
            }
            InputField::Username | InputField::Email => {
                self.help_text = COMMON_HELP;
            }
            InputField::Password | InputField::ForceInitPass | InputField::IsActive => {
                self.help_text = CHECKBOX_HELP;
            }
        }
    }

    fn save_user(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn max_scroll_offset(&self) -> usize {
        5
    }

    fn window_height(&self) -> u16 {
        25
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
                Constraint::Length(8), // Authorized Keys
            ])
            .split(content_area);

        // Username field
        self.render_textarea(
            chunks[0],
            &mut editor_buf,
            "*Username*",
            &self.username_text,
            InputField::Username,
        );

        // Email field
        self.render_textarea(
            chunks[1],
            &mut editor_buf,
            "Email",
            &self.email_text,
            InputField::Email,
        );

        // Password field
        self.render_checkbox(
            chunks[2],
            &mut editor_buf,
            "Generate New Password",
            self.generate_password,
            InputField::Password,
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

        // Authorized Keys field
        self.render_textarea(
            chunks[5],
            &mut editor_buf,
            "Authorized Keys (one per line)",
            &self.authorized_keys_text,
            InputField::AuthorizedKeys,
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
            self.render_cancel_dialog(area, buf);
        }
    }

    fn render_textarea<W: Widget>(
        &self,
        area: Rect,
        buf: &mut Buffer,
        label: &str,
        textarea: W,
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
            Style::default().fg(self.colors.editor)
        } else if is_focused {
            Style::default().fg(self.colors.focus)
        } else {
            Style::default()
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .title(label)
            .border_style(border_style)
            .title_style(title_style);

        let inner = block.inner(area);

        block.render(area, buf);
        textarea.render(inner, buf);
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
                .fg(self.colors.focus)
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
