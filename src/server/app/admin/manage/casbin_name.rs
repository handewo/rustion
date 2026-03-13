use crate::database::error::DatabaseError;
use crate::database::models::CasbinName;
use crate::error::Error;
use crate::server::app::admin::widgets::*;
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::palette::tailwind,
    widgets::{Scrollbar, ScrollbarOrientation, ScrollbarState, StatefulWidget, Widget},
};

// Radio button options for ptype selection (static for RadioButtons widget)
const PTYPE_OPTIONS: [RadioOption; 3] = [
    RadioOption::new("Rule", "g1"),   // g1 - user groups/roles
    RadioOption::new("Target", "g2"), // g2 - object groups
    RadioOption::new("Action", "g3"), // g3 - action groups
];

#[derive(Debug, Clone, Copy, PartialEq)]
enum InputField {
    Ptype,
    Name,
    IsActive,
}

impl InputField {
    fn next(&self) -> Self {
        match self {
            Self::Ptype => Self::Name,
            Self::Name => Self::IsActive,
            Self::IsActive => Self::Ptype,
        }
    }

    fn previous(&self) -> Self {
        match self {
            Self::Ptype => Self::IsActive,
            Self::Name => Self::Ptype,
            Self::IsActive => Self::Name,
        }
    }
}

#[derive(Debug)]
pub struct CasbinNameEditor {
    pub casbin_name: CasbinName,
    focused_field: InputField,
    name_text: SingleLineText,
    ptype_radio: RadioButtons,
    scroll_offset: usize,
    colors: EditorColors,
    pub show_cancel_confirmation: bool,
    editing_mode: bool,
    save_error: Option<Error>,
    pub help_text: [&'static str; 2],
}

impl CasbinNameEditor {
    pub fn new(casbin_name: CasbinName) -> Self {
        let name_text = SingleLineText::new(Some(casbin_name.name.clone()));
        let ptype_radio = RadioButtons::new(&PTYPE_OPTIONS, &casbin_name.ptype);

        Self {
            casbin_name,
            focused_field: InputField::Ptype,
            name_text,
            ptype_radio,
            scroll_offset: 0,
            colors: EditorColors::new(&tailwind::BLUE),
            show_cancel_confirmation: false,
            editing_mode: false,
            save_error: None,
            help_text: RADIO_HELP,
        }
    }

    pub fn handle_paste_event(&mut self, paste: &str) -> bool {
        if let InputField::Name = self.focused_field {
            return self.name_text.handle_paste(paste);
        }
        false
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
                    if let Err(e) = self.save_casbin_name() {
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
                InputField::Ptype => {
                    if self.ptype_radio.handle_input(key) {
                        self.editing_mode = false;
                        self.help_text = RADIO_HELP
                    }
                }
                InputField::Name => {
                    if self.name_text.handle_input(key) {
                        self.editing_mode = false;
                        self.name_text.clear_style();
                    }
                }
                _ => {
                    unreachable!()
                }
            }

            match key {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Up | KeyCode::Down | KeyCode::Char(_) => {
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
                    self.casbin_name.is_active = !self.casbin_name.is_active;
                }
                InputField::Ptype => {
                    self.editing_mode = true;
                    self.help_text = RADIO_EDIT_HELP;
                }
                InputField::Name => {
                    self.editing_mode = true;
                    text_editing_style(self.colors.input_cursor, &mut self.name_text.textarea);
                    text_input_position(key, &mut self.name_text.textarea);
                }
            },
            KeyCode::Char('d') if !self.editing_mode => {
                if let InputField::Name = self.focused_field {
                    self.name_text.clear_line();
                }
            }
            KeyCode::Char(' ') => {
                if let InputField::IsActive = self.focused_field {
                    self.casbin_name.is_active = !self.casbin_name.is_active;
                }
            }
            _ => {}
        }
        false
    }

    fn next(&mut self) {
        self.focused_field = self.focused_field.next();
        match self.focused_field {
            InputField::IsActive => {
                self.help_text = CHECKBOX_HELP;
            }
            InputField::Ptype => {
                self.help_text = RADIO_HELP;
            }
            InputField::Name => {
                self.help_text = COMMON_HELP;
            }
        }
    }

    fn previous(&mut self) {
        self.focused_field = self.focused_field.previous();
        match self.focused_field {
            InputField::IsActive => {
                self.help_text = CHECKBOX_HELP;
            }
            InputField::Ptype => {
                self.help_text = RADIO_HELP;
            }
            InputField::Name => {
                self.help_text = COMMON_HELP;
            }
        }
    }

    fn save_casbin_name(&mut self) -> Result<(), Error> {
        // Update ptype from radio button selection
        self.casbin_name.ptype = self.ptype_radio.selected_value().to_string();

        let name = self.name_text.get_input();
        self.casbin_name.name = name.trim().into();

        self.casbin_name
            .validate()
            .map_err(|e| Error::Database(DatabaseError::CasbinNameValidation(e)))
    }

    fn max_scroll_offset(&self) -> usize {
        2
    }

    fn window_height(&self) -> u16 {
        11
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
                Constraint::Length(5), // Ptype radio buttons (3 options + borders)
                Constraint::Length(3), // Name
                Constraint::Length(3), // Is Active
            ])
            .split(content_area);

        // Ptype radio buttons
        render_radio_buttons(
            chunks[0],
            &mut editor_buf,
            "*Type*",
            &self.ptype_radio,
            self.editing_mode,
            &self.colors,
            self.focused_field == InputField::Ptype,
        );

        // Name field
        render_textarea(
            chunks[1],
            &mut editor_buf,
            "*Name*",
            &self.name_text,
            self.editing_mode,
            &self.colors,
            self.focused_field == InputField::Name,
        );

        // Is Active checkbox
        render_checkbox(
            chunks[2],
            &mut editor_buf,
            "Is Active",
            self.casbin_name.is_active,
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

impl Widget for &mut CasbinNameEditor {
    fn render(self, area: Rect, buf: &mut Buffer) {
        self.render_ui(area, buf);
    }
}
