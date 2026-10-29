use super::*;
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::Color,
    widgets::{Scrollbar, ScrollbarOrientation, ScrollbarState, StatefulWidget},
};

/// The type of widget backing a form field.
#[derive(Debug)]
pub enum FormFieldWidget {
    Text(SingleLineText),
    MultiLine(MultiLineText),
    Checkbox(bool),
    Radio(RadioButtons),
}

/// A single field in a form: label, layout height, and widget.
#[derive(Debug)]
pub struct FormField {
    pub label: Label,
    pub height: u16,
    pub widget: FormFieldWidget,
    /// Whether the user can edit this field. Read-only fields can still be
    /// focused and scrolled to, but reject edit/insert/clear/toggle actions.
    pub editable: bool,
}

impl FormField {
    pub fn text(label: Label, initial: Option<String>) -> Self {
        Self {
            label,
            height: 3,
            widget: FormFieldWidget::Text(SingleLineText::new(initial)),
            editable: true,
        }
    }

    pub fn text_masked(label: Label, initial: Option<String>, mask: char) -> Self {
        let mut text = SingleLineText::new(initial);
        text.textarea.set_mask_char(mask);
        Self {
            label,
            height: 3,
            widget: FormFieldWidget::Text(text),
            editable: true,
        }
    }

    pub fn multiline(label: Label, lines: Option<&[String]>, height: u16) -> Self {
        Self {
            label,
            height,
            widget: FormFieldWidget::MultiLine(MultiLineText::new(lines)),
            editable: true,
        }
    }

    pub fn checkbox(label: Label, checked: bool) -> Self {
        Self {
            label,
            height: 3,
            widget: FormFieldWidget::Checkbox(checked),
            editable: true,
        }
    }

    pub fn radio(
        label: Label,
        options: &'static [RadioOption],
        initial: &str,
        height: u16,
    ) -> Self {
        Self {
            label,
            height,
            widget: FormFieldWidget::Radio(RadioButtons::new(options, initial)),
            editable: true,
        }
    }

    /// Builder: mark this field as read-only.
    ///
    /// ```ignore
    /// FormField::text(|tr| tr.field_name, Some(id)).readonly()
    /// ```
    pub fn readonly(mut self) -> Self {
        self.editable = false;
        self
    }
}

/// Result of a key event processed by `FormEditor`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FormEvent {
    /// Nothing happened that the caller needs to act on.
    None,
    /// Ctrl+S was pressed and the form is ready to save.
    /// The caller should validate, persist, and call `set_save_error` on failure.
    Save,
    /// The user confirmed the cancel dialog.
    Cancel,
}

/// A generic, data-driven form editor.
///
/// Handles field navigation, editing mode, paste, scrolling, cancel/error
/// dialogs, and rendering. The caller owns the domain model and save logic.
#[derive(Debug)]
pub struct FormEditor {
    fields: Vec<FormField>,
    focused: usize,
    scroll_offset: usize,
    /// The theme's cursor colour, as of the last render. Edit mode styles the
    /// textarea with it when entered, between two renders.
    cursor_color: Color,
    pub show_cancel_confirmation: bool,
    editing_mode: bool,
    save_error: Option<Vec<String>>,
    pub help_text: Help,
}

impl FormEditor {
    pub fn new(fields: Vec<FormField>) -> Self {
        let help_text = match fields.first() {
            Some(f) if !f.editable => READONLY_HELP,
            Some(f) => match &f.widget {
                FormFieldWidget::Text(_) => COMMON_HELP,
                FormFieldWidget::MultiLine(_) => MULTILINES_HELP,
                FormFieldWidget::Checkbox(_) => CHECKBOX_HELP,
                FormFieldWidget::Radio(_) => RADIO_HELP,
            },
            None => COMMON_HELP,
        };
        Self {
            fields,
            focused: 0,
            scroll_offset: 0,
            cursor_color: theme::DEFAULT.accent_dim,
            show_cancel_confirmation: false,
            editing_mode: false,
            save_error: None,
            help_text,
        }
    }

    /// Report a save error to be displayed as a dialog.
    pub fn set_save_error(&mut self, lines: Vec<String>) {
        self.save_error = Some(lines);
    }

    /// Read a `SingleLineText` field value.
    pub fn get_text(&self, index: usize) -> String {
        match &self.fields[index].widget {
            FormFieldWidget::Text(t) => t.get_input(),
            _ => panic!("field {} is not Text", index),
        }
    }

    /// Read a `MultiLineText` field value.
    pub fn get_multiline(&self, index: usize) -> &[String] {
        match &self.fields[index].widget {
            FormFieldWidget::MultiLine(t) => t.get_input(),
            _ => panic!("field {} is not MultiLine", index),
        }
    }

    /// Read a checkbox field value.
    pub fn get_checkbox(&self, index: usize) -> bool {
        match &self.fields[index].widget {
            FormFieldWidget::Checkbox(v) => *v,
            _ => panic!("field {} is not Checkbox", index),
        }
    }

    /// Read a radio button field value.
    pub fn get_radio(&self, index: usize) -> &'static str {
        match &self.fields[index].widget {
            FormFieldWidget::Radio(r) => r.selected_value(),
            _ => panic!("field {} is not Radio", index),
        }
    }

    /// Get a mutable reference to the `MultiLineText` at `index`.
    pub fn get_multiline_mut(&mut self, index: usize) -> &mut MultiLineText {
        match &mut self.fields[index].widget {
            FormFieldWidget::MultiLine(t) => t,
            _ => panic!("field {} is not MultiLine", index),
        }
    }

    pub fn handle_paste_event(&mut self, paste: &str) -> bool {
        if !self.editing_mode || !self.fields[self.focused].editable {
            return false;
        }
        match &mut self.fields[self.focused].widget {
            FormFieldWidget::Text(t) => t.handle_paste(paste),
            FormFieldWidget::MultiLine(t) => t.handle_paste(paste),
            FormFieldWidget::Checkbox(_) | FormFieldWidget::Radio(_) => false,
        }
    }

    pub fn handle_key_event(&mut self, key: KeyCode, modifiers: KeyModifiers) -> FormEvent {
        // Cancel confirmation dialog
        if self.show_cancel_confirmation {
            match key {
                KeyCode::Char('y') | KeyCode::Char('Y') => return FormEvent::Cancel,
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.show_cancel_confirmation = false;
                }
                _ => {}
            }
            return FormEvent::None;
        }

        // Save error dialog — dismiss on Enter
        if self.save_error.is_some() {
            if key == KeyCode::Enter {
                self.save_error = None;
            }
            return FormEvent::None;
        }

        // Global shortcuts
        if modifiers.contains(KeyModifiers::CONTROL) {
            match key {
                KeyCode::Char('s') => return FormEvent::Save,
                KeyCode::Char('c') => {
                    self.show_cancel_confirmation = true;
                    return FormEvent::None;
                }
                _ => {}
            }
        }

        // Editing mode — delegate to focused field
        if self.editing_mode {
            self.handle_editing_input(key);
            match key {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char(_) => return FormEvent::None,
                _ => {}
            }
            // For Radio or MultiLine fields, also consume Up/Down in editing mode
            if matches!(
                &self.fields[self.focused].widget,
                FormFieldWidget::Radio(_) | FormFieldWidget::MultiLine(_)
            ) && matches!(key, KeyCode::Up | KeyCode::Down)
            {
                return FormEvent::None;
            }
        }

        // Normal mode
        match key {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.show_cancel_confirmation = true;
            }
            KeyCode::Tab | KeyCode::Char('j') | KeyCode::Down => {
                self.editing_mode = false;
                self.focus_next();
                self.scroll_offset = if self.scroll_offset == self.max_scroll_offset() {
                    0
                } else {
                    self.scroll_offset.saturating_add(1)
                };
            }
            KeyCode::BackTab | KeyCode::Char('k') | KeyCode::Up => {
                self.editing_mode = false;
                self.focus_previous();
                self.scroll_offset = if self.scroll_offset == 0 {
                    self.max_scroll_offset()
                } else {
                    self.scroll_offset.saturating_sub(1)
                };
            }
            KeyCode::Enter | KeyCode::Char('i') | KeyCode::Char('a')
                if self.fields[self.focused].editable =>
            {
                self.enter_edit_mode(key);
            }
            KeyCode::Char('d') if !self.editing_mode && self.fields[self.focused].editable => {
                self.clear_focused_field();
            }
            KeyCode::Char(' ') if self.fields[self.focused].editable => {
                if let FormFieldWidget::Checkbox(ref mut v) = self.fields[self.focused].widget {
                    *v = !*v;
                }
            }
            _ => {}
        }
        FormEvent::None
    }

    fn handle_editing_input(&mut self, key: KeyCode) {
        match &mut self.fields[self.focused].widget {
            FormFieldWidget::Text(t) => {
                if t.handle_input(key) {
                    self.editing_mode = false;
                    t.clear_style();
                }
            }
            FormFieldWidget::MultiLine(t) => {
                if t.handle_input(key) {
                    self.editing_mode = false;
                    t.clear_style();
                    self.help_text = MULTILINES_HELP;
                } else if t.editing_mode {
                    self.help_text = MULTILINES_INPUT_HELP;
                } else {
                    self.help_text = MULTILINES_EDIT_HELP;
                }
            }
            FormFieldWidget::Radio(r) => {
                if r.handle_input(key) {
                    self.editing_mode = false;
                    self.help_text = RADIO_HELP;
                }
            }
            FormFieldWidget::Checkbox(_) => unreachable!(),
        }
    }

    fn enter_edit_mode(&mut self, key: KeyCode) {
        match &mut self.fields[self.focused].widget {
            FormFieldWidget::Checkbox(v) => {
                *v = !*v;
            }
            FormFieldWidget::Text(t) => {
                self.editing_mode = true;
                if t.textarea.mask_char().is_some() {
                    t.clear_line()
                }
                text_editing_style(self.cursor_color, &mut t.textarea);
                text_input_position(key, &mut t.textarea);
            }
            FormFieldWidget::MultiLine(t) => {
                self.editing_mode = true;
                t.cursor_color = self.cursor_color;
                t.highlight();
                self.help_text = MULTILINES_EDIT_HELP;
            }
            FormFieldWidget::Radio(_) => {
                self.editing_mode = true;
                self.help_text = RADIO_EDIT_HELP;
            }
        }
    }

    fn clear_focused_field(&mut self) {
        match &mut self.fields[self.focused].widget {
            FormFieldWidget::Text(t) => t.clear_line(),
            FormFieldWidget::MultiLine(t) => {
                *t = MultiLineText::new(None);
            }
            _ => {}
        }
    }

    fn focus_next(&mut self) {
        self.focused = (self.focused + 1) % self.fields.len();
        self.update_help_text();
    }

    fn focus_previous(&mut self) {
        self.focused = if self.focused == 0 {
            self.fields.len() - 1
        } else {
            self.focused - 1
        };
        self.update_help_text();
    }

    fn update_help_text(&mut self) {
        let field = &self.fields[self.focused];
        self.help_text = if !field.editable {
            READONLY_HELP
        } else {
            match &field.widget {
                FormFieldWidget::Text(_) => COMMON_HELP,
                FormFieldWidget::MultiLine(_) => MULTILINES_HELP,
                FormFieldWidget::Checkbox(_) => CHECKBOX_HELP,
                FormFieldWidget::Radio(_) => RADIO_HELP,
            }
        };
    }

    fn window_height(&self) -> u16 {
        self.fields.iter().map(|f| f.height).sum()
    }

    fn max_scroll_offset(&self) -> usize {
        self.fields.len().saturating_sub(1)
    }

    pub fn render_ui(&mut self, area: Rect, buf: &mut Buffer, theme: &Theme, tr: &Strings) {
        self.cursor_color = theme.accent_dim;
        let height = self.window_height();
        let inner_area = centered_area(area, area.width - 2, area.height - 2);
        let editor_area = Rect::new(0, 0, inner_area.width, height);
        let mut editor_buf = theme.buffer(editor_area);
        let scrollbar_needed = height > inner_area.height;
        let content_area = if scrollbar_needed {
            Rect {
                width: editor_area.width - 1,
                ..editor_area
            }
        } else {
            editor_area
        };

        // Build layout constraints from field heights
        let constraints: Vec<Constraint> = self
            .fields
            .iter()
            .map(|f| Constraint::Length(f.height))
            .collect();

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(constraints)
            .split(content_area);

        // Render each field
        for (i, field) in self.fields.iter().enumerate() {
            let is_focused = i == self.focused;
            // Read-only fields never show the "editing" border and get a lock marker.
            let editing = self.editing_mode && field.editable;
            let label = if field.editable {
                (field.label)(tr).to_string()
            } else {
                format!("{} {}", (field.label)(tr), tr.read_only)
            };
            match &field.widget {
                FormFieldWidget::Text(t) => {
                    render_textarea(
                        chunks[i],
                        &mut editor_buf,
                        &label,
                        t,
                        editing,
                        theme,
                        is_focused,
                    );
                }
                FormFieldWidget::MultiLine(t) => {
                    render_textarea(
                        chunks[i],
                        &mut editor_buf,
                        &label,
                        t,
                        editing,
                        theme,
                        is_focused,
                    );
                }
                FormFieldWidget::Checkbox(checked) => {
                    render_checkbox(
                        chunks[i],
                        &mut editor_buf,
                        &label,
                        *checked,
                        theme,
                        is_focused,
                    );
                }
                FormFieldWidget::Radio(r) => {
                    render_radio_buttons(
                        chunks[i],
                        &mut editor_buf,
                        &label,
                        r,
                        editing,
                        theme,
                        tr,
                        is_focused,
                    );
                }
            }
        }

        // Copy editor buffer to main buffer (with scroll offset)
        if scrollbar_needed {
            let visible_content = editor_buf
                .content
                .into_iter()
                .skip(inner_area.width as usize * self.scroll_offset * 3)
                .take(inner_area.area() as usize);
            for (i, cell) in visible_content.enumerate() {
                let x = i as u16 % inner_area.width;
                let y = i as u16 / inner_area.width;
                buf[(inner_area.x + x, inner_area.y + y)] = cell;
            }
        } else {
            for (i, cell) in editor_buf.content.into_iter().enumerate() {
                let x = i as u16 % inner_area.width;
                let y = i as u16 / inner_area.width;
                buf[(inner_area.x + x, inner_area.y + y)] = cell;
            }
        }

        if scrollbar_needed {
            let area = inner_area.intersection(buf.area);
            let mut state =
                ScrollbarState::new(self.max_scroll_offset()).position(self.scroll_offset);
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .style(Style::new().fg(theme.muted))
                .render(area, buf, &mut state);
        }

        // Dialogs
        if self.show_cancel_confirmation {
            render_cancel_dialog(area, buf, theme, tr);
        }

        if let Some(ref lines) = self.save_error {
            render_message_dialog(area, buf, &Message::Error(lines.clone()), theme, tr);
        }
    }
}
