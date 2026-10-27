pub mod common;
pub mod form;
pub mod table;
pub mod theme;
pub mod tree;

pub use form::*;
pub use table::*;
pub use theme::Theme;

use crossterm::event::KeyCode;
use ratatui::{
    buffer::Buffer,
    layout::{Alignment, Constraint, Direction, Flex, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, BorderType, Borders, Paragraph, Widget},
};
use tui_textarea::{CursorMove, Input, Key, TextArea};

/// Radio button options for selection
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RadioOption {
    pub label: &'static str,
    pub value: &'static str,
}

impl RadioOption {
    pub const fn new(label: &'static str, value: &'static str) -> Self {
        Self { label, value }
    }
}

#[derive(Debug)]
pub struct RadioButtons {
    options: &'static [RadioOption],
    selected_index: usize,
}

impl RadioButtons {
    pub fn new(options: &'static [RadioOption], initial_value: &str) -> Self {
        let initial_index = options
            .iter()
            .position(|opt| opt.value == initial_value)
            .unwrap_or(0);

        Self {
            options,
            selected_index: initial_index,
        }
    }

    pub fn selected_value(&self) -> &'static str {
        self.options[self.selected_index].value
    }

    pub fn handle_input(&mut self, key: KeyCode) -> bool {
        match key {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Tab | KeyCode::BackTab => {
                // Exit editing mode on navigation keys
                return true;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected_index = if self.selected_index == 0 {
                    self.options.len() - 1
                } else {
                    self.selected_index - 1
                };
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.selected_index = if self.selected_index == self.options.len() - 1 {
                    0
                } else {
                    self.selected_index + 1
                };
            }
            KeyCode::Char(c) if ('1'..='9').contains(&c) => {
                let idx = c.to_digit(10).unwrap() as usize;
                if idx > 0 && idx <= self.options.len() {
                    self.selected_index = idx - 1;
                }
            }
            KeyCode::Char(' ') => {
                // Confirm current selection
            }
            _ => return false,
        }
        false
    }
}

impl RadioButtons {
    pub fn render_vertical(
        &self,
        area: Rect,
        buf: &mut Buffer,
        editing_mode: bool,
        theme: &Theme,
        is_focused: bool,
    ) {
        let radio_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints(
                std::iter::repeat_n(Constraint::Length(1), self.options.len()).collect::<Vec<_>>(),
            )
            .split(area);

        for (i, option) in self.options.iter().enumerate() {
            let is_selected = i == self.selected_index;
            let is_option_focused = is_focused && editing_mode && i == self.selected_index;

            let radio_symbol = if is_selected { "(*)" } else { "( )" };
            let style = if is_option_focused {
                Style::default()
                    .fg(theme.editing)
                    .add_modifier(Modifier::BOLD)
            } else if is_selected {
                Style::default().add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            let text = format!("{} {}", radio_symbol, option.label);
            let span = Span::styled(text, style);
            let line = Line::from(span);

            let paragraph = Paragraph::new(line).alignment(Alignment::Left);
            paragraph.render(radio_layout[i], buf);
        }
    }
}

pub fn render_radio_buttons(
    area: Rect,
    buf: &mut Buffer,
    label: &str,
    radio_buttons: &RadioButtons,
    editing_mode: bool,
    theme: &Theme,
    is_focused: bool,
) {
    let block = field_block(label, editing_mode, theme, is_focused);
    let inner = block.inner(area);
    block.render(area, buf);

    radio_buttons.render_vertical(inner, buf, editing_mode, theme, is_focused);
}

pub const COMMON_HELP: [&str; 2] = [
    "(Enter) edit | (i) insert | (a) append | (d) clear",
    "(Ctrl+s) save | (Esc) cancel | (Tab) next | (Shift Tab) previous",
];
pub const RADIO_HELP: [&str; 2] = [
    "(Enter) edit",
    "(Ctrl+s) save | (Esc) cancel | (Tab) next | (Shift Tab) previous",
];
pub const RADIO_EDIT_HELP: [&str; 2] = [
    "(Enter) confirm | (Up/Down) select",
    "(Ctrl+s) save | (Esc) cancel | (Tab) next | (Shift Tab) previous",
];
pub const CHECKBOX_HELP: [&str; 2] = [
    "(Space) toggle",
    "(Ctrl+s) save | (Esc) cancel | (Tab) next | (Shift Tab) previous",
];
pub const MULTILINES_HELP: [&str; 2] = [
    "(Enter) activate | (d) clear all",
    "(Ctrl+s) save | (Esc) cancel | (Tab) next | (Shift Tab) previous",
];
pub const MULTILINES_EDIT_HELP: [&str; 2] = [
    "(Enter) edit | (i) insert | (a) append | (d) delete line | (o) newline",
    "(Esc) cancel | (Up) next line | (Down) previous line",
];
pub const MULTILINES_INPUT_HELP: [&str; 2] = ["(Enter) newline", "(Esc) quit edit"];
pub const READONLY_HELP: [&str; 2] = [
    "(Read-only)",
    "(Ctrl+s) save | (Esc) cancel | (Tab) next | (Shift Tab) previous",
];

pub fn text_editing_style(color: Color, textarea: &mut TextArea) {
    textarea.set_cursor_line_style(Style::default().add_modifier(Modifier::UNDERLINED));
    textarea.set_cursor_style(Style::default().add_modifier(Modifier::REVERSED).fg(color));
}

pub fn text_input_position(key: KeyCode, textarea: &mut TextArea) {
    if key == KeyCode::Char('i') {
        textarea.move_cursor(CursorMove::Head);
    } else {
        textarea.move_cursor(CursorMove::End);
    }
}

#[derive(Debug)]
pub struct SingleLineText {
    pub textarea: TextArea,
}

impl SingleLineText {
    pub fn new(line: Option<String>) -> Self {
        let textarea = match line {
            Some(l) => {
                let mut ta = [l].iter().collect::<TextArea>();
                ta.set_cursor_line_style(Style::default());
                ta.set_cursor_style(Style::default());
                ta
            }
            None => {
                let mut ta = TextArea::default();
                ta.set_cursor_line_style(Style::default());
                ta.set_cursor_style(Style::default());
                ta
            }
        };
        SingleLineText { textarea }
    }

    pub fn clear_line(&mut self) {
        self.textarea.move_cursor(CursorMove::End);
        self.textarea.delete_line_by_head();
    }

    pub fn get_input(&self) -> String {
        let line = self.textarea.lines().iter().next().unwrap();
        line.to_string()
    }

    pub fn clear_style(&mut self) {
        self.textarea.set_cursor_line_style(Style::default());
        self.textarea.set_cursor_style(Style::default());
    }

    /// Just save first line if there are multi-lines pasted.
    pub fn handle_paste(&mut self, paste: &str) -> bool {
        let input = paste.trim().split('\n').next().unwrap();
        self.textarea.insert_str(input)
    }

    pub fn handle_input(&mut self, key: KeyCode) -> bool {
        match key {
            KeyCode::Esc
            | KeyCode::Tab
            | KeyCode::BackTab
            | KeyCode::Up
            | KeyCode::Down
            | KeyCode::Enter => return true,
            _ => {
                self.textarea.input(Input {
                    key: Key::from(key),
                    ctrl: false,
                    alt: false,
                    shift: false,
                });
            }
        }
        false
    }
}

#[derive(Debug)]
pub struct MultiLineText {
    pub textarea: TextArea,
    pub editing_mode: bool,
    pub cursor_color: Color,
}

impl MultiLineText {
    pub fn new(lines: Option<&[String]>) -> Self {
        let textarea = match lines {
            Some(l) => {
                let mut ta = l.iter().collect::<TextArea>();
                ta.set_cursor_line_style(Style::default());
                ta.set_cursor_style(Style::default());
                ta
            }
            None => {
                let mut ta = TextArea::default();
                ta.set_cursor_line_style(Style::default());
                ta.set_cursor_style(Style::default());
                ta
            }
        };
        MultiLineText {
            textarea,
            editing_mode: false,
            cursor_color: Color::default(),
        }
    }

    pub fn clear_style(&mut self) {
        self.textarea.set_cursor_line_style(Style::default());
        self.textarea.set_cursor_style(Style::default());
    }

    pub fn get_input(&self) -> &[String] {
        self.textarea.lines()
    }

    pub fn reset_lines(&mut self, lines: &[String]) {
        let style = self.textarea.style();
        let cursor_style = self.textarea.cursor_style();
        let cursur_line_style = self.textarea.cursor_line_style();
        self.textarea = TextArea::from_iter(lines);
        self.textarea.set_style(style);
        self.textarea.set_cursor_style(cursor_style);
        self.textarea.set_cursor_line_style(cursur_line_style);
    }

    pub fn handle_paste(&mut self, paste: &str) -> bool {
        if self.editing_mode {
            self.textarea.insert_str(paste.trim())
        } else {
            false
        }
    }

    pub fn handle_input(&mut self, key: KeyCode) -> bool {
        match key {
            KeyCode::Esc | KeyCode::Char('q') if !self.editing_mode => return true,
            KeyCode::Esc => {
                self.textarea.set_cursor_style(Style::default());
                self.highlight();
                let lines = self
                    .get_input()
                    .iter()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<String>>();

                self.reset_lines(&lines);
                self.editing_mode = false;
            }
            KeyCode::Char('d') if !self.editing_mode => {
                self.textarea.move_cursor(CursorMove::End);
                let (row, _) = self.textarea.cursor();
                self.textarea.delete_line_by_head();
                self.textarea.delete_newline();
                if row == 0 {
                    self.textarea.delete_str(1);
                }
            }
            KeyCode::Char('o') if !self.editing_mode => {
                self.editing_mode = true;
                self.textarea.move_cursor(CursorMove::End);
                self.textarea.insert_newline();
                text_editing_style(self.cursor_color, &mut self.textarea);
                text_input_position(key, &mut self.textarea);
            }
            KeyCode::Up | KeyCode::Char('k') if !self.editing_mode => {
                self.textarea.move_cursor(CursorMove::Up);
                self.highlight();
            }
            KeyCode::Down | KeyCode::Char('j') if !self.editing_mode => {
                self.textarea.move_cursor(CursorMove::Down);
                self.highlight();
            }
            KeyCode::Left | KeyCode::Char('h') if !self.editing_mode => {
                self.textarea.move_cursor(CursorMove::Back);
            }
            KeyCode::Right | KeyCode::Char('l') if !self.editing_mode => {
                self.textarea.move_cursor(CursorMove::Forward);
            }
            KeyCode::Enter | KeyCode::Char('i') | KeyCode::Char('a') if !self.editing_mode => {
                self.editing_mode = true;
                text_editing_style(self.cursor_color, &mut self.textarea);
                text_input_position(key, &mut self.textarea);
            }
            _ if self.editing_mode => {
                self.textarea.input(Input {
                    key: Key::from(key),
                    ctrl: false,
                    alt: false,
                    shift: false,
                });
            }
            _ => {}
        };
        false
    }
    pub fn highlight(&mut self) {
        self.textarea.set_cursor_line_style(
            Style::default()
                .fg(self.cursor_color)
                .add_modifier(Modifier::REVERSED),
        );
    }
}

impl Widget for &MultiLineText {
    fn render(self, area: Rect, buf: &mut Buffer)
    where
        Self: Sized,
    {
        self.textarea.render(area, buf);
    }
}

impl Widget for &SingleLineText {
    fn render(self, area: Rect, buf: &mut Buffer)
    where
        Self: Sized,
    {
        self.textarea.render(area, buf);
    }
}

pub enum Message {
    #[allow(dead_code)]
    Info(Vec<String>),
    #[allow(dead_code)]
    Warning(Vec<String>),
    Error(Vec<String>),
    Success(Vec<String>),
}

impl Message {
    pub fn lines(&self) -> &[String] {
        use Message::*;
        match self {
            Info(lines) => lines,
            Warning(lines) => lines,
            Error(lines) => lines,
            Success(lines) => lines,
        }
    }

    pub fn len(&self) -> usize {
        use Message::*;
        match self {
            Info(lines) => lines.len(),
            Warning(lines) => lines.len(),
            Error(lines) => lines.len(),
            Success(lines) => lines.len(),
        }
    }
}

pub fn render_message_dialog(area: Rect, buf: &mut Buffer, message: &Message, theme: &Theme) {
    let height = message.len() as u16 + 5;
    let dialog_area = centered_area(area, area.width, height);

    use Message::*;
    let (title, color) = match message {
        Info(_) => ("Info", theme.accent),
        Warning(_) => ("Warning", theme.warning),
        Error(_) => ("Error", theme.error),
        Success(_) => ("Success", theme.success),
    };

    theme.clear(dialog_area, buf);
    let block = dialog_block(title, color);

    let mut text = message
        .lines()
        .iter()
        .map(|v| Line::from(v.as_str()))
        .collect::<Vec<Line>>();
    text.insert(0, Line::from(""));
    text.push(Line::from(""));
    text.push(Line::from(vec![Span::styled(
        " <OK> ",
        Style::default().fg(theme.bg).bg(color).bold(),
    )]));

    let paragraph = Paragraph::new(text)
        .block(block)
        .alignment(Alignment::Center);
    paragraph.render(dialog_area, buf);
}

pub fn centered_area(area: Rect, x: u16, y: u16) -> Rect {
    let vertical = Layout::vertical([Constraint::Length(y)]).flex(Flex::Center);
    let horizontal = Layout::horizontal([Constraint::Length(x)]).flex(Flex::Center);
    let [area] = area.layout(&vertical);
    let [area] = area.layout(&horizontal);
    area
}

pub fn render_confirm_dialog(area: Rect, buf: &mut Buffer, lines: &[String], theme: &Theme) {
    let height = lines.len() as u16 + 5;
    let dialog_area = centered_area(area, area.width, height);

    theme.clear(dialog_area, buf);
    let block = dialog_block("Confirm Delete", theme.error);

    let mut text = lines
        .iter()
        .map(|v| Line::from(v.as_str()))
        .collect::<Vec<Line>>();
    text.insert(0, Line::from(""));
    text.push(Line::from(""));
    text.push(yes_no(theme));

    let paragraph = Paragraph::new(text)
        .block(block)
        .alignment(Alignment::Center);
    paragraph.render(dialog_area, buf);
}

pub fn render_cancel_dialog(area: Rect, buf: &mut Buffer, theme: &Theme) {
    let dialog_area = centered_area(area, area.width, 7);

    theme.clear(dialog_area, buf);
    let block = dialog_block("Confirm Cancel", theme.error);

    let text = vec![
        Line::from(""),
        Line::from("Are you sure you want to cancel?"),
        Line::from("All unsaved changes will be lost."),
        Line::from(""),
        yes_no(theme),
    ];

    let paragraph = Paragraph::new(text)
        .block(block)
        .alignment(Alignment::Center);
    paragraph.render(dialog_area, buf);
}

fn dialog_block(title: &str, color: Color) -> Block<'_> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .title(Line::from(format!(" {title} ")).bold())
        .title_style(Style::new().fg(color))
        .border_style(Style::new().fg(color))
}

fn yes_no(theme: &Theme) -> Line<'static> {
    Line::from(vec![
        Span::styled("Y", Style::new().fg(theme.success).bold()),
        Span::raw("es / "),
        Span::styled("N", Style::new().fg(theme.error).bold()),
        Span::raw("o"),
    ])
}

/// The border of one form field: accent with focus, `editing` while edited.
fn field_block<'a>(
    label: &'a str,
    editing_mode: bool,
    theme: &Theme,
    is_focused: bool,
) -> Block<'a> {
    let (title_style, border_style) = match (is_focused, editing_mode) {
        (true, true) => (
            Style::new().fg(theme.title).bold(),
            Style::new().fg(theme.editing),
        ),
        (true, false) => (
            Style::new().fg(theme.title).bold(),
            Style::new().fg(theme.accent),
        ),
        (false, _) => (Style::new().fg(theme.muted), Style::new().fg(theme.border)),
    };
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(label)
        .border_style(border_style)
        .title_style(title_style)
}

pub fn render_textarea<W: Widget>(
    area: Rect,
    buf: &mut Buffer,
    label: &str,
    textarea: W,
    editing_mode: bool,
    theme: &Theme,
    is_focused: bool,
) {
    let block = field_block(label, editing_mode, theme, is_focused);
    let inner = block.inner(area);
    block.render(area, buf);
    textarea.render(inner, buf);
}

pub fn render_checkbox(
    area: Rect,
    buf: &mut Buffer,
    label: &str,
    checked: bool,
    theme: &Theme,
    is_focused: bool,
) {
    let checkbox = if checked { "[X]" } else { "[ ]" };

    let style = if is_focused {
        Style::default()
            .fg(theme.accent)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };

    let text = format!("{} {}", checkbox, label);
    let paragraph = Paragraph::new(text)
        .style(style)
        .block(field_block("", false, theme, is_focused));
    paragraph.render(area, buf);
}

/// The frame of a popup editor: a double accent border, the title on top.
pub fn popup_block<'a>(title: impl Into<Line<'a>>, theme: &Theme) -> Block<'a> {
    Block::bordered()
        .title(title.into().bold())
        .title_style(Style::new().fg(theme.title))
        .border_style(Style::new().fg(theme.accent))
        .border_type(BorderType::Double)
}

/// A one-line bar with a centred title: the header of a panel without tabs.
pub fn render_title_bar(area: Rect, buf: &mut Buffer, title: &str, theme: &Theme) {
    Paragraph::new(title)
        .style(Style::new().bold().fg(theme.bar_fg).bg(theme.bar_bg))
        .centered()
        .render(area, buf);
}

/// The help footer at the bottom of every panel, with the theme's name on its
/// border.
pub fn render_footer(area: Rect, buf: &mut Buffer, lines: [&str; 2], theme: &Theme) {
    let name = Line::from(format!(" theme: {} ", theme.name))
        .right_aligned()
        .style(Style::new().fg(theme.muted));
    Paragraph::new(Text::from_iter(lines))
        .style(theme.base())
        .centered()
        .block(
            Block::bordered()
                .border_type(BorderType::Double)
                .border_style(Style::new().fg(theme.accent))
                .title_bottom(name),
        )
        .render(area, buf);
}

/// A row of tabs that scrolls to keep the selected one in view when the
/// terminal is too narrow for all of them.
#[derive(Debug, Default)]
pub struct TabBar {
    scroll_offset: usize,
}

impl TabBar {
    const TAB_W: usize = 17;
    const DIV_W: usize = 1;
    const ARROW_W: usize = 2; // "◄ " or " ►"

    /// Returns (full_tab_count, has_left_arrow, has_right_arrow) for the given
    /// scroll offset and available width. Only counts tabs that fit completely.
    fn visibility(offset: usize, tab_count: usize, area_width: usize) -> (usize, bool, bool) {
        let (tab_w, div_w, arrow_w) = (Self::TAB_W, Self::DIV_W, Self::ARROW_W);

        let has_left = offset > 0;
        let left_res = if has_left { arrow_w } else { 0 };
        let remaining = tab_count.saturating_sub(offset);

        // Try with right arrow reserved
        let usable_r = area_width.saturating_sub(left_res + arrow_w);
        let count_r = if usable_r >= tab_w {
            ((usable_r + div_w) / (tab_w + div_w)).min(remaining)
        } else {
            0
        };

        // Check if all remaining tabs fit without right arrow
        // FIXME: The last tab at least has two space tail.
        // Since the usable_r = area_width - left_res - **arrow_w**
        if offset + count_r >= tab_count {
            let usable_nr = area_width.saturating_sub(left_res);
            let count_nr = if usable_nr >= tab_w {
                ((usable_nr + div_w) / (tab_w + div_w)).min(remaining)
            } else {
                0
            };
            if offset + count_nr >= tab_count {
                return (count_nr, has_left, false);
            }
        }

        (count_r, has_left, offset + count_r < tab_count)
    }

    pub fn render(
        &mut self,
        area: Rect,
        buf: &mut Buffer,
        labels: &[&str],
        selected: usize,
        theme: &Theme,
    ) {
        let width = area.width as usize;
        let tab_count = labels.len();
        let tab_w = Self::TAB_W;
        let arrow_w = Self::ARROW_W;

        // Scroll left if selected tab is before the visible window
        if selected < self.scroll_offset {
            self.scroll_offset = selected;
        }

        // Scroll right if selected tab is beyond the visible window
        loop {
            let (visible_count, _, _) = Self::visibility(self.scroll_offset, tab_count, width);
            if visible_count == 0 || selected < self.scroll_offset + visible_count {
                break;
            }
            self.scroll_offset += 1;
        }

        let (visible_count, has_left, has_right) =
            Self::visibility(self.scroll_offset, tab_count, width);

        if visible_count == 0 {
            return;
        }

        let dim_style = Style::default().fg(theme.muted);

        let mut spans: Vec<Span> = Vec::new();
        let mut used: usize = 0;

        if has_left {
            spans.push(Span::styled("◄ ", dim_style));
            used += arrow_w;
        }

        let start = self.scroll_offset;
        let end = start + visible_count;
        for (i, item) in labels.iter().enumerate().take(end).skip(start) {
            if i > start {
                spans.push(Span::raw(" "));
                used += 1;
            }

            let label = format!("{:^17}", item);
            let style = if i == selected {
                Style::default().bold().fg(theme.bar_fg).bg(theme.bar_bg)
            } else {
                dim_style
            };
            spans.push(Span::styled(label, style));
            used += tab_w;
        }

        // Fill remaining space with a partial next tab if one exists
        if has_right {
            let leftover = width.saturating_sub(used + arrow_w);
            let next_idx = end;
            if leftover > 1 && next_idx < tab_count {
                // divider + partial label
                spans.push(Span::raw(" "));
                let partial_w = leftover - 1; // 1 for divider
                let full_label = format!("{:^17}", labels[next_idx]);
                let truncated: String = full_label.chars().take(partial_w).collect();
                spans.push(Span::styled(truncated, dim_style));
            }
            spans.push(Span::styled(" ►", dim_style));
        }

        Paragraph::new(Line::from(spans))
            .style(Style::new().bg(theme.alt_bg))
            .render(area, buf);
    }
}

pub fn render_message_popup(area: Rect, buf: &mut Buffer, message: &Message, theme: &Theme) {
    let popup_area = if area.width <= common::MAX_POPUP_WINDOW_COL {
        area
    } else {
        centered_area(
            area,
            common::MAX_POPUP_WINDOW_COL,
            area.height.min(common::MAX_POPUP_WINDOW_ROW),
        )
    };

    render_message_dialog(popup_area, buf, message, theme);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ThemeName;

    fn text(buf: &Buffer) -> String {
        buf.content.iter().map(|c| c.symbol()).collect()
    }

    /// Every cell of a painted frame carries the theme's colours, never the
    /// terminal's own, whichever shared widget drew it. `default` is left out:
    /// the terminal's colours are its own.
    #[test]
    fn shared_widgets_leave_no_terminal_default_colours() {
        for name in ThemeName::ALL
            .into_iter()
            .filter(|n| *n != ThemeName::Default)
        {
            let theme = Theme::of(name);
            let area = Rect::new(0, 0, 60, 12);
            let mut buf = Buffer::empty(area);
            theme.paint(area, &mut buf);

            let [tabs, table, footer] = Layout::vertical([
                Constraint::Length(1),
                Constraint::Min(5),
                Constraint::Length(4),
            ])
            .areas(area);
            TabBar::default().render(tabs, &mut buf, &["One", "Two", "Three", "Four"], 1, theme);
            let rows = vec![object_group("a"), object_group("b")];
            let mut t = AdminTable::new(&rows);
            t.size = (table.width, table.height);
            t.render(
                &mut buf,
                table,
                &rows,
                &table_object_group_len_calculator(&rows),
                DisplayMode::Manage,
                theme,
            );
            render_footer(footer, &mut buf, ["help", "more help"], theme);
            render_message_popup(table, &mut buf, &Message::Error(vec!["bad".into()]), theme);

            for cell in buf.content.iter() {
                assert_ne!(cell.fg, Color::Reset, "{name}: fg left at the default");
                assert_ne!(cell.bg, Color::Reset, "{name}: bg left at the default");
            }
        }
    }

    #[test]
    fn the_footer_names_the_theme() {
        let area = Rect::new(0, 0, 40, 4);
        let mut buf = Buffer::empty(area);
        render_footer(area, &mut buf, ["", ""], Theme::of(ThemeName::OledWhite));
        assert!(text(&buf).contains("theme: oled-white"));
    }

    #[test]
    fn the_tab_bar_scrolls_to_the_selected_tab() {
        let labels = ["Alpha", "Beta", "Gamma", "Delta", "Epsilon"];
        let area = Rect::new(0, 0, 40, 1);
        let mut buf = Buffer::empty(area);
        let mut bar = TabBar::default();
        bar.render(area, &mut buf, &labels, 4, &theme::DEFAULT);
        let shown = text(&buf);
        assert!(shown.contains("Epsilon"), "{shown}");
        assert!(shown.starts_with('◄'), "{shown}");
    }

    fn object_group(name: &str) -> crate::database::models::ObjectGroup {
        crate::database::models::ObjectGroup {
            id: uuid::Uuid::nil(),
            name: name.into(),
            is_group: true,
        }
    }
}
