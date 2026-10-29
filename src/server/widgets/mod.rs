pub mod common;
pub mod form;
pub mod table;
pub mod theme;
pub mod tree;

pub use form::*;
pub use table::*;
pub use theme::Theme;

use crate::fill;
pub use crate::i18n::Strings;

use crossterm::event::KeyCode;
use ratatui::{
    buffer::Buffer,
    layout::{Alignment, Constraint, Direction, Flex, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Padding, Paragraph, Widget},
};
use tui_textarea::{CursorMove, Input, Key, TextArea};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Text a widget keeps and words only when it draws, so it follows the
/// session's language when that changes: `|tr| tr.field_name`.
pub type Label = fn(&Strings) -> &'static str;

/// Help text, as [`Label`] is a label: `(key) what | (key) what`, two lines.
pub type Help = fn(&Strings) -> [&'static str; 2];

/// Radio button options for selection
#[derive(Debug, Clone, Copy)]
pub struct RadioOption {
    pub label: Label,
    pub value: &'static str,
}

impl RadioOption {
    pub const fn new(label: Label, value: &'static str) -> Self {
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
        tr: &Strings,
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

            let (symbol, symbol_style) = if is_selected {
                ("(*)", Style::new().fg(theme.accent).bold())
            } else {
                ("( )", Style::new().fg(theme.muted))
            };
            let label_style = if is_option_focused {
                Style::new().fg(theme.editing).bold()
            } else if is_selected {
                Style::new().fg(theme.title).bold()
            } else {
                Style::new().fg(theme.fg)
            };

            let line = Line::from(vec![
                Span::styled(symbol, symbol_style),
                Span::raw(" "),
                Span::styled((option.label)(tr), label_style),
            ]);

            let paragraph = Paragraph::new(line).alignment(Alignment::Left);
            paragraph.render(radio_layout[i], buf);
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn render_radio_buttons(
    area: Rect,
    buf: &mut Buffer,
    label: &str,
    radio_buttons: &RadioButtons,
    editing_mode: bool,
    theme: &Theme,
    tr: &Strings,
    is_focused: bool,
) {
    let block = field_block(label, editing_mode, theme, is_focused);
    let inner = block.inner(area);
    block.render(area, buf);

    radio_buttons.render_vertical(inner, buf, editing_mode, theme, tr, is_focused);
}

pub const COMMON_HELP: Help = |tr| [tr.help_form_edit, tr.help_form_nav];
pub const RADIO_HELP: Help = |tr| [tr.help_radio, tr.help_form_nav];
pub const RADIO_EDIT_HELP: Help = |tr| [tr.help_radio_edit, tr.help_form_nav];
pub const CHECKBOX_HELP: Help = |tr| [tr.help_checkbox, tr.help_form_nav];
pub const MULTILINES_HELP: Help = |tr| [tr.help_multiline, tr.help_form_nav];
pub const MULTILINES_EDIT_HELP: Help = |tr| [tr.help_multiline_edit, tr.help_multiline_edit_nav];
pub const MULTILINES_INPUT_HELP: Help = |tr| [tr.help_multiline_input, tr.help_multiline_input_nav];
pub const READONLY_HELP: Help = |tr| [tr.read_only, tr.help_form_nav];

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
}

pub fn render_message_dialog(
    area: Rect,
    buf: &mut Buffer,
    message: &Message,
    theme: &Theme,
    tr: &Strings,
) {
    use Message::*;
    let (title, color) = match message {
        Info(_) => (tr.dialog_info, theme.accent),
        Warning(_) => (tr.dialog_warning, theme.warning),
        Error(_) => (tr.dialog_error, theme.error),
        Success(_) => (tr.dialog_success, theme.success),
    };
    let ok = Line::from(button(tr.ok, color, theme));
    render_dialog(area, buf, title, color, message.lines(), ok, theme);
}

pub fn centered_area(area: Rect, x: u16, y: u16) -> Rect {
    let vertical = Layout::vertical([Constraint::Length(y)]).flex(Flex::Center);
    let horizontal = Layout::horizontal([Constraint::Length(x)]).flex(Flex::Center);
    let [area] = area.layout(&vertical);
    let [area] = area.layout(&horizontal);
    area
}

pub fn render_confirm_dialog(
    area: Rect,
    buf: &mut Buffer,
    lines: &[String],
    theme: &Theme,
    tr: &Strings,
) {
    render_dialog(
        area,
        buf,
        tr.confirm_delete,
        theme.error,
        lines,
        yes_no(theme, tr),
        theme,
    );
}

pub fn render_cancel_dialog(area: Rect, buf: &mut Buffer, theme: &Theme, tr: &Strings) {
    let lines = [tr.cancel_sure.to_string(), tr.cancel_lost.to_string()];
    render_dialog(
        area,
        buf,
        tr.confirm_cancel,
        theme.error,
        &lines,
        yes_no(theme, tr),
        theme,
    );
}

/// The narrowest a dialog gets, so a one-word message still looks like one.
const DIALOG_MIN_WIDTH: u16 = 32;
/// Columns a dialog spends around its text: the border and the padding.
const DIALOG_FRAME_WIDTH: u16 = 6;
/// Rows a dialog spends around its text: the border, a blank line above and
/// below, and the buttons.
const DIALOG_FRAME_HEIGHT: u16 = 5;

/// A dialog sized to its message within `area`: as wide as the longest line
/// needs, and as tall as the lines once wrapped to that width. What still does
/// not fit `area` is cut, and the last line shown says so.
fn render_dialog(
    area: Rect,
    buf: &mut Buffer,
    title: &str,
    color: Color,
    body: &[String],
    buttons: Line<'static>,
    theme: &Theme,
) {
    let longest = body
        .iter()
        .flat_map(|l| l.split('\n'))
        .map(|l| l.width())
        .max()
        .unwrap_or(0);
    let wanted = (longest as u16)
        .max(title.width() as u16 + 4)
        .saturating_add(DIALOG_FRAME_WIDTH)
        .max(DIALOG_MIN_WIDTH);
    let width = wanted.min(area.width);
    let text_width = width.saturating_sub(DIALOG_FRAME_WIDTH).max(1) as usize;

    let mut lines = body
        .iter()
        .flat_map(|l| wrap_text(l, text_width))
        .collect::<Vec<_>>();
    let room = area.height.saturating_sub(DIALOG_FRAME_HEIGHT) as usize;
    if lines.len() > room {
        lines.truncate(room);
        if let Some(last) = lines.last_mut() {
            *last = "…".into();
        }
    }
    let height = (lines.len() as u16 + DIALOG_FRAME_HEIGHT).min(area.height);
    let dialog_area = centered_area(area, width, height);

    theme.clear(dialog_area, buf);
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(color))
        .title(badge_title(title, color, theme))
        .padding(Padding::horizontal(2));

    let mut text = vec![Line::from("")];
    text.extend(lines.into_iter().map(Line::from));
    text.push(Line::from(""));
    text.push(buttons);

    Paragraph::new(text)
        .style(theme.base())
        .block(block)
        .alignment(Alignment::Center)
        .render(dialog_area, buf);
}

/// Word-wraps `text` to `width` columns. A word wider than a line is split
/// where the line ends; newlines in `text` start a new line.
pub fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut out = Vec::new();
    for paragraph in text.split('\n') {
        let mut line = String::new();
        let mut line_width = 0;
        for word in paragraph.split_whitespace() {
            let word_width = word.width();
            if line_width > 0 && line_width + 1 + word_width <= width {
                line.push(' ');
                line.push_str(word);
                line_width += 1 + word_width;
                continue;
            }
            if line_width > 0 {
                out.push(std::mem::take(&mut line));
                line_width = 0;
            }
            for ch in word.chars() {
                let ch_width = ch.width().unwrap_or(0);
                if line_width > 0 && line_width + ch_width > width {
                    out.push(std::mem::take(&mut line));
                    line_width = 0;
                }
                line.push(ch);
                line_width += ch_width;
            }
        }
        out.push(line);
    }
    out
}

/// A title on a border, as a filled badge with a space either side.
fn badge_title(title: &str, color: Color, theme: &Theme) -> Line<'static> {
    Line::from(vec![
        Span::raw(" "),
        Span::styled(
            format!(" {} ", title.trim()),
            Style::new().fg(theme.on_accent).bg(color).bold(),
        ),
        Span::raw(" "),
    ])
}

/// A filled button: ` OK `.
fn button(label: &str, color: Color, theme: &Theme) -> Span<'static> {
    Span::styled(
        format!(" {label} "),
        Style::new().fg(theme.on_accent).bg(color).bold(),
    )
}

/// The keys stay `Y` and `N` in every language: they are what is pressed.
fn yes_no(theme: &Theme, tr: &Strings) -> Line<'static> {
    let label = Style::new().fg(theme.fg);
    Line::from(vec![
        button("Y", theme.success, theme),
        Span::styled(format!(" {}", tr.yes), label),
        Span::raw("     "),
        button("N", theme.error, theme),
        Span::styled(format!(" {}", tr.no), label),
    ])
}

/// The border of one form field: accent with focus, `editing` while edited.
fn field_block(label: &str, editing_mode: bool, theme: &Theme, is_focused: bool) -> Block<'static> {
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
    let title = if label.is_empty() {
        String::new()
    } else {
        format!(" {label} ")
    };
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(title)
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
    let (symbol, symbol_style) = if checked {
        ("[x]", Style::new().fg(theme.accent).bold())
    } else {
        ("[ ]", Style::new().fg(theme.muted))
    };
    let label_style = if is_focused {
        Style::new().fg(theme.title).bold()
    } else {
        Style::new().fg(theme.fg)
    };

    let line = Line::from(vec![
        Span::styled(symbol, symbol_style),
        Span::raw(" "),
        Span::styled(label.to_string(), label_style),
    ]);
    Paragraph::new(line)
        .block(field_block("", false, theme, is_focused))
        .render(area, buf);
}

/// The frame of a popup editor: a rounded accent border, the title as a badge.
pub fn popup_block(title: &str, theme: &Theme) -> Block<'static> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(theme.accent))
        .title(badge_title(title, theme.accent, theme))
}

/// The frame of one pane of a split panel: accent with focus, its title then
/// a badge.
pub fn pane_block(title: &str, focused: bool, theme: &Theme) -> Block<'static> {
    let block = Block::bordered().border_type(BorderType::Rounded);
    if focused {
        block
            .border_style(Style::new().fg(theme.accent))
            .title(badge_title(title, theme.accent, theme))
    } else {
        block
            .border_style(Style::new().fg(theme.border))
            .title(Line::styled(format!("  {}  ", title.trim()), theme.muted))
    }
}

/// The product's name, at the left of every panel's header.
const BRAND: &str = " Rustion ";

/// The header row every panel starts with: its background, and the product's
/// name as a badge. Returns what is left of the row, right of the badge.
fn render_header(area: Rect, buf: &mut Buffer, theme: &Theme) -> Rect {
    buf.set_style(area, Style::new().fg(theme.fg).bg(theme.alt_bg));
    let brand = Line::from(vec![
        Span::styled(
            BRAND,
            Style::new().fg(theme.on_accent).bg(theme.accent).bold(),
        ),
        Span::raw(" "),
    ]);
    let used = (brand.width() as u16).min(area.width);
    brand.render(area, buf);
    Rect {
        x: area.x + used,
        width: area.width - used,
        ..area
    }
}

/// The header of a panel without tabs: the product's name, then the panel's
/// as if it were the one tab.
pub fn render_title_bar(area: Rect, buf: &mut Buffer, title: &str, theme: &Theme) {
    let rest = render_header(area, buf, theme);
    Span::styled(format!(" {title} "), tab_style(theme)).render(rest, buf);
}

fn tab_style(theme: &Theme) -> Style {
    Style::new().fg(theme.bar_fg).bg(theme.bar_bg).bold()
}

/// A key, drawn as a key cap.
fn key_style(theme: &Theme) -> Style {
    Style::new().fg(theme.bar_fg).bg(theme.bar_bg).bold()
}

/// One `(key) what it does` hint of a help text.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Hint<'a> {
    Key(&'a str, &'a str),
    /// A key with nothing to say about it is a notice: `(Read-only)`.
    Notice(&'a str),
    /// Text with no key at all.
    Plain(&'a str),
}

impl<'a> Hint<'a> {
    fn parse(hint: &'a str) -> Self {
        let hint = hint.trim();
        match hint.strip_prefix('(').and_then(|r| r.split_once(')')) {
            Some((key, what)) if what.trim().is_empty() => Hint::Notice(key),
            Some((key, what)) => Hint::Key(key, what.trim()),
            None => Hint::Plain(hint),
        }
    }

    /// Every hint of help text written `(key) what | (key) what`.
    fn all(help: &[&'a str]) -> Vec<Self> {
        help.iter()
            .flat_map(|l| l.split(" | "))
            .filter(|h| !h.trim().is_empty())
            .map(Hint::parse)
            .collect()
    }

    /// The key cap's width, and the description's.
    fn widths(&self) -> (usize, usize) {
        match self {
            Hint::Key(key, what) => (key.width() + 2, what.width()),
            Hint::Notice(key) => (key.width() + 2, 0),
            Hint::Plain(what) => (0, what.width()),
        }
    }

    fn key_span(&self, theme: &Theme) -> Option<Span<'static>> {
        match self {
            Hint::Key(key, _) => Some(Span::styled(format!(" {key} "), key_style(theme))),
            Hint::Notice(key) => Some(Span::styled(
                format!(" {key} "),
                Style::new().fg(theme.on_accent).bg(theme.warning).bold(),
            )),
            Hint::Plain(_) => None,
        }
    }

    fn what_span(&self, theme: &Theme) -> Option<Span<'a>> {
        match self {
            Hint::Key(_, what) => Some(Span::styled(*what, Style::new().fg(theme.muted))),
            Hint::Notice(_) => None,
            Hint::Plain(what) => Some(Span::styled(*what, Style::new().fg(theme.fg))),
        }
    }
}

/// Space between two columns of hints.
const HINT_GAP: usize = 4;
/// Rows of hints the footer grows to before it cuts the rest.
const MAX_HINT_ROWS: u16 = 6;
/// Rows of hints the footer always keeps, so the panel above does not jump
/// as the help changes.
const MIN_HINT_ROWS: u16 = 3;

/// Hints laid out row by row in `columns` columns: each column's key caps
/// right-aligned to one edge and its descriptions left-aligned to the next.
struct HintGrid<'a> {
    hints: Vec<Hint<'a>>,
    columns: usize,
    /// Per column: the widest key cap, and the widest description.
    widths: Vec<(usize, usize)>,
}

impl<'a> HintGrid<'a> {
    /// The most columns that fit `width`; one when not even that does.
    fn new(help: &[&'a str], width: u16) -> Self {
        let hints = Hint::all(help);
        let mut grid = Self::with_columns(hints.clone(), 1);
        for columns in 2..=hints.len() {
            let wider = Self::with_columns(hints.clone(), columns);
            if wider.width() > width as usize {
                break;
            }
            grid = wider;
        }
        grid
    }

    fn with_columns(hints: Vec<Hint<'a>>, columns: usize) -> Self {
        let mut widths = vec![(0, 0); columns];
        for (i, hint) in hints.iter().enumerate() {
            let (key, what) = hint.widths();
            let col = &mut widths[i % columns];
            col.0 = col.0.max(key);
            col.1 = col.1.max(what);
        }
        Self {
            hints,
            columns,
            widths,
        }
    }

    fn rows(&self) -> usize {
        self.hints.len().div_ceil(self.columns)
    }

    /// One column: its key caps, the space after them, its descriptions.
    fn column_width((key, what): (usize, usize)) -> usize {
        let space = if key > 0 && what > 0 { 1 } else { 0 };
        key + space + what
    }

    fn width(&self) -> usize {
        let columns = self.widths.iter().map(|w| Self::column_width(*w));
        columns.sum::<usize>() + HINT_GAP * self.columns.saturating_sub(1)
    }

    fn line(&self, row: usize, theme: &Theme) -> Line<'a> {
        let mut spans = Vec::new();
        let cells = self
            .hints
            .iter()
            .skip(row * self.columns)
            .take(self.columns);
        for (col, hint) in cells.enumerate() {
            let (key_w, what_w) = self.widths[col];
            if col > 0 {
                spans.push(Span::raw(" ".repeat(HINT_GAP)));
            }
            let (key, what) = hint.widths();
            spans.push(Span::raw(" ".repeat(key_w - key)));
            spans.extend(hint.key_span(theme));
            if key_w > 0 && what_w > 0 {
                spans.push(Span::raw(" "));
            }
            spans.extend(hint.what_span(theme));
            spans.push(Span::raw(" ".repeat(what_w - what)));
        }
        Line::from(spans)
    }
}

/// The rows the footer for `help` takes at `width`: the rule, then the hints.
/// Panels lay themselves out with it, so a narrow terminal gets a taller
/// footer rather than hints cut off at the edge.
pub fn footer_height(help: [&str; 2], width: u16) -> u16 {
    let rows = HintGrid::new(&help, width).rows() as u16;
    1 + rows.clamp(MIN_HINT_ROWS, MAX_HINT_ROWS)
}

/// Help text on one line, for a status bar.
fn hint_line<'a>(help: &'a str, theme: &Theme) -> Vec<Span<'a>> {
    let mut spans = Vec::new();
    for (i, hint) in Hint::all(&[help]).into_iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("   "));
        }
        let key = hint.key_span(theme);
        let has_key = key.is_some();
        spans.extend(key);
        if let Some(what) = hint.what_span(theme) {
            if has_key {
                spans.push(Span::raw(" "));
            }
            spans.push(what);
        }
    }
    spans
}

/// A one-line status bar: a `state` badge in its colour, the key hints, and
/// `info` at the right when there is room for it.
pub fn render_status_bar(
    area: Rect,
    buf: &mut Buffer,
    (state, color): (&str, Color),
    help: &str,
    info: &str,
    theme: &Theme,
) {
    buf.set_style(area, Style::new().fg(theme.fg).bg(theme.alt_bg));
    let mut spans = vec![button(state, color, theme), Span::raw("  ")];
    spans.extend(hint_line(help, theme));
    let line = Line::from(spans);
    let info = Span::styled(format!(" {info} "), Style::new().fg(theme.muted));
    let room = area.width as usize;
    if line.width() + info.width() + 2 <= room {
        info.into_right_aligned_line().render(area, buf);
    }
    line.render(area, buf);
}

/// The help footer at the bottom of every panel: a rule naming the theme and
/// the language, then the key hints in aligned columns, centred as one block.
/// Give it the height [`footer_height`] asks for; hints beyond that are cut,
/// and the last row says how many. The language is left off the rule when
/// there is no room for both.
pub fn render_footer(area: Rect, buf: &mut Buffer, lines: [&str; 2], theme: &Theme, tr: &Strings) {
    buf.set_style(area, theme.base());
    if area.height == 0 {
        return;
    }
    let [rule, hints] = Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(area);

    let border = Style::new().fg(theme.border);
    let label = Style::new().fg(theme.muted);
    let theme_spans = [
        Span::styled(format!(" {} ", tr.footer_theme), label),
        Span::styled(format!(" {} ", theme.name), key_style(theme)),
        Span::styled(" ─", border),
    ];
    let language_spans = [
        Span::styled(format!(" {} ", tr.footer_language), label),
        Span::styled(format!(" {} ", tr.lang_name), key_style(theme)),
        Span::styled(" ─", border),
    ];
    let mut name = Line::from(language_spans.to_vec());
    name.spans.extend(theme_spans.clone());
    // Room for a stretch of rule on the left, or it reads as a header.
    if name.width() + 4 > rule.width as usize {
        name = Line::from(theme_spans.to_vec());
    }
    let name_width = (name.width() as u16).min(rule.width);
    Line::styled("─".repeat(rule.width as usize), border).render(rule, buf);
    name.render(
        Rect {
            x: rule.right() - name_width,
            width: name_width,
            ..rule
        },
        buf,
    );

    let grid = HintGrid::new(&lines, hints.width);
    let room = hints.height as usize;
    let cut = grid.rows() > room;
    let shown = if cut {
        room.saturating_sub(1)
    } else {
        grid.rows()
    };
    let used = shown + cut as usize;

    // One left edge for every row, so the columns line up.
    let left = hints.width.saturating_sub(grid.width() as u16) / 2;
    let top = (room - used) as u16 / 2;
    for row in 0..shown {
        let y = hints.y + top + row as u16;
        let line_area = Rect::new(hints.x + left, y, hints.width - left, 1);
        grid.line(row, theme).render(line_area, buf);
    }
    if cut {
        let y = hints.y + top + shown as u16;
        let hidden = grid.hints.len() - shown * grid.columns;
        Line::styled(fill!(tr.footer_more, count = hidden), theme.muted)
            .centered()
            .render(
                Rect {
                    y,
                    height: 1,
                    ..hints
                },
                buf,
            );
    }
}

/// A row of tabs that scrolls to keep the selected one in view when the
/// terminal is too narrow for all of them.
#[derive(Debug, Default)]
pub struct TabBar {
    scroll_offset: usize,
}

impl TabBar {
    /// The narrowest a tab gets. Wider labels, as translations often are,
    /// widen every tab to the widest of them, so all tabs stay one size.
    const TAB_W: usize = 17;
    const DIV_W: usize = 1;
    const ARROW_W: usize = 2; // "◄ " or " ►"

    /// Returns (full_tab_count, has_left_arrow, has_right_arrow) for the given
    /// scroll offset and available width. Only counts tabs that fit completely.
    fn visibility(
        offset: usize,
        tab_count: usize,
        area_width: usize,
        tab_w: usize,
    ) -> (usize, bool, bool) {
        let (div_w, arrow_w) = (Self::DIV_W, Self::ARROW_W);

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
        let area = render_header(area, buf, theme);
        let width = area.width as usize;
        let tab_count = labels.len();
        let tab_w = labels
            .iter()
            .map(|l| l.width() + 2)
            .fold(Self::TAB_W, usize::max);
        let arrow_w = Self::ARROW_W;

        // Scroll left if selected tab is before the visible window
        if selected < self.scroll_offset {
            self.scroll_offset = selected;
        }

        // Scroll right if selected tab is beyond the visible window
        loop {
            let (visible_count, _, _) =
                Self::visibility(self.scroll_offset, tab_count, width, tab_w);
            if visible_count == 0 || selected < self.scroll_offset + visible_count {
                break;
            }
            self.scroll_offset += 1;
        }

        let (visible_count, has_left, has_right) =
            Self::visibility(self.scroll_offset, tab_count, width, tab_w);

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

            let label = center(item, tab_w);
            let style = if i == selected {
                tab_style(theme)
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
                let full_label = center(labels[next_idx], tab_w);
                let truncated = clip(&full_label, partial_w);
                spans.push(Span::styled(truncated, dim_style));
            }
            spans.push(Span::styled(" ►", dim_style));
        }

        Line::from(spans).render(area, buf);
    }
}

/// `text` centred in `width` columns, by display width: a CJK character takes
/// two, which `format!("{:^n}")` would count as one. Cut when it is wider.
fn center(text: &str, width: usize) -> String {
    let text = clip(text, width);
    let room = width - text.width();
    let left = room / 2;
    format!("{}{text}{}", " ".repeat(left), " ".repeat(room - left))
}

/// The longest start of `text` that fits `width` columns.
fn clip(text: &str, width: usize) -> String {
    let mut out = String::new();
    let mut used = 0;
    for ch in text.chars() {
        let w = ch.width().unwrap_or(0);
        if used + w > width {
            break;
        }
        used += w;
        out.push(ch);
    }
    out
}

pub fn render_message_popup(
    area: Rect,
    buf: &mut Buffer,
    message: &Message,
    theme: &Theme,
    tr: &Strings,
) {
    let popup_area = if area.width <= common::MAX_POPUP_WINDOW_COL {
        area
    } else {
        centered_area(
            area,
            common::MAX_POPUP_WINDOW_COL,
            area.height.min(common::MAX_POPUP_WINDOW_ROW),
        )
    };

    render_message_dialog(popup_area, buf, message, theme, tr);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ThemeName;
    use crate::i18n::Lang;

    const EN: &Strings = Lang::En.strings();

    fn text(buf: &Buffer) -> String {
        buf.content.iter().map(|c| c.symbol()).collect()
    }

    fn rows(buf: &Buffer) -> Vec<String> {
        let width = buf.area.width as usize;
        buf.content
            .chunks(width)
            .map(|row| row.iter().map(|c| c.symbol()).collect())
            .collect()
    }

    /// Where `needle` is drawn, as the cell of its first character.
    fn find(buf: &Buffer, needle: &str) -> (u16, u16) {
        for (y, row) in rows(buf).iter().enumerate() {
            if let Some(i) = row.find(needle) {
                let x = row[..i].chars().count();
                return (x as u16, y as u16);
            }
        }
        panic!("{needle:?} not drawn:\n{}", rows(buf).join("\n"));
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
                EN,
            );
            render_footer(
                footer,
                &mut buf,
                ["(q) quit | help", "(Read-only)"],
                theme,
                EN,
            );
            let message = Message::Error(vec!["bad".into()]);
            render_message_popup(table, &mut buf, &message, theme, EN);
            render_status_bar(
                tabs,
                &mut buf,
                ("PAUSED", theme.warning),
                "(q) quit",
                "",
                theme,
            );

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
        render_footer(
            area,
            &mut buf,
            ["", ""],
            Theme::of(ThemeName::OledWhite),
            EN,
        );
        assert!(text(&buf).contains(" theme  oled-white "), "{}", text(&buf));
    }

    /// The footer tells keys from what they do: a key is a key cap, its
    /// description is muted text.
    #[test]
    fn the_footer_draws_keys_apart_from_their_descriptions() {
        let theme = &theme::NORD;
        let area = Rect::new(0, 0, 60, 4);
        let mut buf = Buffer::empty(area);
        render_footer(area, &mut buf, ["(Esc) quit | (t) theme", ""], theme, EN);

        let (x, y) = find(&buf, "Esc");
        let key = &buf[(x, y)];
        assert_eq!((key.fg, key.bg), (theme.bar_fg, theme.bar_bg));
        let (x, y) = find(&buf, "quit");
        let what = &buf[(x, y)];
        assert_eq!((what.fg, what.bg), (theme.muted, theme.bg));
        assert!(
            !text(&buf).contains('('),
            "brackets left in: {}",
            text(&buf)
        );
    }

    const MANAGE_HELP: [&str; 2] = [
        "(a) add | (e) edit | (d) delete | (r) grant role | (t) theme | (Esc) quit | (↑↓←→) move around",
        "(Tab/Shift Tab) next/previous tab | (+/-) zoom in/out | (PgUp/PgDn) page up/down",
    ];

    fn footer(help: [&str; 2], width: u16) -> Buffer {
        let area = Rect::new(0, 0, width, footer_height(help, width));
        let mut buf = Buffer::empty(area);
        render_footer(area, &mut buf, help, &theme::NORD, EN);
        buf
    }

    /// Hints sit in columns: in each one the key caps end at one edge and the
    /// descriptions start at the next, whatever the width of the keys.
    #[test]
    fn the_footer_lines_its_hints_up_in_columns() {
        let buf = footer(MANAGE_HELP, 80);
        // The first column at 80 wide, top to bottom.
        let grid = HintGrid::new(&MANAGE_HELP, 80);
        let column: Vec<(&str, &str)> = grid
            .hints
            .iter()
            .step_by(grid.columns)
            .filter_map(|h| match h {
                Hint::Key(key, what) => Some((*key, *what)),
                _ => None,
            })
            .collect();
        assert!(column.len() >= 3, "{column:?}");
        // Row `i` of the grid is the footer's row `i + 1`, under the rule. A
        // short key like ` d ` can turn up elsewhere, so look only there.
        let at = |row: usize, needle: &str| {
            let line = &rows(&buf)[row + 1];
            let i = line
                .find(needle)
                .unwrap_or_else(|| panic!("{needle:?} not in {line:?}"));
            line[..i].chars().count() as u16
        };
        let key_ends = column
            .iter()
            .enumerate()
            .map(|(row, (key, _))| at(row, &format!(" {key} ")) + key.chars().count() as u16 + 2)
            .collect::<Vec<_>>();
        let starts = column
            .iter()
            .enumerate()
            .map(|(row, (_, what))| at(row, what))
            .collect::<Vec<_>>();
        assert!(key_ends.windows(2).all(|w| w[0] == w[1]), "{key_ends:?}");
        assert!(starts.windows(2).all(|w| w[0] == w[1]), "{starts:?}");
        assert_eq!(starts[0], key_ends[0] + 1);
    }

    /// A narrower terminal gets a taller footer, with every key still shown.
    #[test]
    fn the_footer_grows_on_a_narrow_terminal() {
        assert!(footer_height(MANAGE_HELP, 60) > footer_height(MANAGE_HELP, 120));
        assert_eq!(footer_height(["(q) quit", ""], 120), 1 + MIN_HINT_ROWS);
        let buf = footer(MANAGE_HELP, 60);
        for hint in MANAGE_HELP.iter().flat_map(|l| l.split(" | ")) {
            let (_, what) = hint.split_once(") ").unwrap();
            find(&buf, what);
        }
    }

    /// Past its tallest the footer cuts whole hints and counts them.
    #[test]
    fn the_footer_counts_the_keys_it_cannot_show() {
        let buf = footer(MANAGE_HELP, 25);
        assert_eq!(buf.area.height, 1 + MAX_HINT_ROWS);
        let shown = MAX_HINT_ROWS as usize - 1;
        let total = MANAGE_HELP.iter().flat_map(|l| l.split(" | ")).count();
        find(&buf, &format!("… {} more", total - shown));
        find(&buf, "theme");
        assert!(!text(&buf).contains("quit"), "{}", rows(&buf).join("\n"));
    }

    #[test]
    fn wrap_text_breaks_between_words() {
        assert_eq!(
            wrap_text("the quick brown fox", 10),
            ["the quick", "brown fox"]
        );
        assert_eq!(wrap_text("", 10), [""]);
        assert_eq!(wrap_text("one\ntwo", 10), ["one", "two"]);
    }

    #[test]
    fn wrap_text_splits_a_word_wider_than_the_line() {
        assert_eq!(wrap_text("abcdefgh ij", 3), ["abc", "def", "gh", "ij"]);
        assert_eq!(wrap_text("中文字符", 5), ["中文", "字符"]);
    }

    /// A message longer than the popup is wrapped inside it, every word shown.
    #[test]
    fn a_long_message_wraps_inside_the_popup() {
        let message = "Failed to connect to target db-primary-01: connection refused \
                       by 10.0.0.12:22 after 3 attempts, check the proxy settings";
        let area = Rect::new(0, 0, 100, 20);
        let mut buf = Buffer::empty(area);
        render_message_popup(
            area,
            &mut buf,
            &Message::Error(vec![message.into()]),
            &theme::NORD,
            EN,
        );
        for word in message.split_whitespace() {
            find(&buf, word);
        }
        let (x, _) = find(&buf, "Failed");
        assert!(
            x >= (100 - common::MAX_POPUP_WINDOW_COL) / 2,
            "outside the popup"
        );
    }

    /// A message taller than the screen keeps its buttons and says it is cut.
    #[test]
    fn a_message_taller_than_the_area_is_cut_with_an_ellipsis() {
        let lines = (0..30).map(|i| format!("line {i}")).collect();
        let area = Rect::new(0, 0, 40, 10);
        let mut buf = Buffer::empty(area);
        render_message_dialog(area, &mut buf, &Message::Info(lines), &theme::NORD, EN);
        find(&buf, "line 0");
        find(&buf, "…");
        find(&buf, " OK ");
    }

    #[test]
    fn an_empty_table_says_so() {
        let rows: Vec<crate::database::models::ObjectGroup> = Vec::new();
        let area = Rect::new(0, 0, 40, 6);
        let mut buf = Buffer::empty(area);
        let mut t = AdminTable::new(&rows);
        t.size = (area.width, area.height);
        t.render(
            &mut buf,
            area,
            &rows,
            &table_object_group_len_calculator(&rows),
            DisplayMode::Manage,
            &theme::DEFAULT,
            EN,
        );
        find(&buf, "No records yet");
    }

    #[test]
    fn the_tab_bar_scrolls_to_the_selected_tab() {
        let labels = ["Alpha", "Beta", "Gamma", "Delta", "Epsilon"];
        let area = Rect::new(0, 0, 40, 1);
        let mut buf = Buffer::empty(area);
        let mut bar = TabBar::default();
        bar.render(area, &mut buf, &labels, 4, &theme::DEFAULT);
        let shown = text(&buf);
        assert!(shown.starts_with(BRAND), "{shown}");
        assert!(shown.contains("Epsilon"), "{shown}");
        assert!(shown.contains('◄'), "{shown}");
    }

    #[test]
    fn the_footer_names_the_language_when_there_is_room() {
        let ja = Lang::Ja.strings();
        let area = Rect::new(0, 0, 60, 4);
        let mut buf = Buffer::empty(area);
        render_footer(area, &mut buf, ["", ""], &theme::NORD, ja);
        // A wide character's second cell is blank, so compare without spaces.
        let shown = text(&buf).replace(' ', "");
        assert!(shown.contains("言語日本語"), "{shown}");
        assert!(shown.contains("テーマnord"), "{shown}");

        // Too narrow for both: the theme stays, the language goes.
        let area = Rect::new(0, 0, 30, 4);
        let mut buf = Buffer::empty(area);
        render_footer(area, &mut buf, ["", ""], &theme::NORD, EN);
        let shown = text(&buf);
        assert!(shown.contains("nord"), "{shown}");
        assert!(!shown.contains("English"), "{shown}");
    }

    /// Every language's help is drawn as key caps: the footer still finds the
    /// keys once the descriptions are translated, and every one is shown.
    #[test]
    fn translated_help_keeps_its_key_caps() {
        let theme = &theme::NORD;
        for lang in Lang::ALL {
            let tr = lang.strings();
            let help = [tr.help_manage_user, tr.help_manage_nav];
            let area = Rect::new(0, 0, 120, footer_height(help, 120));
            let mut buf = Buffer::empty(area);
            render_footer(area, &mut buf, help, theme, tr);
            let (x, y) = find(&buf, " Esc ");
            assert_eq!(buf[(x + 1, y)].bg, theme.bar_bg, "{lang}");
            assert!(!text(&buf).contains("(Esc)"), "{lang}: {}", text(&buf));
        }
    }

    /// A tab is centred by the columns its label takes, so a CJK label fills
    /// the tab rather than spilling past it.
    #[test]
    fn tabs_centre_wide_labels_by_width() {
        assert_eq!(center("ユーザー", 12), "  ユーザー  ");
        assert_eq!(center("ab", 5).width(), 5);
        assert_eq!(center("ターゲットグループ", 17).width(), 17);
        assert_eq!(clip("ターゲット", 5), "ター");
    }

    /// A label wider than a tab widens every tab rather than being cut.
    #[test]
    fn tabs_widen_for_long_labels() {
        let labels = ["Utilisateurs", "Hiérarchie des rôles"];
        let area = Rect::new(0, 0, 80, 1);
        let mut buf = Buffer::empty(area);
        TabBar::default().render(area, &mut buf, &labels, 1, &theme::DEFAULT);
        let shown = text(&buf);
        assert!(shown.contains("Hiérarchie des rôles"), "{shown}");
        assert!(shown.contains("Utilisateurs"), "{shown}");
    }

    #[test]
    fn dialogs_speak_the_session_language() {
        let fr = Lang::Fr.strings();
        let area = Rect::new(0, 0, 60, 12);
        let mut buf = Buffer::empty(area);
        render_cancel_dialog(area, &mut buf, &theme::NORD, fr);
        find(&buf, fr.confirm_cancel);
        find(&buf, " Oui");
        find(&buf, " Y ");
    }

    fn object_group(name: &str) -> crate::database::models::ObjectGroup {
        crate::database::models::ObjectGroup {
            id: uuid::Uuid::nil(),
            name: name.into(),
            is_group: true,
        }
    }
}
