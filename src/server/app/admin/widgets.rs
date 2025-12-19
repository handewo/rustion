use crossterm::event::KeyCode;
use ratatui::{
    buffer::Buffer,
    layout::{Alignment, Constraint, Flex, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Widget},
};
use tui_textarea::{CursorMove, Input, Key, TextArea};

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
        self.textarea
            .set_cursor_line_style(Style::default().bg(self.cursor_color));
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
    Info(Vec<String>),
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

pub fn render_message_dialog(area: Rect, buf: &mut Buffer, message: &Message) {
    let height = message.len() as u16 + 5;
    let dialog_area = centered_area(area, area.width, height);

    use Message::*;
    let (title, color) = match message {
        Info(_) => ("Info", Color::default()),
        Warning(_) => ("Warning", Color::Yellow),
        Error(_) => ("Error", Color::Red),
        Success(_) => ("Success", Color::Green),
    };

    // Clear the area
    Clear.render(dialog_area, buf);

    // Render dialog
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(color));

    let mut text = message
        .lines()
        .iter()
        .map(|v| Line::from(v.as_str()))
        .collect::<Vec<Line>>();
    text.insert(0, Line::from(""));
    text.push(Line::from(""));
    text.push(Line::from(vec![Span::styled(
        " <OK> ",
        Style::default().bg(color),
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

pub fn render_cancel_dialog(area: Rect, buf: &mut Buffer) {
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
