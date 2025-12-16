use crossterm::event::KeyCode;
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::Widget,
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

    pub fn get_input(&self) -> Option<String> {
        let line = self.textarea.lines().iter().next();
        line.map(|v| v.trim().to_string())
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

    pub fn handle_input(&mut self, key: KeyCode) -> bool {
        match key {
            KeyCode::Esc | KeyCode::Char('q') if !self.editing_mode => return true,
            KeyCode::Esc => {
                self.textarea.set_cursor_style(Style::default());
                self.highlight();
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
