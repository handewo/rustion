use super::super::table::{AdminTable, DisplayMode, FieldsToArray, TableData};
use crate::database::models::{SecretInfo, TargetInfo};
use crate::error::Error;
use crate::server::app::admin::widgets::*;
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::palette::tailwind,
    style::{Color, Style},
    widgets::{Block, BorderType, Widget},
};
use std::sync::Arc;
use tokio::runtime::Handle;
use unicode_width::UnicodeWidthStr;

pub const HELP_TEXT: [&str; 2] = [
    "(Space) toggle | (←→) switch window | (↑↓) select item",
    "(Tab) next tab | (Shift Tab) previous tab | (+/-) zoom in/out | (PgUp/PgDn) page up/down",
];

#[derive(Debug, Clone, Copy, PartialEq)]
enum FocusedTable {
    Left,  // Targets
    Right, // Secrets
}

impl FocusedTable {
    fn next(&self) -> Self {
        match self {
            Self::Left => Self::Right,
            Self::Right => Self::Left,
        }
    }
}

pub(super) struct BindEditor<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    targets: Vec<TargetInfo>,
    secrets: Vec<SecretInfo>,
    longest_target_lens: Vec<Constraint>,
    longest_secret_lens: Vec<Constraint>,
    target_table: AdminTable,
    secret_table: AdminTable,
    focused_table: FocusedTable,
    editor_colors: EditorColors,
    backend: Arc<B>,
    t_handle: Handle,
    handler_id: String,
    user_id: String,
    save_error: Option<Error>,
    pub help_text: [&'static str; 2],
}

impl<B> BindEditor<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    pub fn new(
        targets: Vec<TargetInfo>,
        secrets: Vec<SecretInfo>,
        backend: Arc<B>,
        t_handle: Handle,
        handler_id: String,
        user_id: String,
    ) -> Self {
        Self {
            targets: targets.clone(),
            secrets: secrets.clone(),
            longest_target_lens: target_len_calculator(&targets),
            longest_secret_lens: secret_len_calculator(&secrets),
            target_table: AdminTable::new(&targets, &tailwind::BLUE),
            secret_table: AdminTable::new(&secrets, &tailwind::BLUE),
            focused_table: FocusedTable::Left,
            editor_colors: EditorColors::new(&tailwind::BLUE),
            backend,
            t_handle,
            handler_id,
            user_id,
            save_error: None,
            help_text: HELP_TEXT,
        }
    }

    pub fn handle_key_event(&mut self, key: KeyCode, modifiers: KeyModifiers) -> bool {
        if self.save_error.is_some() {
            if key == KeyCode::Enter {
                self.save_error = None;
            }
            return false;
        }

        // Store current state to avoid borrowing issues
        let focused_table = self.focused_table;

        let (table, items_len) = match focused_table {
            FocusedTable::Left => (&mut self.target_table, self.targets.len()),
            FocusedTable::Right => (&mut self.secret_table, self.secrets.len()),
        };

        let ctrl_pressed = modifiers.contains(KeyModifiers::CONTROL);

        match key {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Tab | KeyCode::BackTab => return true,
            KeyCode::Char('+') => {
                self.target_table.zoom_in();
                self.secret_table.zoom_in();
            }
            KeyCode::Char('-') => {
                self.target_table.zoom_out();
                self.secret_table.zoom_out();
            }
            KeyCode::PageDown => {
                table.next_page(items_len);
                if self.focused_table == FocusedTable::Left {
                    self.refresh_secrets();
                }
            }
            KeyCode::PageUp => {
                table.previous_page();
                if self.focused_table == FocusedTable::Left {
                    self.refresh_secrets();
                }
            }
            KeyCode::Char('f') if ctrl_pressed => {
                table.next_page(items_len);
                if self.focused_table == FocusedTable::Left {
                    self.refresh_secrets();
                }
            }
            KeyCode::Char('b') if ctrl_pressed => {
                table.previous_page();
                if self.focused_table == FocusedTable::Left {
                    self.refresh_secrets();
                }
            }
            KeyCode::Right | KeyCode::Char('l') => {
                self.focused_table = self.focused_table.next();
            }
            KeyCode::Left | KeyCode::Char('h') => {
                self.focused_table = self.focused_table.next();
            }
            KeyCode::Down | KeyCode::Char('j') => {
                table.next_row(items_len);
                if self.focused_table == FocusedTable::Left {
                    self.refresh_secrets();
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                table.previous_row(items_len);
                if self.focused_table == FocusedTable::Left {
                    self.refresh_secrets();
                }
            }
            KeyCode::Char(' ') | KeyCode::Enter => {
                if let Err(e) = self.save_bindings() {
                    self.save_error = Some(e);
                }
                self.refresh_secrets();
            }
            _ => {}
        }

        false
    }

    fn save_bindings(&mut self) -> Result<(), Error> {
        let t_idx = self.target_table.state.selected().unwrap();
        let s_idx = self.secret_table.state.selected().unwrap();
        let t = self.targets.get(t_idx).unwrap();
        let s = self.secrets.get(s_idx).unwrap();

        self.t_handle
            .block_on(self.backend.db_repository().upsert_target_secret(
                &t.id,
                &s.id,
                !s.is_bound,
                &self.user_id,
            ))
    }

    fn refresh_secrets(&mut self) {
        let idx = self.target_table.state.selected().unwrap();
        if let Some(t) = self.targets.get(idx).as_ref() {
            let result = self
                .t_handle
                .block_on(self.backend.db_repository().list_secrets_for_target(&t.id));
            match result {
                Ok(res) => self.secrets = res,
                Err(e) => self.save_error = Some(e),
            }
        }
    }

    fn render_ui(&mut self, area: Rect, buf: &mut Buffer) {
        // Create main layout with two columns
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(50), // Left table (Targets)
                Constraint::Percentage(50), // Right table (Secrets)
            ])
            .split(area);

        let mut target_border = Block::bordered()
            .title("targets")
            .border_type(BorderType::Double);

        let mut secret_border = Block::bordered()
            .title("secrets")
            .border_type(BorderType::Double);

        match self.focused_table {
            FocusedTable::Left => {
                target_border = target_border
                    .title_style(Style::new().fg(self.editor_colors.title_color))
                    .border_style(Style::new().fg(self.editor_colors.border_color))
            }
            FocusedTable::Right => {
                secret_border = secret_border
                    .title_style(Style::new().fg(self.editor_colors.title_color))
                    .border_style(Style::new().fg(self.editor_colors.border_color))
            }
        };

        target_border.render(chunks[0], buf);
        secret_border.render(chunks[1], buf);

        let left_table = centered_area(chunks[0], chunks[0].width - 2, chunks[0].height - 2);
        let right_table = centered_area(chunks[1], chunks[1].width - 2, chunks[1].height - 2);

        self.target_table.size = (left_table.width, left_table.height);
        self.secret_table.size = (right_table.width, right_table.height);

        // Render left table (Targets)
        self.target_table.render(
            buf,
            left_table,
            &self.targets,
            &self.longest_target_lens,
            DisplayMode::Manage,
        );
        // Render right table (Secrets)
        self.secret_table.render(
            buf,
            right_table,
            &self.secrets,
            &self.longest_secret_lens,
            DisplayMode::Manage,
        );

        if self.save_error.is_some() {
            render_message_popup(area, buf, &Message::Error(vec!["Internal error".into()]));
        }
    }
}

impl<B> Widget for &mut BindEditor<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    fn render(self, area: Rect, buf: &mut Buffer) {
        self.render_ui(area, buf);
    }
}

impl TableData for Vec<TargetInfo> {
    fn header(&self) -> Vec<&str> {
        vec!["name", "hostname", "port"]
    }

    fn as_vec(&self) -> Vec<&dyn FieldsToArray> {
        self.iter()
            .map(|v| v as &dyn FieldsToArray)
            .collect::<Vec<_>>()
    }

    fn len(&self) -> usize {
        self.len()
    }
}

impl FieldsToArray for TargetInfo {
    fn to_array(&self, mode: DisplayMode) -> Vec<String> {
        match mode {
            DisplayMode::Full => {
                todo!()
            }
            DisplayMode::Manage => {
                vec![
                    self.name.clone(),
                    self.hostname.clone(),
                    self.port.to_string(),
                ]
            }
        }
    }
}

impl TableData for Vec<SecretInfo> {
    fn header(&self) -> Vec<&str> {
        vec!["", "name", "user"]
    }

    fn as_vec(&self) -> Vec<&dyn FieldsToArray> {
        self.iter()
            .map(|v| v as &dyn FieldsToArray)
            .collect::<Vec<_>>()
    }

    fn len(&self) -> usize {
        self.len()
    }
}

impl FieldsToArray for SecretInfo {
    fn to_array(&self, mode: DisplayMode) -> Vec<String> {
        match mode {
            DisplayMode::Full => {
                todo!()
            }
            DisplayMode::Manage => {
                vec![
                    if self.is_bound {
                        "[X]".to_string()
                    } else {
                        "[ ]".to_string()
                    },
                    self.name.clone(),
                    self.user.clone(),
                ]
            }
        }
    }
}

fn target_len_calculator(data: &[TargetInfo]) -> Vec<Constraint> {
    let name_len = data
        .iter()
        .map(|v| v.name.as_str())
        .map(UnicodeWidthStr::width)
        .max()
        .unwrap_or(0)
        .max(4);

    let hostname_len = data
        .iter()
        .map(|v| v.hostname.len())
        .max()
        .unwrap_or(0)
        .max(8);

    vec![
        Constraint::Length(name_len as u16),
        Constraint::Length(hostname_len as u16),
        Constraint::Length(5),
    ]
}

fn secret_len_calculator(data: &[SecretInfo]) -> Vec<Constraint> {
    let name_len = data
        .iter()
        .map(|v| v.name.as_str())
        .map(UnicodeWidthStr::width)
        .max()
        .unwrap_or(0)
        .max(4);

    let user_len = data
        .iter()
        .map(|v| v.user.as_str())
        .map(UnicodeWidthStr::width)
        .max()
        .unwrap_or(0)
        .max(4);

    vec![
        Constraint::Length(4),
        Constraint::Length(name_len as u16),
        Constraint::Length(user_len as u16),
    ]
}

struct EditorColors {
    border_color: Color,
    title_color: Color,
}

impl EditorColors {
    const fn new(color: &tailwind::Palette) -> Self {
        Self {
            border_color: color.c400,
            title_color: tailwind::SLATE.c200,
        }
    }
}
