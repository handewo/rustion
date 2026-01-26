use super::super::table::{AdminTable, DisplayMode, FieldsToArray, TableData};
use super::super::tree;
use crate::database::models::{SecretInfo, TargetInfo};
use crate::error::Error;
use crate::server::casbin::RoleType;
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::palette::tailwind,
    style::{Color, Modifier, Style},
    text::Text,
    widgets::{Block, BorderType, StatefulWidget},
};
use std::sync::Arc;
use tokio::runtime::Handle;
use tui_tree_widget::{Tree, TreeItem, TreeState};
use unicode_width::UnicodeWidthStr;

pub const HELP_TEXT: [&str; 2] = [
    "(Space) toggle | (←→) switch window | (↑↓) select item",
    "(Tab) next tab | (Shift Tab) previous tab | (+/-) zoom in/out | (PgUp/PgDn) page up/down",
];

pub(super) struct RoleEditor<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    state: TreeState<tree::Identifier>,
    items: Vec<TreeItem<'static, tree::Identifier>>,
    editor_colors: EditorColors,
    role_selector: Option<AdminTable>,
    backend: Arc<B>,
    t_handle: Handle,
    handler_id: String,
    user_id: String,
    save_error: Option<Error>,
    pub help_text: [&'static str; 2],
}

impl<B> RoleEditor<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    pub fn new(backend: Arc<B>, t_handle: Handle, handler_id: String, user_id: String) -> Self {
        let graph = t_handle.block_on(backend.get_role_graph(RoleType::Subject));
        // TODO: handle error
        let items = tree::build_tree(&graph).unwrap();
        let mut state = TreeState::default();
        for i in &items {
            state.open(vec![i.identifier().clone()]);
            for k in i.children() {
                state.open(vec![i.identifier().clone(), k.identifier().clone()]);
            }
        }
        Self {
            state,
            items,
            editor_colors: EditorColors::new(&tailwind::BLUE),
            role_selector: None,
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

        let ctrl_pressed = modifiers.contains(KeyModifiers::CONTROL);

        match key {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Tab | KeyCode::BackTab => return true,
            KeyCode::Left | KeyCode::Char('h') => {
                let _ = self.state.key_left();
            }
            KeyCode::Right | KeyCode::Char('l') => {
                let _ = self.state.key_right();
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let _ = self.state.key_down();
            }
            KeyCode::Up | KeyCode::Char('k') => {
                let _ = self.state.key_up();
            }
            KeyCode::Home => {
                let _ = self.state.select_first();
            }
            KeyCode::End => {
                let _ = self.state.select_last();
            }
            KeyCode::PageDown => {
                let _ = self.state.scroll_down(3);
            }
            KeyCode::PageUp => {
                let _ = self.state.scroll_up(3);
            }
            KeyCode::Char('a') => self.create_selector(),
            _ => {}
        };
        false
    }

    fn create_selector(&mut self) {}

    pub fn draw(&mut self, area: Rect, buf: &mut Buffer) {
        let widget = Tree::new(&self.items)
            .expect("all item identifiers are unique")
            .block(
                Block::bordered()
                    .border_type(BorderType::Double)
                    .border_style(Style::new().fg(self.editor_colors.border_color)),
            )
            .highlight_style(
                Style::new()
                    .add_modifier(Modifier::REVERSED)
                    .fg(self.editor_colors.border_color),
            );
        widget.render(area, buf, &mut self.state);
    }
}

struct EditorColors {
    border_color: Color,
    focus: Color,
}

impl EditorColors {
    const fn new(color: &tailwind::Palette) -> Self {
        Self {
            border_color: color.c400,
            focus: tailwind::SLATE.c200,
        }
    }
}
