use super::super::table::{table_object_group_len_calculator, AdminTable, DisplayMode};
use super::super::{common::*, tree, widgets};
use crate::database::models::{CasbinRule, ObjectGroup};
use crate::database::Uuid;
use crate::error::Error;
use crate::server::casbin::GroupType;
use crossterm::event::{KeyCode, KeyModifiers};
use log::{error, info, warn};
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Rect},
    style::palette::tailwind,
    style::{Color, Modifier, Style},
    widgets::{Block, BorderType, Clear},
};
use std::sync::Arc;
use tokio::runtime::Handle;
use tui_tree_widget::{Tree, TreeItem, TreeState};

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
    group_type: GroupType,
    selector_items: Vec<ObjectGroup>,
    selector_table: AdminTable,
    longest_item_lens: Vec<Constraint>,
    backend: Arc<B>,
    t_handle: Handle,
    handler_id: Uuid,
    admin_id: Uuid,
    is_editing: bool,
    message: Option<widgets::Message>,
    save_error: Option<Error>,
    pub help_text: [&'static str; 2],
}

impl<B> RoleEditor<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    pub fn new(
        backend: Arc<B>,
        t_handle: Handle,
        handler_id: Uuid,
        admin_id: Uuid,
        group_type: GroupType,
    ) -> Self {
        let graph = t_handle.block_on(backend.get_graph(group_type));
        let selector_items = match group_type {
            GroupType::Subject => {
                match t_handle.block_on(backend.db_repository().list_user_group()) {
                    Ok(i) => i,
                    Err(e) => {
                        // TODO: handle error
                        error!("[{}] Failed to list 'target group': {}", handler_id, e);
                        Vec::new()
                    }
                }
            }
            GroupType::Object => {
                match t_handle.block_on(backend.db_repository().list_target_group()) {
                    Ok(i) => i,
                    Err(e) => {
                        // TODO: handle error
                        error!("[{}] Failed to list 'target group': {}", handler_id, e);
                        Vec::new()
                    }
                }
            }
            GroupType::Action => {
                match t_handle.block_on(backend.db_repository().list_action_group()) {
                    Ok(i) => i,
                    Err(e) => {
                        // TODO: handle error
                        error!("[{}] Failed to list 'target group': {}", handler_id, e);
                        Vec::new()
                    }
                }
            }
        };
        let items = match tree::build_tree(
            &graph,
            selector_items.iter().filter(|v| v.is_group).collect(),
        ) {
            Ok(i) => i,
            Err(e) => {
                // TODO: handle error
                error!("[{}] Failed to build tree: {}", handler_id, e);
                Vec::new()
            }
        };
        let mut state = TreeState::default();
        for i in &items {
            state.open(vec![i.identifier().clone()]);
        }

        let longest_item_lens = table_object_group_len_calculator(&selector_items);
        Self {
            state,
            items,
            group_type,
            editor_colors: EditorColors::new(&tailwind::BLUE),
            selector_table: AdminTable::new(&selector_items, &tailwind::BLUE),
            selector_items,
            longest_item_lens,
            backend,
            t_handle,
            handler_id,
            admin_id,
            is_editing: false,
            message: None,
            save_error: None,
            help_text: HELP_TEXT,
        }
    }

    pub fn handle_key_event(&mut self, key: KeyCode, modifiers: KeyModifiers) -> bool {
        if self.message.is_some() {
            match key {
                KeyCode::Enter => {
                    self.message = None;
                }
                _ => return false,
            }
            return false;
        }
        if self.save_error.is_some() {
            if key == KeyCode::Enter {
                self.save_error = None;
            }
            return false;
        }

        let ctrl_pressed = modifiers.contains(KeyModifiers::CONTROL);

        if self.is_editing {
            match key {
                KeyCode::Esc | KeyCode::Char('q') => self.is_editing = false,
                KeyCode::Char('+') => {
                    self.selector_table.zoom_in();
                }
                KeyCode::Char('-') => {
                    self.selector_table.zoom_out();
                }
                KeyCode::PageDown => {
                    self.selector_table.next_page(self.selector_items.len());
                }
                KeyCode::PageUp => {
                    self.selector_table.previous_page();
                }
                KeyCode::Char('f') if ctrl_pressed => {
                    self.selector_table.next_page(self.selector_items.len());
                }
                KeyCode::Char('b') if ctrl_pressed => {
                    self.selector_table.previous_page();
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.selector_table.next_row(self.selector_items.len());
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.selector_table.previous_row(self.selector_items.len());
                }
                KeyCode::Char(' ') | KeyCode::Enter => {
                    self.is_editing = false;

                    self.insert_group()
                }
                _ => {}
            }
            return false;
        }
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
            KeyCode::Char('a') => {
                let iden = self.state.selected();
                if iden.is_empty() {
                    self.message = Some(widgets::Message::Error(vec![String::from(
                        "Please select one group.",
                    )]));
                    return false;
                }
                self.is_editing = true;
                info!("{:?}", iden);
            }
            KeyCode::Char('d') => {
                let iden = self.state.selected();
                if iden.is_empty() {
                    self.message = Some(widgets::Message::Error(vec![String::from(
                        "Please select one group.",
                    )]));
                    return false;
                }
            }
            _ => {}
        };
        false
    }

    fn insert_group(&mut self) {
        let idx = self.selector_table.state.selected().unwrap();
        let obj = self.selector_items.get(idx).unwrap();
        let iden = match self.state.selected().first() {
            Some(i) => i,
            None => {
                self.message = Some(widgets::Message::Error(vec!["Internal error".into()]));
                return;
            }
        };
        let g_name = self
            .selector_items
            .iter()
            .find(|v| v.id == iden.rid)
            .map(|v| v.name.clone())
            .unwrap_or_else(|| {
                warn!(
                    "[{}] Couldn't find group name by ID: {}",
                    self.handler_id, iden.rid
                );
                "Unknown".to_string()
            });
        match self.group_type {
            GroupType::Subject => {}
            GroupType::Object => {
                let cr = CasbinRule::new(
                    "g2".into(),
                    obj.id,
                    iden.rid,
                    None,
                    String::new(),
                    String::new(),
                    String::new(),
                    self.admin_id,
                );
                let t_type = if obj.is_group {
                    String::from("Group")
                } else {
                    String::from("Target")
                };

                //TODO: Prevent cycle when add group
                match self
                    .t_handle
                    .block_on(self.backend.db_repository().create_casbin_rule(&cr))
                {
                    Ok(_) => {
                        self.message = Some(widgets::Message::Success(vec![format!(
                            "{}: {} added in {}",
                            t_type, obj.name, g_name
                        )]));
                    }
                    Err(ref err) => {
                        let msg = match err {
                            Error::Sqlx(sqlx::Error::Database(ref db_err))
                                if db_err.kind() == sqlx::error::ErrorKind::UniqueViolation =>
                            {
                                format!(
                                    "{}: {} has already existed in {}",
                                    t_type, obj.name, g_name
                                )
                            }
                            _ => "Internal error".to_string(),
                        };
                        self.message = Some(widgets::Message::Error(vec![msg]));
                    }
                };
            }
            GroupType::Action => {}
        }
    }

    pub fn draw(&mut self, area: Rect, buf: &mut Buffer) {
        let widget = Tree::new(&self.items)
            .expect("all item identifiers must be unique")
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
        use ratatui::widgets::StatefulWidget;
        widget.render(area, buf, &mut self.state);

        let popup_area = if area.width <= MAX_POPUP_WINDOW_COL {
            area
        } else {
            widgets::centered_area(
                area,
                MAX_POPUP_WINDOW_COL,
                area.height.min(MAX_POPUP_WINDOW_ROW),
            )
        };

        if self.is_editing {
            self.draw_popup(popup_area, buf);
        }
        if let Some(ref msg) = self.message {
            widgets::render_message_popup(popup_area, buf, msg);
        }
    }

    fn draw_popup(&mut self, area: Rect, buf: &mut Buffer) {
        let iden = match self.state.selected().first() {
            Some(i) => i,
            None => {
                self.message = Some(widgets::Message::Error(vec!["Internal error".into()]));
                return;
            }
        };
        let g_name = self
            .selector_items
            .iter()
            .find(|v| v.id == iden.rid)
            .map(|v| v.name.clone())
            .unwrap_or_else(|| {
                warn!(
                    "[{}] Couldn't find group name by ID: {}",
                    self.handler_id, iden.rid
                );
                "Unknown".to_string()
            });
        let title = format!("Add in Group: {}", g_name);
        let popup = Block::bordered()
            .title(title)
            .title_style(Style::new().fg(self.editor_colors.title_color))
            .border_style(Style::new().fg(self.editor_colors.border_color))
            .border_type(BorderType::Double);
        use ratatui::widgets::Widget;
        Clear.render(area, buf);
        popup.render(area, buf);

        let table_area = widgets::centered_area(area, area.width - 2, area.height - 2);
        self.selector_table.size = (table_area.width, table_area.height);
        self.selector_table.render(
            buf,
            table_area,
            &self.selector_items,
            &self.longest_item_lens,
            DisplayMode::Manage,
        );
    }
}

struct EditorColors {
    title_color: Color,
    border_color: Color,
    focus: Color,
}

impl EditorColors {
    const fn new(color: &tailwind::Palette) -> Self {
        Self {
            border_color: color.c400,
            focus: tailwind::SLATE.c200,
            title_color: tailwind::SLATE.c200,
        }
    }
}
