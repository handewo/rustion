use super::LOG_TYPE;
use crate::database::models::{CasbinRule, ObjectGroup};
use crate::database::Uuid;
use crate::error::Error;
use crate::server::casbin::GroupType;
use crate::server::widgets::tree;
use crate::server::widgets::{
    centered_area, common::*, render_confirm_dialog, render_message_popup,
    table_object_group_len_calculator, AdminTable, DisplayMode, Message,
};
use crate::server::HandlerLog;
use crossterm::event::{KeyCode, KeyModifiers};
use log::{error, info, warn};
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Rect},
    style::palette::tailwind,
    style::{Color, Modifier, Style},
    widgets::{Block, BorderType, Clear, Scrollbar, ScrollbarOrientation},
};
use std::sync::Arc;
use tokio::runtime::Handle;
use tui_tree_widget::{Tree, TreeItem, TreeState};

pub const HELP_TEXT: [&str; 2] = [
    "(←→) collapse/expand | (a) add | (d) delete",
    "(Tab) next tab | (Shift Tab) previous tab | (↑↓) move around | (PgUp/PgDn) page up/down",
];

pub const HELP_TABLE: [&str; 2] = [
    "(Space/Enter) select and save",
    "(↑↓) move around | (+/-) zoom in/out | (PgUp/PgDn) page up/down",
];

pub(super) struct CasbinGroupEditor<B>
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
    log: HandlerLog,
    pub is_editing: bool,
    pub is_deleting: bool,
    win_size: (u16, u16),
    message: Option<Message>,
    pub help_text: [&'static str; 2],
}

type BuildTreeResult = (
    TreeState<tree::Identifier>,
    Vec<TreeItem<'static, tree::Identifier>>,
    Vec<ObjectGroup>,
);

impl<B> CasbinGroupEditor<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    pub fn new(
        backend: Arc<B>,
        t_handle: Handle,
        handler_id: Uuid,
        admin_id: Uuid,
        group_type: GroupType,
        log: HandlerLog,
    ) -> Self {
        let mut message = None;
        let (state, items, selector_items) =
            match CasbinGroupEditor::build_tree(handler_id, &backend, &t_handle, group_type) {
                Ok(res) => res,
                Err(_) => {
                    message = Some(Message::Error(vec!["Internal error".into()]));
                    (TreeState::default(), Vec::new(), Vec::new())
                }
            };
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
            log,
            is_editing: false,
            is_deleting: false,
            win_size: (0, 0),
            message,
            help_text: HELP_TEXT,
        }
    }

    fn build_tree(
        handler_id: Uuid,
        backend: &Arc<B>,
        t_handle: &Handle,
        group_type: GroupType,
    ) -> Result<BuildTreeResult, Error>
    where
        B: 'static + crate::server::HandlerBackend + Send + Sync,
    {
        let graph = t_handle.block_on(backend.get_graph(group_type));
        let mut selector_items = match group_type {
            GroupType::Subject => {
                match t_handle.block_on(backend.db_repository().list_user_group()) {
                    Ok(i) => i,
                    Err(e) => {
                        error!("[{}] Failed to list 'user role': {}", handler_id, e);
                        return Err(e);
                    }
                }
            }
            GroupType::Object => {
                match t_handle.block_on(backend.db_repository().list_target_group()) {
                    Ok(i) => i,
                    Err(e) => {
                        error!("[{}] Failed to list 'target group': {}", handler_id, e);
                        return Err(e);
                    }
                }
            }
            GroupType::Action => {
                match t_handle.block_on(backend.db_repository().list_action_group()) {
                    Ok(i) => i,
                    Err(e) => {
                        error!("[{}] Failed to list 'action group': {}", handler_id, e);
                        return Err(e);
                    }
                }
            }
        };
        let mut items = match tree::build_tree(
            &graph,
            selector_items.iter().filter(|v| v.is_group).collect(),
        ) {
            Ok(i) => i,
            Err(e) => {
                error!("[{}] Failed to build tree: {}", handler_id, e);
                return Err(Error::IO(e));
            }
        };
        if group_type == GroupType::Subject {
            selector_items.retain(|i| i.is_group);
            let group_items = selector_items.iter().map(|v| v.id).collect::<Vec<_>>();
            items.retain(|item| group_items.contains(&item.identifier().rid));
        }
        let mut state = TreeState::default();
        for i in &items {
            state.open(vec![i.identifier().clone()]);
        }
        Ok((state, items, selector_items))
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

        let ctrl_pressed = modifiers.contains(KeyModifiers::CONTROL);

        if self.is_deleting {
            match key {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    self.do_delete();
                    self.is_deleting = false
                }
                KeyCode::Char('n') | KeyCode::Char('N') => self.is_deleting = false,
                _ => {
                    return false;
                }
            }
        }
        if self.is_editing {
            match key {
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.is_editing = false;
                    self.help_text = HELP_TEXT
                }
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
                    self.help_text = HELP_TEXT;

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
            KeyCode::Char('b') => {
                self.page_up();
            }
            KeyCode::Char('f') => {
                self.page_down();
            }
            KeyCode::PageDown => {
                self.page_down();
            }
            KeyCode::PageUp => {
                self.page_up();
            }
            KeyCode::Char('a') => {
                let iden = self.state.selected();
                if iden.is_empty() {
                    self.message = Some(Message::Error(vec![String::from(
                        "Please select one group.",
                    )]));
                    return false;
                }
                self.help_text = HELP_TABLE;
                self.is_editing = true;
            }
            KeyCode::Char('d') => {
                let iden = self.state.selected();
                match iden.len() {
                    0 => {
                        self.message = Some(Message::Error(vec![String::from(
                            "Please select one group.",
                        )]));
                        return false;
                    }
                    1 => {
                        let id = iden.first().unwrap().rid;
                        let g_name = self
                            .selector_items
                            .iter()
                            .find(|v| v.id == id)
                            .map(|v| v.name.clone())
                            .unwrap_or_else(|| {
                                warn!(
                                    "[{}] Couldn't find group name by ID: {}",
                                    self.handler_id, id
                                );
                                "Unknown".to_string()
                            });

                        self.message = Some(Message::Error(vec![format!(
                            "Please select one item in group: {}",
                            g_name
                        )]));
                        return false;
                    }
                    _ => self.is_deleting = true,
                }
            }
            _ => {}
        };
        false
    }

    fn page_down(&mut self) {
        let height: usize = (self.win_size.1 - 2) as usize;
        let viewable_len = self.state.flatten(&self.items).len();
        let next_offset = self.state.get_offset() + height;
        let scroll_len = if next_offset + height >= viewable_len {
            viewable_len.saturating_sub(next_offset)
        } else {
            height
        };
        self.state.select_relative(|current| {
            // When nothing is selected, fall back to start
            current.map_or(0, |current| current.saturating_add(scroll_len))
        });
        let _ = self.state.scroll_down(scroll_len);
    }

    fn page_up(&mut self) {
        let height: usize = (self.win_size.1 - 2) as usize;
        self.state.select_relative(|current| {
            // When nothing is selected, fall back to end
            current.map_or(usize::MAX, |current| current.saturating_sub(height))
        });
        let _ = self.state.scroll_up(height);
    }

    fn refreash_data(&mut self) {
        if let Err(e) = self.t_handle.block_on(self.backend.load_role_manager()) {
            error!("[{}] Load role manager error: {}", self.handler_id, e);
            self.message = Some(Message::Error(vec!["Internal error".into()]));
        }
        let (state, items, selector_items) = match CasbinGroupEditor::build_tree(
            self.handler_id,
            &self.backend,
            &self.t_handle,
            self.group_type,
        ) {
            Ok(res) => res,
            Err(_) => {
                self.message = Some(Message::Error(vec!["Internal error".into()]));
                (TreeState::default(), Vec::new(), Vec::new())
            }
        };

        self.state = state;
        self.items = items;
        self.selector_items = selector_items;
    }

    fn do_delete(&mut self) {
        let iden_list = self.state.selected();
        if iden_list.len() > 1 {
            let group_iden = self.state.selected().first().unwrap();
            let item_iden = self.state.selected().get(1).unwrap();
            match self
                .t_handle
                .block_on(self.backend.db_repository().delete_casbin_rule_by_v0_v1(
                    &self.group_type.to_string(),
                    &item_iden.rid,
                    &group_iden.rid,
                )) {
                Ok(res) => {
                    if res {
                        self.t_handle.block_on((self.log)(
                            LOG_TYPE.into(),
                            format!(
                                "Deleted {} '{}' from group '{}' (ptype={}, v0={}, v1={})",
                                self.group_type,
                                item_iden.rid,
                                group_iden.rid,
                                self.group_type,
                                item_iden.rid,
                                group_iden.rid
                            ),
                        ));
                        info!(
                            "[{}] Deleted casbin_rule successfully: ptype={}, v0={}, v1={}",
                            self.handler_id, self.group_type, item_iden.rid, group_iden.rid
                        );
                        self.message = Some(Message::Success(vec!["Deleted successfully".into()]));
                        self.refreash_data();
                    } else {
                        warn!(
                            "[{}] Delete casbin_rule not effect, ptype={}, v0={}, v1={}",
                            self.handler_id, self.group_type, item_iden.rid, group_iden.rid
                        );
                        self.message = Some(Message::Error(vec!["Internal error".into()]));
                    }
                }
                Err(e) => {
                    error!(
                        "[{}] Failed to delete casbin_rule, ptype={}, v0={}, v1={}, error: {}",
                        self.handler_id, self.group_type, item_iden.rid, group_iden.rid, e
                    );
                    self.message = Some(Message::Error(vec!["Internal error".into()]));
                }
            }
        }
    }

    fn insert_group(&mut self) {
        let idx = self.selector_table.state.selected().unwrap();
        let obj = self.selector_items.get(idx).unwrap();
        let iden = match self.state.selected().first() {
            Some(i) => i,
            None => {
                self.message = Some(Message::Error(vec!["Internal error".into()]));
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
        let cr = CasbinRule::new(
            self.group_type.to_string(),
            obj.id,
            iden.rid,
            Uuid::default(),
            String::new(),
            String::new(),
            String::new(),
            self.admin_id,
        );
        let t_type = if obj.is_group {
            String::from("Group")
        } else {
            match self.group_type {
                GroupType::Subject => String::from("User"),
                GroupType::Object => String::from("Target"),
                GroupType::Action => String::from("Action"),
            }
        };

        // Prevent cycle when adding group-to-group relationship
        if obj.is_group {
            if obj.id == iden.rid {
                self.message = Some(Message::Error(vec![
                    "Cannot add a group to itself".to_string()
                ]));
                return;
            }
            let graph = self
                .t_handle
                .block_on(self.backend.get_graph(self.group_type));
            // Find NodeIndex for both UUIDs
            let obj_node = graph
                .node_indices()
                .find(|&n| graph[n].fetch_role() == obj.id);
            let group_node = graph
                .node_indices()
                .find(|&n| graph[n].fetch_role() == iden.rid);
            // If both nodes exist in the graph, check if adding this edge creates a cycle.
            // A cycle occurs if iden.rid is already reachable from obj.id (since the new
            // edge goes iden.rid → obj.id).
            if let (Some(obj_idx), Some(group_idx)) = (obj_node, group_node) {
                use petgraph::visit::{Bfs, Walker};
                let has_cycle = Bfs::new(&graph, obj_idx)
                    .iter(&graph)
                    .any(|n| n == group_idx);
                if has_cycle {
                    warn!(
                        "[{}] Cycle detected: adding group '{}' to group '{}' would create a cycle",
                        self.handler_id, obj.name, g_name
                    );
                    self.message = Some(Message::Error(vec![format!(
                        "Cannot add {}: would create a cycle in group hierarchy",
                        obj.name
                    )]));
                    return;
                }
            }
        }

        match self
            .t_handle
            .block_on(self.backend.db_repository().create_casbin_rule(&cr))
        {
            Ok(_) => {
                self.t_handle.block_on((self.log)(
                    LOG_TYPE.into(),
                    format!(
                        "{} '{}' added to group '{}' (ptype={}, v0={}, v1={})",
                        t_type, obj.name, g_name, cr.ptype, cr.v0, cr.v1
                    ),
                ));
                info!(
                    "[{}] {} '{}' added to group '{}' (ptype={}, v0={}, v1={})",
                    self.handler_id, t_type, obj.name, g_name, cr.ptype, cr.v0, cr.v1
                );
                self.message = Some(Message::Success(vec![format!(
                    "{}: {} added in {}",
                    t_type, obj.name, g_name
                )]));
                self.refreash_data();
            }
            Err(ref err) => {
                let msg = match err {
                    Error::Sqlx(sqlx::Error::Database(ref db_err))
                        if db_err.kind() == sqlx::error::ErrorKind::UniqueViolation =>
                    {
                        warn!(
                            "[{}] Duplicate entry: {} '{}' already exists in group '{}'",
                            self.handler_id, t_type, obj.name, g_name
                        );
                        format!("{}: {} has already existed in {}", t_type, obj.name, g_name)
                    }
                    _ => {
                        error!(
                            "[{}] Failed to add {} '{}' to group '{}': {}",
                            self.handler_id, t_type, obj.name, g_name, err
                        );
                        "Internal error".to_string()
                    }
                };
                self.message = Some(Message::Error(vec![msg]));
            }
        };
    }

    pub fn draw(&mut self, area: Rect, buf: &mut Buffer) {
        {
            let mut block = Block::bordered()
                .border_type(BorderType::Double)
                .border_style(Style::new().fg(self.editor_colors.border_color));
            if self.is_editing || self.is_deleting || self.message.is_some() {
                block = block.border_style(Style::default());
            }

            use ratatui::widgets::Widget;
            block.render(area, buf);
        }
        let inner_area = centered_area(area, area.width - 2, area.height - 2);
        self.win_size = (inner_area.width, inner_area.height);
        let mut widget = Tree::new(&self.items)
            .expect("all item identifiers must be unique")
            .experimental_scrollbar(Some(Scrollbar::new(ScrollbarOrientation::VerticalRight)))
            .highlight_style(
                Style::new()
                    .add_modifier(Modifier::REVERSED)
                    .fg(self.editor_colors.border_color),
            );

        if self.is_editing || self.is_deleting || self.message.is_some() {
            widget = widget.highlight_style(
                Style::new()
                    .add_modifier(Modifier::REVERSED)
                    .fg(tailwind::GRAY.c400),
            );
        }
        use ratatui::widgets::StatefulWidget;
        widget.render(inner_area, buf, &mut self.state);

        let popup_area = if area.width <= MAX_POPUP_WINDOW_COL {
            area
        } else {
            centered_area(
                area,
                MAX_POPUP_WINDOW_COL,
                area.height.min(MAX_POPUP_WINDOW_ROW),
            )
        };

        if self.is_editing {
            self.draw_popup(popup_area, buf);
        }
        if self.is_deleting {
            self.draw_delete(popup_area, buf);
        }
        if let Some(ref msg) = self.message {
            render_message_popup(popup_area, buf, msg);
        }
    }

    fn draw_delete(&mut self, area: Rect, buf: &mut Buffer) {
        let iden_list = self.state.selected();
        if iden_list.len() > 1 {
            let group_iden = self.state.selected().first().unwrap();
            let item_iden = self.state.selected().get(1).unwrap();
            let mut g_name = String::from("Unknown");
            let mut i_name = g_name.clone();
            for i in self.selector_items.iter() {
                if i.id == group_iden.rid {
                    g_name = i.name.clone();
                }
                if i.id == item_iden.rid {
                    i_name = i.name.clone();
                }
            }
            render_confirm_dialog(
                area,
                buf,
                &[format!("Delete {} in group: {}?", i_name, g_name)],
            );
        }
    }
    fn draw_popup(&mut self, area: Rect, buf: &mut Buffer) {
        let iden = match self.state.selected().first() {
            Some(i) => i,
            None => {
                self.message = Some(Message::Error(vec!["Internal error".into()]));
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
        let title = format!("Add to Group: {}", g_name);
        let popup = Block::bordered()
            .title(title)
            .title_style(Style::new().fg(self.editor_colors.title_color))
            .border_style(Style::new().fg(self.editor_colors.border_color))
            .border_type(BorderType::Double);
        use ratatui::widgets::Widget;
        Clear.render(area, buf);
        popup.render(area, buf);

        let table_area = centered_area(area, area.width - 2, area.height - 2);
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
}

impl EditorColors {
    const fn new(color: &tailwind::Palette) -> Self {
        Self {
            border_color: color.c400,
            title_color: tailwind::SLATE.c200,
        }
    }
}
