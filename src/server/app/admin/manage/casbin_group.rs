use crate::database::Uuid;
use crate::database::entity::casbin_rule;
use crate::database::models::{GroupType, ObjectGroup};
use crate::error::Error;
use crate::fill;
use crate::server::event_log::{Audit, EventLogger, MemberKind, labelled};
use crate::server::widgets::tree;
use crate::server::widgets::{
    AdminTable, DisplayMode, Help, Message, Strings, Theme, centered_area, common::*, popup_block,
    render_confirm_dialog, render_message_popup, table_object_group_len_calculator,
};
use crossterm::event::{KeyCode, KeyModifiers};
use log::{error, info, warn};
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Rect},
    style::{Modifier, Style},
    widgets::{Block, BorderType, Scrollbar, ScrollbarOrientation},
};
use sea_orm::ActiveValue::Set;
use std::sync::Arc;
use tui_tree_widget::{Tree, TreeItem, TreeState};

pub const HELP_TEXT: Help = |tr| [tr.help_group, tr.help_group_nav];

pub const HELP_TABLE: Help = |tr| [tr.help_group_pick, tr.help_pick_nav];

pub(super) struct CasbinGroupEditor<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    state: TreeState<tree::Identifier>,
    items: Vec<TreeItem<'static, tree::Identifier>>,
    group_type: GroupType,
    selector_items: Vec<ObjectGroup>,
    selector_table: AdminTable,
    longest_item_lens: Vec<Constraint>,
    backend: Arc<B>,
    handler_id: Uuid,
    admin_id: Uuid,
    log: EventLogger<B>,
    pub is_editing: bool,
    pub is_deleting: bool,
    win_size: (u16, u16),
    message: Option<Message>,
    tr: &'static Strings,
    pub help_text: Help,
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
    pub async fn new(
        backend: Arc<B>,
        handler_id: Uuid,
        admin_id: Uuid,
        group_type: GroupType,
        log: EventLogger<B>,
        tr: &'static Strings,
    ) -> Self {
        let mut message = None;
        let (state, items, selector_items) =
            match CasbinGroupEditor::build_tree(handler_id, &backend, group_type, tr).await {
                Ok(res) => res,
                Err(_) => {
                    message = Some(Message::Error(vec![tr.internal_error.into()]));
                    (TreeState::default(), Vec::new(), Vec::new())
                }
            };
        let longest_item_lens = table_object_group_len_calculator(&selector_items);
        Self {
            state,
            items,
            group_type,
            selector_table: AdminTable::new(&selector_items),
            selector_items,
            longest_item_lens,
            backend,
            handler_id,
            admin_id,
            log,
            is_editing: false,
            is_deleting: false,
            win_size: (0, 0),
            message,
            tr,
            help_text: HELP_TEXT,
        }
    }

    async fn build_tree(
        handler_id: Uuid,
        backend: &Arc<B>,
        group_type: GroupType,
        tr: &Strings,
    ) -> Result<BuildTreeResult, Error>
    where
        B: 'static + crate::server::HandlerBackend + Send + Sync,
    {
        let graph = backend.get_graph(group_type).await;
        let mut selector_items = match group_type {
            GroupType::Subject => match backend.db_repository().list_user_group().await {
                Ok(i) => i,
                Err(e) => {
                    error!("[{}] Failed to list 'user role': {}", handler_id, e);
                    return Err(e);
                }
            },
            GroupType::Object => match backend.db_repository().list_target_group().await {
                Ok(i) => i,
                Err(e) => {
                    error!("[{}] Failed to list 'target group': {}", handler_id, e);
                    return Err(e);
                }
            },
            GroupType::Action => match backend.db_repository().list_action_group().await {
                Ok(i) => i,
                Err(e) => {
                    error!("[{}] Failed to list 'action group': {}", handler_id, e);
                    return Err(e);
                }
            },
        };
        let mut items = match tree::build_tree(
            &graph,
            selector_items.iter().filter(|v| v.is_group).collect(),
            tr,
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

    pub async fn handle_key_event(&mut self, key: KeyCode, modifiers: KeyModifiers) -> bool {
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
                    self.do_delete().await;
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

                    self.insert_group().await
                }
                _ => {}
            }
            return false;
        }
        match key {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Tab | KeyCode::BackTab => return true,
            KeyCode::Char('c') if ctrl_pressed => return true,
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
                    self.message = Some(Message::Error(vec![self.tr.select_one_group.into()]));
                    return false;
                }
                self.help_text = HELP_TABLE;
                self.is_editing = true;
            }
            KeyCode::Char('d') if !ctrl_pressed => {
                let iden = self.state.selected();
                match iden.len() {
                    0 => {
                        self.message = Some(Message::Error(vec![self.tr.select_one_group.into()]));
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
                                self.tr.unknown.to_string()
                            });

                        self.message = Some(Message::Error(vec![fill!(
                            self.tr.select_item_in_group,
                            group = g_name
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

    async fn refreash_data(&mut self) {
        if let Err(e) = self.backend.load_role_manager().await {
            error!("[{}] Load role manager error: {}", self.handler_id, e);
            self.message = Some(Message::Error(vec![self.tr.internal_error.into()]));
        }
        let (state, items, selector_items) = match CasbinGroupEditor::build_tree(
            self.handler_id,
            &self.backend,
            self.group_type,
            self.tr,
        )
        .await
        {
            Ok(res) => res,
            Err(_) => {
                self.message = Some(Message::Error(vec![self.tr.internal_error.into()]));
                (TreeState::default(), Vec::new(), Vec::new())
            }
        };

        self.state = state;
        self.items = items;
        self.selector_items = selector_items;
    }

    async fn do_delete(&mut self) {
        let iden_list = self.state.selected();
        if iden_list.len() > 1 {
            let group_iden = self.state.selected().first().unwrap();
            let item_iden = self.state.selected().get(1).unwrap();
            match self
                .backend
                .db_repository()
                .delete_casbin_rule_by_group(self.group_type, item_iden.rid, group_iden.rid)
                .await
            {
                Ok(res) => {
                    if res {
                        let (kind, member, group) =
                            self.member_labels(item_iden.rid, group_iden.rid);
                        self.log
                            .record(Audit::MemberRemoved {
                                kind,
                                member,
                                group,
                            })
                            .await;
                        info!(
                            "[{}] Deleted casbin_rule successfully: ptype={}, v0={}, v1={}",
                            self.handler_id, self.group_type, item_iden.rid, group_iden.rid
                        );
                        self.message = Some(Message::Success(vec![self.tr.deleted.into()]));
                        self.refreash_data().await;
                    } else {
                        warn!(
                            "[{}] Delete casbin_rule not effect, ptype={}, v0={}, v1={}",
                            self.handler_id, self.group_type, item_iden.rid, group_iden.rid
                        );
                        self.message = Some(Message::Error(vec![self.tr.internal_error.into()]));
                    }
                }
                Err(e) => {
                    error!(
                        "[{}] Failed to delete casbin_rule, ptype={}, v0={}, v1={}, error: {}",
                        self.handler_id, self.group_type, item_iden.rid, group_iden.rid, e
                    );
                    self.message = Some(Message::Error(vec![self.tr.internal_error.into()]));
                }
            }
        }
    }

    async fn insert_group(&mut self) {
        let idx = self.selector_table.state.selected().unwrap();
        let obj = self.selector_items.get(idx).unwrap();
        let iden = match self.state.selected().first() {
            Some(i) => i,
            None => {
                self.message = Some(Message::Error(vec![self.tr.internal_error.into()]));
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
                self.tr.unknown.to_string()
            });
        let cr = casbin_rule::ActiveModel {
            id: Set(Uuid::now_v7()),
            ptype: Set(self.group_type.into()),
            v0: Set(obj.id),
            v1: Set(iden.rid),
            v2: Set(Uuid::default()),
            v3: Set(String::new()),
            v4: Set(String::new()),
            v5: Set(String::new()),
            updated_by: Set(self.admin_id),
            ..Default::default()
        };
        let kind = member_kind(obj.is_group, self.group_type);
        let t_type = kind.text(self.tr);

        // Prevent cycle when adding group-to-group relationship
        if obj.is_group {
            if obj.id == iden.rid {
                self.message = Some(Message::Error(vec![self.tr.group_self.into()]));
                return;
            }
            let graph = self.backend.get_graph(self.group_type).await;
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
                    self.message = Some(Message::Error(vec![fill!(
                        self.tr.group_cycle,
                        name = obj.name
                    )]));
                    return;
                }
            }
        }

        match self.backend.db_repository().create_casbin_rule(cr).await {
            Ok(cr) => {
                self.log
                    .record(Audit::MemberAdded {
                        kind,
                        member: labelled(&obj.name, cr.v0),
                        group: labelled(&g_name, cr.v1),
                    })
                    .await;
                info!(
                    "[{}] {} '{}' added to group '{}' (ptype={}, v0={}, v1={})",
                    self.handler_id, t_type, obj.name, g_name, cr.ptype, cr.v0, cr.v1
                );
                self.message = Some(Message::Success(vec![fill!(
                    self.tr.member_added,
                    kind = t_type,
                    name = obj.name,
                    group = g_name
                )]));
                self.refreash_data().await;
            }
            Err(ref err) => {
                let msg = match err {
                    e if e.is_unique_violation() => {
                        warn!(
                            "[{}] Duplicate entry: {} '{}' already exists in group '{}'",
                            self.handler_id, t_type, obj.name, g_name
                        );
                        fill!(
                            self.tr.member_exists,
                            kind = t_type,
                            name = obj.name,
                            group = g_name
                        )
                    }
                    _ => {
                        error!(
                            "[{}] Failed to add {} '{}' to group '{}': {}",
                            self.handler_id, t_type, obj.name, g_name, err
                        );
                        self.tr.internal_error.to_string()
                    }
                };
                self.message = Some(Message::Error(vec![msg]));
            }
        };
    }

    pub fn draw(&mut self, area: Rect, buf: &mut Buffer, theme: &Theme) {
        let covered = self.is_editing || self.is_deleting || self.message.is_some();
        {
            let block = Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(Style::new().fg(if covered { theme.border } else { theme.accent }));

            use ratatui::widgets::Widget;
            block.render(area, buf);
        }
        let inner_area = centered_area(area, area.width - 2, area.height - 2);
        self.win_size = (inner_area.width, inner_area.height);
        let widget = Tree::new(&self.items)
            .expect("all item identifiers must be unique")
            .experimental_scrollbar(Some(
                Scrollbar::new(ScrollbarOrientation::VerticalRight)
                    .style(Style::new().fg(theme.muted)),
            ))
            .style(theme.base())
            .highlight_style(
                Style::new()
                    .add_modifier(Modifier::REVERSED)
                    .fg(if covered {
                        theme.inactive
                    } else {
                        theme.accent
                    }),
            );
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
            self.draw_popup(popup_area, buf, theme);
        }
        if self.is_deleting {
            self.draw_delete(popup_area, buf, theme);
        }
        if let Some(ref msg) = self.message {
            render_message_popup(popup_area, buf, msg, theme, self.tr);
        }
    }

    fn draw_delete(&mut self, area: Rect, buf: &mut Buffer, theme: &Theme) {
        let iden_list = self.state.selected();
        if iden_list.len() > 1 {
            let group_iden = self.state.selected().first().unwrap();
            let item_iden = self.state.selected().get(1).unwrap();
            let mut g_name = self.tr.unknown.to_string();
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
                &[fill!(
                    self.tr.delete_member_q,
                    name = i_name,
                    group = g_name
                )],
                theme,
                self.tr,
            );
        }
    }
    fn draw_popup(&mut self, area: Rect, buf: &mut Buffer, theme: &Theme) {
        let iden = match self.state.selected().first() {
            Some(i) => i,
            None => {
                self.message = Some(Message::Error(vec![self.tr.internal_error.into()]));
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
                self.tr.unknown.to_string()
            });
        let popup = popup_block(&fill!(self.tr.title_add_to_group, group = g_name), theme);
        use ratatui::widgets::Widget;
        theme.clear(area, buf);
        popup.render(area, buf);

        let table_area = centered_area(area, area.width - 2, area.height - 2);
        self.selector_table.size = (table_area.width, table_area.height);
        self.selector_table.render(
            buf,
            table_area,
            &self.selector_items,
            &self.longest_item_lens,
            DisplayMode::Manage,
            theme,
            self.tr,
        );
    }

    /// The kind of a group's member and both their `name(id)`s, for the row
    /// that records taking it out. A member the selector does not list (a
    /// user, under a role) is stored by its id alone: the row is stored in no
    /// language, so it cannot say "unknown".
    fn member_labels(&self, member: Uuid, group: Uuid) -> (MemberKind, String, String) {
        let find = |id: Uuid| self.selector_items.iter().find(|v| v.id == id);
        let label = |id: Uuid| find(id).map_or(id.to_string(), |v| labelled(&v.name, id));
        let is_group = find(member).is_some_and(|v| v.is_group);
        (
            member_kind(is_group, self.group_type),
            label(member),
            label(group),
        )
    }
}

/// What a group's member is: another group, or what this kind of group holds.
fn member_kind(is_group: bool, group_type: GroupType) -> MemberKind {
    if is_group {
        return MemberKind::Group;
    }
    match group_type {
        GroupType::Subject => MemberKind::User,
        GroupType::Object => MemberKind::Target,
        GroupType::Action => MemberKind::Action,
    }
}
