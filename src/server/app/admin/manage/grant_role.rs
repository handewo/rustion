use super::super::table::{AdminTable, DisplayMode, FieldsToArray, TableData};
use crate::database::models::{CasbinRule, Role};
use crate::database::Uuid;
use crate::error::Error;
use crate::server::app::admin::widgets::*;
use crate::server::error::ServerError;
use crate::server::HandlerLog;
use ::log::info;
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Rect},
    style::palette::tailwind,
    widgets::Widget,
};
use std::sync::Arc;
use tokio::runtime::Handle;
use unicode_width::UnicodeWidthStr;

use super::LOG_TYPE;

pub const HELP_TEXT: [&str; 2] = [
    "(Space) toggle | (↑↓) select item",
    "(Esc) quit | (+/-) zoom in/out | (PgUp/PgDn) page up/down",
];

pub(super) struct GrantRoleEditor<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    items: Vec<Role>,
    selected_user_id: Uuid,
    longest_role_lens: Vec<Constraint>,
    role_table: AdminTable,
    backend: Arc<B>,
    t_handle: Handle,
    handler_id: Uuid,
    admin_id: Uuid,
    save_error: Option<Error>,
    log: HandlerLog,
    pub help_text: [&'static str; 2],
}

impl<B> GrantRoleEditor<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    pub fn new(
        selected_user_id: Uuid,
        backend: Arc<B>,
        t_handle: Handle,
        handler_id: Uuid,
        admin_id: Uuid,
        log: HandlerLog,
    ) -> Self {
        let mut save_error = None;
        let items = match t_handle.block_on(
            backend
                .db_repository()
                .list_roles_by_user_id(&selected_user_id),
        ) {
            Ok(items) => items,
            Err(e) => {
                save_error = Some(e);
                Vec::new()
            }
        };
        Self {
            items: items.clone(),
            selected_user_id,
            longest_role_lens: table_len_calculator(&items),
            role_table: AdminTable::new(&items, &tailwind::BLUE),
            backend,
            t_handle,
            handler_id,
            admin_id,
            save_error,
            log,
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

        let table = &mut self.role_table;
        let items_len = self.items.len();
        let ctrl_pressed = modifiers.contains(KeyModifiers::CONTROL);

        match key {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Tab | KeyCode::BackTab => return true,
            KeyCode::Char('+') => {
                table.zoom_in();
            }
            KeyCode::Char('-') => {
                table.zoom_out();
            }
            KeyCode::PageDown => {
                table.next_page(items_len);
            }
            KeyCode::PageUp => {
                table.previous_page();
            }
            KeyCode::Char('f') if ctrl_pressed => {
                table.next_page(items_len);
            }
            KeyCode::Char('b') if ctrl_pressed => {
                table.previous_page();
            }
            KeyCode::Down | KeyCode::Char('j') => {
                table.next_row(items_len);
            }
            KeyCode::Up | KeyCode::Char('k') => {
                table.previous_row(items_len);
            }
            KeyCode::Char(' ') | KeyCode::Enter => {
                if let Err(e) = self.save_bindings() {
                    self.save_error = Some(e);
                }
            }
            _ => {}
        }

        false
    }

    fn save_bindings(&mut self) -> Result<(), Error> {
        let idx = self.role_table.state.selected().unwrap();
        let t = self.items.get_mut(idx).unwrap();
        if t.is_bound {
            let id = t
                .rule_id
                .as_ref()
                .ok_or(Error::Server(ServerError::MissingRuleId))?;
            self.t_handle
                .block_on(self.backend.db_repository().delete_casbin_rule(id))?;
            info!(
                "[{}] Role '{}({})' revoked from user_id={} by admin_id={}",
                self.handler_id, t.role, t.rid, self.selected_user_id, self.admin_id
            );
            self.t_handle.block_on((self.log)(
                LOG_TYPE.into(),
                format!("Role '{}({})' revoked from user_id={}", t.role, t.rid, self.selected_user_id),
            ));
        } else {
            let cr = CasbinRule::new(
                "g1".to_string(),
                t.rid,
                self.selected_user_id,
                None,
                String::new(),
                String::new(),
                String::new(),
                self.admin_id,
            );
            self.t_handle
                .block_on(self.backend.db_repository().create_casbin_rule(&cr))?;
            info!(
                "[{}] Role '{}({})' granted to user_id={} by admin_id={}",
                self.handler_id, t.role, t.rid, self.selected_user_id, self.admin_id
            );
            self.t_handle.block_on((self.log)(
                LOG_TYPE.into(),
                format!("Role '{}({})' granted to user_id={}", t.role, t.rid, self.selected_user_id),
            ));
        }
        t.is_bound = !t.is_bound;
        self.t_handle.block_on(self.backend.load_role_manager())?;
        Ok(())
    }

    fn render_ui(&mut self, area: Rect, buf: &mut Buffer) {
        let area = centered_area(area, area.width - 2, area.height - 2);
        self.role_table.size = (area.width, area.height);

        // Render left table (Targets)
        self.role_table.render(
            buf,
            area,
            &self.items,
            &self.longest_role_lens,
            DisplayMode::Manage,
        );

        if self.save_error.is_some() {
            render_message_popup(area, buf, &Message::Error(vec!["Internal error".into()]));
        }
    }
}

impl<B> Widget for &mut GrantRoleEditor<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    fn render(self, area: Rect, buf: &mut Buffer) {
        self.render_ui(area, buf);
    }
}

impl TableData for Vec<Role> {
    fn header(&self) -> Vec<&str> {
        vec!["", "role"]
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

impl FieldsToArray for Role {
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
                    self.role.clone(),
                ]
            }
        }
    }
}

fn table_len_calculator(data: &[Role]) -> Vec<Constraint> {
    let role_len = data
        .iter()
        .map(|v| v.role.as_str())
        .map(UnicodeWidthStr::width)
        .max()
        .unwrap_or(0)
        .max(4);

    vec![Constraint::Length(4), Constraint::Length(role_len as u16)]
}
