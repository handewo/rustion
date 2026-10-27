use super::Theme;
use super::common::print_short_uuid;
use crate::database::models::*;
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Margin, Rect};
use ratatui::style::{Modifier, Style, Stylize};
use ratatui::text::{Line, Text};
use ratatui::widgets::{
    Cell, HighlightSpacing, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, StatefulWidget,
    Table, TableState, Widget,
};
use unicode_width::UnicodeWidthStr;

pub struct AdminTable {
    pub state: TableState,
    scroll_state: ScrollbarState,
    row_height: usize,
    /// Drawn in the theme's inactive colours, for while a popup is on top.
    dimmed: bool,
    pub size: (u16, u16),
}

impl AdminTable {
    pub fn new<T: TableData>(items: &T) -> Self {
        AdminTable {
            state: TableState::default().with_selected(0),
            scroll_state: ScrollbarState::new((items.len().max(1) - 1) * 2),
            row_height: 2,
            dimmed: false,
            size: (0, 0),
        }
    }

    pub fn dim(&mut self, dimmed: bool) {
        self.dimmed = dimmed;
    }

    pub fn previous_page(&mut self) {
        let rows = (self.size.1 as usize - 1) / self.row_height;
        *self.state.offset_mut() = if self.state.offset() < rows {
            0
        } else {
            self.state.offset() - rows
        };

        let i = match self.state.selected() {
            Some(i) => {
                if i < rows {
                    i
                } else {
                    i - rows
                }
            }
            None => 0,
        };

        self.state.select(Some(i));
        self.scroll_state = self.scroll_state.position(i * self.row_height);
    }

    pub fn next_page(&mut self, items_len: usize) {
        let rows = (self.size.1 as usize - 1) / self.row_height;
        let mut is_offset = false;

        if self.state.offset() + rows <= items_len {
            *self.state.offset_mut() = self.state.offset() + rows;
        } else {
            is_offset = true;
        }

        let i = match self.state.selected() {
            Some(i) => {
                if is_offset {
                    i
                } else if i >= items_len - rows {
                    self.state.offset()
                } else {
                    i + rows
                }
            }
            None => 0,
        };

        self.state.select(Some(i));
        self.scroll_state = self.scroll_state.position(i * self.row_height);
    }

    pub fn next_row(&mut self, items_len: usize) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= items_len - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };

        self.state.select(Some(i));
        self.scroll_state = self.scroll_state.position(i * self.row_height);
    }

    pub fn previous_row(&mut self, items_len: usize) {
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    items_len - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };

        self.state.select(Some(i));
        self.scroll_state = self.scroll_state.position(i * self.row_height);
    }

    pub fn next_column(&mut self) {
        self.state.select_next_column();
    }

    pub fn previous_column(&mut self) {
        self.state.select_previous_column();
    }

    pub fn zoom_in(&mut self) {
        self.row_height = self.row_height.saturating_add(1).min(20);
    }

    pub fn zoom_out(&mut self) {
        self.row_height = self.row_height.saturating_sub(1).max(1);
    }

    pub fn render<T: TableData>(
        &mut self,
        buf: &mut Buffer,
        area: Rect,
        items: &T,
        longest_item_lens: &Vec<Constraint>,
        mode: DisplayMode,
        theme: &Theme,
    ) {
        let (header_bg, selected, selected_cell) = if self.dimmed {
            (theme.inactive_bar, theme.inactive, theme.inactive_dim)
        } else {
            (theme.bar_bg, theme.accent, theme.accent_dim)
        };
        let header_style = Style::default().fg(theme.bar_fg).bg(header_bg).bold();

        let selected_row_style = Style::default()
            .add_modifier(Modifier::REVERSED)
            .fg(selected);

        let selected_col_style = Style::default().fg(selected);

        let selected_cell_style = Style::default()
            .add_modifier(Modifier::REVERSED)
            .fg(selected_cell);

        let header = items
            .header()
            .into_iter()
            .map(Cell::from)
            .collect::<Row>()
            .style(header_style)
            .height(1);

        let items = items.as_vec();
        let empty = items.is_empty();
        let rows = items.iter().enumerate().map(|(i, data)| {
            let color = match i % 2 {
                0 => theme.bg,
                _ => theme.alt_bg,
            };

            let item = data.to_array(mode);
            item.into_iter()
                .map(|content| Cell::from(Text::from(content.to_string())))
                .collect::<Row>()
                .style(Style::new().fg(theme.fg).bg(color))
                .height(self.row_height as u16)
        });

        let bar = vec!["   ".into(); self.row_height];
        let t = Table::new(rows, longest_item_lens)
            .header(header)
            .row_highlight_style(selected_row_style)
            .column_highlight_style(selected_col_style)
            .cell_highlight_style(selected_cell_style)
            .highlight_symbol(Text::from(bar))
            .bg(theme.bg)
            .highlight_spacing(HighlightSpacing::Always);

        StatefulWidget::render(t, area, buf, &mut self.state);

        if empty {
            let below_header = Rect {
                y: area.y + 1,
                height: area.height.saturating_sub(1),
                ..area
            };
            let notice = Rect {
                y: below_header.y + below_header.height / 2,
                height: below_header.height.min(1),
                ..below_header
            };
            Line::styled("No records yet", Style::new().fg(theme.muted).italic())
                .centered()
                .render(notice, buf);
            return;
        }

        self.scroll_state = self
            .scroll_state
            .content_length((items.len().max(1) - 1) * self.row_height)
            .position(self.state.selected().unwrap_or(0) * self.row_height);

        Scrollbar::default()
            .orientation(ScrollbarOrientation::VerticalRight)
            .track_style(Style::new().fg(theme.border))
            .thumb_style(Style::new().fg(if self.dimmed {
                theme.inactive
            } else {
                theme.accent
            }))
            .begin_style(Style::new().fg(theme.muted))
            .end_style(Style::new().fg(theme.muted))
            .render(
                area.inner(Margin {
                    vertical: 1,
                    horizontal: 1,
                }),
                buf,
                &mut self.scroll_state,
            );
    }
}

pub trait TableData {
    fn header(&self) -> Vec<&str>;
    fn as_vec(&self) -> Vec<&dyn FieldsToArray>;
    fn len(&self) -> usize;
}

#[derive(Clone, Copy)]
pub enum DisplayMode {
    Full,
    Manage,
}

pub trait FieldsToArray {
    fn to_array(&self, mode: DisplayMode) -> Vec<String>;
}

impl FieldsToArray for UserWithRole {
    fn to_array(&self, mode: DisplayMode) -> Vec<String> {
        match mode {
            DisplayMode::Full => {
                todo!()
            }
            DisplayMode::Manage => {
                vec![
                    self.user.username.clone(),
                    self.user.email.clone().unwrap_or_default(),
                    self.user.print_password(),
                    self.user.print_authorized_keys(),
                    self.user.force_init_pass.to_string(),
                    self.user.is_active.to_string(),
                    self.role.clone(),
                ]
            }
        }
    }
}

impl FieldsToArray for User {
    fn to_array(&self, mode: DisplayMode) -> Vec<String> {
        match mode {
            DisplayMode::Full => {
                vec![
                    self.id.to_string(),
                    self.username.clone(),
                    self.email.clone().unwrap_or_default(),
                    self.print_password(),
                    self.print_authorized_keys(),
                    self.force_init_pass.to_string(),
                    self.is_active.to_string(),
                    self.updated_by.to_string(),
                    self.updated_at.to_string(),
                ]
            }
            DisplayMode::Manage => {
                vec![
                    self.username.clone(),
                    self.email.clone().unwrap_or_default(),
                    self.print_password(),
                    self.print_authorized_keys(),
                    self.force_init_pass.to_string(),
                    self.is_active.to_string(),
                ]
            }
        }
    }
}

impl FieldsToArray for Target {
    fn to_array(&self, mode: DisplayMode) -> Vec<String> {
        match mode {
            DisplayMode::Full => {
                vec![
                    self.id.to_string(),
                    self.name.clone(),
                    self.hostname.clone(),
                    self.port.to_string(),
                    self.print_server_key(),
                    self.description.clone().unwrap_or_default(),
                    self.proxy.clone().unwrap_or_default(),
                    self.is_active.to_string(),
                    self.updated_by.to_string(),
                    self.updated_at.to_string(),
                ]
            }
            DisplayMode::Manage => {
                vec![
                    self.name.clone(),
                    self.hostname.clone(),
                    self.port.to_string(),
                    self.print_server_key(),
                    self.description.clone().unwrap_or_default(),
                    self.proxy.clone().unwrap_or_default(),
                    self.is_active.to_string(),
                ]
            }
        }
    }
}

impl FieldsToArray for TargetSecret {
    fn to_array(&self, mode: DisplayMode) -> Vec<String> {
        match mode {
            DisplayMode::Full => {
                vec![
                    self.id.to_string(),
                    self.target_id.to_string(),
                    self.secret_id.to_string(),
                    self.is_active.to_string(),
                    self.updated_by.to_string(),
                    self.updated_at.to_string(),
                ]
            }
            DisplayMode::Manage => {
                todo!()
            }
        }
    }
}

impl FieldsToArray for Secret {
    fn to_array(&self, mode: DisplayMode) -> Vec<String> {
        match mode {
            DisplayMode::Full => {
                vec![
                    self.id.to_string(),
                    self.name.clone(),
                    self.user.clone(),
                    self.print_password(),
                    self.print_private_key(),
                    self.print_public_key(),
                    self.is_active.to_string(),
                    self.updated_by.to_string(),
                    self.updated_at.to_string(),
                ]
            }
            DisplayMode::Manage => {
                vec![
                    self.name.clone(),
                    self.user.clone(),
                    self.print_password(),
                    self.print_private_key(),
                    self.print_public_key(),
                    self.is_active.to_string(),
                ]
            }
        }
    }
}

impl FieldsToArray for CasbinName {
    fn to_array(&self, mode: DisplayMode) -> Vec<String> {
        match mode {
            DisplayMode::Full => {
                vec![
                    self.id.to_string(),
                    self.ptype.to_string(),
                    self.name.clone(),
                    self.is_active.to_string(),
                    self.updated_by.to_string(),
                    self.updated_at.to_string(),
                ]
            }
            DisplayMode::Manage => {
                // Convert ptype to friendly name for display
                let ptype_display = match self.ptype {
                    NamePtype::G1 => "Role",
                    NamePtype::G2 => "Target",
                    NamePtype::G3 => "Action",
                    other => other.as_str(),
                };
                vec![
                    ptype_display.to_string(),
                    self.name.clone(),
                    self.is_active.to_string(),
                ]
            }
        }
    }
}

impl FieldsToArray for PermissionPolicy {
    fn to_array(&self, mode: DisplayMode) -> Vec<String> {
        match mode {
            DisplayMode::Full => {
                todo!()
            }
            DisplayMode::Manage => {
                vec![
                    self.user_role.clone(),
                    self.target_group.clone(),
                    self.action_group.clone(),
                    self.rule.v3.clone(),
                ]
            }
        }
    }
}

impl FieldsToArray for CasbinRule {
    fn to_array(&self, mode: DisplayMode) -> Vec<String> {
        match mode {
            DisplayMode::Full => {
                vec![
                    self.id.to_string(),
                    self.ptype.to_string(),
                    self.v0.to_string(),
                    self.v1.to_string(),
                    self.v2.to_string(),
                    self.v3.clone(),
                    self.v4.clone(),
                    self.v5.clone(),
                    self.updated_by.to_string(),
                    self.updated_at.to_string(),
                ]
            }
            DisplayMode::Manage => {
                todo!()
            }
        }
    }
}

impl FieldsToArray for EventLog {
    fn to_array(&self, mode: DisplayMode) -> Vec<String> {
        match mode {
            DisplayMode::Full => {
                vec![
                    self.id.to_string(),
                    print_short_uuid(self.connection_id),
                    self.log_type.to_string(),
                    print_short_uuid(self.user_id),
                    self.detail.clone(),
                    self.created_at.to_string(),
                ]
            }
            DisplayMode::Manage => {
                todo!()
            }
        }
    }
}

impl FieldsToArray for SessionRecording {
    fn to_array(&self, mode: DisplayMode) -> Vec<String> {
        match mode {
            DisplayMode::Full => {
                vec![
                    print_short_uuid(self.id),
                    print_short_uuid(self.user_id),
                    print_short_uuid(self.target_id),
                    print_short_uuid(self.secret_id),
                    self.target_label.to_string(),
                    self.file_path.clone(),
                    self.started_at.to_string(),
                    self.ended_at.map(|t| t.to_string()).unwrap_or_default(),
                    print_short_uuid(self.connection_id),
                    self.status.to_string(),
                ]
            }
            DisplayMode::Manage => {
                todo!()
            }
        }
    }
}

impl TableData for Vec<ObjectGroup> {
    fn header(&self) -> Vec<&str> {
        vec!["Object", "Is Group"]
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

pub fn table_object_group_len_calculator(data: &[ObjectGroup]) -> Vec<Constraint> {
    let len = data
        .iter()
        .map(|v| v.name.as_str())
        .map(UnicodeWidthStr::width)
        .max()
        .unwrap_or(0)
        .max(6);

    vec![Constraint::Length(len as u16), Constraint::Length(8)]
}

impl FieldsToArray for ObjectGroup {
    fn to_array(&self, mode: DisplayMode) -> Vec<String> {
        match mode {
            DisplayMode::Full => {
                todo!()
            }
            DisplayMode::Manage => {
                vec![
                    self.name.clone(),
                    if self.is_group {
                        "Y".to_string()
                    } else {
                        "N".to_string()
                    },
                ]
            }
        }
    }
}

impl FieldsToArray for RecordingView {
    fn to_array(&self, _mode: DisplayMode) -> Vec<String> {
        let label = if !self.current_label.is_empty() && self.current_label != self.target_label {
            format!("{}({})", self.current_label, self.target_label)
        } else {
            self.target_label.clone()
        };
        vec![
            label,
            super::common::format_timestamp(self.started_at),
            self.ended_at
                .map(super::common::format_timestamp)
                .unwrap_or_default(),
            self.status.to_string(),
        ]
    }
}

impl TableData for Vec<RecordingView> {
    fn header(&self) -> Vec<&str> {
        vec!["Target Label", "Started At", "Ended At", "Status"]
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
