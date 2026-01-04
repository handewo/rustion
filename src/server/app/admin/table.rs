use crate::database::models::*;
use ratatui::layout::{Constraint, Margin, Rect};
use ratatui::style::{self, Color, Modifier, Style, Stylize};
use ratatui::text::Text;
use ratatui::widgets::{
    Cell, HighlightSpacing, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table, TableState,
};
use ratatui::Frame;
use style::palette::tailwind;

pub struct Colors {
    pub buffer_bg: Color,
    pub header_bg: Color,
    pub header_fg: Color,
    pub row_fg: Color,
    pub tab_font: Color,
    selected_row_style_fg: Color,
    selected_column_style_fg: Color,
    selected_cell_style_fg: Color,
    normal_row_color: Color,
    alt_row_color: Color,
    pub footer_border_color: Color,
}

impl Colors {
    pub const fn new(color: &tailwind::Palette) -> Self {
        Self {
            buffer_bg: tailwind::SLATE.c950,
            header_bg: color.c900,
            header_fg: tailwind::SLATE.c200,
            row_fg: tailwind::SLATE.c200,
            tab_font: tailwind::SLATE.c400,
            selected_row_style_fg: color.c400,
            selected_column_style_fg: color.c400,
            selected_cell_style_fg: color.c600,
            normal_row_color: tailwind::SLATE.c950,
            alt_row_color: tailwind::SLATE.c900,
            footer_border_color: color.c400,
        }
    }

    pub fn gray(&mut self) {
        self.header_bg = tailwind::GRAY.c900;
        self.selected_row_style_fg = tailwind::GRAY.c400;
        self.selected_column_style_fg = tailwind::GRAY.c400;
        self.selected_cell_style_fg = tailwind::GRAY.c600;
    }
}

pub struct AdminTable {
    pub state: TableState,
    scroll_state: ScrollbarState,
    row_height: usize,
    pub colors: Colors,
    pub size: (u16, u16),
}

impl AdminTable {
    pub fn new<T: TableData>(items: &T, color: &tailwind::Palette) -> Self {
        AdminTable {
            state: TableState::default().with_selected(0),
            scroll_state: ScrollbarState::new((items.len().max(1) - 1) * 2),
            row_height: 2,
            colors: Colors::new(color),
            size: (0, 0),
        }
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

    pub fn next_page<T: TableData>(&mut self, items: &T) {
        let rows = (self.size.1 as usize - 1) / self.row_height;
        let mut is_offset = false;

        if self.state.offset() + rows <= items.len() {
            *self.state.offset_mut() = self.state.offset() + rows;
        } else {
            is_offset = true;
        }

        let i = match self.state.selected() {
            Some(i) => {
                if is_offset {
                    i
                } else if i >= items.len() - rows {
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

    pub fn next_row<T: TableData>(&mut self, items: &T) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= items.len() - 1 {
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

    pub fn previous_row<T: TableData>(&mut self, items: &T) {
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    items.len() - 1
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
        frame: &mut Frame,
        area: Rect,
        items: &T,
        longest_item_lens: &Vec<Constraint>,
        mode: DisplayMode,
    ) {
        let header_style = Style::default()
            .fg(self.colors.header_fg)
            .bg(self.colors.header_bg);

        let selected_row_style = Style::default()
            .add_modifier(Modifier::REVERSED)
            .fg(self.colors.selected_row_style_fg);

        let selected_col_style = Style::default().fg(self.colors.selected_column_style_fg);

        let selected_cell_style = Style::default()
            .add_modifier(Modifier::REVERSED)
            .fg(self.colors.selected_cell_style_fg);

        let header = items
            .header()
            .into_iter()
            .map(Cell::from)
            .collect::<Row>()
            .style(header_style)
            .height(1);

        let items = items.as_vec();
        let rows = items.iter().enumerate().map(|(i, data)| {
            let color = match i % 2 {
                0 => self.colors.normal_row_color,
                _ => self.colors.alt_row_color,
            };

            let item = data.to_array(mode);
            item.into_iter()
                .map(|content| Cell::from(Text::from(content.to_string())))
                .collect::<Row>()
                .style(Style::new().fg(self.colors.row_fg).bg(color))
                .height(self.row_height as u16)
        });

        let bar = vec!["   ".into(); self.row_height];
        let t = Table::new(rows, longest_item_lens)
            .header(header)
            .row_highlight_style(selected_row_style)
            .column_highlight_style(selected_col_style)
            .cell_highlight_style(selected_cell_style)
            .highlight_symbol(Text::from(bar))
            .bg(self.colors.buffer_bg)
            .highlight_spacing(HighlightSpacing::Always);

        frame.render_stateful_widget(t, area, &mut self.state);

        self.scroll_state = self
            .scroll_state
            .content_length((items.len().max(1) - 1) * self.row_height)
            .position(self.state.selected().unwrap_or(0) * self.row_height);

        frame.render_stateful_widget(
            Scrollbar::default().orientation(ScrollbarOrientation::VerticalRight),
            area.inner(Margin {
                vertical: 1,
                horizontal: 1,
            }),
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

impl FieldsToArray for User {
    fn to_array(&self, mode: DisplayMode) -> Vec<String> {
        match mode {
            DisplayMode::Full => {
                vec![
                    self.id.clone(),
                    self.username.clone(),
                    self.email.clone().unwrap_or_default(),
                    self.print_password(),
                    self.print_authorized_keys(),
                    self.force_init_pass.to_string(),
                    self.is_active.to_string(),
                    self.updated_by.clone(),
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
                    self.id.clone(),
                    self.name.clone(),
                    self.hostname.clone(),
                    self.port.to_string(),
                    self.print_server_key(),
                    self.description.clone().unwrap_or_default(),
                    self.is_active.to_string(),
                    self.updated_by.clone(),
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
                    self.id.clone(),
                    self.target_id.clone(),
                    self.secret_id.clone(),
                    self.is_active.to_string(),
                    self.updated_by.clone(),
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
                    self.id.clone(),
                    self.name.clone(),
                    self.user.clone(),
                    self.print_password(),
                    self.print_private_key(),
                    self.print_public_key(),
                    self.is_active.to_string(),
                    self.updated_by.clone(),
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

impl FieldsToArray for InternalObject {
    fn to_array(&self, mode: DisplayMode) -> Vec<String> {
        match mode {
            DisplayMode::Full => {
                vec![
                    self.name.clone(),
                    self.is_active.to_string(),
                    self.updated_by.clone(),
                    self.updated_at.to_string(),
                ]
            }
            DisplayMode::Manage => {
                todo!()
            }
        }
    }
}

impl FieldsToArray for CasbinRule {
    fn to_array(&self, mode: DisplayMode) -> Vec<String> {
        match mode {
            DisplayMode::Full => {
                vec![
                    self.id.clone(),
                    self.ptype.clone(),
                    self.v0.clone(),
                    self.v1.clone(),
                    self.v2.clone(),
                    self.v3.clone(),
                    self.v4.clone(),
                    self.v5.clone(),
                    self.updated_by.clone(),
                    self.updated_at.to_string(),
                ]
            }
            DisplayMode::Manage => {
                todo!()
            }
        }
    }
}

impl FieldsToArray for Log {
    fn to_array(&self, mode: DisplayMode) -> Vec<String> {
        match mode {
            DisplayMode::Full => {
                vec![
                    self.connection_id.clone(),
                    self.log_type.clone(),
                    self.user_id.clone(),
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
