use super::super::error::AdminError;
use super::super::validate;
use crate::database::entity::command_set;
use crate::database::models::CommandSet;
use crate::error::Error;
use crate::fill;
use crate::server::app::error::AppError;
use crate::server::widgets::*;
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{buffer::Buffer, layout::Rect};
use sea_orm::ActiveValue::{Set, Unchanged};

// Field indices
const F_NAME: usize = 0;
const F_CONFIG: usize = 1;
const F_IS_ACTIVE: usize = 2;

/// What a new set starts with: one command, to show the shape.
const CONFIG_TEMPLATE: &str = r#"{
  "commands": [
    {"alias": "cmd", "exec": "cmd {{args}}", "argsList": [], "options": [], "description": ""}
  ],
  "cd": []
}"#;

/// Adds or edits a command set: its name, its JSON config and whether it is
/// active. The config is saved only when the limited shell could load it.
#[derive(Debug)]
pub struct CommandSetEditor {
    pub command_set: CommandSet,
    pub active_model: command_set::ActiveModel,
    pub form: FormEditor,
    tr: &'static Strings,
}

impl CommandSetEditor {
    pub fn new(command_set: CommandSet, is_new: bool, tr: &'static Strings) -> Self {
        let config = if is_new {
            CONFIG_TEMPLATE.to_string()
        } else {
            command_set.config.clone()
        };
        let lines: Vec<String> = config.lines().map(str::to_string).collect();
        let form = FormEditor::new(vec![
            FormField::text(|tr| tr.field_name, Some(command_set.name.clone())),
            FormField::multiline(|tr| tr.field_command_config, Some(&lines), 16),
            FormField::checkbox(|tr| tr.field_is_active, command_set.is_active),
        ]);

        let active_model = if is_new {
            command_set::ActiveModel {
                id: Set(command_set.id),
                is_active: Set(command_set.is_active),
                updated_by: Set(command_set.updated_by),
                ..Default::default()
            }
        } else {
            command_set::ActiveModel {
                id: Unchanged(command_set.id),
                updated_by: Set(command_set.updated_by),
                ..Default::default()
            }
        };

        Self {
            command_set,
            active_model,
            form,
            tr,
        }
    }

    pub fn handle_paste_event(&mut self, paste: &str) -> bool {
        self.form.handle_paste_event(paste)
    }

    pub fn handle_key_event(&mut self, key: KeyCode, modifiers: KeyModifiers) -> bool {
        match self.form.handle_key_event(key, modifiers) {
            FormEvent::Save => {
                if let Err(lines) = self.save_command_set() {
                    self.form.set_save_error(lines);
                    return false;
                }
                true
            }
            FormEvent::Cancel => {
                self.form.show_cancel_confirmation = true;
                true
            }
            FormEvent::None => false,
        }
    }

    fn save_command_set(&mut self) -> Result<(), Vec<String>> {
        let name = self.form.get_text(F_NAME).trim().to_string();
        if self.command_set.name != name || self.command_set.name.is_empty() {
            validate::varify_group_name(&name).map_err(|e| {
                let e: Error = AppError::Admin(AdminError::Validate(e)).into();
                vec![validate::describe(&e, self.tr)]
            })?;
            self.active_model.name = Set(name);
        }

        let config = self.form.get_multiline(F_CONFIG).join("\n");
        // The check the snapshot makes when it loads the set, so a config
        // saved here is one the limited shell can use.
        if let Err(e) = crate::command::Policy::from_json(&config) {
            return Err(vec![fill!(self.tr.v_command_config, error = e)]);
        }
        if self.command_set.config != config || self.command_set.config.is_empty() {
            self.active_model.config = Set(config);
        }

        let is_active = self.form.get_checkbox(F_IS_ACTIVE);
        if self.command_set.is_active != is_active {
            self.active_model.is_active = Set(is_active);
        }

        Ok(())
    }
}

impl CommandSetEditor {
    pub fn render(&mut self, area: Rect, buf: &mut Buffer, theme: &Theme) {
        self.form.render_ui(area, buf, theme, self.tr);
    }
}
