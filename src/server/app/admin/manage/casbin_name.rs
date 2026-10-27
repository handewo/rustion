use super::super::error::AdminError;
use super::super::validate;
use crate::database::entity::casbin_name;
use crate::database::models::{CasbinName, NamePtype};
use crate::error::Error;
use crate::server::app::error::AppError;
use crate::server::widgets::*;
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{buffer::Buffer, layout::Rect};
use sea_orm::ActiveValue::{Set, Unchanged};

// Radio button options for ptype selection (static for RadioButtons widget)
const PTYPE_OPTIONS: [RadioOption; 3] = [
    RadioOption::new("Role", "g1"),   // g1 - user groups/roles
    RadioOption::new("Target", "g2"), // g2 - object groups
    RadioOption::new("Action", "g3"), // g3 - action groups
];

// Field indices
const F_PTYPE: usize = 0;
const F_NAME: usize = 1;
const F_IS_ACTIVE: usize = 2;

#[derive(Debug)]
pub struct CasbinNameEditor {
    pub casbin_name: CasbinName,
    pub active_model: casbin_name::ActiveModel,
    pub form: FormEditor,
}

impl CasbinNameEditor {
    pub fn new(casbin_name: CasbinName, is_new: bool) -> Self {
        let mut type_radio =
            FormField::radio("*Type*", &PTYPE_OPTIONS, casbin_name.ptype.as_str(), 5);
        if !is_new {
            type_radio = type_radio.readonly()
        }
        let form = FormEditor::new(vec![
            type_radio,
            FormField::text("*Name*", Some(casbin_name.name.clone())),
            FormField::checkbox("Is Active", casbin_name.is_active),
        ]);

        let active_model = if is_new {
            casbin_name::ActiveModel {
                id: Set(casbin_name.id),
                ptype: Set(casbin_name.ptype),
                is_active: Set(casbin_name.is_active),
                updated_by: Set(casbin_name.updated_by),
                ..Default::default()
            }
        } else {
            casbin_name::ActiveModel {
                id: Unchanged(casbin_name.id),
                updated_by: Set(casbin_name.updated_by),
                ..Default::default()
            }
        };

        Self {
            casbin_name,
            active_model,
            form,
        }
    }

    pub fn handle_paste_event(&mut self, paste: &str) -> bool {
        self.form.handle_paste_event(paste)
    }

    pub fn handle_key_event(&mut self, key: KeyCode, modifiers: KeyModifiers) -> bool {
        match self.form.handle_key_event(key, modifiers) {
            FormEvent::Save => {
                if let Err(e) = self.save_casbin_name() {
                    self.form.set_save_error(vec![e.to_string()]);
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

    fn save_casbin_name(&mut self) -> Result<(), Error> {
        // The radio carries the name, not the stored value. Both failures are
        // unreachable in practice — `PTYPE_OPTIONS` only offers g1/g2/g3, and the
        // radio is read-only on edit — but it hands back a plain `&str`, so an
        // unknown or internal name has to be rejected somewhere.
        let ptype = NamePtype::from_name(self.form.get_radio(F_PTYPE))
            .filter(|p| !p.is_internal())
            .ok_or(AppError::Admin(AdminError::Validate(
                validate::ValidateError::PtypeInvalid,
            )))?;
        if self.casbin_name.ptype != ptype {
            self.active_model.ptype = Set(ptype);
        }

        let name = self.form.get_text(F_NAME).trim().to_string();
        if self.casbin_name.name != name || self.casbin_name.name.is_empty() {
            validate::varify_group_name(&name)
                .map_err(|e| AppError::Admin(AdminError::Validate(e)))?;
            self.active_model.name = Set(name.clone());
        }

        let is_active = self.form.get_checkbox(F_IS_ACTIVE);
        if self.casbin_name.is_active != is_active {
            self.active_model.is_active = Set(is_active);
        }

        Ok(())
    }
}

impl CasbinNameEditor {
    pub fn render(&mut self, area: Rect, buf: &mut Buffer, theme: &Theme) {
        self.form.render_ui(area, buf, theme);
    }
}
