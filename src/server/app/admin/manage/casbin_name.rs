use crate::database::error::DatabaseError;
use crate::database::models::CasbinName;
use crate::error::Error;
use crate::server::widgets::*;
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{buffer::Buffer, layout::Rect, widgets::Widget};

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
    pub form: FormEditor,
}

impl CasbinNameEditor {
    pub fn new(casbin_name: CasbinName) -> Self {
        let form = FormEditor::new(vec![
            FormField::radio("*Type*", &PTYPE_OPTIONS, &casbin_name.ptype, 5),
            FormField::text("*Name*", Some(casbin_name.name.clone())),
            FormField::checkbox("Is Active", casbin_name.is_active),
        ]);
        Self { casbin_name, form }
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
        self.casbin_name.ptype = self.form.get_radio(F_PTYPE).to_string();
        self.casbin_name.name = self.form.get_text(F_NAME).trim().into();
        self.casbin_name.is_active = self.form.get_checkbox(F_IS_ACTIVE);

        self.casbin_name
            .validate()
            .map_err(|e| Error::Database(DatabaseError::CasbinNameValidation(e)))
    }
}

impl Widget for &mut CasbinNameEditor {
    fn render(self, area: Rect, buf: &mut Buffer) {
        self.form.render_ui(area, buf);
    }
}
