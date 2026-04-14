use crate::database::error::DatabaseError;
use crate::database::models::target::ValidateError;
use crate::database::models::Target;
use crate::error::Error;
use crate::server::widgets::*;
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    widgets::Widget,
};

// Field indices
const F_NAME: usize = 0;
const F_HOSTNAME: usize = 1;
const F_PORT: usize = 2;
const F_SERVER_PUBLIC_KEY: usize = 3;
const F_DESCRIPTION: usize = 4;
const F_IS_ACTIVE: usize = 5;

#[derive(Debug)]
pub struct TargetEditor {
    pub target: Target,
    pub form: FormEditor,
}

impl TargetEditor {
    pub fn new(target: Target) -> Self {
        let form = FormEditor::new(vec![
            FormField::text("*Name*", Some(target.name.clone())),
            FormField::text("*Hostname*", Some(target.hostname.clone())),
            FormField::text("*Port*", Some(target.port.to_string())),
            FormField::text("*Server Public Key*", Some(target.server_public_key.clone())),
            FormField::text("Description", target.description.clone()),
            FormField::checkbox("Is Active", target.is_active),
        ]);
        Self { target, form }
    }

    pub fn handle_paste_event(&mut self, paste: &str) -> bool {
        self.form.handle_paste_event(paste)
    }

    pub fn handle_key_event(&mut self, key: KeyCode, modifiers: KeyModifiers) -> bool {
        match self.form.handle_key_event(key, modifiers) {
            FormEvent::Save => {
                if let Err(e) = self.save_target() {
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

    fn save_target(&mut self) -> Result<(), Error> {
        self.target.name = self.form.get_text(F_NAME).trim().into();
        self.target.hostname = self.form.get_text(F_HOSTNAME).trim().into();

        let port_str = self.form.get_text(F_PORT).trim().to_string();
        let port: u64 = match port_str.parse() {
            Ok(p) => {
                if (1..=65535).contains(&p) {
                    p
                } else {
                    return Err(Error::Database(DatabaseError::TargetValidation(
                        ValidateError::PortInvalid,
                    )));
                }
            }
            Err(_) => {
                return Err(Error::Database(DatabaseError::TargetValidation(
                    ValidateError::PortNotNumber,
                )))
            }
        };
        self.target.port = port as u16;

        self.target.server_public_key =
            self.form.get_text(F_SERVER_PUBLIC_KEY).trim().to_string();

        let desc = self.form.get_text(F_DESCRIPTION).trim().to_string();
        self.target.description = (!desc.is_empty()).then_some(desc);

        self.target.is_active = self.form.get_checkbox(F_IS_ACTIVE);

        self.target
            .validate()
            .map_err(|e| Error::Database(DatabaseError::TargetValidation(e)))
    }
}

impl Widget for &mut TargetEditor {
    fn render(self, area: Rect, buf: &mut Buffer) {
        self.form.render_ui(area, buf);
    }
}
