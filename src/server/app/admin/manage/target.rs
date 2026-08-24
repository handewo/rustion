use super::super::error::AdminError;
use super::super::validate;
use crate::database::entity::target;
use crate::database::models::Target;
use crate::error::Error;
use crate::server::app::error::AppError;
use crate::server::widgets::*;
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{buffer::Buffer, layout::Rect, widgets::Widget};
use sea_orm::ActiveValue::{Set, Unchanged};

// Field indices
const F_NAME: usize = 0;
const F_HOSTNAME: usize = 1;
const F_PORT: usize = 2;
const F_SERVER_PUBLIC_KEY: usize = 3;
const F_DESCRIPTION: usize = 4;
const F_PROXY: usize = 5;
const F_IS_ACTIVE: usize = 6;

#[derive(Debug)]
pub struct TargetEditor {
    pub target: Target,
    pub active_model: target::ActiveModel,
    pub form: FormEditor,
}

impl TargetEditor {
    pub fn new(target: Target, is_new: bool) -> Self {
        let form = FormEditor::new(vec![
            FormField::text("*Name*", Some(target.name.clone())),
            FormField::text("*Hostname*", Some(target.hostname.clone())),
            FormField::text("*Port*", Some(target.port.to_string())),
            FormField::text(
                "*Server Public Key*",
                Some(target.server_public_key.clone()),
            ),
            FormField::text("Description", target.description.clone()),
            FormField::text("Proxy", target.proxy.clone()),
            FormField::checkbox("Is Active", target.is_active),
        ]);

        let active_model = if is_new {
            target::ActiveModel {
                id: Set(target.id),
                port: Set(target.port.into()),
                is_active: Set(target.is_active),
                updated_by: Set(target.updated_by),
                ..Default::default()
            }
        } else {
            target::ActiveModel {
                id: Unchanged(target.id),
                updated_by: Set(target.updated_by),
                ..Default::default()
            }
        };

        Self {
            target,
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
        let name = self.form.get_text(F_NAME).trim().to_string();
        if self.target.name != name || self.target.name.is_empty() {
            validate::varify_name(&name).map_err(|e| AppError::Admin(AdminError::Validate(e)))?;
            self.active_model.name = Set(name.clone());
        }

        let hostname = self.form.get_text(F_HOSTNAME).trim().to_string();
        if self.target.hostname != hostname || self.target.hostname.is_empty() {
            validate::varify_hostname(&hostname)
                .map_err(|e| AppError::Admin(AdminError::Validate(e)))?;
            self.active_model.hostname = Set(hostname.clone());
        }

        // Compared as text, so a re-typed but identical port is not a write.
        let port = self.form.get_text(F_PORT).trim().to_string();
        if self.target.port.to_string() != port {
            let port = validate::varify_port(&port)
                .map_err(|e| AppError::Admin(AdminError::Validate(e)))?;
            self.active_model.port = Set(port.into());
        }

        let server_public_key = self.form.get_text(F_SERVER_PUBLIC_KEY).trim().to_string();
        if self.target.server_public_key != server_public_key
            || self.target.server_public_key.is_empty()
        {
            validate::varify_server_public_key(&server_public_key)
                .map_err(|e| AppError::Admin(AdminError::Validate(e)))?;
            self.active_model.server_public_key = Set(server_public_key.clone());
        }

        let description = self.form.get_text(F_DESCRIPTION).trim().to_string();
        let description = (!description.is_empty()).then_some(description);
        if self.target.description != description {
            self.active_model.description = Set(description.clone());
        }

        let proxy = self.form.get_text(F_PROXY).trim().to_string();
        let proxy = (!proxy.is_empty()).then_some(proxy);
        if self.target.proxy != proxy {
            if let Some(p) = proxy.as_ref() {
                validate::varify_proxy(p).map_err(|e| AppError::Admin(AdminError::Validate(e)))?;
            }
            self.active_model.proxy = Set(proxy.clone());
        }

        let is_active = self.form.get_checkbox(F_IS_ACTIVE);
        if self.target.is_active != is_active {
            self.active_model.is_active = Set(is_active);
        }

        Ok(())
    }
}

impl Widget for &mut TargetEditor {
    fn render(self, area: Rect, buf: &mut Buffer) {
        self.form.render_ui(area, buf);
    }
}
