use crate::database::error::DatabaseError;
use crate::database::models::target_secret::Secret;
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
const F_USER: usize = 1;
const F_PASSWORD: usize = 2;
const F_IS_ACTIVE: usize = 3;
const F_PRIVATE_KEY: usize = 4;

#[derive(Debug)]
pub struct SecretEditor {
    pub secret: Secret,
    pub form: FormEditor,
    pub private_key_updated: bool,
    pub password_updated: bool,
}

impl SecretEditor {
    pub fn new(secret: Secret) -> Self {
        let form = FormEditor::new(vec![
            FormField::text("*Name*", Some(secret.name.clone())),
            FormField::text("*User*", Some(secret.user.clone())),
            FormField::text_masked("Password", Some(secret.print_password()), '*'),
            FormField::checkbox("Is Active", secret.is_active),
            FormField::multiline("Private Key", Some(&[secret.print_private_key()]), 8),
        ]);
        Self {
            secret,
            form,
            private_key_updated: false,
            password_updated: false,
        }
    }

    pub fn handle_paste_event(&mut self, paste: &str) -> bool {
        self.form.handle_paste_event(paste)
    }

    pub fn handle_key_event(&mut self, key: KeyCode, modifiers: KeyModifiers) -> bool {
        match self.form.handle_key_event(key, modifiers) {
            FormEvent::Save => {
                if let Err(e) = self.save_secret() {
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

    fn save_secret(&mut self) -> Result<(), Error> {
        self.secret.name = self.form.get_text(F_NAME).trim().into();
        self.secret.user = self.form.get_text(F_USER).trim().into();

        let password = self.form.get_text(F_PASSWORD).trim().to_string();
        // If the password field was modified (not the placeholder), update it
        // TODO: A better method is needed here.
        if password != self.secret.print_password() {
            if password.is_empty() {
                let _ = self.secret.take_password();
            } else {
                self.secret.set_password(Some(password));
            }
            self.password_updated = true;
        }

        self.secret.is_active = self.form.get_checkbox(F_IS_ACTIVE);

        let private_key = self
            .form
            .get_multiline(F_PRIVATE_KEY)
            .join("\n")
            .trim()
            .to_string();
        // If the private key field was modified (not the placeholder), update it
        // TODO: A better method is needed here.
        if private_key != self.secret.print_private_key() {
            if private_key.is_empty() {
                let _ = self.secret.take_private_key();
                let _ = self.secret.take_public_key();
            } else {
                self.secret.set_private_key(Some(private_key));
            }
            self.private_key_updated = true;
        }

        self.secret
            .validate(self.private_key_updated)
            .map_err(|e| Error::Database(DatabaseError::SecretValidation(e)))
    }
}

impl Widget for &mut SecretEditor {
    fn render(self, area: Rect, buf: &mut Buffer) {
        self.form.render_ui(area, buf);
    }
}
