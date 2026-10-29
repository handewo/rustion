use super::super::error::AdminError;
use super::super::validate;
use crate::database::entity::secret;
use crate::database::models::target_secret::Secret;
use crate::error::Error;
use crate::server::app::error::AppError;
use crate::server::widgets::*;
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{buffer::Buffer, layout::Rect};
use sea_orm::ActiveValue::{Set, Unchanged};
use std::sync::Arc;

// Field indices
const F_NAME: usize = 0;
const F_USER: usize = 1;
const F_PASSWORD: usize = 2;
const F_IS_ACTIVE: usize = 3;
const F_PRIVATE_KEY: usize = 4;

/// The two secret columns leave this editor as plaintext: deriving the public key
/// from a private key needs the key in the clear, and so does the passphrase that
/// unlocks it. `manage.rs` encrypts them on the way to the repository — see
/// [`Self::password_updated`] and [`Self::private_key_updated`].
#[derive(Debug)]
pub(super) struct SecretEditor<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    pub secret: Secret,
    pub active_model: secret::ActiveModel,
    pub form: FormEditor,
    backend: Arc<B>,
    tr: &'static Strings,
}

impl<B> SecretEditor<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    pub fn new(secret: Secret, is_new: bool, backend: Arc<B>, tr: &'static Strings) -> Self {
        let form = FormEditor::new(vec![
            FormField::text(|tr| tr.field_name, Some(secret.name.clone())),
            FormField::text(|tr| tr.field_secret_user, Some(secret.user.clone())),
            FormField::text_masked(|tr| tr.field_password, Some(secret.print_password()), '*'),
            FormField::checkbox(|tr| tr.field_is_active, secret.is_active),
            FormField::multiline(
                |tr| tr.field_private_key,
                Some(&[secret.print_private_key()]),
                8,
            ),
        ]);

        let active_model = if is_new {
            secret::ActiveModel {
                id: Set(secret.id),
                is_active: Set(secret.is_active),
                updated_by: Set(secret.updated_by),
                ..Default::default()
            }
        } else {
            secret::ActiveModel {
                id: Unchanged(secret.id),
                updated_by: Set(secret.updated_by),
                ..Default::default()
            }
        };

        Self {
            secret,
            active_model,
            form,
            backend,
            tr,
        }
    }

    pub fn handle_paste_event(&mut self, paste: &str) -> bool {
        self.form.handle_paste_event(paste)
    }

    pub fn handle_key_event(&mut self, key: KeyCode, modifiers: KeyModifiers) -> bool {
        match self.form.handle_key_event(key, modifiers) {
            FormEvent::Save => {
                if let Err(e) = self.save_secret() {
                    self.form
                        .set_save_error(vec![validate::describe(&e, self.tr)]);
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
        let name = self.form.get_text(F_NAME).trim().to_string();
        if self.secret.name != name || self.secret.name.is_empty() {
            validate::varify_name(&name).map_err(|e| AppError::Admin(AdminError::Validate(e)))?;
            self.active_model.name = Set(name.clone());
        }

        let user = self.form.get_text(F_USER).trim().to_string();
        if self.secret.user != user || self.secret.user.is_empty() {
            validate::varify_secret_user(&user)
                .map_err(|e| AppError::Admin(AdminError::Validate(e)))?;
            self.active_model.user = Set(user.clone());
        }

        // The form only ever shows a mask, so "differs from the mask" is the one
        // available signal that the operator typed something.
        // TODO: A better method is needed here.
        let password = self.form.get_text(F_PASSWORD).trim().to_string();
        if !password.is_empty() {
            self.active_model.password = Set(Some(self.backend.encrypt_plain_text(&password)?))
        } else {
            if !self.secret.print_password().is_empty() {
                self.active_model.password = Set(None)
            }
        }

        let is_active = self.form.get_checkbox(F_IS_ACTIVE);
        if self.secret.is_active != is_active {
            self.active_model.is_active = Set(is_active);
        }

        // TODO: A better method is needed here.
        let private_key = self
            .form
            .get_multiline(F_PRIVATE_KEY)
            .join("\n")
            .trim()
            .to_string();
        if private_key.is_empty() {
            if !self.secret.print_private_key().is_empty() {
                self.active_model.private_key = Set(None);
                self.active_model.public_key = Set(None);
            }
        } else {
            // Only a passphrase entered in this same edit can unlock an
            // encrypted key; the stored one is ciphertext by now.
            let public_key = validate::varify_private_key(
                &private_key,
                (!password.is_empty()).then_some(password.as_str()),
            )
            .map_err(|e| AppError::Admin(AdminError::Validate(e)))?;
            self.active_model.private_key =
                Set(Some(self.backend.encrypt_plain_text(&private_key)?));
            self.active_model.public_key = Set(Some(public_key));
        }

        Ok(())
    }
}

impl<B> SecretEditor<B>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    pub fn render(&mut self, area: Rect, buf: &mut Buffer, theme: &Theme) {
        self.form.render_ui(area, buf, theme, self.tr);
    }
}
