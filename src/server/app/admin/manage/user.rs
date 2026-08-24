use super::super::error::AdminError;
use super::super::validate;
use crate::database::entity::user;
use crate::database::models::User;
use crate::error::Error;
use crate::server::app::error::AppError;
use crate::server::widgets::*;
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{buffer::Buffer, layout::Rect, widgets::Widget};
use sea_orm::ActiveValue::{Set, Unchanged};

// Field indices
const F_USERNAME: usize = 0;
const F_EMAIL: usize = 1;
const F_PASSWORD: usize = 2;
const F_FORCE_INIT_PASS: usize = 3;
const F_IS_ACTIVE: usize = 4;
const F_AUTHORIZED_KEYS: usize = 5;

#[derive(Debug)]
pub struct UserEditor {
    pub user: User,
    pub active_model: user::ActiveModel,
    pub form: FormEditor,
    pub generate_password: bool,
}

impl UserEditor {
    pub fn new(user: User, is_new: bool) -> Self {
        let form = FormEditor::new(vec![
            FormField::text("*Username*", Some(user.username.clone())),
            FormField::text("Email", user.email.clone()),
            FormField::checkbox("Generate New Password", false),
            FormField::checkbox("Force Init Password", user.force_init_pass),
            FormField::checkbox("Is Active", user.is_active),
            FormField::multiline(
                "Authorized Keys (one per line)",
                user.get_authorized_keys(),
                8,
            ),
        ]);

        let active_model = if is_new {
            user::ActiveModel {
                id: Set(user.id),
                force_init_pass: Set(user.force_init_pass),
                is_active: Set(user.is_active),
                updated_by: Set(user.updated_by),
                ..Default::default()
            }
        } else {
            user::ActiveModel {
                id: Unchanged(user.id),
                updated_by: Set(user.updated_by),
                ..Default::default()
            }
        };

        Self {
            user,
            active_model,
            form,
            generate_password: false,
        }
    }

    pub fn handle_paste_event(&mut self, paste: &str) -> bool {
        self.form.handle_paste_event(paste)
    }

    pub fn handle_key_event(&mut self, key: KeyCode, modifiers: KeyModifiers) -> bool {
        match self.form.handle_key_event(key, modifiers) {
            FormEvent::Save => {
                if let Err(e) = self.save_user() {
                    let lines = if let Error::App(AppError::Admin(AdminError::Validate(
                        validate::ValidateError::AuthorizedKeyInvalid(ref idx),
                    ))) = e
                    {
                        vec![
                            String::from("Invalid authorized keys"),
                            format!(
                                "Line number: {}",
                                idx.iter()
                                    .map(|x| (x + 1).to_string())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ),
                        ]
                    } else {
                        vec![e.to_string()]
                    };
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

    fn save_user(&mut self) -> Result<(), Error> {
        let username = self.form.get_text(F_USERNAME).trim().to_string();
        if self.user.username != username || self.user.username.is_empty() {
            validate::varify_username(&username)
                .map_err(|e| AppError::Admin(AdminError::Validate(e)))?;
            self.active_model.username = Set(username);
        }

        let email = self.form.get_text(F_EMAIL).trim().to_string();
        let email = (!email.is_empty()).then_some(email);
        if self.user.email != email {
            if let Some(e) = email.as_ref() {
                validate::varify_email(e).map_err(|e| AppError::Admin(AdminError::Validate(e)))?;
            }
            self.active_model.email = Set(email);
        }

        self.generate_password = self.form.get_checkbox(F_PASSWORD);

        let force_init_pass = self.form.get_checkbox(F_FORCE_INIT_PASS);
        if self.user.force_init_pass != force_init_pass {
            self.active_model.force_init_pass = Set(force_init_pass);
        }
        let is_active = self.form.get_checkbox(F_IS_ACTIVE);
        if self.user.is_active != is_active {
            self.active_model.is_active = Set(is_active);
        }

        let authorized_keys = self
            .form
            .get_multiline(F_AUTHORIZED_KEYS)
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<String>>();
        self.form
            .get_multiline_mut(F_AUTHORIZED_KEYS)
            .reset_lines(&authorized_keys);
        let authorized_keys = (!authorized_keys.is_empty()).then_some(authorized_keys);
        if self.user.get_authorized_keys() != authorized_keys.as_deref() {
            if let Some(ref keys) = authorized_keys {
                validate::varify_authorized_keys(keys)
                    .map_err(|e| AppError::Admin(AdminError::Validate(e)))?;
            }
            self.active_model.authorized_keys = Set(authorized_keys.map(|v| v.into()))
        }

        Ok(())
    }
}

impl Widget for &mut UserEditor {
    fn render(self, area: Rect, buf: &mut Buffer) {
        self.form.render_ui(area, buf);
    }
}
