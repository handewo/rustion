use crate::database::error::DatabaseError;
use crate::database::models::user::ValidateError;
use crate::database::models::User;
use crate::error::Error;
use crate::server::widgets::*;
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    widgets::Widget,
};

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
    pub form: FormEditor,
    pub generate_password: bool,
}

impl UserEditor {
    pub fn new(user: User) -> Self {
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
        Self {
            user,
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
                    let lines = if let Error::Database(DatabaseError::UserValidation(
                        ValidateError::AuthorizedKeyInvalid(ref idx),
                    )) = e
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
        self.user.username = self.form.get_text(F_USERNAME).trim().into();

        let email = self.form.get_text(F_EMAIL).trim().to_string();
        self.user.email = (!email.is_empty()).then_some(email);

        self.generate_password = self.form.get_checkbox(F_PASSWORD);
        self.user.force_init_pass = self.form.get_checkbox(F_FORCE_INIT_PASS);
        self.user.is_active = self.form.get_checkbox(F_IS_ACTIVE);

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
        self.user
            .set_authorized_keys((!authorized_keys.is_empty()).then_some(authorized_keys));

        self.user
            .validate()
            .map_err(|e| Error::Database(DatabaseError::UserValidation(e)))
    }
}

impl Widget for &mut UserEditor {
    fn render(self, area: Rect, buf: &mut Buffer) {
        self.form.render_ui(area, buf);
    }
}
