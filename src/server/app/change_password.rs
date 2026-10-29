use super::PtyParams;
use crate::database::entity::user;
use crate::database::models::User;
use crate::error::Error;
use crate::fill;
use crate::i18n::Strings;
use crate::server::event_log::{Audit, EventKind};
use bytes::Bytes;
use crossterm::event::SenderWriter;
use inquire::{
    Password, PasswordDisplayMode, min_length,
    validator::{StringValidator, Validation},
};
use log::{debug, warn};
use russh::ChannelId;
use russh::server as ru_server;
use sea_orm::ActiveValue::{Set, Unchanged};
use tokio::sync::mpsc;

// Custom validators for password requirements
#[derive(Clone)]
struct HasDigitValidator(&'static Strings);

impl StringValidator for HasDigitValidator {
    fn validate(&self, input: &str) -> Result<Validation, inquire::error::CustomUserError> {
        Ok(if input.chars().any(|c| c.is_ascii_digit()) {
            Validation::Valid
        } else {
            Validation::Invalid(self.0.pw_digit.into())
        })
    }
}

#[derive(Clone)]
struct OldPasswordValidator(User, &'static Strings);

impl StringValidator for OldPasswordValidator {
    fn validate(&self, input: &str) -> Result<Validation, inquire::error::CustomUserError> {
        Ok(if !self.0.verify_password(input) {
            Validation::Valid
        } else {
            Validation::Invalid(self.1.pw_same.into())
        })
    }
}

#[derive(Clone)]
struct HasUppercaseValidator(&'static Strings);

impl StringValidator for HasUppercaseValidator {
    fn validate(&self, input: &str) -> Result<Validation, inquire::error::CustomUserError> {
        Ok(if input.chars().any(|c| c.is_ascii_uppercase()) {
            Validation::Valid
        } else {
            Validation::Invalid(self.0.pw_uppercase.into())
        })
    }
}

#[derive(Clone)]
struct HasLowercaseValidator(&'static Strings);

impl StringValidator for HasLowercaseValidator {
    fn validate(&self, input: &str) -> Result<Validation, inquire::error::CustomUserError> {
        Ok(if input.chars().any(|c| c.is_ascii_lowercase()) {
            Validation::Valid
        } else {
            Validation::Invalid(self.0.pw_lowercase.into())
        })
    }
}

#[derive(Clone)]
struct HasSpecialCharValidator(&'static Strings);

impl StringValidator for HasSpecialCharValidator {
    fn validate(&self, input: &str) -> Result<Validation, inquire::error::CustomUserError> {
        Ok(if input.chars().any(|c| c.is_ascii_punctuation()) {
            Validation::Valid
        } else {
            Validation::Invalid(self.0.pw_special.into())
        })
    }
}

/// The shortest new password accepted.
const MIN_LENGTH: usize = 8;

enum Status {
    Finish(String),
    Terminate,
}

pub(crate) async fn shell_request<B>(
    user: User,
    params: PtyParams<B>,
    channel: ChannelId,
    session: &mut ru_server::Session,
) -> Result<(), Error>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    let tr = params.lang.strings();
    let (handler_id, _, _, backend, tty, mut recv_from_tty, log, _) = params.split();
    let handle_prompt = session.handle();
    let (send_status, mut recv_status) = mpsc::channel(1);
    let (tty, _) = tty.split();

    let (send_to_session, mut recv_from_prompt) = mpsc::channel::<Bytes>(4);
    let send_to_session_from_tty = send_to_session.clone();
    let user_for_prompt = user.clone();
    let username = user.username.clone();
    let user_id = user.id;
    let log = log.scoped(EventKind::Password);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                data = recv_from_prompt.recv() => {
                    match data {
                        Some(d) => {
                            if handle_prompt.data(channel, d).await.is_err() {
                                warn!("[{}] Fail to send data to session from prompt",handler_id);
                                break;
                            };
                        }
                        // Every sender is gone, so nothing more can arrive. The
                        // `is_closed()` check it used to guard on is always true here for
                        // exactly that reason, and when it was false this arm did nothing
                        // and `select!` re-polled a closed channel — a hot spin measured
                        // at ~5.8M iterations in 200ms.
                        None => {
                            if handle_prompt.close(channel).await.is_err() {
                                warn!("[{}] Fail to close channel",handler_id);
                            };
                            break;
                        }
                    }
                }
                status = recv_status.recv() => {
                    match status {
                        Some(s) => {
                            // Drop-order, not write-order, is what puts data here. `Password::prompt`
                            // owns its `Backend` as a local, so it is dropped as `prompt` returns —
                            // before `res` is bound and so before `send_status.send()`. Both `Drop`
                            // impls (inquire's `FrameRenderer` and `CrosstermTerminal`) flush their
                            // remaining buffer with `thread::spawn(blocking_write_all) + join()`,
                            // which only guarantees the bytes are *buffered* into `recv_from_prompt`.
                            // They are still sitting there when we get here, so drain them first:
                            // otherwise `close` below discards the cursor-show and end-position
                            // teardown, and the `Status::Finish` arm prints its result line *before*
                            // teardown that was written before it. `try_recv` because the tty task
                            // holds a `send_to_session` clone for the connection's lifetime, so this
                            // channel never closes and `recv` would block forever.
                            while let Ok(d) = recv_from_prompt.try_recv() {
                                if handle_prompt.data(channel, d).await.is_err() {
                                    warn!("[{}] Fail to flush prompt teardown to session", handler_id);
                                    break;
                                }
                            }
                            match s {
                                Status::Finish(password) => {
                                    let mut active_model = user::ActiveModel{
                                        id: Unchanged(user_id),
                                        updated_by: Set(user_id),
                                        ..Default::default()
                                    };
                                    if user.force_init_pass {
                                        active_model.force_init_pass=Set(false)
                                    };
                                    let mut exit_status = 0;
                                    if backend.update_user_password(password, active_model).await.is_err() {
                                        exit_status = 1;
                                        warn!("[{}] Password update failed for user '{}({})'", handler_id, username, user_id);
                                        handle_prompt.data(channel, format!("{}\r\n", tr.pw_failed)
                                            ).await.is_err().then(|| warn!("[{}] Fail to send password prompt to session from prompt", handler_id));
                                    } else {
                                        debug!("[{}] Password updated successfully for user '{}({})'", handler_id, username, user_id);
                                        handle_prompt.data(channel, format!("{}\r\n", tr.pw_updated)
                                            ).await.is_err().then(|| warn!("[{}] Fail to send password prompt to session from prompt", handler_id));
                                        log.record(Audit::PasswordChanged).await;
                                    }
                                    if handle_prompt.exit_status_request(channel, exit_status).await.is_err() {
                                        warn!("[{}] Fail to send exit status", handler_id);
                                    };
                                    if handle_prompt.close(channel).await.is_err() {
                                        warn!("[{}] Fail to close channel", handler_id);
                                    };
                                    break;
                                }
                                Status::Terminate => {
                                    if handle_prompt.close(channel).await.is_err() {
                                        warn!("[{}] Fail to close channel", handler_id);
                                    };
                                    break;
                                }
                            }
                        }
                        // The prompt task returned without sending a status, so
                        // `send_status` dropped. Drain first for the same reason the
                        // `Some` arm does: the `Drop` teardown may still be buffered.
                        None => {
                            while let Ok(d) = recv_from_prompt.try_recv() {
                                if handle_prompt.data(channel, d).await.is_err() {
                                    break;
                                }
                            }
                            if handle_prompt.close(channel).await.is_err() {
                                warn!("[{}] Fail to close channel", handler_id);
                            };
                            break;
                        }
                    }
                }
            }
        }
    });

    tokio::spawn(async move {
        let validators: &[Box<dyn StringValidator>] = &[
            Box::new(min_length!(
                MIN_LENGTH,
                fill!(tr.pw_min_length, min = MIN_LENGTH)
            )),
            Box::new(HasDigitValidator(tr)),
            Box::new(HasUppercaseValidator(tr)),
            Box::new(HasLowercaseValidator(tr)),
            Box::new(HasSpecialCharValidator(tr)),
            Box::new(OldPasswordValidator(user_for_prompt, tr)),
        ];

        let res = Password::new(tr.pw_prompt)
            .with_display_toggle_enabled()
            .with_display_mode(PasswordDisplayMode::Hidden)
            .with_validators(validators)
            .with_formatter(&|_| String::new())
            .with_help_message(tr.pw_help)
            .with_custom_confirmation_message(tr.pw_confirm)
            .with_custom_confirmation_error_message(tr.pw_mismatch)
            .prompt(tty, SenderWriter::new(send_to_session))
            .await;

        let status = match res {
            Ok(password) => Status::Finish(password),
            Err(e) => {
                debug!("[{}] Change password error: {}", handler_id, e);
                Status::Terminate
            }
        };

        if let Err(e) = send_status.send(status).await {
            warn!("[{}] Fail to send status: {}", handler_id, e);
        };
    });

    tokio::spawn(async move {
        while let Some(data) = recv_from_tty.recv().await {
            if send_to_session_from_tty.send(data).await.is_err() {
                debug!("[{}] Fail to send data to session from tty", handler_id);
                break;
            }
        }
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Lang;
    use inquire::validator::StringValidator;

    const EN: &Strings = Lang::En.strings();

    fn validate_all(input: &str) -> bool {
        let validators: &[Box<dyn StringValidator>] = &[
            Box::new(min_length!(8)),
            Box::new(HasDigitValidator(EN)),
            Box::new(HasUppercaseValidator(EN)),
            Box::new(HasLowercaseValidator(EN)),
            Box::new(HasSpecialCharValidator(EN)),
        ];
        validators
            .iter()
            .all(|v| matches!(v.validate(input), Ok(Validation::Valid)))
    }

    #[test]
    fn ok_passwords() {
        assert!(validate_all("Abcdef1!"));
        assert!(validate_all("Str0ng&P@ssw0rd"));
    }

    #[test]
    fn bad_passwords() {
        assert!(!validate_all("short1!")); // too short
        assert!(!validate_all("C5e5xNA0")); // no punctuation
        assert!(!validate_all("LongEnough")); // no digit, no special
        assert!(!validate_all("longenough1")); // no upper, no special
        assert!(!validate_all("LONGENOUGH1!")); // no lower
    }

    #[test]
    fn individual_validators() {
        let min_len = min_length!(8);
        let digit = HasDigitValidator(EN);
        let upper = HasUppercaseValidator(EN);
        let lower = HasLowercaseValidator(EN);
        let special = HasSpecialCharValidator(EN);

        // Test min length validator
        assert!(matches!(
            min_len.validate("12345678"),
            Ok(Validation::Valid)
        ));
        assert!(matches!(
            min_len.validate("1234567"),
            Ok(Validation::Invalid(_))
        ));

        // Test digit validator
        assert!(matches!(digit.validate("a1b"), Ok(Validation::Valid)));
        assert!(matches!(digit.validate("abc"), Ok(Validation::Invalid(_))));

        // Test uppercase validator
        assert!(matches!(upper.validate("Abc"), Ok(Validation::Valid)));
        assert!(matches!(upper.validate("abc"), Ok(Validation::Invalid(_))));

        // Test lowercase validator
        assert!(matches!(lower.validate("ABC"), Ok(Validation::Invalid(_))));
        assert!(matches!(lower.validate("AbC"), Ok(Validation::Valid)));

        // Test special character validator
        assert!(matches!(special.validate("abc!"), Ok(Validation::Valid)));
        assert!(matches!(
            special.validate("abc"),
            Ok(Validation::Invalid(_))
        ));
    }

    /// The reason a password is refused is in the session's language.
    #[test]
    fn refusals_are_worded_in_the_session_language() {
        let ja = Lang::Ja.strings();
        let refused = HasDigitValidator(ja).validate("abc").unwrap();
        assert_eq!(refused, Validation::Invalid(ja.pw_digit.into()));
    }
}
