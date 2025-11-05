use crate::database::models::User;
use crate::error::Error;
use crate::server::HandlerLog;
use crossbeam_channel::{unbounded, Receiver, Sender};
use crossterm::event::{NoTtyEvent, SenderWriter};
use log::{debug, warn};
use russh::server as ru_server;
use russh::{ChannelId, Pty};
use std::sync::Arc;
use tokio::sync::mpsc;

static LOG_TYPE: &str = "password";

pub(crate) struct ChangePassword {
    handler_id: String,
    tty: NoTtyEvent,
    send_to_tty: Sender<Vec<u8>>,
    recv_from_tty: Receiver<Vec<u8>>,
    user: Option<User>,
    log: HandlerLog,
}

enum Status {
    Type,
    Retype,
    FinishType(String),
    Invalid,
    SameAsOri,
    DoNotMatch,
    Terminate,
}

impl ChangePassword {
    pub(crate) fn new(handler_id: String, user: Option<User>, log: HandlerLog) -> Self {
        let (send_to_tty, recv_from_session) = unbounded();
        let (tty, recv_from_tty) = NoTtyEvent::new(recv_from_session);
        Self {
            handler_id,
            tty,
            send_to_tty,
            recv_from_tty,
            user,
            log,
        }
    }

    pub(crate) async fn window_change_request(
        &mut self,
        _channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _session: &mut ru_server::Session,
    ) -> Result<(), Error> {
        let win_raw = crate::terminal::window_change(
            &mut self.tty,
            col_width,
            row_height,
            pix_width,
            pix_height,
        );

        self.send_to_tty
            .send(win_raw)
            .map_err(std::io::Error::other)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn pty_request(
        &mut self,
        _channel: ChannelId,
        _term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _modes: &[(Pty, u32)],
        _session: &mut ru_server::Session,
    ) -> Result<(), Error> {
        let _ = crate::terminal::window_change(
            &mut self.tty,
            col_width,
            row_height,
            pix_width,
            pix_height,
        );

        Ok(())
    }

    pub(crate) async fn shell_request<B>(
        &mut self,
        backend: Arc<B>,
        channel: ChannelId,
        session: &mut ru_server::Session,
    ) -> Result<(), Error>
    where
        B: 'static + crate::server::HandlerBackend + Send + Sync,
    {
        let handler_id = self.handler_id.clone();
        let handle_prompt = session.handle();
        let (send_status, mut recv_status) = mpsc::channel(1);
        let tty = self.tty.clone();

        let (send_to_session, mut recv_from_prompt) = mpsc::channel::<Vec<u8>>(1);
        let send_to_session_from_tty = send_to_session.clone();
        let mut user = self
            .user
            .take()
            .unwrap_or_else(|| panic!("[{}] user should not be none", handler_id));
        let user_clone = user.clone();
        let log = self.log.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    data = recv_from_prompt.recv() => {
                        match data {
                            Some(d) => {
                                if handle_prompt.data(channel, d.into()).await.is_err() {
                                    warn!("[{}] Fail to send data to session from prompt",handler_id);
                                    break;
                                };
                            }
                            None => {
                                if recv_from_prompt.is_closed() {
                                    if handle_prompt.close(channel).await.is_err() {
                                        warn!("[{}] Fail to close channel",handler_id);
                                    };
                                    break;
                                }
                            }
                        }
                    }
                    status = recv_status.recv() => {
                        match status {
                            Some(s) => {
                                match s {
                                    Status::FinishType(password) => {
                                        user.force_init_pass=false;
                                        let mut exit_status = 0;
                                        if backend.update_user_password(password.clone(),user).await.is_err() {
                                            exit_status = 1;
                                             handle_prompt.data(channel, "\r\npassword updated failed.\r\n"
                                                .into()).await.is_err().then(|| warn!("[{}] Fail to send password prompt to session from prompt", handler_id));

                                        } else {
                                            handle_prompt.data(channel, "\r\npassword updated successfully.\r\n"
                                                .into()).await.is_err().then(|| warn!("[{}] Fail to send password prompt to session from prompt", handler_id));
                                            log(LOG_TYPE.into(),"password updated successfully".into()).await;
                                        }
                                        if handle_prompt.exit_status_request(channel,exit_status).await.is_err() {
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
                                    _ =>{
                                        unreachable!();
                                    }
                                }

                            }
                            None => {
                                if recv_status.is_closed() {
                                    if handle_prompt.close(channel).await.is_err() {
                                        warn!("[{}] Fail to close channel", handler_id);
                                    };
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        });
        let handler_id = self.handler_id.clone();

        use reedline::{DefaultPrompt, DefaultPromptSegment, FileBackedHistory, Reedline, Signal};
        let history = Box::new(
            FileBackedHistory::new(0).unwrap_or_else(|_| panic!("[{}] safe capacity", handler_id)),
        );

        let mut line_editor = Reedline::create(tty, SenderWriter::new(send_to_session.clone()))
            .with_ansi_colors(false)
            .with_disable_echo(true)
            .with_history(history);

        tokio::task::spawn_blocking(move || {
            let title = "You have to change password.\r\n";
            if let Err(e) = send_to_session.blocking_send(title.into()) {
                warn!(
                    "[{}] Fail to send data to channel from prompt: {}",
                    e, handler_id
                );
                return;
            };
            let prompt = "New password";
            let re_prompt = "Retype new password";
            let do_not_match = "Sorry, passwords do not match.\r\n";
            let same_as_ori = "The new password cannot be the same as the original password.\r\n";
            let requires = "Password must meet ALL these requirements:\r
- Minimum 8 characters\r
- At least one digit (0-9)\r
- At least one uppercase letter (A-Z)\r
- At least one lowercase letter (a-z)\r
- At least one special character (e.g., !@#$%^&*)\r\n";

            let mut password = String::new();
            let mut status = Status::Type;

            loop {
                match status {
                    Status::Type => {
                        let prompt = DefaultPrompt::new(
                            DefaultPromptSegment::Basic(prompt.to_string()),
                            DefaultPromptSegment::Empty,
                        );
                        let sig = line_editor.read_line(&prompt);
                        match sig {
                            Ok(Signal::Success(p)) => {
                                password = p;
                                if !is_valid_password(&password) {
                                    status = Status::Invalid;
                                } else if user_clone.verify_password(&password) {
                                    status = Status::SameAsOri;
                                } else {
                                    status = Status::Retype;
                                }
                            }
                            Ok(Signal::CtrlD | Signal::CtrlC) => {
                                status = Status::Terminate;
                            }
                            Err(e) => {
                                status = Status::Terminate;
                                warn!("[{}] Fail to get signal from prompt: {}", e, handler_id);
                            }
                        }
                    }
                    Status::Retype => {
                        let prompt = DefaultPrompt::new(
                            DefaultPromptSegment::Basic(re_prompt.to_string()),
                            DefaultPromptSegment::Empty,
                        );
                        let sig = line_editor.read_line(&prompt);
                        match sig {
                            Ok(Signal::Success(p)) => {
                                if p != password {
                                    status = Status::DoNotMatch;
                                } else {
                                    status = Status::FinishType(p);
                                }
                            }
                            Ok(Signal::CtrlD | Signal::CtrlC) => {
                                status = Status::Terminate;
                            }
                            Err(e) => {
                                status = Status::Terminate;
                                warn!("[{}] Fail to get signal from prompt: {}", e, handler_id);
                            }
                        }
                    }
                    Status::DoNotMatch => {
                        if let Err(e) = send_to_session.blocking_send(do_not_match.into()) {
                            warn!(
                                "[{}] Fail to send data to channel from prompt: {}",
                                e, handler_id
                            );
                            break;
                        };
                        status = Status::Type;
                    }
                    Status::SameAsOri => {
                        if let Err(e) = send_to_session.blocking_send(same_as_ori.into()) {
                            warn!(
                                "[{}] Fail to send data to channel from prompt: {}",
                                e, handler_id
                            );
                            break;
                        };
                        status = Status::Type;
                    }
                    Status::Invalid => {
                        if let Err(e) = send_to_session.blocking_send(requires.into()) {
                            warn!(
                                "[{}] Fail to send data to channel from prompt: {}",
                                e, handler_id
                            );
                            break;
                        };
                        status = Status::Type;
                    }
                    Status::Terminate => {
                        if let Err(e) = send_status.blocking_send(status) {
                            warn!("[{}] Fail to send status: {}", e, handler_id);
                        };
                        break;
                    }
                    Status::FinishType(_) => {
                        if let Err(e) = send_status.blocking_send(status) {
                            warn!("[{}] Fail to send status: {}", e, handler_id);
                        };
                        break;
                    }
                }
            }
        });

        let recv_from_tty = self.recv_from_tty.clone();
        let handler_id = self.handler_id.clone();
        tokio::task::spawn_blocking(move || {
            while let Ok(data) = recv_from_tty.recv() {
                if send_to_session_from_tty.blocking_send(data).is_err() {
                    debug!("[{}] Fail to send data to session from tty", handler_id);
                    break;
                }
            }
        });

        session.channel_success(channel)?;
        Ok(())
    }

    pub(crate) async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut ru_server::Session,
    ) -> Result<(), Error> {
        self.send_to_tty
            .send(data.into())
            .map_err(std::io::Error::other)?;
        Ok(())
    }
}

/// Returns `true` when `password` complies with every rule.
pub fn is_valid_password(p: &str) -> bool {
    p.len() >= 8
        && p.len() < 64
        && p.chars().any(|c| c.is_ascii_digit())
        && p.chars().any(|c| c.is_ascii_uppercase())
        && p.chars().any(|c| c.is_ascii_lowercase())
        && !p.chars().any(|c| c.is_ascii_whitespace())
        && p.is_ascii()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_passwords() {
        assert!(is_valid_password("Abcdef1!"));
        assert!(is_valid_password("Str0ng&P@ssw0rd"));
    }

    #[test]
    fn bad_passwords() {
        assert!(!is_valid_password("short1!")); // too short
        assert!(!is_valid_password("LongEnough")); // no digit, no special
        assert!(!is_valid_password("longenough1")); // no upper, no special
        assert!(!is_valid_password("LONGENOUGH1!")); // no lower
    }
}
