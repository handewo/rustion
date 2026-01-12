use crate::database::models::{TargetSecretName, User};
use crate::error::Error;
use crate::server::app::{Application, ConnectTarget};
use crate::server::HandlerLog;
use crossbeam_channel::{unbounded, Sender};
use crossterm::event::{NoTtyEvent, SenderWriter};
use log::{debug, trace, warn};
use reedline::{
    default_emacs_keybindings, ColumnarMenu, DefaultPrompt, DefaultPromptSegment, Emacs,
    ExampleHighlighter, FileBackedHistory, MenuBuilder, Reedline, ReedlineMenu, Signal,
};
use reedline::{KeyCode, KeyModifiers, Keybindings, ReedlineEvent};
use russh::server as ru_server;
use russh::{Channel, ChannelId};
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Clone)]
enum TerminalStatus {
    SelectTarget,
    SelectUser,
    Connect,
    Terminate,
}

pub(crate) struct TargetSelector {
    handler_id: String,
    user: Option<User>,

    allowed_targets: Option<Vec<TargetSecretName>>,

    // shell
    tty: Option<NoTtyEvent>,
    send_to_tty: Option<Sender<Vec<u8>>>,

    log: HandlerLog,
}

impl TargetSelector {
    pub(crate) fn new(id: String, user: Option<User>, log: HandlerLog) -> Self {
        Self {
            handler_id: id,
            user,
            allowed_targets: None,
            tty: None,
            send_to_tty: None,
            log,
        }
    }

    pub(crate) async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut ru_server::Session,
    ) -> Result<(), Error> {
        if let Some(sender) = self.send_to_tty.as_ref() {
            sender.send(data.into()).map_err(std::io::Error::other)?;
        }

        Ok(())
    }

    pub(crate) async fn channel_open_with_target_name<
        B: 'static + crate::server::HandlerBackend + Send + Sync,
    >(
        &mut self,
        backend: Arc<B>,
        target_name: String,
        _channel: Channel<ru_server::Msg>,
        _session: &mut ru_server::Session,
    ) -> Result<bool, Error> {
        let user = if let Some(u) = self.user.as_ref() {
            u
        } else {
            return Ok(false);
        };

        let user_id = user.id.as_str();
        let mut allowed_targets = backend.list_targets_for_user(user_id, true).await?;
        if allowed_targets.is_empty() {
            return Ok(false);
        }

        allowed_targets.retain(|target| target.target_name == target_name);

        if allowed_targets.is_empty() {
            return Ok(false);
        }

        self.allowed_targets = Some(allowed_targets);
        Ok(true)
    }

    pub(crate) async fn channel_open_session<
        B: 'static + crate::server::HandlerBackend + Send + Sync,
    >(
        &mut self,
        backend: Arc<B>,
        _channel: Channel<ru_server::Msg>,
        _session: &mut ru_server::Session,
    ) -> Result<bool, Error> {
        let user = if let Some(u) = self.user.as_ref() {
            u
        } else {
            return Ok(false);
        };

        let user_id = user.id.as_str();
        let allowed_targets = backend.list_targets_for_user(user_id, true).await?;
        trace!(
            "[{}] list targets: {:?}",
            self.handler_id,
            allowed_targets
                .iter()
                .map(|v| v.id.as_str())
                .collect::<Vec<&str>>()
        );
        if allowed_targets.is_empty() {
            return Ok(false);
        }

        self.allowed_targets = Some(allowed_targets);

        Ok(true)
    }

    pub(crate) async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: &mut ru_server::Session,
    ) -> Result<(), Error> {
        if let Some(tty) = self.tty.as_mut() {
            let win_raw =
                crate::terminal::window_change(tty, col_width, row_height, pix_width, pix_height);
            if let Some(sender) = self.send_to_tty.as_ref() {
                sender.send(win_raw).map_err(std::io::Error::other)?;
            }
            session.channel_success(channel)?;
        }

        session.channel_failure(channel)?;

        Ok(())
    }

    pub(crate) async fn shell_request<B>(
        &mut self,
        backend: Arc<B>,
        channel: ChannelId,
        session: &mut ru_server::Session,
        app_sender: mpsc::Sender<(ChannelId, Application)>,
        window_size: (u32, u32, u32, u32),
    ) -> Result<(), Error>
    where
        B: 'static + crate::server::HandlerBackend + Send + Sync,
    {
        let handler_id = self.handler_id.clone();
        let channel_id = channel;

        let user = self
            .user
            .take()
            .unwrap_or_else(|| panic!("[{}] user should not be none", handler_id));

        let allowed_targets = self
            .allowed_targets
            .take()
            .unwrap_or_else(|| panic!("[{}] at least one target available", handler_id));

        if allowed_targets.is_empty() {
            return Err(Error::App("No target available".into()));
        }

        let (send_status, mut recv_status) = mpsc::channel(1);

        let handle_prompt = session.handle();
        let handle_status = session.handle();

        // init tty
        let (send_to_tty, recv_from_session) = unbounded();
        let (mut tty, recv_from_tty) = NoTtyEvent::new(recv_from_session);

        let ws = window_size;
        let _ = crate::terminal::window_change(&mut tty, ws.0, ws.1, ws.2, ws.3);

        self.tty = Some(tty.clone());
        self.send_to_tty = Some(send_to_tty);

        let (send_to_session, mut recv_from_prompt) = mpsc::channel::<Vec<u8>>(1);
        let send_to_session_from_tty = send_to_session.clone();

        tokio::spawn(async move {
            // Not sure whether, if `recv_from_prompt.recv()` get `None` and
            // we don’t call `handle.close()`, the client will hang.
            while let Some(d) = recv_from_prompt.recv().await {
                if handle_prompt.data(channel, d.into()).await.is_err() {
                    warn!("[{}] Fail to send data to session from prompt", handler_id);
                    break;
                };
            }
        });

        let handler_id = self.handler_id.clone();
        tokio::spawn(async move {
            loop {
                match recv_status.recv().await {
                    Some(s) => match s {
                        TerminalStatus::SelectTarget => {}
                        TerminalStatus::SelectUser => {}
                        TerminalStatus::Connect => {
                            break;
                        }
                        TerminalStatus::Terminate => {
                            if handle_status.close(channel).await.is_err() {
                                warn!("[{}] Fail to close channel", handler_id);
                            };
                            break;
                        }
                    },
                    None => {
                        if recv_status.is_closed() {
                            if handle_status.close(channel).await.is_err() {
                                warn!("[{}] Fail to close channel", handler_id);
                            };
                            break;
                        }
                    }
                }
            }
        });

        let handler_id = self.handler_id.clone();
        tokio::task::spawn_blocking(move || {
            while let Ok(data) = recv_from_tty.recv() {
                if send_to_session_from_tty.blocking_send(data).is_err() {
                    debug!("[{}] Fail to send data to session from tty", handler_id);
                    break;
                }
            }
        });

        let tokio_handle = tokio::runtime::Handle::current();
        let handler_log = self.log.clone();
        let handler_id = self.handler_id.clone();

        tokio::task::spawn_blocking(move || {
            // TODO: Classify different target type in future
            let server_prompt = "Select server";
            let user_prompt = "Select system user";
            let mut status = TerminalStatus::SelectTarget;
            let mut selected_target_name = String::new();

            let allowed_targets = allowed_targets;

            let mut selected_target_sec_name = None;
            let backend = backend;
            let target_commands: Vec<String> = allowed_targets
                .iter()
                .map(|v| v.target_name.clone())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();

            // init prompt
            let history = Box::new(
                FileBackedHistory::new(0)
                    .unwrap_or_else(|_| panic!("[{}] safe capacity", handler_id)),
            );

            let mut line_editor = Reedline::create(tty, SenderWriter::new(send_to_session.clone()))
                .with_quick_completions(true)
                .with_menu(ReedlineMenu::EngineCompleter(Box::new(
                    ColumnarMenu::default().with_name("completion_menu"),
                )))
                .with_partial_completions(true)
                .with_history(history);

            let mut keybindings = default_emacs_keybindings();
            add_menu_keybindings(&mut keybindings);

            let edit_mode = Box::new(Emacs::new(keybindings));

            line_editor = line_editor.with_edit_mode(edit_mode);

            loop {
                match status {
                    TerminalStatus::SelectTarget => {
                        if target_commands.len() == 1 {
                            status = TerminalStatus::SelectUser;
                            selected_target_name = target_commands.first().unwrap().clone();
                            continue;
                        }
                        let prompt = DefaultPrompt::new(
                            DefaultPromptSegment::Basic(server_prompt.to_string()),
                            DefaultPromptSegment::Empty,
                        );

                        let mut completer = Box::new(
                            crate::terminal::BastionCompleter::with_inclusions(&['-', '_'])
                                .set_min_word_len(0),
                        );
                        completer.insert(target_commands.clone());

                        line_editor =
                            line_editor
                                .with_completer(completer)
                                .with_highlighter(Box::new(ExampleHighlighter::new(
                                    target_commands.clone(),
                                )));
                        let sig = line_editor.read_line(&prompt);

                        match sig {
                            Ok(Signal::Success(p)) => {
                                if p.is_empty() {
                                    continue;
                                }
                                if p.as_str() == "quit" || p.as_str() == "exit" {
                                    status = TerminalStatus::Terminate;
                                    continue;
                                }
                                if !target_commands.iter().any(|v| v == &p) {
                                    status = TerminalStatus::SelectTarget;
                                    if let Err(e) = send_to_session.blocking_send(
                                        format!("Server: {} doesn't exist", p).into(),
                                    ) {
                                        warn!(
                                            "[{}] Fail to send data to channel from prompt: {}",
                                            handler_id, e
                                        );
                                        status = TerminalStatus::Terminate;
                                    };
                                    continue;
                                }
                                status = TerminalStatus::SelectUser;
                                selected_target_name = p;
                            }
                            Ok(Signal::CtrlC) => {
                                continue;
                            }
                            Ok(Signal::CtrlD) => status = TerminalStatus::Terminate,
                            Err(e) => {
                                warn!("[{}] Fail to get signal from prompt: {}", handler_id, e);
                            }
                        }
                    }
                    TerminalStatus::SelectUser => {
                        let user_commands: Vec<String> = allowed_targets
                            .iter()
                            .filter(|v| v.target_name == selected_target_name)
                            .map(|v| v.secret_user.clone())
                            .collect::<std::collections::HashSet<_>>()
                            .into_iter()
                            .collect();

                        if user_commands.len() == 1 {
                            selected_target_sec_name = Some(
                                allowed_targets
                                    .iter()
                                    .find(|v| {
                                        &v.secret_user == user_commands.first().unwrap()
                                            && v.target_name == selected_target_name
                                    })
                                    .unwrap_or_else(|| panic!("[{}] secret must exist", handler_id))
                                    .clone(),
                            );
                            status = TerminalStatus::Connect;
                            continue;
                        }

                        let prompt = DefaultPrompt::new(
                            DefaultPromptSegment::Basic(user_prompt.to_string()),
                            DefaultPromptSegment::Empty,
                        );

                        let mut completer = Box::new(
                            crate::terminal::BastionCompleter::with_inclusions(&['-', '_'])
                                .set_min_word_len(0),
                        );
                        completer.insert(user_commands.clone());

                        line_editor =
                            line_editor
                                .with_completer(completer)
                                .with_highlighter(Box::new(ExampleHighlighter::new(
                                    user_commands.clone(),
                                )));

                        let sig = line_editor.read_line(&prompt);

                        match sig {
                            Ok(Signal::Success(p)) => {
                                if p.is_empty() {
                                    continue;
                                }
                                if p.as_str() == "quit" || p.as_str() == "exit" {
                                    status = TerminalStatus::Terminate;
                                    continue;
                                }
                                if !user_commands.iter().any(|v| v == &p) {
                                    status = TerminalStatus::SelectUser;
                                    if let Err(e) = send_to_session.blocking_send(
                                        format!("System user: {} doesn't exist", p).into(),
                                    ) {
                                        warn!(
                                            "[{}] Fail to send data to channel from prompt: {}",
                                            handler_id, e
                                        );
                                        status = TerminalStatus::Terminate;
                                    };
                                    continue;
                                }
                                let target_sec_name = allowed_targets
                                    .iter()
                                    .find(|v| {
                                        v.secret_user == p && v.target_name == selected_target_name
                                    })
                                    .unwrap_or_else(|| {
                                        panic!("[{}] secret should exist", handler_id)
                                    })
                                    .clone();

                                selected_target_sec_name = Some(target_sec_name);
                                status = TerminalStatus::Connect;
                            }
                            Ok(Signal::CtrlC) => {
                                continue;
                            }
                            Ok(Signal::CtrlD) => {
                                status = TerminalStatus::SelectTarget;
                                if allowed_targets
                                    .iter()
                                    .map(|v| v.target_id.clone())
                                    .collect::<std::collections::HashSet<_>>()
                                    .len()
                                    == 1
                                {
                                    status = TerminalStatus::Terminate;
                                }
                            }
                            Err(e) => {
                                warn!("[{}] Fail to get signal from prompt: {}", handler_id, e);
                            }
                        }
                    }
                    TerminalStatus::Terminate => {
                        if let Err(e) = send_status.blocking_send(status) {
                            warn!("[{}] Fail to send status: {}", handler_id, e);
                        };
                        return;
                    }
                    TerminalStatus::Connect => {
                        break;
                    }
                }
            }

            let target_id = allowed_targets
                .iter()
                .find(|v| {
                    v.id == selected_target_sec_name
                        .as_ref()
                        .unwrap_or_else(|| {
                            panic!(
                                "[{}] selected_target_sec_name should not be none",
                                handler_id
                            )
                        })
                        .id
                })
                .unwrap_or_else(|| panic!("[{}] target_secret_id should be found", handler_id))
                .target_id
                .clone();
            let target = match tokio_handle.block_on(backend.get_target_by_id(&target_id, true)) {
                Ok(t) => t,
                Err(e) => {
                    warn!("[{}] Fail to get target: {}", handler_id, e);
                    status = TerminalStatus::Terminate;
                    if let Err(e) = send_status.blocking_send(status) {
                        warn!("[{}] Fail to send status: {}", handler_id, e);
                    };
                    return;
                }
            };

            let connect_target = ConnectTarget::new(handler_id.clone(), Some(user), handler_log)
                .with_target(target)
                .with_target_sec_name(selected_target_sec_name);
            if app_sender
                .blocking_send((
                    channel_id,
                    Application::ConnectTarget(Box::new(connect_target)),
                ))
                .is_err()
            {
                status = TerminalStatus::Terminate;
            }
            if let Err(e) = send_status.blocking_send(status) {
                warn!("[{}] Fail to send status: {}", handler_id, e);
            };
        });
        session.channel_success(channel)?;
        Ok(())
    }
}

impl Drop for TargetSelector {
    fn drop(&mut self) {
        trace!("[{}] drop TargetSelector", self.handler_id);
    }
}

fn add_menu_keybindings(keybindings: &mut Keybindings) {
    keybindings.add_binding(
        KeyModifiers::NONE,
        KeyCode::Tab,
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu("completion_menu".to_string()),
            ReedlineEvent::MenuNext,
        ]),
    );

    keybindings.add_binding(
        KeyModifiers::SHIFT,
        KeyCode::BackTab,
        ReedlineEvent::MenuPrevious,
    );
}
