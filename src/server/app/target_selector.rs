use super::PtyParams;
use crate::database::Uuid;
use crate::database::models::TargetSecretName;
use crate::error::Error;
use crate::server::app::NextApplication;
use crate::server::app::error::AppError;
use bytes::Bytes;
use crossterm::event::SenderWriter;
use log::{debug, trace, warn};
use reedline::{
    ColumnarMenu, DefaultPrompt, DefaultPromptSegment, Emacs, ExampleHighlighter,
    FileBackedHistory, MenuBuilder, Reedline, ReedlineMenu, Signal, default_emacs_keybindings,
};
use reedline::{KeyCode, KeyModifiers, Keybindings, ReedlineEvent};
use russh::ChannelId;
use russh::server as ru_server;
use tokio::sync::mpsc;

#[derive(Clone)]
enum TerminalStatus {
    SelectTarget,
    SelectUser,
    Connect,
    Terminate,
}

pub(crate) async fn shell_request<B>(
    select_target_name: Option<String>,
    params: PtyParams<B>,
    channel: ChannelId,
    session: &mut ru_server::Session,
) -> Result<(), Error>
where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    let (handler_id, user_id, _, backend, tty, mut recv_from_tty, _, app_sender) = params.split();

    let mut allowed_targets = backend.list_targets_for_user(&user_id, true).await?;
    trace!(
        "[{}] list targets: {:?}",
        handler_id,
        allowed_targets.iter().map(|v| v.id).collect::<Vec<Uuid>>()
    );

    if let Some(t) = select_target_name {
        allowed_targets.retain(|target| target.target_name == t);
    }
    if allowed_targets.is_empty() {
        return Err(AppError::NoTargetAvailable.into());
    }

    let (send_status, mut recv_status) = mpsc::channel(1);

    let handle_prompt = session.handle();
    let handle_status = session.handle();

    let (send_to_session, mut recv_from_prompt) = mpsc::channel::<Bytes>(16);
    let send_to_session_from_tty = send_to_session.clone();

    let (tty, _) = tty.split();

    tokio::spawn(async move {
        while let Some(d) = recv_from_prompt.recv().await {
            if handle_prompt.data(channel, d).await.is_err() {
                warn!("[{}] Fail to send data to session from prompt", handler_id);
                break;
            };
        }
    });

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

    tokio::spawn(async move {
        while let Some(data) = recv_from_tty.recv().await {
            if send_to_session_from_tty.send(data).await.is_err() {
                debug!("[{}] Fail to send data to session from tty", handler_id);
                break;
            }
        }
    });

    tokio::spawn(async move {
        // TODO: Classify different target type in future
        let server_prompt = "Select server";
        let user_prompt = "Select system user";
        let mut status = TerminalStatus::SelectTarget;
        let mut selected_target_name = String::new();

        let mut selected_target_secret_name = TargetSecretName::default();
        let backend = backend;
        let target_commands: Vec<String> = allowed_targets
            .iter()
            .map(|v| v.target_name.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        // init prompt
        let history = Box::new(
            FileBackedHistory::new(0).unwrap_or_else(|_| panic!("[{}] safe capacity", handler_id)),
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

                    line_editor = line_editor
                        .with_completer(completer)
                        .with_highlighter(Box::new(ExampleHighlighter::new(
                            target_commands.clone(),
                        )));
                    let sig = line_editor.read_line(&prompt).await;

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
                                if let Err(e) = send_to_session
                                    .send(format!("Server: {} doesn't exist", p).into())
                                    .await
                                {
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
                        Ok(_) => unreachable!(),
                        Err(e) => {
                            warn!("[{}] Fail to get signal from prompt: {}", handler_id, e);
                            return;
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
                        selected_target_secret_name = allowed_targets
                            .iter()
                            .find(|v| {
                                &v.secret_user == user_commands.first().unwrap()
                                    && v.target_name == selected_target_name
                            })
                            .unwrap_or_else(|| panic!("[{}] secret must exist", handler_id))
                            .clone();
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

                    line_editor = line_editor
                        .with_completer(completer)
                        .with_highlighter(Box::new(ExampleHighlighter::new(user_commands.clone())));

                    let sig = line_editor.read_line(&prompt).await;

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
                                if let Err(e) = send_to_session
                                    .send(format!("System user: {} doesn't exist", p).into())
                                    .await
                                {
                                    warn!(
                                        "[{}] Fail to send data to channel from prompt: {}",
                                        handler_id, e
                                    );
                                    status = TerminalStatus::Terminate;
                                };
                                continue;
                            }
                            let target_secret_name = allowed_targets
                                .iter()
                                .find(|v| {
                                    v.secret_user == p && v.target_name == selected_target_name
                                })
                                .unwrap_or_else(|| panic!("[{}] secret should exist", handler_id))
                                .clone();

                            selected_target_secret_name = target_secret_name;
                            status = TerminalStatus::Connect;
                        }
                        Ok(Signal::CtrlC) => {
                            continue;
                        }
                        Ok(Signal::CtrlD) => {
                            status = TerminalStatus::SelectTarget;
                            if allowed_targets
                                .iter()
                                .map(|v| v.target_id)
                                .collect::<std::collections::HashSet<_>>()
                                .len()
                                == 1
                            {
                                status = TerminalStatus::Terminate;
                            }
                        }
                        Ok(_) => unreachable!(),
                        Err(e) => {
                            warn!("[{}] Fail to get signal from prompt: {}", handler_id, e);
                            return;
                        }
                    }
                }
                TerminalStatus::Terminate => {
                    if let Err(e) = send_status.send(status).await {
                        warn!("[{}] Fail to send status: {}", handler_id, e);
                    };
                    return;
                }
                TerminalStatus::Connect => {
                    break;
                }
            }
        }

        let target_id = if let Some(ts) = allowed_targets
            .iter()
            .find(|v| v.id == selected_target_secret_name.id)
        {
            ts.target_id
        } else {
            Uuid::default()
        };
        let target = match backend
            .db_repository()
            .get_target_by_id(target_id, true)
            .await
        {
            Ok(t) => t,
            Err(e) => {
                warn!("[{}] Fail to get target: {}", handler_id, e);
                status = TerminalStatus::Terminate;
                if let Err(e) = send_status.send(status).await {
                    warn!("[{}] Fail to send status: {}", handler_id, e);
                };
                return;
            }
        };

        let next_app = if let Some(target) = target {
            NextApplication::ConnectTargetShell(Box::new((target, selected_target_secret_name)))
        } else {
            warn!("[{}] Target: [{}] not found", handler_id, target_id);
            NextApplication::None
        };
        if app_sender.send((channel, next_app)).await.is_err() {
            status = TerminalStatus::Terminate;
        }
        if let Err(e) = send_status.send(status).await {
            warn!("[{}] Fail to send status: {}", handler_id, e);
        };
    });
    Ok(())
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
