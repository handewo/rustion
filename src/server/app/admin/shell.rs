use crate::database::Uuid;
use crate::server::event_log::EventLogger;
use log::warn;
use reedline::{
    ColumnarMenu, DefaultPrompt, DefaultPromptSegment, Emacs, ExampleHighlighter, KeyCode,
    KeyModifiers, Keybindings, MenuBuilder, Reedline, ReedlineEvent, ReedlineMenu, Signal,
    default_emacs_keybindings,
};
use std::sync::Arc;
use tokio::sync::mpsc;

use super::common::*;
use super::{Status, database, manage};
use crate::server::widgets::Theme;
use bytes::Bytes;
use crossterm::event::{DisableBracketedPaste, EnableBracketedPaste, NoTtyEvent, SenderWriter};

#[allow(clippy::too_many_arguments)]
pub(super) async fn shell<B>(
    tty: NoTtyEvent,
    send_to_session: mpsc::Sender<Bytes>,
    send_status: mpsc::Sender<Status>,
    user_id: Uuid,
    handler_id: Uuid,
    backend: Arc<B>,
    log: EventLogger<B>,
) where
    B: 'static + crate::server::HandlerBackend + Send + Sync,
{
    // init prompt
    let mut line_editor = Reedline::create(tty.clone(), SenderWriter::new(send_to_session.clone()))
        .with_quick_completions(true)
        .with_menu(ReedlineMenu::EngineCompleter(Box::new(
            ColumnarMenu::default().with_name("completion_menu"),
        )))
        .with_partial_completions(true);

    let mut keybindings = default_emacs_keybindings();
    add_menu_keybindings(&mut keybindings);

    let edit_mode = Box::new(Emacs::new(keybindings));

    line_editor = line_editor.with_edit_mode(edit_mode);

    // Shared by the panels below, so a theme picked in one carries over to the
    // next for the rest of the session.
    let mut theme = Theme::of(backend.theme());

    let prompt = DefaultPrompt::new(
        DefaultPromptSegment::Basic("admin".to_string()),
        DefaultPromptSegment::Empty,
    );

    let mut completer = Box::new(
        crate::terminal::BastionCompleter::with_inclusions(&['-', '_']).set_min_word_len(0),
    );
    let command_list: Vec<String> = COMMAND_LIST.iter().map(|v| v.to_string()).collect();
    completer.insert(command_list.clone());

    line_editor = line_editor
        .with_completer(completer)
        .with_highlighter(Box::new(ExampleHighlighter::new(command_list.clone())));

    loop {
        let sig = line_editor.read_line(&prompt).await;
        match sig {
            Ok(Signal::Success(p)) => {
                if p.trim().is_empty() {
                    continue;
                }
                match p.trim() {
                    CMD_QUIT | CMD_EXIT => {
                        let _ = send_status.send(Status::Terminate(0)).await;
                        break;
                    }
                    CMD_DATABASE => {
                        let _ = database::query_table(
                            tty.clone(),
                            SenderWriter::new(send_to_session.clone()),
                            backend.clone(),
                            &mut theme,
                        )
                        .await;
                    }
                    CMD_MANAGE => {
                        let w = SenderWriter::new(send_to_session.clone());
                        let _ = crossterm::async_execute!(&w, EnableBracketedPaste).await;
                        if let Err(e) = manage::manage(
                            tty.clone(),
                            SenderWriter::new(send_to_session.clone()),
                            user_id,
                            handler_id,
                            backend.clone(),
                            log.clone(),
                            &mut theme,
                        )
                        .await
                        {
                            warn!("[{}] Manage error: {}", handler_id, e);
                        };
                        let _ = crossterm::async_execute!(&w, DisableBracketedPaste).await;
                    }
                    CMD_FLUSH_PRIVILEGES => {
                        if let Err(e) = backend.load_role_manager().await {
                            let _ = send_to_session
                                .send(format!("flush previleges error: {}", e).into())
                                .await;
                        } else {
                            let _ = send_to_session.send("flushed successfully".into()).await;
                        }
                    }
                    _ => {
                        let _ = send_to_session
                            .send(format!("Unknown command: {}", p).into())
                            .await;
                    }
                }
            }
            Ok(Signal::CtrlC) => {
                continue;
            }
            Ok(Signal::CtrlD) => {
                let _ = send_status.send(Status::Terminate(0)).await;
                break;
            }
            Ok(_) => unreachable!(),
            Err(e) => {
                let _ = send_status.send(Status::Terminate(1)).await;
                warn!("[{}] Fail to get signal from prompt: {}", handler_id, e);
                break;
            }
        }
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
