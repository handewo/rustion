use crate::database::Uuid;
use crate::server::HandlerLog;
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
use crossterm::event::{DisableBracketedPaste, EnableBracketedPaste, NoTtyEvent, SenderWriter};

#[allow(clippy::too_many_arguments)]
pub(super) fn shell<B>(
    tty: NoTtyEvent,
    send_to_session: mpsc::Sender<Vec<u8>>,
    send_status: mpsc::Sender<Status>,
    user_id: Uuid,
    handler_id: Uuid,
    backend: Arc<B>,
    t_handle: tokio::runtime::Handle,
    log: HandlerLog,
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
        let sig = line_editor.read_line(&prompt);
        match sig {
            Ok(Signal::Success(p)) => {
                if p.trim().is_empty() {
                    continue;
                }
                match p.trim() {
                    CMD_QUIT | CMD_EXIT => {
                        let _ = send_status.blocking_send(Status::Terminate(0));
                        break;
                    }
                    CMD_DATABASE => {
                        let _ = database::query_table(
                            tty.clone(),
                            SenderWriter::new(send_to_session.clone()),
                            backend.clone(),
                            t_handle.clone(),
                        );
                    }
                    CMD_MANAGE => {
                        let mut w = SenderWriter::new(send_to_session.clone());
                        let _ = crossterm::execute!(w, EnableBracketedPaste);
                        if let Err(e) = manage::manage(
                            tty.clone(),
                            SenderWriter::new(send_to_session.clone()),
                            user_id,
                            handler_id,
                            backend.clone(),
                            t_handle.clone(),
                            log.clone(),
                        ) {
                            warn!("[{}] Manage error: {}", handler_id, e);
                        };
                        let _ = crossterm::execute!(w, DisableBracketedPaste);
                    }
                    CMD_FLUSH_PRIVILEGES => {
                        if let Err(e) = t_handle.block_on(backend.load_role_manager()) {
                            let _ = send_to_session
                                .blocking_send(format!("flush previleges error: {}", e).into());
                        } else {
                            let _ = send_to_session.blocking_send("flushed successfully".into());
                        }
                    }
                    _ => {
                        let _ =
                            send_to_session.blocking_send(format!("Unknown command: {}", p).into());
                    }
                }
            }
            Ok(Signal::CtrlC) => {
                continue;
            }
            Ok(Signal::CtrlD) => {
                let _ = send_status.blocking_send(Status::Terminate(0));
                break;
            }
            Ok(_) => unreachable!(),
            Err(e) => {
                let _ = send_status.blocking_send(Status::Terminate(1));
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
