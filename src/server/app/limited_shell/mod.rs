//! The limited shell (`ssh user@cmd@bastion`): a prompt on the bastion that
//! runs only the commands an admin listed in a command set, on the targets
//! the user holds such a set on.
//!
//! Nothing typed reaches a target until it has been checked. A line is read
//! by reedline here, matched against the user's command sets
//! (`crate::command`), and only then sent: as one `exec` on a fresh channel
//! of the target connection, holding exactly the string that was checked,
//! behind a `cd` to the working directory. There is no shell on the target to
//! talk to, so aliases, history expansion, globs and `$(...)` are text.
//!
//! Every line is checked against the policy snapshot as it is now: a set
//! revoked, a time window closed or a binding turned off applies to the next
//! line.

mod commands;
mod run;
#[cfg(test)]
mod test;

pub(crate) use run::{CommandInput, ShellInput, Terminal};

use super::PtyParams;
use crate::asciinema;
use crate::database::Uuid;
use crate::database::entity::session_recording as session_recording_entity;
use crate::database::models::{Target, TargetSecretName, session_recording};
use crate::error::Error;
use crate::fill;
use crate::i18n::Strings;
use crate::server::event_log::{Audit, EventKind, EventLogger, labelled};
use crate::server::extend_policy::{ExtendPolicyReq, RequestKind};
use crate::server::{CompiledCommandSet, HandlerBackend};
use bytes::Bytes;
use commands::{Cd, Commands, EXIT_FAILURE, EXIT_NOT_FOUND, Line, expand_tilde, sh_quote};
use crossterm::event::SenderWriter;
use log::{debug, warn};
use reedline::{
    ColumnarMenu, Emacs, FileBackedHistory, KeyCode, KeyModifiers, Keybindings, MenuBuilder,
    Prompt, PromptEditMode, PromptHistorySearch, Reedline, ReedlineEvent, ReedlineMenu, Signal,
    default_emacs_keybindings,
};
use run::{Job, Outcome};
use russh::client as ru_client;
use russh::server as ru_server;
use russh::{Channel, ChannelId};
use sea_orm::ActiveValue::{Set, Unchanged};
use std::borrow::Cow;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};

pub(crate) use commands::DenyReason;

/// The exit code a run reports when it could not enter its working
/// directory: its exec is `cd -- '<pwd>' || exit 125; <line>`. A directory
/// deleted or unmounted under the visit would otherwise fail every line
/// after it with the target's bare `cd:` error, so on this code the shell
/// asks the target whether the directory is still there and, when it is
/// gone, says so. A command that itself exits 125 keeps its own code,
/// which the check tells apart.
const PWD_GONE: u32 = 125;

/// The recording of one target visit, which the output forwarder writes to.
/// NOTE: Redundent code in @../connect_target.rs
struct Recording {
    session: asciinema::Session,
    id: Uuid,
}

type SharedRecording = Arc<Mutex<Option<Recording>>>;

/// Start the shell on `channel`. Returns once it runs; it closes the channel
/// when the user leaves.
pub(crate) async fn shell_request<B>(
    params: PtyParams<B>,
    terminal: Terminal,
    input: Arc<ShellInput>,
    from_user: CommandInput,
    channel: ChannelId,
    session: &mut ru_server::Session,
) -> Result<(), Error>
where
    B: 'static + HandlerBackend + Send + Sync,
{
    let tr = params.lang.strings();
    let PtyParams {
        handler_id,
        user_id,
        client_ip,
        backend,
        tty,
        mut recv_from_tty,
        log,
        ..
    } = params;

    let (send_to_session, mut recv_from_prompt) = mpsc::channel::<Bytes>(16);
    let (done, mut is_done) = mpsc::channel::<()>(1);
    let recording: SharedRecording = Arc::new(Mutex::new(None));

    // Everything the user sees goes through here, so a visit's recording
    // holds the prompt, the commands and their output.
    let handle = session.handle();
    let record = recording.clone();
    tokio::spawn(async move {
        let send = async |d: Bytes| {
            if let Some(r) = record.lock().await.as_mut() {
                r.session.handle_output(&d).await;
            }
            handle.data(channel, d).await.is_ok()
        };
        loop {
            tokio::select! {
                data = recv_from_prompt.recv() => match data {
                    Some(d) => if !send(d).await {
                        warn!("[{}] Fail to send data to session from limited shell", handler_id);
                        break;
                    },
                    None => break,
                },
                _ = is_done.recv() => {
                    // What the shell wrote last is still queued: deliver it
                    // before the channel closes.
                    while let Ok(d) = recv_from_prompt.try_recv() {
                        if !send(d).await {
                            break;
                        }
                    }
                    break;
                }
            }
        }
        if handle.close(channel).await.is_err() {
            warn!("[{}] Fail to close channel", handler_id);
        }
    });

    let to_session = send_to_session.clone();
    tokio::spawn(async move {
        while let Some(data) = recv_from_tty.recv().await {
            if to_session.send(data).await.is_err() {
                break;
            }
        }
    });

    let (tty, _) = tty.split();
    tokio::spawn(async move {
        let history = Box::new(FileBackedHistory::new(0).expect("a zero capacity is valid"));
        let mut keybindings = default_emacs_keybindings();
        add_menu_keybindings(&mut keybindings);
        let editor = Reedline::create(tty, SenderWriter::new(send_to_session.clone()))
            .with_quick_completions(true)
            .with_partial_completions(true)
            .with_menu(ReedlineMenu::EngineCompleter(Box::new(
                ColumnarMenu::default().with_name("completion_menu"),
            )))
            .with_history(history)
            .with_edit_mode(Box::new(Emacs::new(keybindings)));

        let mut shell = Shell {
            handler_id,
            user_id,
            client_ip,
            backend,
            log: log.scoped(EventKind::Command),
            tr,
            out: send_to_session,
            input,
            from_user,
            terminal,
            recording,
        };
        let mut editor = Editor {
            handler_id,
            reedline: Some(editor),
        };
        if let Err(e) = shell.top(&mut editor).await {
            warn!("[{}] Limited shell ended: {}", handler_id, e);
        }
        let _ = done.send(()).await;
    });
    Ok(())
}

struct Shell<B: 'static + HandlerBackend + Send + Sync> {
    handler_id: Uuid,
    user_id: Uuid,
    client_ip: Option<std::net::IpAddr>,
    backend: Arc<B>,
    log: EventLogger<B>,
    tr: &'static Strings,
    out: mpsc::Sender<Bytes>,
    input: Arc<ShellInput>,
    from_user: CommandInput,
    terminal: Terminal,
    recording: SharedRecording,
}

/// The line editor. Apart from [`Shell`], which is shared across awaits and
/// so must be `Sync`, as reedline is not.
struct Editor {
    handler_id: Uuid,
    /// Always `Some` between calls: taken to swap its completer in.
    reedline: Option<Reedline>,
}

impl Editor {
    async fn read_line(&mut self, prompt: String, words: Vec<String>) -> Option<String> {
        let mut completer = Box::new(
            crate::terminal::BastionCompleter::with_inclusions(&['-', '_', '@', '.'])
                .set_min_word_len(0),
        );
        completer.insert(words);
        let reedline = self.reedline.take()?.with_completer(completer);
        let reedline = self.reedline.insert(reedline);
        loop {
            match reedline.read_line(&PlainPrompt(prompt.clone())).await {
                Ok(Signal::Success(line)) => return Some(line),
                Ok(Signal::CtrlC) => continue,
                Ok(Signal::CtrlD) => return None,
                Ok(_) => continue,
                Err(e) => {
                    warn!("[{}] Fail to read a line: {}", self.handler_id, e);
                    return None;
                }
            }
        }
    }
}

/// One target visit: the binding, its connection and where the user is.
struct Visit {
    binding: TargetSecretName,
    target: Target,
    /// `user@target(<binding id>)`, for the log and the audit rows.
    label: String,
    handle: Option<Arc<ru_client::Handle<Target>>>,
    home: String,
    pwd: String,
    oldpwd: String,
    /// The exit code of the last command, kept for the prompt.
    last_status: u32,
}

enum Next {
    Stay,
    Leave,
}

impl<B: 'static + HandlerBackend + Send + Sync> Shell<B> {
    async fn say(&self, text: &str) -> Result<(), Error> {
        let mut text = text.replace('\n', "\r\n");
        text.push_str("\r\n");
        self.out
            .send(text.into())
            .await
            .map_err(|e| Error::IO(std::io::Error::other(e)))
    }

    async fn say_lines(&self, lines: &[String]) -> Result<(), Error> {
        self.say(&lines.join("\n")).await
    }

    fn request(&self) -> ExtendPolicyReq {
        ExtendPolicyReq::of(self.client_ip, RequestKind::Other)
    }

    async fn sets(&self, binding: Uuid) -> Result<Vec<Arc<CompiledCommandSet>>, Error> {
        self.backend
            .command_sets_for(self.user_id, binding, self.request())
            .await
    }

    /// The bindings the user holds a command set on.
    async fn targets(&self) -> Result<Vec<TargetSecretName>, Error> {
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for t in self
            .backend
            .list_targets_for_user(&self.user_id, true)
            .await?
        {
            if seen.insert(t.id) && !self.sets(t.id).await?.is_empty() {
                out.push(t);
            }
        }
        out.sort_by(|a, b| (&a.target_name, &a.secret_user).cmp(&(&b.target_name, &b.secret_user)));
        Ok(out)
    }

    /// The `>` prompt: pick a target.
    async fn top(&mut self, editor: &mut Editor) -> Result<(), Error> {
        self.say(self.tr.ls_welcome).await?;
        loop {
            // TODO: Refresh targets every time after press enter? It's too expensive
            let targets = self.targets().await?;
            let names = target_names(&targets);
            let Some(line) = editor.read_line("> ".into(), names.clone()).await else {
                return Ok(());
            };
            match line.trim() {
                "" => {}
                "exit" => return Ok(()),
                "help" => {
                    if targets.is_empty() {
                        self.say(self.tr.ls_no_targets).await?;
                    } else {
                        let mut lines = vec![self.tr.ls_targets.to_owned()];
                        lines.extend(
                            targets
                                .iter()
                                .map(|t| format!("  {}@{}", t.secret_user, t.target_name)),
                        );
                        self.say_lines(&lines).await?;
                    }
                }
                name => match pick(&targets, name) {
                    Pick::One(t) => {
                        let t = t.clone();
                        self.visit(editor, t).await?;
                    }
                    Pick::None => {
                        self.say(&fill!(self.tr.ls_no_such_target, name = name))
                            .await?
                    }
                    Pick::Many(choices) => {
                        self.say(&fill!(
                            self.tr.ls_ambiguous_target,
                            name = name,
                            choices = choices.join(self.tr.list_separator)
                        ))
                        .await?
                    }
                },
            }
        }
    }

    /// `user@target>`: run commands there until `exit`.
    async fn visit(&mut self, editor: &mut Editor, binding: TargetSecretName) -> Result<(), Error> {
        let tr = self.tr;
        let label = labelled(
            &session_recording::compose_label(&binding.secret_user, &binding.target_name),
            binding.id,
        );
        let commands = Commands::new(self.sets(binding.id).await?);
        if commands.is_empty() {
            return self
                .say(&fill!(tr.ls_no_commands, target = binding.target_name))
                .await;
        }
        let Some(target) = self
            .backend
            .db_repository()
            .get_target_by_id(binding.target_id, true)
            .await?
        else {
            return self
                .say(&fill!(tr.ls_connect_failed, target = binding.target_name))
                .await;
        };
        let mut visit = Visit {
            binding,
            target,
            label,
            handle: None,
            home: String::new(),
            pwd: String::new(),
            oldpwd: String::new(),
            last_status: 0,
        };
        let home = match self.query(&mut visit, "pwd -P").await {
            Ok(Ok(home)) => home,
            other => {
                if let Err(e) = other {
                    warn!(
                        "[{}] Limited shell cannot reach {}: {}",
                        self.handler_id, visit.label, e
                    );
                }
                return self
                    .say(&fill!(
                        tr.ls_connect_failed,
                        target = visit.binding.target_name
                    ))
                    .await;
            }
        };
        visit.home = home.clone();
        visit.pwd = home.clone();
        visit.oldpwd = home;
        warn_duplicates(self.handler_id, &visit.label, &commands);
        self.log
            .record(Audit::CommandShell {
                target: visit.label.clone(),
            })
            .await;
        self.start_recording(&visit).await;
        self.say(tr.ls_entered).await?;

        let result = self.visit_loop(editor, &mut visit, commands).await;
        self.finish_recording().await;
        result
    }

    async fn visit_loop(
        &mut self,
        editor: &mut Editor,
        visit: &mut Visit,
        mut commands: Commands,
    ) -> Result<(), Error> {
        loop {
            // The prompt carries the last command's exit code when it
            // failed, until the next command runs.
            let prompt = if visit.last_status == 0 {
                format!(
                    "{}@{}> ",
                    visit.binding.secret_user, visit.binding.target_name
                )
            } else {
                // The code in light red, then back to the light green the
                // line editor paints the rest of the prompt in.
                format!(
                    "{}@{} \x1b[91m[{}]\x1b[92m> ",
                    visit.binding.secret_user, visit.binding.target_name, visit.last_status
                )
            };
            let Some(line) = editor.read_line(prompt, commands.completions()).await else {
                return Ok(());
            };
            commands = Commands::new(self.sets(visit.binding.id).await?);
            if commands.is_empty() {
                return self.say(self.tr.ls_revoked).await;
            }
            let line = line.trim();
            match commands.parse(line, &visit.pwd) {
                Ok(parsed) => {
                    // An empty line keeps the last code, as a shell keeps
                    // `$?`; every other line starts clean, and what fails
                    // on it sets its own.
                    if !matches!(parsed, Line::Empty) {
                        visit.last_status = 0;
                    }
                    if let Next::Leave = self.act(visit, &commands, line, parsed).await? {
                        return Ok(());
                    }
                }
                Err(refusal) => {
                    visit.last_status = refusal.code();
                    self.say(&refusal.message(self.tr)).await?;
                    self.log
                        .record(Audit::CommandDenied {
                            target: visit.label.clone(),
                            line: line.to_owned(),
                            reason: refusal.reason(),
                        })
                        .await;
                }
            }
        }
    }

    async fn act(
        &mut self,
        visit: &mut Visit,
        commands: &Commands,
        line: &str,
        parsed: Line,
    ) -> Result<Next, Error> {
        let tr = self.tr;
        match parsed {
            Line::Empty => {}
            Line::Exit => return Ok(Next::Leave),
            Line::Pwd => self.say(&visit.pwd).await?,
            Line::Help(None) => self.say_lines(&commands.help(tr)).await?,
            Line::Help(Some(alias)) => match commands.help_for(&alias, tr) {
                Some(lines) => self.say_lines(&lines).await?,
                None => {
                    visit.last_status = EXIT_NOT_FOUND;
                    self.say(&fill!(tr.ls_unknown_command, name = alias))
                        .await?
                }
            },
            Line::Cd(cd) => self.cd(visit, commands, line, cd).await?,
            Line::Run {
                alias: _,
                set,
                approved,
            } => {
                // The `|| exit 125` makes a working directory that no
                // longer exists tell its own story, instead of failing the
                // command with a bare 1.
                let command = format!(
                    "cd -- {} || exit {PWD_GONE}; {}",
                    sh_quote(&visit.pwd),
                    approved.command_line
                );
                let channel = match self.open(visit).await {
                    Ok(ch) => ch,
                    Err(e) => {
                        warn!(
                            "[{}] Cannot open a channel on {}: {}",
                            self.handler_id, visit.label, e
                        );
                        // The command never ran, but this attempt failed.
                        visit.last_status = EXIT_FAILURE;
                        self.say(&fill!(
                            tr.ls_connect_failed,
                            target = visit.binding.target_name
                        ))
                        .await?;
                        return Ok(Next::Stay);
                    }
                };
                let job = Job {
                    command: &command,
                    pty: approved.pty.then_some(&self.terminal),
                    stdin: approved.stdin,
                    timeout: self.backend.command_timeout(),
                };
                debug!(
                    "[{}] Limited shell runs on {}: {}",
                    self.handler_id, visit.label, command
                );
                let (outcome, at_line_start) =
                    run::run(channel, job, &self.input, &mut self.from_user, &self.out).await?;
                if !at_line_start {
                    self.out.send(Bytes::from_static(b"\r\n")).await.ok();
                }
                // A failed command's exit code rides in the prompt until
                // the next line runs; anything but an exit leaves the
                // prompt clean, its own message having said what happened.
                match &outcome {
                    // The working directory could not be entered: it may
                    // have been deleted or unmounted under the visit. When
                    // the target confirms it is gone, say so — the visit
                    // stays there, and every line fails the same way until
                    // the user `cd`s out of it; a command's own 125 keeps
                    // its own code, which the check tells apart. Either
                    // way the audit row keeps the code the target reported.
                    Outcome::Exited(n) if *n == PWD_GONE => {
                        if self.query(visit, &cd_check(&visit.pwd)).await?.is_err() {
                            self.pwd_gone(visit).await?;
                            visit.last_status = EXIT_FAILURE;
                        } else {
                            visit.last_status = PWD_GONE;
                        }
                    }
                    Outcome::Exited(n) => visit.last_status = *n,
                    Outcome::Signalled(sig) => {
                        self.say(&fill!(tr.ls_signalled, signal = sig)).await?
                    }
                    Outcome::TimedOut => {
                        let limit = humantime::format_duration(self.backend.command_timeout());
                        self.say(&fill!(tr.ls_timed_out, limit = limit)).await?
                    }
                    Outcome::Closed => self.say(tr.ls_stopped).await?,
                    Outcome::Refused => self.say(tr.ls_not_started).await?,
                }
                if let Some(r) = self.recording.lock().await.as_mut()
                    && let Outcome::Exited(n) = outcome
                {
                    r.session.handle_marker(format!("exit {n}")).await;
                }
                self.log
                    .record(Audit::CommandRan {
                        target: visit.label.clone(),
                        line: line.to_owned(),
                        command: approved.command_line,
                        set,
                        status: match outcome {
                            Outcome::Exited(n) => Some(n),
                            _ => None,
                        },
                        timed_out: outcome == Outcome::TimedOut,
                    })
                    .await;
            }
        }
        Ok(Next::Stay)
    }

    /// `cd`: checked by the path the user named, then by the path the target
    /// resolves it to, so a symlink cannot lead outside the allowlist.
    async fn cd(
        &mut self,
        visit: &mut Visit,
        commands: &Commands,
        line: &str,
        cd: Cd,
    ) -> Result<(), Error> {
        // The path as typed, with `~` read, and what it names lexically.
        // The allowlist reads the lexical one; the target is handed the one
        // as typed and resolves it itself, so `cd a/..` with no `a` fails
        // there as it would in a shell, instead of quietly meaning the
        // current directory.
        let (named, dir) = match cd {
            Cd::Home => (visit.home.clone(), visit.home.clone()),
            Cd::Back => (visit.oldpwd.clone(), visit.oldpwd.clone()),
            Cd::Dir(d) => {
                let named = expand_tilde(&d, &visit.home);
                let dir = Commands::resolve(&visit.pwd, &named);
                (named, dir)
            }
        };
        if !commands.cd_allows(&dir, &visit.home) {
            visit.last_status = EXIT_FAILURE;
            return self.cd_denied(visit, line, &dir).await;
        }
        let query = format!(
            "cd -- {} && cd -- {} && pwd -P",
            sh_quote(&visit.pwd),
            sh_quote(&named)
        );
        match self.query(visit, &query).await? {
            answer @ Ok(_) => self.cd_answer(visit, commands, line, &dir, answer).await,
            Err(stderr) => {
                visit.last_status = EXIT_FAILURE;
                // A `cd` fails the same way whatever the user named when
                // the working directory itself is gone, and the visit is
                // not moved without the user. Their own `cd` is their way
                // out, and it says so only when it is news: an absolute
                // path — bare `cd` and `cd -` included, both absolute by
                // nature — resolves from any start, so it is asked of the
                // target once more on its own, with no anchor: the visit's
                // only anchor is the dead directory, and a live one could
                // only fail the chain. When it goes through it says
                // nothing — the hint would tell the user to do what they
                // just did. A relative path cannot be resolved without
                // the directory that held it; the hint is all there is
                // to say for it.
                if self.query(visit, &cd_check(&visit.pwd)).await?.is_err() {
                    if !named.starts_with('/') {
                        return self.pwd_gone(visit).await;
                    }
                    let retry = format!("cd -- {} && pwd -P", sh_quote(&named));
                    let answer = self.query(visit, &retry).await?;
                    return self.cd_answer(visit, commands, line, &dir, answer).await;
                }
                self.cd_answer(visit, commands, line, &dir, Err(stderr))
                    .await
            }
        }
    }

    async fn cd_denied(&self, visit: &Visit, line: &str, dir: &str) -> Result<(), Error> {
        self.say(&fill!(self.tr.ls_cd_not_allowed, dir = dir))
            .await?;
        self.log
            .record(Audit::CommandDenied {
                target: visit.label.clone(),
                line: line.to_owned(),
                reason: DenyReason::CdNotAllowed,
            })
            .await;
        Ok(())
    }

    /// The working directory stopped existing on the target. Say so and
    /// change nothing: the visit stays in the deleted directory, as a shell
    /// does, and the user chooses where to go next.
    async fn pwd_gone(&self, visit: &Visit) -> Result<(), Error> {
        self.say(&fill!(
            self.tr.ls_pwd_gone,
            dir = visit.pwd,
            home = visit.home
        ))
        .await
    }

    /// What a `cd` query's answer does: move when the target resolved it to
    /// an allowed directory, deny it when it did not, and show the target's
    /// own words when it failed.
    async fn cd_answer(
        &mut self,
        visit: &mut Visit,
        commands: &Commands,
        line: &str,
        dir: &str,
        answer: Result<String, Vec<u8>>,
    ) -> Result<(), Error> {
        match answer {
            Ok(physical) if commands.cd_allows(&physical, &visit.home) => {
                visit.oldpwd = std::mem::replace(&mut visit.pwd, physical);
                visit.last_status = 0;
                Ok(())
            }
            Ok(_) => {
                visit.last_status = EXIT_FAILURE;
                self.cd_denied(visit, line, dir).await
            }
            Err(stderr) => {
                visit.last_status = EXIT_FAILURE;
                // The target's own words when it said any: a missing
                // directory, no permission. The generic message only when
                // it said nothing.
                let text = String::from_utf8_lossy(&stderr);
                let text = text.trim();
                if text.is_empty() {
                    self.say(&fill!(self.tr.ls_cd_failed, dir = dir)).await
                } else {
                    self.say(text).await
                }
            }
        }
    }

    /// A session channel on the target, over the pooled connection.
    async fn open(&self, visit: &mut Visit) -> Result<Channel<ru_client::Msg>, Error> {
        for force in [false, true] {
            if force || visit.handle.is_none() {
                visit.handle = self
                    .backend
                    .connect_to_target(visit.target.clone(), visit.binding.id, force)
                    .await?;
            }
            let Some(handle) = visit.handle.as_ref() else {
                continue;
            };
            match handle.channel_open_session().await {
                Ok(ch) => return Ok(ch),
                // A pooled connection that went away: build a new one.
                Err(
                    russh::Error::ChannelOpenFailure(
                        russh::ChannelOpenFailure::AdministrativelyProhibited,
                    )
                    | russh::Error::SendError,
                ) if !force => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(crate::server::app::error::AppError::NoTargetAvailable.into())
    }

    /// Run one of the bastion's own commands and return its first line of
    /// output, or its stderr when it fails.
    async fn query(
        &self,
        visit: &mut Visit,
        command: &str,
    ) -> Result<Result<String, Vec<u8>>, Error> {
        let channel = self.open(visit).await?;
        let (outcome, stdout, stderr) = run::query(channel, command).await?;
        let text = String::from_utf8_lossy(&stdout);
        let line = text.strip_suffix('\n').unwrap_or(&text);
        // A path with a newline in it cannot be told from two lines.
        if outcome == Outcome::Exited(0) && line.starts_with('/') && !line.contains('\n') {
            Ok(Ok(line.to_owned()))
        } else {
            Ok(Err(stderr))
        }
    }

    // TODO: It should return error and stop session init failed
    async fn start_recording(&self, visit: &Visit) {
        if !self.backend.enable_record() {
            return;
        }
        let id = Uuid::now_v7();
        let file_path = session_recording::generate_path(id);
        let (cols, rows, _, _) = self.input.size();
        let session = match asciinema::new_recorder(
            Some(self.terminal.term.clone()),
            std::path::PathBuf::from(self.backend.record_path()).join(&file_path),
            (cols as u16, rows as u16),
            None,
            self.backend.record_input(),
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                log::error!("[{}] Failed to start a recording: {}", self.handler_id, e);
                return;
            }
        };
        if let Err(e) = self
            .backend
            .db_repository()
            .create_session_recording(session_recording_entity::ActiveModel {
                id: Set(id),
                user_id: Set(self.user_id),
                target_id: Set(visit.binding.target_id),
                secret_id: Set(visit.binding.secret_id),
                target_label: Set(session_recording::compose_label(
                    &visit.binding.secret_user,
                    &visit.binding.target_name,
                )),
                file_path: Set(file_path),
                connection_id: Set(self.handler_id),
                status: Set(session_recording::RecordingStatus::Active),
                ..Default::default()
            })
            .await
        {
            log::error!(
                "[{}] Failed to create session recording: {}",
                self.handler_id,
                e
            );
            return;
        }
        *self.recording.lock().await = Some(Recording { session, id });
    }

    async fn finish_recording(&self) {
        let Some(r) = self.recording.lock().await.take() else {
            return;
        };
        drop(r.session);
        if let Err(e) = self
            .backend
            .db_repository()
            .update_session_recording(session_recording_entity::ActiveModel {
                id: Unchanged(r.id),
                ended_at: Set(Some(chrono::Utc::now().timestamp_millis())),
                status: Set(session_recording::RecordingStatus::Completed),
                ..Default::default()
            })
            .await
        {
            log::error!(
                "[{}] Failed to update session recording: {}",
                self.handler_id,
                e
            );
        }
    }
}

/// `cd -- '<dir>' && pwd -P`: how the shell asks the target whether a
/// directory still exists.
fn cd_check(dir: &str) -> String {
    format!("cd -- {} && pwd -P", sh_quote(dir))
}

fn warn_duplicates(handler_id: Uuid, label: &str, commands: &Commands) {
    for (alias, sets) in commands.duplicates() {
        warn!(
            "[{}] Command '{}' on {} is defined by more than one set ({}); it runs nowhere",
            handler_id,
            alias,
            label,
            sets.join(", ")
        );
    }
}

/// What the `>` prompt completes: `user@target` for every binding, and the
/// bare target name where it has one user.
fn target_names(targets: &[TargetSecretName]) -> Vec<String> {
    let mut names: Vec<String> = targets
        .iter()
        .map(|t| format!("{}@{}", t.secret_user, t.target_name))
        .collect();
    for t in targets {
        if targets
            .iter()
            .filter(|o| o.target_name == t.target_name)
            .count()
            == 1
        {
            names.push(t.target_name.clone());
        }
    }
    names.push("help".into());
    names.push("exit".into());
    names
}

enum Pick<'a> {
    One(&'a TargetSecretName),
    None,
    /// `user@target` for each binding the bare name could mean.
    Many(Vec<String>),
}

/// The binding `name` means: `user@target`, or a target with one user.
fn pick<'a>(targets: &'a [TargetSecretName], name: &str) -> Pick<'a> {
    if let Some((user, target)) = name.split_once('@') {
        return match targets
            .iter()
            .find(|t| t.secret_user == user && t.target_name == target)
        {
            Some(t) => Pick::One(t),
            None => Pick::None,
        };
    }
    let matching: Vec<_> = targets.iter().filter(|t| t.target_name == name).collect();
    match matching[..] {
        [] => Pick::None,
        [one] => Pick::One(one),
        _ => Pick::Many(
            matching
                .iter()
                .map(|t| format!("{}@{}", t.secret_user, t.target_name))
                .collect(),
        ),
    }
}

/// A prompt shown as given, with no mode indicator.
struct PlainPrompt(String);

impl Prompt for PlainPrompt {
    fn render_prompt_left(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.0)
    }
    fn render_prompt_right(&self) -> Cow<'_, str> {
        Cow::Borrowed("")
    }
    fn render_prompt_indicator(&self, _mode: PromptEditMode) -> Cow<'_, str> {
        Cow::Borrowed("")
    }
    fn render_prompt_multiline_indicator(&self) -> Cow<'_, str> {
        Cow::Borrowed("")
    }
    fn render_prompt_history_search_indicator(&self, _search: PromptHistorySearch) -> Cow<'_, str> {
        Cow::Borrowed("")
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
