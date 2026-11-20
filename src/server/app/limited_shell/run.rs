//! Running one approved command on its own target channel, and the plumbing
//! between that channel and the user's terminal.

use crate::server::error::ServerError;
use bytes::Bytes;
use russh::client as ru_client;
use russh::{Channel, ChannelMsg, Pty, Sig};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::Instant;
use unicode_width::UnicodeWidthChar;

/// How long the bastion waits for a stopped command's channel to close.
const GRACE: Duration = Duration::from_secs(2);
/// The longest `pwd` or `cd` may take on the target.
const QUERY_TIMEOUT: Duration = Duration::from_secs(10);

/// The client's terminal, for commands that run on a pty.
#[derive(Debug, Clone)]
pub(crate) struct Terminal {
    pub term: String,
    pub modes: Vec<(Pty, u32)>,
}

/// Where the user's keystrokes and window changes go: to the line editor,
/// or, while a command runs, to the command.
///
/// The handler feeds it from `data` and `window_change_request`. Bytes that
/// arrive while no command runs go to the line editor, as for any other app.
pub(crate) struct ShellInput {
    running: AtomicBool,
    input: mpsc::Sender<Bytes>,
    resize: mpsc::Sender<(u32, u32, u32, u32)>,
    size: Mutex<(u32, u32, u32, u32)>,
}

/// The command's ends of [`ShellInput`].
pub(crate) struct CommandInput {
    pub input: mpsc::Receiver<Bytes>,
    pub resize: mpsc::Receiver<(u32, u32, u32, u32)>,
}

impl ShellInput {
    pub(crate) fn new(size: (u32, u32, u32, u32)) -> (std::sync::Arc<Self>, CommandInput) {
        let (input, input_rx) = mpsc::channel(64);
        let (resize, resize_rx) = mpsc::channel(4);
        (
            std::sync::Arc::new(Self {
                running: AtomicBool::new(false),
                input,
                resize,
                size: Mutex::new(size),
            }),
            CommandInput {
                input: input_rx,
                resize: resize_rx,
            },
        )
    }

    /// Hand `data` to the running command. `false` when none runs, and the
    /// caller gives it to the line editor.
    pub(crate) async fn data(&self, data: &[u8]) -> bool {
        if !self.running.load(Ordering::Acquire) {
            return false;
        }
        // A full queue holds the session loop until the command reads, as
        // russh's own channel queue would. A closed one means the shell ended.
        let _ = self.input.send(Bytes::copy_from_slice(data)).await;
        true
    }

    pub(crate) fn resize(&self, size: (u32, u32, u32, u32)) {
        *self.size.lock().unwrap() = size;
        if self.running.load(Ordering::Acquire) {
            let _ = self.resize.try_send(size);
        }
    }

    pub(crate) fn size(&self) -> (u32, u32, u32, u32) {
        *self.size.lock().unwrap()
    }

    fn set_running(&self, running: bool) {
        self.running.store(running, Ordering::Release);
    }
}

/// How a command ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    Exited(u32),
    /// Killed by a signal, as the target reports it: `INT`, `KILL`, ...
    Signalled(String),
    /// Stopped by the bastion: `command_timeout` ran out.
    TimedOut,
    /// The channel closed with no exit status: the user stopped it twice, or
    /// the target went away.
    Closed,
    /// The target refused to run it.
    Refused,
}

/// What one command needs.
pub(crate) struct Job<'a> {
    /// The whole exec string: the working directory and the approved line.
    pub command: &'a str,
    /// `Some` to run on a pty with the client's terminal.
    pub pty: Option<&'a Terminal>,
    pub stdin: bool,
    /// Zero is no limit.
    pub timeout: Duration,
}

/// Run `job` on `channel`, a session channel just opened on the target, with
/// the user's terminal at `out`. Returns once the channel closes, with whether
/// the output left the cursor at the start of a line.
pub(crate) async fn run(
    channel: Channel<ru_client::Msg>,
    job: Job<'_>,
    shell: &ShellInput,
    from_user: &mut CommandInput,
    out: &mpsc::Sender<Bytes>,
) -> Result<(Outcome, bool), ServerError> {
    // Keystrokes typed before the command started were meant for the prompt.
    // drops the previous command's undelivered input
    while from_user.input.try_recv().is_ok() {}
    while from_user.resize.try_recv().is_ok() {}

    let (mut read, write) = channel.split();
    if let Some(t) = job.pty {
        let (cols, rows, pw, ph) = shell.size();
        write
            .request_pty(false, &t.term, cols, rows, pw, ph, &t.modes)
            .await?;
    }
    write.exec(true, job.command).await?;
    if !job.stdin {
        write.eof().await?;
    }

    shell.set_running(true);
    let result = pump(&mut read, &write, &job, from_user, out).await;
    shell.set_running(false);
    result
}

async fn pump(
    read: &mut russh::ChannelReadHalf,
    write: &russh::ChannelWriteHalf<ru_client::Msg>,
    job: &Job<'_>,
    from_user: &mut CommandInput,
    out: &mpsc::Sender<Bytes>,
) -> Result<(Outcome, bool), ServerError> {
    let pty = job.pty.is_some();
    // With a pty and stdin the target's terminal handles every key, Ctrl-C
    // included. Otherwise the bastion does: there is no terminal on the
    // target to turn Ctrl-C into a signal.
    let raw = pty && job.stdin;
    let mut crlf = Crlf::default();
    let mut at_line_start = true;
    let mut line = LineInput::default();
    let mut outcome = None;
    let mut interrupts = 0;
    let mut timed_out = false;
    let mut closing_since: Option<Instant> = None;
    let deadline = (!job.timeout.is_zero()).then(|| Instant::now() + job.timeout);
    let far = Instant::now() + Duration::from_secs(365 * 24 * 3600);

    loop {
        let wake = match (closing_since, deadline) {
            (Some(at), _) => at + GRACE,
            (None, Some(d)) if !timed_out => d,
            _ => far,
        };
        tokio::select! {
            msg = read.wait() => {
                let Some(msg) = msg else { break };
                match msg {
                    ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, ext: 1 } => {
                        let data = if pty { Bytes::copy_from_slice(&data) } else { crlf.convert(&data) };
                        if let Some(&last) = data.last() {
                            at_line_start = last == b'\n';
                        }
                        if out.send(data).await.is_err() {
                            write.close().await?;
                            break;
                        }
                    }
                    ChannelMsg::ExitStatus { exit_status } => {
                        outcome.get_or_insert(Outcome::Exited(exit_status));
                    }
                    ChannelMsg::ExitSignal { signal_name, .. } => {
                        outcome.get_or_insert(Outcome::Signalled(signal_name_text(&signal_name)));
                    }
                    ChannelMsg::Failure => {
                        outcome.get_or_insert(Outcome::Refused);
                        write.close().await?;
                        closing_since.get_or_insert_with(Instant::now);
                    }
                    ChannelMsg::Close => break,
                    _ => {}
                }
            }
            Some(data) = from_user.input.recv() => {
                if raw {
                    write.data(&data[..]).await?;
                    continue;
                }
                for action in line.feed(&data, job.stdin) {
                    match action {
                        Key::Echo(b) => {
                            at_line_start = b.ends_with(b"\n");
                            let _ = out.send(b).await;
                        }
                        Key::Send(b) => write.data(&b[..]).await?,
                        Key::Eof => write.eof().await?,
                        Key::Interrupt => {
                            interrupts += 1;
                            if interrupts == 1 {
                                write.signal(Sig::INT).await?;
                            } else {
                                write.close().await?;
                                closing_since.get_or_insert_with(Instant::now);
                            }
                        }
                    }
                }
            }
            Some((cols, rows, pw, ph)) = from_user.resize.recv(), if pty => {
                write.window_change(cols, rows, pw, ph).await?;
            }
            _ = tokio::time::sleep_until(wake) => {
                if closing_since.is_some() {
                    break;
                }
                timed_out = true;
                write.signal(Sig::TERM).await?;
                write.close().await?;
                closing_since = Some(Instant::now());
            }
        }
    }
    if timed_out {
        return Ok((Outcome::TimedOut, at_line_start));
    }
    Ok((outcome.unwrap_or(Outcome::Closed), at_line_start))
}

/// Run `command` with no pty and no input, and collect what it prints on
/// stdout and stderr. For the bastion's own queries: `pwd`, `cd`.
pub(crate) async fn query(
    channel: Channel<ru_client::Msg>,
    command: &str,
) -> Result<(Outcome, Vec<u8>, Vec<u8>), ServerError> {
    let (mut read, write) = channel.split();
    write.exec(true, command).await?;
    write.eof().await?;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut outcome = Outcome::Closed;
    let deadline = Instant::now() + QUERY_TIMEOUT;
    loop {
        tokio::select! {
            msg = read.wait() => match msg {
                Some(ChannelMsg::Data { data }) => stdout.extend_from_slice(&data),
                Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
                    stderr.extend_from_slice(&data)
                }
                Some(ChannelMsg::ExitStatus { exit_status }) => outcome = Outcome::Exited(exit_status),
                Some(ChannelMsg::Failure) => outcome = Outcome::Refused,
                Some(ChannelMsg::Close) | None => break,
                Some(_) => {}
            },
            _ = tokio::time::sleep_until(deadline) => {
                write.close().await?;
                return Ok((Outcome::TimedOut, stdout, stderr));
            }
        }
    }
    Ok((outcome, stdout, stderr))
}

fn signal_name_text(sig: &Sig) -> String {
    match sig {
        Sig::Custom(name) => name.clone(),
        other => format!("{other:?}"),
    }
}

/// Turns the target's `\n` into `\r\n`: without a pty nothing on the target
/// does, and the user's terminal is in raw mode.
#[derive(Default)]
struct Crlf {
    last: u8,
}

impl Crlf {
    // Builds a fresh buffer: the caller's data is only read, and only
    // the last byte carries over from one call to the next, so a trailing
    // CR still pairs with the LF of the next chunk.
    fn convert(&mut self, data: &[u8]) -> Bytes {
        let mut out = Vec::with_capacity(data.len() + data.len() / 16);
        for &b in data {
            if b == b'\n' && self.last != b'\r' {
                out.push(b'\r');
            }
            out.push(b);
            self.last = b;
        }
        out.into()
    }
}

/// What a keystroke does to a command running without a pty.
#[derive(Debug, PartialEq, Eq)]
enum Key {
    Echo(Bytes),
    Send(Bytes),
    Eof,
    Interrupt,
}

/// A minimal line discipline, for `stdin` commands without a pty: the target
/// has no terminal to echo and edit what the user types, so the bastion does.
/// A line is sent on Enter; Backspace edits it; Ctrl-D sends what is typed,
/// or end-of-input on an empty line; Ctrl-C interrupts. Escape sequences
/// (arrow keys) are dropped.
#[derive(Default)]
struct LineInput {
    line: Vec<u8>,
    escape: Escape,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Escape {
    #[default]
    None,
    Esc,
    Csi,
}

impl LineInput {
    /// With `stdin` off, only Ctrl-C does anything.
    fn feed(&mut self, data: &[u8], stdin: bool) -> Vec<Key> {
        let mut keys = Vec::new();
        for &b in data {
            if b == 0x03 {
                keys.push(Key::Interrupt);
                continue;
            }
            if !stdin {
                continue;
            }
            match self.escape {
                Escape::Esc => {
                    self.escape = if b == b'[' || b == b'O' {
                        Escape::Csi
                    } else {
                        Escape::None
                    };
                    continue;
                }
                // The rest of a CSI sequence is swallowed whole. ECMA-48
                // clause 5.4 fixes the parameter bytes at 0x30-0x3f and the
                // intermediate bytes at 0x20-0x2f, so the first byte in
                // 0x40-0x7e must be the one final byte, which ends the
                // sequence; 0x7f (DEL) is excluded by the standard.
                Escape::Csi => {
                    if (0x40..=0x7e).contains(&b) {
                        self.escape = Escape::None;
                    }
                    continue;
                }
                Escape::None => {}
            }
            match b {
                0x1b => self.escape = Escape::Esc,
                b'\r' | b'\n' => {
                    self.line.push(b'\n');
                    keys.push(Key::Echo(Bytes::from_static(b"\r\n")));
                    keys.push(Key::Send(std::mem::take(&mut self.line).into()));
                }
                0x04 if self.line.is_empty() => keys.push(Key::Eof),
                0x04 => keys.push(Key::Send(std::mem::take(&mut self.line).into())),
                // Backspace: DEL (0x7f), or Ctrl-H (0x08) on some terminals.
                // Erase one whole character, not one byte of it, and every
                // cell it covered: a CJK character is two cells wide.
                0x7f | 0x08 => {
                    if let Some(echo) = self.backspace() {
                        keys.push(Key::Echo(echo));
                    }
                }
                b'\t' => {
                    self.line.push(b);
                    keys.push(Key::Echo(Bytes::from_static(b"\t")));
                }
                b if b < 0x20 => {}
                b => {
                    self.line.push(b);
                    keys.push(Key::Echo(Bytes::copy_from_slice(&[b])));
                }
            }
        }
        keys
    }

    /// Pop one character off the line and give the bytes that blank it on
    /// the screen. The erase covers one cell per point of the character's
    /// width: two for a CJK character, none for a combining mark, which was
    /// drawn over the cell before it. `None` when the line is empty, so
    /// backspace then does nothing at all instead of eating the prompt.
    fn backspace(&mut self) -> Option<Bytes> {
        let mut popped = [0u8; 4];
        let mut n = 0;
        // The bytes of one character, popped back to front: continuation
        // bytes first, the lead byte last.
        while n < 4 {
            let Some(b) = self.line.pop() else {
                break;
            };
            popped[n] = b;
            n += 1;
            if b & 0xc0 != 0x80 {
                break;
            }
        }
        if n == 0 {
            return None;
        }
        popped[..n].reverse();
        let width = std::str::from_utf8(&popped[..n])
            .ok()
            .and_then(|s| s.chars().next())
            .map_or(1, |c| c.width().unwrap_or(1));
        (width > 0).then(|| {
            // Back over the cells, blank them, back again.
            let mut echo = Vec::with_capacity(width * 3);
            echo.resize(width, 0x08);
            echo.resize(width * 2, b' ');
            echo.resize(width * 3, 0x08);
            echo.into()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newlines_become_crlf_once() {
        let mut c = Crlf::default();
        assert_eq!(&c.convert(b"a\nb\r\nc\n")[..], b"a\r\nb\r\nc\r\n");
        // A `\r` at the end of one chunk still pairs with the `\n` of the next.
        assert_eq!(&c.convert(b"d\r")[..], b"d\r");
        assert_eq!(&c.convert(b"\ne")[..], b"\ne");
    }

    #[test]
    fn lines_are_edited_on_the_bastion() {
        let mut l = LineInput::default();
        let keys = l.feed("ab\x7fc\u{e9}\x7f\x1b[Dd\r".as_bytes(), true);
        let sent: Vec<_> = keys
            .iter()
            .filter_map(|k| match k {
                Key::Send(b) => Some(b.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(sent, [Bytes::from_static(b"acd\n")]);
        assert_eq!(l.feed(b"\x04", true), [Key::Eof]);
        assert_eq!(
            l.feed(b"x\x04", true),
            [
                Key::Echo(Bytes::from_static(b"x")),
                Key::Send(Bytes::from_static(b"x"))
            ]
        );
    }

    #[test]
    fn backspace_blanks_every_cell_of_a_wide_character() {
        let mut l = LineInput::default();
        // Two CJK characters, each three bytes and two cells wide.
        let keys = l.feed("\u{6211}\u{4eec}\x7f\x7f".as_bytes(), true);
        let echo: Vec<Bytes> = keys
            .iter()
            .filter_map(|k| match k {
                Key::Echo(b) => Some(b.clone()),
                _ => None,
            })
            .collect();
        // The six bytes of the two characters, then a two-cell erase each.
        assert_eq!(echo.len(), 8);
        assert_eq!(&echo[6], &Bytes::from_static(b"\x08\x08  \x08\x08"));
        assert_eq!(&echo[7], &Bytes::from_static(b"\x08\x08  \x08\x08"));
        assert!(l.line.is_empty());
        // Nothing left to erase: no echo, and the prompt is safe.
        assert_eq!(l.feed(b"\x7f", true), []);
    }

    #[test]
    fn backspace_after_a_combining_mark_erases_no_cell() {
        let mut l = LineInput::default();
        let keys = l.feed("e\u{301}\x7f\r".as_bytes(), true);
        let sent: Vec<_> = keys
            .iter()
            .filter_map(|k| match k {
                Key::Send(b) => Some(b.clone()),
                _ => None,
            })
            .collect();
        // The mark is popped whole but blanks nothing; `e` survives.
        assert_eq!(sent, [Bytes::from_static(b"e\n")]);
    }

    #[test]
    fn without_stdin_only_ctrl_c_counts() {
        let mut l = LineInput::default();
        assert_eq!(l.feed(b"rm -rf /\r\x03", false), [Key::Interrupt]);
    }
}
