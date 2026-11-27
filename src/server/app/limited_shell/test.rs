//! The runner end to end: a russh client channel to a fake target over
//! `tokio::io::duplex`. The target records what reaches it, so the tests can
//! assert on the exact exec string, the pty request, the input and EOF.

use super::run::{self, CommandInput, Job, Outcome, ShellInput, Terminal};
use bytes::Bytes;
use russh::keys::{Algorithm, PrivateKey, PublicKeyOrCertificate};
use russh::server::{self as ru_server, Auth, Msg, Session};
use russh::{Channel, ChannelId, Pty, Sig, client as ru_client};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Ev {
    Pty(String, u32, u32),
    Exec(String),
    Data(Vec<u8>),
    Eof,
    Signal(String),
    Window(u32, u32),
}

#[derive(Clone, Default)]
struct Target {
    seen: Arc<Mutex<Vec<Ev>>>,
    /// The program of the last exec, by the part after `&&`.
    program: Arc<Mutex<String>>,
    /// The directories that exist: a path, and what `pwd -P` says there.
    /// `/bin/rmdir /var/log/gone` removes one, so a test can delete the visit's
    /// working directory under it.
    dirs: Arc<Mutex<std::collections::HashMap<String, String>>>,
    /// Whether the shell's own queries (`cd -- ... && pwd -P`) are answered
    /// more slowly than their timeout: to the shell, not answered at all.
    slow_queries: Arc<std::sync::atomic::AtomicBool>,
}

impl Target {
    fn seen(&self) -> Vec<Ev> {
        self.seen.lock().unwrap().clone()
    }

    fn push(&self, e: Ev) {
        self.seen.lock().unwrap().push(e);
    }

    /// The directory table, filled on first use.
    fn dirs(&self) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, String>> {
        let mut dirs = self.dirs.lock().unwrap();
        if dirs.is_empty() {
            *dirs = [
                ("/srv/link", "/etc"),
                ("/var/log", "/var/log"),
                ("/var/log/nginx", "/var/log/nginx"),
                ("/home/u", "/home/u"),
                ("/etc", "/etc"),
                ("/var/log/gone", "/var/log/gone"),
                ("/", "/"),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        }
        dirs
    }
}

fn finish(session: &mut Session, channel: ChannelId, status: u32) -> Result<(), russh::Error> {
    session.exit_status_request(channel, status)?;
    session.eof(channel)?;
    session.close(channel)
}

impl ru_server::Handler for Target {
    type Error = russh::Error;
    type Data = ();

    async fn auth_none(&mut self, _: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn auth_password(&mut self, _: &str, _: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ru_server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        drop(channel);
        reply.accept().await;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn pty_request(
        &mut self,
        _: ChannelId,
        term: &str,
        cols: u32,
        rows: u32,
        _: u32,
        _: u32,
        _: &[(Pty, u32)],
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.push(Ev::Pty(term.into(), cols, rows));
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        _: ChannelId,
        cols: u32,
        rows: u32,
        _: u32,
        _: u32,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.push(Ev::Window(cols, rows));
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let cmd = String::from_utf8_lossy(data).into_owned();
        // A test can make the target answer the shell's own queries more
        // slowly than their timeout (50ms under the test harness), which
        // is indistinguishable from a target that does not answer at all.
        if self.slow_queries.load(std::sync::atomic::Ordering::Relaxed)
            && cmd.contains("&& pwd -P")
        {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        self.push(Ev::Exec(cmd.clone()));
        session.channel_success(channel)?;
        // A run is `cd -- '<pwd>' || exit 125; <program>`, a `cd` query
        // `cd -- '<pwd>' && cd -- '<named>' && pwd -P`. The program is what
        // follows the last of those.
        let program = match cmd.split_once("|| exit 125; ") {
            Some((_, rest)) => rest.to_owned(),
            None => cmd.rsplit("&& ").next().unwrap_or(&cmd).to_owned(),
        };
        *self.program.lock().unwrap() = program.clone();
        // The working directory the line starts from: a directory the fake
        // does not know fails, as it would on a real target, and a run then
        // reports the sentinel of its own accord.
        if let Some(dir) = cmd
            .strip_prefix("cd -- '")
            .and_then(|r| r.split('\'').next())
            && !self.dirs().contains_key(dir)
        {
            session.extended_data(channel, 1, Bytes::from(format!("cd: can't cd to {dir}\n")))?;
            let status = if cmd.contains("|| exit 125; ") {
                125
            } else {
                1
            };
            return finish(session, channel, status);
        }
        match program.as_str() {
            "pwd -P" if !cmd.contains("&&") => {
                session.data(channel, Bytes::from_static(b"/home/u\n"))?;
                finish(session, channel, 0)
            }
            // `cd -- '<pwd>' && cd -- '<named>' && pwd -P`: `/srv/link`
            // is a symlink to `/etc`.
            "pwd -P" => {
                // The suffix strip takes the closing quote with it, so
                // what follows the last `cd -- '` is the directory as-is.
                let dir = cmd
                    .strip_suffix("' && pwd -P")
                    .and_then(|r| r.rsplit("cd -- '").next())
                    .map(str::to_owned)
                    .unwrap_or_default();
                let physical = self.dirs().get(&dir).cloned();
                match physical {
                    Some(p) => {
                        session.data(channel, Bytes::from(format!("{p}\n")))?;
                        finish(session, channel, 0)
                    }
                    None => {
                        // The target's own wording, on stderr, as sh would.
                        session.extended_data(
                            channel,
                            1,
                            Bytes::from(format!("cd: can't cd to {dir}\n")),
                        )?;
                        finish(session, channel, 1)
                    }
                }
            }
            "/bin/echo hi" => {
                session.data(channel, Bytes::from_static(b"hi\nthere\n"))?;
                finish(session, channel, 0)
            }
            "/bin/false" => finish(session, channel, 3),
            // A command that exits the sentinel's number of its own accord.
            "/usr/bin/code125" => finish(session, channel, 125),
            "/usr/bin/df -h" => {
                session.data(channel, Bytes::from_static(b"disk\n"))?;
                finish(session, channel, 0)
            }
            "/bin/rmdir /var/log/gone" => {
                self.dirs().remove("/var/log/gone");
                finish(session, channel, 0)
            }
            // `/bin/cat`, `/bin/wait` and `/bin/hang` answer input, signals,
            // or nothing at all.
            _ => Ok(()),
        }
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.push(Ev::Data(data.to_vec()));
        if self.program.lock().unwrap().as_str() == "/bin/cat" {
            session.data(channel, Bytes::copy_from_slice(data))?;
            if data.contains(&b'q') {
                finish(session, channel, 0)?;
            }
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.push(Ev::Eof);
        if self.program.lock().unwrap().as_str() == "/bin/cat" {
            finish(session, channel, 0)?;
        }
        Ok(())
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.push(Ev::Signal(format!("{signal:?}")));
        if self.program.lock().unwrap().as_str() == "/bin/wait" && matches!(signal, Sig::INT) {
            finish(session, channel, 130)?;
        }
        Ok(())
    }
}

struct AnyHostKey;

impl ru_client::Handler for AnyHostKey {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A client connection to a fresh fake target.
async fn connect() -> (ru_client::Handle<AnyHostKey>, Target) {
    let target = Target::default();
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("host key");
    let config = Arc::new(ru_server::Config {
        keys: vec![key],
        ..Default::default()
    });
    let (server_io, client_io) = tokio::io::duplex(1 << 16);
    let handler = target.clone();
    tokio::spawn(async move {
        ru_server::run_stream(config, server_io, handler)
            .await?
            .await
    });
    let mut client = ru_client::connect_stream(
        Arc::new(ru_client::Config::default()),
        client_io,
        AnyHostKey,
    )
    .await
    .expect("connect");
    assert!(client.authenticate_none("u").await.expect("auth").success());
    (client, target)
}

/// One command run in the background, with the user's side of it.
struct Running {
    shell: Arc<ShellInput>,
    out: mpsc::Receiver<Bytes>,
    task: tokio::task::JoinHandle<(Outcome, bool)>,
}

impl Running {
    async fn start(
        client: &ru_client::Handle<AnyHostKey>,
        command: &str,
        pty: bool,
        stdin: bool,
        timeout: Duration,
    ) -> Self {
        let channel = client.channel_open_session().await.expect("open channel");
        let (shell, from_user) = ShellInput::new((80, 24, 0, 0));
        let (out_tx, out) = mpsc::channel(64);
        let command = command.to_owned();
        let shell_task = shell.clone();
        let task = tokio::spawn(async move {
            let mut from_user: CommandInput = from_user;
            let terminal = Terminal {
                term: "xterm".into(),
                modes: Vec::new(),
            };
            let job = Job {
                command: &command,
                pty: pty.then_some(&terminal),
                stdin,
                timeout,
            };
            run::run(channel, job, &shell_task, &mut from_user, &out_tx)
                .await
                .expect("run")
        });
        Self { shell, out, task }
    }

    /// Type `data` once the command is running.
    async fn type_in(&self, data: &[u8]) {
        for _ in 0..200 {
            if self.shell.data(data).await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the command never started reading input");
    }

    async fn finish(mut self) -> (Outcome, bool, Vec<u8>) {
        let (outcome, at_line_start) = tokio::time::timeout(Duration::from_secs(10), self.task)
            .await
            .expect("the command did not end")
            .expect("run task");
        let mut out = Vec::new();
        while let Ok(b) = self.out.try_recv() {
            out.extend_from_slice(&b);
        }
        (outcome, at_line_start, out)
    }
}

const NO_LIMIT: Duration = Duration::ZERO;

#[tokio::test]
async fn a_command_without_pty_gets_eof_and_its_output_crlf() {
    let (client, target) = connect().await;
    let cmd = "cd -- '/home/u' && /bin/echo hi";
    let run = Running::start(&client, cmd, false, false, NO_LIMIT).await;
    let (outcome, at_line_start, out) = run.finish().await;
    assert_eq!(outcome, Outcome::Exited(0));
    assert!(at_line_start);
    assert_eq!(out, b"hi\r\nthere\r\n");
    // The exact string that was checked, with no pty.
    assert_eq!(target.seen()[0], Ev::Exec(cmd.into()));
    assert!(!target.seen().iter().any(|e| matches!(e, Ev::Pty(..))));
}

/// Without `stdin` the command reads end-of-input at once: `cat` cannot wait
/// for a script from the user.
#[tokio::test]
async fn a_command_without_stdin_reads_eof_at_once() {
    let (client, target) = connect().await;
    let run = Running::start(&client, "cd -- '/' && /bin/cat", false, false, NO_LIMIT).await;
    assert_eq!(run.finish().await.0, Outcome::Exited(0));
    let seen = target.seen();
    assert_eq!(seen[1..], [Ev::Eof], "{seen:?}");
}

#[tokio::test]
async fn the_exit_status_comes_back() {
    let (client, _) = connect().await;
    let run = Running::start(&client, "cd -- '/' && /bin/false", false, false, NO_LIMIT).await;
    assert_eq!(run.finish().await.0, Outcome::Exited(3));
}

#[tokio::test]
async fn a_pty_command_gets_the_terminal_its_keys_and_resizes() {
    let (client, target) = connect().await;
    let run = Running::start(&client, "cd -- '/' && /bin/cat", true, true, NO_LIMIT).await;
    run.type_in(b"ab\x03").await;
    run.shell.resize((100, 30, 0, 0));
    tokio::time::sleep(Duration::from_millis(50)).await;
    run.type_in(b"q").await;
    let (outcome, _, out) = run.finish().await;
    assert_eq!(outcome, Outcome::Exited(0));
    // Raw: the bytes the target's pty would see, Ctrl-C included, and the
    // output untouched.
    assert_eq!(out, b"ab\x03q");
    let seen = target.seen();
    assert_eq!(seen[0], Ev::Pty("xterm".into(), 80, 24));
    assert!(seen.contains(&Ev::Data(b"ab\x03".to_vec())), "{seen:?}");
    assert!(seen.contains(&Ev::Window(100, 30)), "{seen:?}");
    assert!(!seen.contains(&Ev::Eof), "{seen:?}");
}

#[tokio::test]
async fn ctrl_c_signals_a_command_without_a_terminal() {
    let (client, target) = connect().await;
    let run = Running::start(&client, "cd -- '/' && /bin/wait", false, false, NO_LIMIT).await;
    // Typed input goes nowhere without `stdin`; Ctrl-C is a signal.
    run.type_in(b"rm -rf /\r\x03").await;
    assert_eq!(run.finish().await.0, Outcome::Exited(130));
    let seen = target.seen();
    assert!(seen.contains(&Ev::Signal("INT".into())), "{seen:?}");
    assert!(!seen.iter().any(|e| matches!(e, Ev::Data(_))), "{seen:?}");
}

#[tokio::test]
async fn a_second_ctrl_c_closes_a_command_that_ignores_the_first() {
    let (client, _) = connect().await;
    let run = Running::start(&client, "cd -- '/' && /bin/hang", false, false, NO_LIMIT).await;
    run.type_in(b"\x03").await;
    run.type_in(b"\x03").await;
    assert_eq!(run.finish().await.0, Outcome::Closed);
}

#[tokio::test]
async fn stdin_without_a_pty_is_edited_on_the_bastion() {
    let (client, target) = connect().await;
    let run = Running::start(&client, "cd -- '/' && /bin/cat", false, true, NO_LIMIT).await;
    run.type_in(b"ab\x7fc\r").await;
    run.type_in(b"\x04").await;
    let (outcome, at_line_start, out) = run.finish().await;
    assert_eq!(outcome, Outcome::Exited(0));
    assert!(at_line_start);
    let seen = target.seen();
    assert_eq!(seen[1..], [Ev::Data(b"ac\n".to_vec()), Ev::Eof], "{seen:?}");
    // The echo, then what cat printed back.
    assert_eq!(out, b"ab\x08 \x08c\r\nac\r\n");
}

#[tokio::test]
async fn the_time_limit_stops_a_command() {
    let (client, target) = connect().await;
    let limit = Duration::from_millis(200);
    let run = Running::start(&client, "cd -- '/' && /bin/hang", false, false, limit).await;
    assert_eq!(run.finish().await.0, Outcome::TimedOut);
    assert!(target.seen().contains(&Ev::Signal("TERM".into())));
}

#[tokio::test]
async fn input_goes_to_the_prompt_while_no_command_runs() {
    let (shell, _) = ShellInput::new((80, 24, 0, 0));
    assert!(!shell.data(b"x").await);
}

#[tokio::test]
async fn queries_collect_the_output() {
    let (client, _) = connect().await;
    let channel = client.channel_open_session().await.unwrap();
    let (outcome, stdout, _) = run::query(channel, "pwd -P").await.unwrap();
    assert_eq!(
        (outcome, stdout),
        (Outcome::Exited(0), b"/home/u\n".to_vec())
    );

    let channel = client.channel_open_session().await.unwrap();
    let (outcome, _, stderr) = run::query(channel, "cd -- '/nope' && pwd -P")
        .await
        .unwrap();
    assert_eq!(outcome, Outcome::Exited(1));
    // The target's stderr is collected, not swallowed.
    assert_eq!(stderr, b"cd: can't cd to /nope\n".to_vec());
}

mod through_the_bastion {
    use super::{AnyHostKey, Ev, Target};
    use crate::config::Config;
    use crate::database::Uuid;
    use crate::database::common::InternalUuids;
    use crate::database::entity::{
        casbin_name, casbin_rule, command_set, secret, target, target_secret,
    };
    use crate::database::fixture::{self, LUKA, PASSWORD};
    use crate::database::models::{EventKind, HistoryScope, NamePtype, Ptype};
    use crate::server::{BastionServer, HandlerBackend};
    use russh::keys::{Algorithm, PrivateKey};
    use russh::{ChannelMsg, client as ru_client, server as ru_server};
    use sea_orm::ActiveValue::Set;
    use std::sync::Arc;
    use std::time::Duration;

    const CONFIG: &str = r#"{"commands":[{"alias":"code125","exec":"/usr/bin/code125","description":"Exits 125"},{"alias":"df","exec":"/usr/bin/df -h","description":"Disk usage"},{"alias":"false","exec":"/bin/false","description":"Fails"},{"alias":"rmdir","exec":"/bin/rmdir /var/log/gone","description":"Deletes /var/log/gone"}],"cd":["/var/log(/.*)?"]}"#;

    async fn policy(server: &BastionServer, admin: Uuid, v0: Uuid, v1: Uuid, v2: Uuid) {
        server
            .db_repository()
            .create_casbin_rule(casbin_rule::ActiveModel {
                id: Set(Uuid::now_v7()),
                ptype: Set(Ptype::Policy),
                v0: Set(v0),
                v1: Set(v1),
                v2: Set(v2),
                v3: Set("{}".into()),
                v4: Set(String::new()),
                v5: Set(String::new()),
                updated_by: Set(admin),
                ..Default::default()
            })
            .await
            .expect("insert policy");
    }

    /// A target on a local port, bound with a secret, and a set granting `df`
    /// on it to `user`. Returns the target's name and what it sees.
    async fn target_with_commands(
        server: &BastionServer,
        f: &fixture::Fixture,
        user: Uuid,
    ) -> (String, Target) {
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("host key");
        let public = key.public_key().to_openssh().expect("openssh key");
        let config = Arc::new(ru_server::Config {
            keys: vec![key],
            ..Default::default()
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let fake = Target::default();
        let handler = fake.clone();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let (config, handler) = (config.clone(), handler.clone());
                tokio::spawn(
                    async move { ru_server::run_stream(config, socket, handler).await?.await },
                );
            }
        });

        let repo = server.db_repository();
        let name = format!("cmd-{port}");
        let t = repo
            .create_target(target::ActiveModel {
                id: Set(Uuid::now_v7()),
                name: Set(name.clone()),
                hostname: Set("127.0.0.1".into()),
                port: Set(port as i32),
                server_public_key: Set(public),
                is_active: Set(true),
                updated_by: Set(f.admin_id),
                ..Default::default()
            })
            .await
            .expect("target");
        let s = repo
            .create_secret(secret::ActiveModel {
                id: Set(Uuid::now_v7()),
                name: Set(format!("cmd-secret-{port}")),
                user: Set("root".into()),
                password: Set(Some(server.encrypt_plain_text("pw").unwrap())),
                is_active: Set(true),
                updated_by: Set(f.admin_id),
                ..Default::default()
            })
            .await
            .expect("secret");
        let binding = repo
            .create_target_secret(target_secret::ActiveModel {
                id: Set(Uuid::now_v7()),
                target_id: Set(t.id),
                secret_id: Set(s.id),
                is_active: Set(true),
                updated_by: Set(f.admin_id),
                ..Default::default()
            })
            .await
            .expect("binding")
            .id;
        let set = repo
            .create_command_set(command_set::ActiveModel {
                id: Set(Uuid::now_v7()),
                name: Set("ops".into()),
                config: Set(CONFIG.into()),
                is_active: Set(true),
                updated_by: Set(f.admin_id),
                ..Default::default()
            })
            .await
            .expect("command set")
            .id;
        policy(server, f.admin_id, user, binding, set).await;
        (name, fake)
    }

    /// Let `user` log in under the process-wide `InternalUuids`, which belong
    /// to whichever server in the test binary was built first.
    async fn grant_login(server: &BastionServer, f: &fixture::Fixture, user: Uuid) {
        let ids = InternalUuids::get();
        if ids.obj_login != f.name(crate::database::common::OBJ_LOGIN) {
            server
                .db_repository()
                .create_casbin_name(casbin_name::ActiveModel {
                    id: Set(ids.obj_login),
                    ptype: Set(NamePtype::InternalObjectType),
                    name: Set(format!("login-{}", ids.obj_login)),
                    is_active: Set(true),
                    updated_by: Set(f.admin_id),
                    ..Default::default()
                })
                .await
                .expect("insert login object");
        }
        policy(server, f.admin_id, user, ids.obj_login, ids.act_login).await;
    }

    /// What the client has been shown, answering the cursor-position queries
    /// the line editor makes as a terminal would.
    struct Screen {
        channel: russh::Channel<ru_client::Msg>,
        text: String,
    }

    impl Screen {
        async fn until(&mut self, want: &str) {
            let wait = async {
                while !self.text.contains(want) {
                    match self.channel.wait().await {
                        Some(ChannelMsg::Data { data }) => {
                            let chunk = String::from_utf8_lossy(&data);
                            if chunk.contains("\x1b[6n") {
                                self.channel.data(&b"\x1b[1;1R"[..]).await.unwrap();
                            }
                            self.text.push_str(&chunk);
                        }
                        Some(ChannelMsg::Close) | None => break,
                        Some(_) => {}
                    }
                }
            };
            tokio::time::timeout(Duration::from_secs(10), wait)
                .await
                .unwrap_or_else(|_| panic!("{want:?} never shown; screen:\n{}", self.text));
            assert!(
                self.text.contains(want),
                "{want:?} never shown; screen:\n{}",
                self.text
            );
        }

        /// Wait for the server to close the channel, still collecting what
        /// it says on the way out.
        async fn until_closed(&mut self) {
            let wait = async {
                loop {
                    match self.channel.wait().await {
                        Some(ChannelMsg::Data { data }) => {
                            let chunk = String::from_utf8_lossy(&data);
                            if chunk.contains("\x1b[6n") {
                                self.channel.data(&b"\x1b[1;1R"[..]).await.unwrap();
                            }
                            self.text.push_str(&chunk);
                        }
                        Some(ChannelMsg::Close) | None => break,
                        Some(_) => {}
                    }
                }
            };
            tokio::time::timeout(Duration::from_secs(10), wait)
                .await
                .unwrap_or_else(|_| panic!("channel never closed; screen:\n{}", self.text));
        }

        async fn type_line(&mut self, line: &str) {
            self.text.clear();
            self.channel
                .data(format!("{line}\r").as_bytes())
                .await
                .unwrap();
        }

        /// Type the line one key at a time, as a terminal sends them, then
        /// Enter. A paste sends the whole line as one chunk; this shifts
        /// the timing the line editor sees.
        async fn type_keys(&mut self, line: &str) {
            self.text.clear();
            for c in line.chars() {
                self.channel.data(c.to_string().as_bytes()).await.unwrap();
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            self.channel.data(&b"\r"[..]).await.unwrap();
        }
    }

    /// A client logged in as `user@cmd`, with a pty and the shell asked
    /// for, and the screen it is shown.
    async fn connect_shell(server: &mut BastionServer) -> Screen {
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let server_config = Arc::new(ru_server::Config {
            keys: vec![key],
            ..Default::default()
        });
        let handler = ru_server::Server::new_client(server, None);
        let (server_io, client_io) = tokio::io::duplex(1 << 20);
        tokio::spawn(async move {
            ru_server::run_stream(server_config, server_io, handler)
                .await?
                .await
        });

        let mut client = ru_client::connect_stream(
            Arc::new(ru_client::Config::default()),
            client_io,
            AnyHostKey,
        )
        .await
        .expect("connect");
        let auth = client
            .authenticate_password(format!("{LUKA}@cmd"), PASSWORD)
            .await
            .expect("authenticate");
        assert!(auth.success());
        let channel = client.channel_open_session().await.expect("session");
        channel
            .request_pty(false, "xterm", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        channel.request_shell(false).await.unwrap();
        Screen {
            channel,
            text: String::new(),
        }
    }

    #[tokio::test]
    async fn a_user_runs_only_what_the_set_allows() {
        let db = fixture::seed().await;
        let mut config = Config::default().gen_secret_token();
        config.database = db.url.clone();
        config.reuse_target_connection = false;
        let mut server = BastionServer::with_config(config).await.expect("server");
        let f = &db.fixture;
        let luka = f.user(LUKA);
        grant_login(&server, f, luka).await;
        let (target, fake) = target_with_commands(&server, f, luka).await;
        server.reload_policies().await.unwrap();

        let mut screen = connect_shell(&mut server).await;

        screen.until("> ").await;
        screen.type_line("help").await;
        screen.until(&format!("root@{target}")).await;

        screen.type_line(&target).await;
        let prompt = format!("root@{target}> ");
        screen.until(&prompt).await;

        screen.type_line("df").await;
        screen.until("disk\r\n").await;
        screen.until(&prompt).await;

        // A `cd` the target cannot do: the target's own words come back.
        screen.type_line("cd /var/log/nope").await;
        screen.until("cd: can't cd to /var/log/nope").await;
        screen.until(&prompt).await;

        // A failed command leaves its exit code in the prompt, in red.
        screen.type_line("false").await;
        screen.until("\x1b[91m[3]\x1b[92m> ").await;

        // Refused on the bastion: nothing reaches the target, and the
        // refusal leaves its shell-style code in the prompt.
        screen.type_line("df ; sh").await;
        screen.until("arguments not allowed").await;
        screen.until("\x1b[91m[126]\x1b[92m> ").await;
        screen.type_line("sh").await;
        screen.until("command not found").await;
        screen.until("\x1b[91m[127]\x1b[92m> ").await;
        // A built-in that succeeds clears the code again.
        screen.type_line("help df").await;
        screen.until("USAGE:").await;
        screen.until(&prompt).await;
        // A `cd` the policy refuses leaves a failed `cd`'s 1.
        screen.type_line("cd /etc").await;
        screen.until("not allowed").await;
        screen.until("\x1b[91m[1]\x1b[92m> ").await;
        assert!(!screen.text.contains("/usr/bin"), "{}", screen.text);

        screen.type_line("exit").await;
        screen.until("\x1b[92m> ").await;
        screen.type_line("exit").await;

        let execs: Vec<String> = fake
            .seen()
            .into_iter()
            .filter_map(|e| match e {
                Ev::Exec(cmd) => Some(cmd),
                _ => None,
            })
            .collect();
        assert_eq!(
            execs,
            [
                "pwd -P",
                "cd -- '/home/u' || exit 125; /usr/bin/df -h",
                "cd -- '/home/u' && cd -- '/var/log/nope' && pwd -P",
                "cd -- '/home/u' && pwd -P",
                "cd -- '/home/u' || exit 125; /bin/false",
            ]
        );

        // The audit trail has the visit, the run and both refusals.
        let wait = async {
            loop {
                let rows: Vec<String> = server
                    .db_repository()
                    .list_logs()
                    .await
                    .unwrap()
                    .into_iter()
                    .filter(|l| l.user_id == luka && l.log_type == EventKind::Command)
                    .map(|l| l.detail)
                    .collect();
                if rows.len() >= 4 {
                    return rows;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        let rows = tokio::time::timeout(Duration::from_secs(5), wait)
            .await
            .expect("audit rows");
        for event in ["command_shell", "command_ran", "command_denied"] {
            assert!(rows.iter().any(|r| r.contains(event)), "{event}: {rows:?}");
        }
    }

    /// The lines accepted at the limited shell's prompts land in
    /// `command_history` under the one `limited` scope, behind the prompt;
    /// the admin shell's scope stays apart.
    #[tokio::test]
    async fn the_lines_run_are_kept_in_the_limited_history() {
        let db = fixture::seed().await;
        let mut config = Config::default().gen_secret_token();
        config.database = db.url.clone();
        config.reuse_target_connection = false;
        let mut server = BastionServer::with_config(config).await.expect("server");
        let f = &db.fixture;
        let luka = f.user(LUKA);
        grant_login(&server, f, luka).await;
        let (target, _fake) = target_with_commands(&server, f, luka).await;
        server.reload_policies().await.unwrap();

        let mut screen = connect_shell(&mut server).await;
        screen.until("> ").await;
        screen.type_line(&target).await;
        let prompt = format!("root@{target}> ");
        screen.until(&prompt).await;
        screen.type_line("df").await;
        screen.until("disk\r\n").await;

        // The write lands behind the prompt; give the drain task its moment.
        let wait = async {
            loop {
                let rows = server
                    .db_repository()
                    .list_history(luka, HistoryScope::Limited)
                    .await
                    .unwrap();
                if rows.iter().any(|r| r.command_line == "df") {
                    return rows;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        let rows = tokio::time::timeout(Duration::from_secs(2), wait)
            .await
            .expect("the run reaches the history table");
        let df = rows.iter().find(|r| r.command_line == "df").unwrap();
        assert!(df.created_at > 0, "the row carries its time: {df:?}");
        // Both prompt levels share the scope: the binding's name, read at
        // `>`, is kept too.
        assert!(
            rows.iter().any(|r| r.command_line == target),
            "{rows:?}"
        );
        // The admin shell's history is another scope entirely.
        assert!(
            server
                .db_repository()
                .list_history(luka, HistoryScope::Admin)
                .await
                .unwrap()
                .is_empty()
        );

        screen.type_line("exit").await;
        screen.until("\x1b[92m> ").await;
        screen.type_line("exit").await;
    }

    /// A command may exit 125 of its own accord — the same number the run
    /// exec uses to say it could not enter its working directory. The check
    /// tells the two apart: the directory is still there, so the prompt
    /// keeps the command's own 125 and nothing is said.
    #[tokio::test]
    async fn a_commands_own_125_is_not_the_sentinel() {
        let db = fixture::seed().await;
        let mut config = Config::default().gen_secret_token();
        config.database = db.url.clone();
        config.reuse_target_connection = false;
        let mut server = BastionServer::with_config(config).await.expect("server");
        let f = &db.fixture;
        let luka = f.user(LUKA);
        grant_login(&server, f, luka).await;
        let (target, fake) = target_with_commands(&server, f, luka).await;
        server.reload_policies().await.unwrap();

        let mut screen = connect_shell(&mut server).await;
        screen.until("> ").await;
        screen.type_line(&target).await;
        let clean = format!("root@{target}> ");
        screen.until(&clean).await;

        // The line runs — the working directory is alive — and exits 125
        // on its own: the prompt keeps the number, and neither the hint
        // nor a `cd:` error is said.
        screen.type_line("code125").await;
        screen.until("\x1b[91m[125]\x1b[92m> ").await;
        assert!(
            !screen.text.contains("no longer exists"),
            "the directory is alive; nothing is said:\n{}",
            screen.text
        );
        assert!(
            !screen.text.contains("can't cd"),
            "the line started fine:\n{}",
            screen.text
        );

        // A clean run after it works as usual.
        screen.type_line("df").await;
        screen.until("disk\r\n").await;
        screen.until(&clean).await;

        screen.type_line("exit").await;
        screen.until("\x1b[92m> ").await;
        screen.type_line("exit").await;

        let execs: Vec<String> = fake
            .seen()
            .into_iter()
            .filter_map(|e| match e {
                Ev::Exec(cmd) => Some(cmd),
                _ => None,
            })
            .collect();
        assert_eq!(
            execs,
            [
                "pwd -P",
                // The run itself, then the check that finds the directory
                // still there — which is what keeps the 125 the command's
                // own instead of reading it as the sentinel.
                "cd -- '/home/u' || exit 125; /usr/bin/code125",
                "cd -- '/home/u' && pwd -P",
                "cd -- '/home/u' || exit 125; /usr/bin/df -h",
            ]
        );
    }

    /// A target slower than the query timeout has not answered, and the
    /// shell must not read silence as a verdict: a 125 keeps its own
    /// meaning — nothing says the directory is gone — and a `cd` the
    /// target never answered moves the visit nowhere and claims nothing.
    #[tokio::test]
    async fn a_target_slower_than_the_query_timeout_claims_nothing() {
        let db = fixture::seed().await;
        let mut config = Config::default().gen_secret_token();
        config.database = db.url.clone();
        config.reuse_target_connection = false;
        let mut server = BastionServer::with_config(config).await.expect("server");
        let f = &db.fixture;
        let luka = f.user(LUKA);
        grant_login(&server, f, luka).await;
        let (target, fake) = target_with_commands(&server, f, luka).await;
        // From here the target answers every query past its timeout.
        fake.slow_queries
            .store(true, std::sync::atomic::Ordering::Relaxed);
        server.reload_policies().await.unwrap();

        let mut screen = connect_shell(&mut server).await;
        screen.until("> ").await;
        screen.type_line(&target).await;
        let clean = format!("root@{target}> ");
        screen.until(&clean).await;

        // The run exits 125 of its own accord, and the check that tells
        // the sentinel apart never gets its answer: the code stays the
        // command's own, and the hint is not said.
        screen.type_line("code125").await;
        screen.until("\x1b[91m[125]\x1b[92m> ").await;
        assert!(
            !screen.text.contains("no longer exists"),
            "a slow target has not said the directory is gone:\n{}",
            screen.text
        );

        // A `cd` the target never answered: no denial, no move, no claim
        // the anchor is gone — the failed prompt alone says the line did
        // not go through.
        screen.type_line("cd /var/log").await;
        screen.until("\x1b[91m[1]\x1b[92m> ").await;
        assert!(
            !screen.text.contains("not allowed"),
            "the target never resolved it:\n{}",
            screen.text
        );
        assert!(
            !screen.text.contains("no longer exists"),
            "the target never said the anchor was gone:\n{}",
            screen.text
        );

        // The visit never moved: still at the home the fast opening `pwd`
        // found, and a later line runs anchored there.
        fake.slow_queries
            .store(false, std::sync::atomic::Ordering::Relaxed);
        screen.type_line("pwd").await;
        screen.until("/home/u\r\n").await;
        screen.type_line("df").await;
        screen.until("disk\r\n").await;
        screen.until(&clean).await;

        screen.type_line("exit").await;
        screen.until("\x1b[92m> ").await;
        screen.type_line("exit").await;

        // The sentinel check is sent — its answer just never comes in
        // time — and the `cd` chain stops at its first unanswered query:
        // no cd_check, no retry, no guess. The later `df` still runs
        // anchored at the home the visit never left.
        let execs: Vec<String> = fake
            .seen()
            .into_iter()
            .filter_map(|e| match e {
                Ev::Exec(cmd) => Some(cmd),
                _ => None,
            })
            .collect();
        assert_eq!(
            execs,
            [
                "pwd -P",
                "cd -- '/home/u' || exit 125; /usr/bin/code125",
                "cd -- '/home/u' && pwd -P",
                "cd -- '/home/u' && cd -- '/var/log' && pwd -P",
                "cd -- '/home/u' || exit 125; /usr/bin/df -h",
            ]
        );
    }

    /// A failed `cd` must not poison the lines after it. The sequence the
    /// bug report showed: a `cd` the target cannot do, Enter on empty
    /// lines, then commands — each one must run what was typed, not replay
    /// the failed `cd` or carry the missing directory into a run.
    #[tokio::test]
    async fn a_failed_cd_does_not_replay_on_later_lines() {
        let db = fixture::seed().await;
        let mut config = Config::default().gen_secret_token();
        config.database = db.url.clone();
        config.reuse_target_connection = false;
        let mut server = BastionServer::with_config(config).await.expect("server");
        let f = &db.fixture;
        let luka = f.user(LUKA);
        grant_login(&server, f, luka).await;
        let (target, fake) = target_with_commands(&server, f, luka).await;
        server.reload_policies().await.unwrap();

        let mut screen = connect_shell(&mut server).await;
        screen.until("> ").await;
        screen.type_line(&target).await;
        let clean = format!("root@{target}> ");
        let failed = "\x1b[91m[1]\x1b[92m> ";
        screen.until(&clean).await;

        for round in 0..3 {
            screen.type_line("cd /var/log/nope").await;
            screen.until("cd: can't cd to /var/log/nope").await;
            screen.until(failed).await;
            // Empty lines keep the failed code; they must keep nothing else.
            for _ in 0..7 {
                screen.type_line("").await;
                screen.until(failed).await;
            }
            for i in 0..3 {
                if round == 0 {
                    screen.type_line("df").await;
                } else {
                    screen.type_keys("df").await;
                }
                // The `df` runs: the target's answer, not the `cd`'s error
                // again, and the prompt comes back clean.
                screen.until("disk\r\n").await;
                screen.until(&clean).await;
                assert!(
                    !screen.text.contains("can't cd"),
                    "round {round} df {i} replayed the cd: {}",
                    screen.text
                );
            }
        }

        screen.type_line("exit").await;
        screen.until("\x1b[92m> ").await;
        screen.type_line("exit").await;

        // One cd query for the `cd`, one run for each `df`: nothing more.
        let mut execs: Vec<String> = fake
            .seen()
            .into_iter()
            .filter_map(|e| match e {
                Ev::Exec(cmd) => Some(cmd),
                _ => None,
            })
            .collect();
        assert_eq!(execs.first().map(String::as_str), Some("pwd -P"));
        execs.remove(0);
        let mut want = Vec::new();
        for _ in 0..3 {
            want.push("cd -- '/home/u' && cd -- '/var/log/nope' && pwd -P".to_owned());
            // The check that the working directory is still there.
            want.push("cd -- '/home/u' && pwd -P".to_owned());
            for _ in 0..3 {
                want.push("cd -- '/home/u' || exit 125; /usr/bin/df -h".to_owned());
            }
        }
        assert_eq!(execs, want);
    }

    /// The visit's working directory can stop existing on the target — a
    /// share unmounted, a directory removed. The bug report showed what
    /// happened before the fix: every line after failed with the target's
    /// bare `cd:` error, and nothing recovered until the user left and
    /// re-entered. Now each failing line says what happened — and moves
    /// nothing: the visit stays in the dead directory until the user `cd`s
    /// out of it themselves.
    #[tokio::test]
    async fn a_run_from_a_vanished_directory_hints_until_the_user_moves() {
        let db = fixture::seed().await;
        let mut config = Config::default().gen_secret_token();
        config.database = db.url.clone();
        config.reuse_target_connection = false;
        let mut server = BastionServer::with_config(config).await.expect("server");
        let f = &db.fixture;
        let luka = f.user(LUKA);
        grant_login(&server, f, luka).await;
        let (target, fake) = target_with_commands(&server, f, luka).await;
        server.reload_policies().await.unwrap();

        let mut screen = connect_shell(&mut server).await;
        screen.until("> ").await;
        screen.type_line(&target).await;
        let clean = format!("root@{target}> ");
        let failed = "\x1b[91m[1]\x1b[92m> ";
        screen.until(&clean).await;

        // Into a directory that is then removed from under the visit.
        screen.type_line("cd /var/log/gone").await;
        screen.until(&clean).await;
        screen.type_line("rmdir").await;
        screen.until(&clean).await;

        // The run cannot enter it: the target's own error, the hint, and a
        // failed `cd`'s code in the prompt.
        screen.type_line("df").await;
        screen.until("cd: can't cd to /var/log/gone").await;
        screen
            .until("no longer exists; type cd to go back to /home/u")
            .await;
        screen.until(failed).await;

        // Nothing was moved: the next run fails the same way, and says so
        // again.
        screen.type_line("df").await;
        screen
            .until("no longer exists; type cd to go back to /home/u")
            .await;
        screen.until(failed).await;

        // The user moves; their `cd` names an absolute path, which needs
        // no dead directory to resolve, and it goes through — silently: the
        // hint would tell them to do what they just did.
        screen.type_line("cd /var/log").await;
        screen.until(&clean).await;
        assert!(
            !screen.text.contains("no longer exists"),
            "the escape says nothing:\n{}",
            screen.text
        );

        screen.type_line("df").await;
        screen.until("disk\r\n").await;
        screen.until(&clean).await;

        screen.type_line("exit").await;
        screen.until("\x1b[92m> ").await;
        screen.type_line("exit").await;

        let execs: Vec<String> = fake
            .seen()
            .into_iter()
            .filter_map(|e| match e {
                Ev::Exec(cmd) => Some(cmd),
                _ => None,
            })
            .collect();
        assert_eq!(
            execs,
            [
                "pwd -P",
                "cd -- '/home/u' && cd -- '/var/log/gone' && pwd -P",
                "cd -- '/var/log/gone' || exit 125; /bin/rmdir /var/log/gone",
                // Both runs fail on the dead directory, each followed by
                // the check that it is really gone.
                "cd -- '/var/log/gone' || exit 125; /usr/bin/df -h",
                "cd -- '/var/log/gone' && pwd -P",
                "cd -- '/var/log/gone' || exit 125; /usr/bin/df -h",
                "cd -- '/var/log/gone' && pwd -P",
                // The user's `cd`: the dead anchor fails, the check finds
                // it gone, and the `cd` is asked once more on its own —
                // an absolute path resolves from any start.
                "cd -- '/var/log/gone' && cd -- '/var/log' && pwd -P",
                "cd -- '/var/log/gone' && pwd -P",
                "cd -- '/var/log' && pwd -P",
                "cd -- '/var/log' || exit 125; /usr/bin/df -h",
            ]
        );
    }

    /// The same failure found by a `cd`: the working directory is gone, and
    /// the `cd` dies on it before reaching the directory the user named.
    /// A relative `cd` cannot be resolved at all, so the hint is the whole
    /// answer; an absolute one is asked once more on its own — silently
    /// when it goes through, and with the target's own words when the
    /// directory the user named is not there either.
    #[tokio::test]
    async fn a_cd_leaves_a_vanished_working_directory() {
        let db = fixture::seed().await;
        let mut config = Config::default().gen_secret_token();
        config.database = db.url.clone();
        config.reuse_target_connection = false;
        let mut server = BastionServer::with_config(config).await.expect("server");
        let f = &db.fixture;
        let luka = f.user(LUKA);
        grant_login(&server, f, luka).await;
        let (target, fake) = target_with_commands(&server, f, luka).await;
        server.reload_policies().await.unwrap();

        let mut screen = connect_shell(&mut server).await;
        screen.until("> ").await;
        screen.type_line(&target).await;
        let clean = format!("root@{target}> ");
        let failed = "\x1b[91m[1]\x1b[92m> ";
        screen.until(&clean).await;

        screen.type_line("cd /var/log/gone").await;
        screen.until(&clean).await;
        screen.type_line("rmdir").await;
        screen.until(&clean).await;

        // A relative `cd` cannot be resolved without the directory that
        // held it; the hint is all there is to say for it.
        screen.type_line("cd sub").await;
        screen
            .until("no longer exists; type cd to go back to /home/u")
            .await;
        screen.until(failed).await;

        // A `cd` naming a directory that does not exist either: asked
        // once more on its own, it shows the target's words for the one
        // the user named — and no hint, which would only repeat what
        // `cd sub` just said.
        screen.type_line("cd /var/log/nope").await;
        screen.until("cd: can't cd to /var/log/nope").await;
        screen.until(failed).await;
        assert!(
            !screen.text.contains("no longer exists"),
            "the failed absolute cd needs no hint:\n{}",
            screen.text
        );

        // A `cd` to a real directory escapes the dead one, silently.
        screen.type_line("cd /var/log").await;
        screen.until(&clean).await;
        assert!(
            !screen.text.contains("no longer exists"),
            "the escape says nothing:\n{}",
            screen.text
        );

        screen.type_line("df").await;
        screen.until("disk\r\n").await;
        screen.until(&clean).await;

        screen.type_line("exit").await;
        screen.until("\x1b[92m> ").await;
        screen.type_line("exit").await;

        let execs: Vec<String> = fake
            .seen()
            .into_iter()
            .filter_map(|e| match e {
                Ev::Exec(cmd) => Some(cmd),
                _ => None,
            })
            .collect();
        assert_eq!(
            execs,
            [
                "pwd -P",
                "cd -- '/home/u' && cd -- '/var/log/gone' && pwd -P",
                "cd -- '/var/log/gone' || exit 125; /bin/rmdir /var/log/gone",
                // A relative `cd` dies on the working directory, and the
                // check that finds it gone is the last query: there is no
                // resolving it from anywhere else.
                "cd -- '/var/log/gone' && cd -- 'sub' && pwd -P",
                "cd -- '/var/log/gone' && pwd -P",
                // The `cd` to a missing directory dies the same way; the
                // check finds the anchor gone, and the `cd` on its own
                // fails on the directory the user named.
                "cd -- '/var/log/gone' && cd -- '/var/log/nope' && pwd -P",
                "cd -- '/var/log/gone' && pwd -P",
                "cd -- '/var/log/nope' && pwd -P",
                // The escape, asked once more on its own.
                "cd -- '/var/log/gone' && cd -- '/var/log' && pwd -P",
                "cd -- '/var/log/gone' && pwd -P",
                "cd -- '/var/log' && pwd -P",
                "cd -- '/var/log' || exit 125; /usr/bin/df -h",
            ]
        );
    }

    #[tokio::test]
    async fn a_visit_that_cannot_be_recorded_ends() {
        let db = fixture::seed().await;
        let mut config = Config::default().gen_secret_token();
        config.database = db.url.clone();
        config.reuse_target_connection = false;
        // Recording is on, but the cast file cannot be made: no directory
        // can be created under a file.
        config.enable_record = true;
        config.record_path = "/dev/null/record".into();
        let mut server = BastionServer::with_config(config).await.expect("server");
        let f = &db.fixture;
        let luka = f.user(LUKA);
        grant_login(&server, f, luka).await;
        let (target, _fake) = target_with_commands(&server, f, luka).await;
        server.reload_policies().await.unwrap();

        let mut screen = connect_shell(&mut server).await;
        screen.until("> ").await;
        screen.type_line(&target).await;
        // The visit ends rather than run unrecorded, and the shell with
        // it: the channel closes without the entered-target greeting.
        screen.until_closed().await;
        assert!(
            !screen.text.contains("Type help to list commands"),
            "the visit never started; screen:\n{}",
            screen.text
        );
    }
}
