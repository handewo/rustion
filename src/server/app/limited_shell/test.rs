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
}

impl Target {
    fn seen(&self) -> Vec<Ev> {
        self.seen.lock().unwrap().clone()
    }

    fn push(&self, e: Ev) {
        self.seen.lock().unwrap().push(e);
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
        self.push(Ev::Exec(cmd.clone()));
        session.channel_success(channel)?;
        let program = cmd.rsplit("&& ").next().unwrap_or(&cmd).to_owned();
        *self.program.lock().unwrap() = program.clone();
        match program.as_str() {
            "pwd -P" if !cmd.contains("&&") => {
                session.data(channel, Bytes::from_static(b"/home/u\n"))?;
                finish(session, channel, 0)
            }
            // `cd -- '<pwd>' && cd -- '<named>' && pwd -P`: `/srv/link`
            // is a symlink to `/etc`, and a path the fake does not know
            // fails, as it would on a real target.
            "pwd -P" => {
                let dir = cmd
                    .strip_suffix("' && pwd -P")
                    .and_then(|r| r.rsplit("cd -- '").next())
                    .and_then(|d| d.strip_suffix('\''))
                    .map(str::to_owned)
                    .unwrap_or_default();
                let physical = match dir.as_str() {
                    "/srv/link" => Some("/etc"),
                    "/var/log" | "/var/log/nginx" | "/home/u" | "/etc" => Some(dir.as_str()),
                    _ => None,
                };
                match physical {
                    Some(p) => {
                        session.data(channel, Bytes::from(format!("{p}\n")))?;
                        finish(session, channel, 0)
                    }
                    None => finish(session, channel, 1),
                }
            }
            "/bin/echo hi" => {
                session.data(channel, Bytes::from_static(b"hi\nthere\n"))?;
                finish(session, channel, 0)
            }
            "/bin/false" => finish(session, channel, 3),
            "/usr/bin/df -h" => {
                session.data(channel, Bytes::from_static(b"disk\n"))?;
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
    let (outcome, stdout) = run::query(channel, "pwd -P").await.unwrap();
    assert_eq!(
        (outcome, stdout),
        (Outcome::Exited(0), b"/home/u\n".to_vec())
    );

    let channel = client.channel_open_session().await.unwrap();
    let (outcome, _) = run::query(channel, "cd -- '/nope' && pwd -P")
        .await
        .unwrap();
    assert_eq!(outcome, Outcome::Exited(1));
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
    use crate::database::models::{EventKind, NamePtype, Ptype};
    use crate::server::{BastionServer, HandlerBackend};
    use russh::keys::{Algorithm, PrivateKey};
    use russh::{ChannelMsg, client as ru_client, server as ru_server};
    use sea_orm::ActiveValue::Set;
    use std::sync::Arc;
    use std::time::Duration;

    const CONFIG: &str =
        r#"{"commands":[{"alias":"df","exec":"/usr/bin/df -h","description":"Disk usage"}]}"#;

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

        async fn type_line(&mut self, line: &str) {
            self.text.clear();
            self.channel
                .data(format!("{line}\r").as_bytes())
                .await
                .unwrap();
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

        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let server_config = Arc::new(ru_server::Config {
            keys: vec![key],
            ..Default::default()
        });
        let handler = ru_server::Server::new_client(&mut server, None);
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
        let mut screen = Screen {
            channel,
            text: String::new(),
        };

        screen.until("> ").await;
        screen.type_line("help").await;
        screen.until(&format!("root@{target}")).await;

        screen.type_line(&target).await;
        let prompt = format!("root@{target}> ");
        screen.until(&prompt).await;

        screen.type_line("df").await;
        screen.until("disk\r\n").await;
        screen.until(&prompt).await;

        // Refused on the bastion: nothing reaches the target.
        screen.type_line("df ; sh").await;
        screen.until("arguments not allowed").await;
        screen.type_line("sh").await;
        screen.until("command not found").await;
        screen.type_line("help df").await;
        screen.until("USAGE:").await;
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
        assert_eq!(execs, ["pwd -P", "cd -- '/home/u' && /usr/bin/df -h"]);

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
}
