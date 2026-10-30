//! End-to-end: a real client session, the proxy, and a fake target, joined by
//! in-memory pipes. Policies are enforced by a real `BastionServer` on the
//! shared fixture database, for a fresh subject that no fixture policy names.

use super::{SftpContext, SftpProxy};
use crate::config::Config;
use crate::database::Uuid;
use crate::database::common::*;
use crate::database::entity::casbin_rule;
use crate::database::fixture::{self, S_MON};
use crate::database::models::Ptype;
use crate::i18n::Lang;
use crate::server::event_log::{self, EventKind, EventLogger};
use crate::server::extend_policy::ExtendPolicyReq;
use crate::server::{BastionServer, HandlerBackend};
use russh_sftp::client::{RawSftpSession, error::Error as SftpError};
use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode,
};
use sea_orm::ActiveValue::Set;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const HOME: &str = "/home/u";
const UNDER_HOME: &str = r#"{"sftp_path":{"Allow":["/home/u(/.*)?"]}}"#;

#[derive(Default)]
struct Fs {
    files: HashMap<String, Vec<u8>>,
    handles: HashMap<String, String>,
    next: u32,
    seen: Vec<String>,
}

#[derive(Clone, Default)]
struct FakeTarget(Arc<Mutex<Fs>>);

impl FakeTarget {
    fn fs(&self) -> std::sync::MutexGuard<'_, Fs> {
        self.0.lock().unwrap()
    }

    fn seen(&self) -> Vec<String> {
        self.fs().seen.clone()
    }

    fn file(&self, path: &str) -> Option<Vec<u8>> {
        self.fs().files.get(path).cloned()
    }
}

fn ok(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "Ok".into(),
        language_tag: "en-US".into(),
    }
}

impl russh_sftp::server::Handler for FakeTarget {
    type Error = StatusCode;

    fn unimplemented(&self) -> StatusCode {
        StatusCode::OpUnsupported
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, StatusCode> {
        self.fs().seen.push(format!("realpath {path}"));
        let resolved = if path == "." { HOME.to_string() } else { path };
        Ok(Name {
            id,
            files: vec![File::dummy(resolved)],
        })
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, StatusCode> {
        let mut fs = self.fs();
        fs.seen.push(format!("open {filename}"));
        if pflags.contains(OpenFlags::CREATE) {
            fs.files.entry(filename.clone()).or_default();
        } else if !fs.files.contains_key(&filename) {
            return Err(StatusCode::NoSuchFile);
        }
        fs.next += 1;
        let handle = format!("t{}", fs.next);
        fs.handles.insert(handle.clone(), filename);
        Ok(Handle { id, handle })
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, StatusCode> {
        let mut fs = self.fs();
        fs.seen.push(format!("read {handle}"));
        let path = fs.handles.get(&handle).ok_or(StatusCode::Failure)?;
        let data = &fs.files[path];
        let start = offset as usize;
        if start >= data.len() {
            return Err(StatusCode::Eof);
        }
        let end = (start + len as usize).min(data.len());
        Ok(Data {
            id,
            data: data[start..end].to_vec(),
        })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, StatusCode> {
        let mut fs = self.fs();
        fs.seen.push(format!("write {handle}"));
        let path = fs.handles.get(&handle).ok_or(StatusCode::Failure)?.clone();
        let file = fs.files.get_mut(&path).unwrap();
        let end = offset as usize + data.len();
        if file.len() < end {
            file.resize(end, 0);
        }
        file[offset as usize..end].copy_from_slice(&data);
        Ok(ok(id))
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, StatusCode> {
        let mut fs = self.fs();
        fs.seen.push(format!("close {handle}"));
        fs.handles.remove(&handle);
        Ok(ok(id))
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, StatusCode> {
        self.fs().seen.push(format!("stat {path}"));
        Ok(Attrs {
            id,
            attrs: FileAttributes::default(),
        })
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, StatusCode> {
        self.fs().seen.push(format!("mkdir {path}"));
        Ok(ok(id))
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, StatusCode> {
        self.fs().seen.push(format!("setstat {path}"));
        Ok(ok(id))
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, StatusCode> {
        self.fs().seen.push(format!("rename {oldpath} {newpath}"));
        Ok(ok(id))
    }

    async fn symlink(
        &mut self,
        id: u32,
        linkpath: String,
        targetpath: String,
    ) -> Result<Status, StatusCode> {
        self.fs()
            .seen
            .push(format!("symlink {linkpath} {targetpath}"));
        Ok(ok(id))
    }
}

/// A seeded database, a server on it, a fresh subject, and the proxy context
/// for that subject on `sun`/`s_mon`.
struct Env {
    db: fixture::TestDb,
    server: Arc<BastionServer>,
    user: Uuid,
    object: Uuid,
}

impl Env {
    async fn new() -> Self {
        let db = fixture::seed().await;
        let mut config = Config::default().gen_secret_token();
        config.database = db.url.clone();
        let server = Arc::new(BastionServer::with_config(config).await.expect("server"));
        let object = db.fixture.binding("sun", S_MON);
        Self {
            db,
            server,
            user: Uuid::now_v7(),
            object,
        }
    }

    fn act(&self, name: &str) -> Uuid {
        self.db.fixture.name(name)
    }

    async fn grant(&self, action: &str, ext: &str) {
        self.server
            .db_repository()
            .create_casbin_rule(casbin_rule::ActiveModel {
                id: Set(Uuid::now_v7()),
                ptype: Set(Ptype::Policy),
                v0: Set(self.user),
                v1: Set(self.object),
                v2: Set(self.act(action)),
                v3: Set(ext.to_string()),
                v4: Set(String::new()),
                v5: Set(String::new()),
                updated_by: Set(self.db.fixture.admin_id),
                ..Default::default()
            })
            .await
            .expect("grant");
    }

    fn ctx(&self) -> SftpContext<BastionServer> {
        SftpContext {
            handler_id: Uuid::now_v7(),
            user_id: self.user,
            client_ip: None,
            object: self.object,
            label: "mon@sun(test)".into(),
            actions: SftpActions::from_lookup(|n| self.act(n)),
            backend: self.server.clone(),
            log: EventLogger::new(
                self.server.clone(),
                Uuid::now_v7(),
                self.user,
                EventKind::Sftp,
            ),
        }
    }

    /// Start target, proxy and client; return the client and the target.
    async fn open(&self) -> (RawSftpSession, FakeTarget) {
        let target = FakeTarget::default();
        let (to_target, target_end) = tokio::io::duplex(1 << 16);
        russh_sftp::server::run(target_end, target.clone()).await;
        let proxy = SftpProxy::connect(self.ctx(), to_target)
            .await
            .expect("connect");
        let (client_end, to_client) = tokio::io::duplex(1 << 16);
        proxy.serve(to_client).await;
        let client = RawSftpSession::new(client_end);
        client.init().await.expect("init");
        (client, target)
    }

    /// `event_log` details for this subject, oldest first, worded in English
    /// as the log view shows them. Waits briefly, because rows written from
    /// `Drop` land on a spawned task.
    async fn rows(&self, at_least: usize) -> Vec<String> {
        for _ in 0..50 {
            let mut rows: Vec<String> = self
                .server
                .db_repository()
                .list_logs()
                .await
                .unwrap()
                .into_iter()
                .filter(|l| l.user_id == self.user && l.log_type == EventKind::Sftp)
                .map(|l| event_log::render(&l.detail, Lang::En.strings()))
                .collect();
            if rows.len() >= at_least {
                rows.reverse();
                return rows;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("fewer than {at_least} sftp rows");
    }
}

fn denied<T>(r: Result<T, SftpError>) -> bool {
    matches!(r, Err(SftpError::Status(ref s)) if s.status_code == StatusCode::PermissionDenied)
}

#[tokio::test]
async fn the_session_gate_is_its_own_action() {
    let env = Env::new().await;
    assert!(!env.ctx().allow_session().await);
    env.grant(ACT_SFTP, "{}").await;
    assert!(env.ctx().allow_session().await);
    // The gate names no path, so a path rule on its policy has nothing to
    // match and is skipped. It used to be read as a failure, which made one
    // path-restricted policy refuse the session it was meant to narrow.
    let env = Env::new().await;
    env.grant(ACT_SFTP, UNDER_HOME).await;
    assert!(env.ctx().allow_session().await);
}

/// One policy, carrying a path rule and an action group, is enough: it opens
/// the session and narrows the operations under it.
#[tokio::test]
async fn one_path_restricted_policy_opens_a_session_and_narrows_it() {
    let env = Env::new().await;
    // Two actions on one policy, the way an admin would use an action group.
    env.grant(ACT_SFTP, UNDER_HOME).await;
    env.grant(ACT_SFTP_LIST, UNDER_HOME).await;

    assert!(env.ctx().allow_session().await);
    let (c, target) = env.open().await;
    // `realpath` names no path either, so it is reachable.
    assert_eq!(c.realpath(".").await.unwrap().files[0].filename, HOME);
    c.stat("a").await.unwrap();
    assert!(denied(c.stat("/etc/passwd").await));
    let stats: Vec<String> = target
        .seen()
        .into_iter()
        .filter(|s| s.starts_with("stat"))
        .collect();
    assert_eq!(stats, vec!["stat /home/u/a"]);
}

/// A policy's extended policy narrows only the kind of request it names.
#[tokio::test]
async fn a_path_rule_does_not_reach_other_request_kinds() {
    let env = Env::new().await;
    // A path rule beside a shell grant: shell carries no path, so the rule has
    // nothing to say about it. What a policy grants is its action list.
    env.grant(ACT_SHELL, UNDER_HOME).await;
    assert!(
        env.server
            .enforce(
                env.user,
                env.object,
                env.act(ACT_SHELL),
                ExtendPolicyReq::new(None),
            )
            .await
            .unwrap()
    );
    // ...and it still grants no SFTP session, because it names no SFTP action.
    assert!(!env.ctx().allow_session().await);
}

#[tokio::test]
async fn each_operation_needs_its_own_action() {
    let env = Env::new().await;
    let (c, target) = env.open().await;

    // `realpath` needs no per-op action; the target answers it.
    assert_eq!(c.realpath(".").await.unwrap().files[0].filename, HOME);
    assert!(denied(c.stat("a").await));
    assert!(denied(c.mkdir("d", FileAttributes::default()).await));
    assert!(denied(
        c.open("f", OpenFlags::READ, FileAttributes::default())
            .await
    ));
    assert!(denied(c.rename("a", "b").await));
    // Nothing denied reached the target.
    assert_eq!(target.seen(), vec!["realpath .", "realpath ."]);

    env.grant(ACT_SFTP_LIST, "{}").await;
    env.grant(ACT_SFTP_MKDIR, "{}").await;
    c.stat("a").await.unwrap();
    c.mkdir("d", FileAttributes::default()).await.unwrap();
    // Resolved against home before it is forwarded.
    assert!(
        target
            .seen()
            .ends_with(&["stat /home/u/a".to_string(), "mkdir /home/u/d".to_string()])
    );
}

#[tokio::test]
async fn read_and_write_are_separate_and_combine() {
    let env = Env::new().await;
    env.grant(ACT_SFTP_READ, "{}").await;
    let (c, target) = env.open().await;
    target
        .fs()
        .files
        .insert("/home/u/f".into(), b"hello".to_vec());

    let h = c
        .open("f", OpenFlags::READ, FileAttributes::default())
        .await
        .unwrap();
    assert_eq!(c.read(&h.handle, 0, 64).await.unwrap().data, b"hello");
    // The handle was opened for reading only; the proxy refuses to write on it.
    assert!(c.write(&h.handle, 0, b"x".to_vec()).await.is_err());
    c.close(&h.handle).await.unwrap();

    let rw = OpenFlags::READ | OpenFlags::WRITE;
    assert!(denied(c.open("f", rw, FileAttributes::default()).await));
    assert!(denied(
        c.open("f", OpenFlags::WRITE, FileAttributes::default())
            .await
    ));
    env.grant(ACT_SFTP_WRITE, "{}").await;
    let h = c.open("f", rw, FileAttributes::default()).await.unwrap();
    c.write(&h.handle, 0, b"J".to_vec()).await.unwrap();
    c.close(&h.handle).await.unwrap();
    assert_eq!(target.file("/home/u/f").unwrap(), b"Jello");
}

#[tokio::test]
async fn path_rules_see_the_resolved_path() {
    let env = Env::new().await;
    env.grant(ACT_SFTP_LIST, UNDER_HOME).await;
    let (c, target) = env.open().await;

    c.stat("sub/x").await.unwrap();
    c.stat("/home/u").await.unwrap();
    // Relative, but resolves outside the allowed pattern.
    assert!(denied(c.stat("../v/x").await));
    assert!(denied(c.stat("/home/u/../../etc/passwd").await));
    assert!(denied(c.stat("/etc/passwd").await));
    let stats: Vec<String> = target
        .seen()
        .into_iter()
        .filter(|s| s.starts_with("stat"))
        .collect();
    assert_eq!(stats, vec!["stat /home/u/sub/x", "stat /home/u"]);
}

#[tokio::test]
async fn a_deny_rule_cannot_be_dodged_with_a_newline() {
    let env = Env::new().await;
    env.grant(
        ACT_SFTP_WRITE,
        r#"{"sftp_path":{"Deny":["/home/u/secret(/.*)?"]}}"#,
    )
    .await;
    let (c, target) = env.open().await;
    let wc = OpenFlags::WRITE | OpenFlags::CREATE;

    assert!(denied(
        c.open("secret/a\nb", wc, FileAttributes::default()).await
    ));
    assert!(
        !target
            .seen()
            .iter()
            .any(|s| s.starts_with("open /home/u/secret")),
        "{:?}",
        target.seen()
    );
    c.open("ok", wc, FileAttributes::default()).await.unwrap();
}

#[tokio::test]
async fn changing_size_through_setstat_needs_write() {
    let env = Env::new().await;
    env.grant(ACT_SFTP_SETSTAT, "{}").await;
    let (c, target) = env.open().await;

    assert!(denied(
        c.setstat(
            "f",
            FileAttributes {
                size: Some(0),
                ..Default::default()
            }
        )
        .await
    ));
    c.setstat(
        "f",
        FileAttributes {
            permissions: Some(0o644),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let setstats: Vec<String> = target
        .seen()
        .into_iter()
        .filter(|s| s.starts_with("setstat"))
        .collect();
    assert_eq!(setstats, vec!["setstat /home/u/f"]);
}

#[tokio::test]
async fn two_path_operations_check_both_paths() {
    let env = Env::new().await;
    env.grant(ACT_SFTP_RENAME, UNDER_HOME).await;
    env.grant(ACT_SFTP_SYMLINK, UNDER_HOME).await;
    let (c, target) = env.open().await;

    assert!(denied(c.rename("a", "/tmp/a").await));
    assert!(denied(c.rename("/tmp/a", "a").await));
    c.rename("a", "b").await.unwrap();
    assert!(denied(c.symlink("l", "/etc/shadow").await));
    // A relative target is stored as the absolute path that was checked.
    c.symlink("l", "../u/t").await.unwrap();
    let seen = target.seen();
    assert!(seen.contains(&"rename /home/u/a /home/u/b".to_string()));
    assert!(seen.contains(&"symlink /home/u/l /home/u/t".to_string()));
    assert_eq!(seen.iter().filter(|s| s.starts_with("rename")).count(), 1);
    assert_eq!(seen.iter().filter(|s| s.starts_with("symlink")).count(), 1);
}

#[tokio::test]
async fn a_handle_the_proxy_did_not_issue_is_refused() {
    let env = Env::new().await;
    env.grant(ACT_SFTP_READ, "{}").await;
    let (c, target) = env.open().await;
    target.fs().files.insert("/home/u/f".into(), b"x".to_vec());
    let h = c
        .open("f", OpenFlags::READ, FileAttributes::default())
        .await
        .unwrap();
    // The proxy hands out the target's handle string; `t999` was never issued.
    assert_ne!(h.handle, "t999");
    assert!(c.read("t999", 0, 1).await.is_err());
    assert!(c.close("t999").await.is_err());
    // Refused by the proxy, not by the target.
    assert!(
        !target.seen().iter().any(|s| s.contains("t999")),
        "{:?}",
        target.seen()
    );
}

#[tokio::test]
async fn audit_rows_cover_files_mutations_denials_and_session_end() {
    let env = Env::new().await;
    env.grant(ACT_SFTP_WRITE, "{}").await;
    env.grant(ACT_SFTP_MKDIR, "{}").await;
    let (c, _target) = env.open().await;

    let h = c
        .open(
            "up",
            OpenFlags::WRITE | OpenFlags::CREATE,
            FileAttributes::default(),
        )
        .await
        .unwrap();
    c.write(&h.handle, 0, vec![0; 512]).await.unwrap();
    c.close(&h.handle).await.unwrap();
    c.mkdir("d", FileAttributes::default()).await.unwrap();
    assert!(denied(c.stat("secret").await));
    // Left open: the session-end rows must say so.
    let h = c
        .open(
            "big",
            OpenFlags::WRITE | OpenFlags::CREATE,
            FileAttributes::default(),
        )
        .await
        .unwrap();
    c.write(&h.handle, 0, vec![0; 64]).await.unwrap();
    drop(c);

    let rows = env.rows(6).await;
    assert!(
        rows[0].starts_with("sftp session started on mon@sun(test)"),
        "{rows:?}"
    );
    assert_eq!(rows[1], r#"sftp wrote "/home/u/up" (512 bytes)"#);
    assert_eq!(rows[2], r#"sftp mkdir "/home/u/d""#);
    assert_eq!(rows[3], r#"sftp denied list "/home/u/secret""#);
    assert_eq!(
        rows[4],
        r#"sftp wrote "/home/u/big" (64 bytes, not closed)"#
    );
    assert_eq!(
        rows[5],
        "sftp session ended: 0 read (0 bytes), 2 written (576 bytes), 1 not closed"
    );
}
