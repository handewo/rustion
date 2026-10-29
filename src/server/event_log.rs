//! Audit-trail events written to the `event_log` table.
//!
//! Distinct from the `log` crate's tracing output: these rows record what a
//! *user* did, are queried by administrators, and are part of the security
//! surface. Tracing output records what the *program* did.
//!
//! Call sites go through [`EventLogger`], which carries the connection and user
//! identity so a call site only has to supply the event:
//!
//! ```ignore
//! self.log.record(Audit::saved(Object::User, Change::Deleted, &u.username, u.id)).await;
//! ```
//!
//! An event is stored as an [`Audit`] serialised to JSON, not as a sentence:
//! the sentence is written when the row is shown, in the language of whoever
//! is reading it ([`render`]). Rows written before this were English text, and
//! are shown as they are.
//!
//! Writes are best-effort. A failed insert is reported by the backend at
//! `error!` level and does not propagate — an audit write must not be able to
//! fail an administrative action that already succeeded.

use crate::database::Uuid;
use crate::i18n::Strings;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Which subsystem an event came from — one variant per module that audits.
///
/// Declared in `entity::event_log`, not here: it is the storage type of the
/// `log_type` column, stored as an integer, and the entity is where the column's
/// shape is declared. Re-exported so the call sites in this crate's server modules
/// read as `EventKind` rather than reaching into `database::entity`.
pub(crate) use crate::database::models::EventKind;

/// One audit event, fully identified. `created_at` is stamped by the repository
/// at insert time.
pub(crate) struct Event {
    pub(crate) connection_id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) kind: EventKind,
    pub(crate) detail: String,
}

/// Records audit events for one authenticated connection.
///
/// Holding `user_id` by value means an `EventLogger` cannot exist before
/// authentication — the pre-auth window is represented as `Option<EventLogger>`
/// on the handler rather than as a logger that silently discards.
pub(crate) struct EventLogger<B> {
    backend: Arc<B>,
    connection_id: Uuid,
    user_id: Uuid,
    kind: EventKind,
}

// Hand-written: `derive(Clone)` would add a `B: Clone` bound, and cloning is
// only ever an `Arc` bump plus three `Copy` fields.
impl<B> Clone for EventLogger<B> {
    fn clone(&self) -> Self {
        Self {
            backend: self.backend.clone(),
            connection_id: self.connection_id,
            user_id: self.user_id,
            kind: self.kind,
        }
    }
}

/// `event_log.detail` is a `varchar(512)`.
pub(crate) const DETAIL_MAX: usize = 512;

/// What an administered object went through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Change {
    Added,
    Updated,
    Deleted,
}

/// English, for log lines.
impl std::fmt::Display for Change {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Change::Added => "added",
            Change::Updated => "updated",
            Change::Deleted => "deleted",
        })
    }
}

/// The objects the manage panel administers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Object {
    User,
    Target,
    Secret,
    Permission,
    /// A casbin name: a role, a target group or an action group.
    Group,
}

/// What was put in a group, or taken out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MemberKind {
    User,
    Target,
    Action,
    Group,
}

/// One thing a user did, in no language. The serialised form is the stored
/// format: tags and field names must not be renamed, and a new field needs a
/// `#[serde(default)]` so rows written without it still read.
///
/// Names are stored as `name(id)`, as they were in the English rows, so a row
/// still says what it was about after the object is renamed or deleted.
/// Client-controlled text (paths, exec commands) is stored raw and escaped
/// when shown.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub(crate) enum Audit {
    LoginPassword,
    LoginPublicKey,
    Logout,
    /// Entering the admin shell.
    Admin,
    /// Entering the session player.
    Player,
    PasswordChanged,
    /// A channel request forwarded to a target: `shell`, `exec: …`.
    TargetRequest {
        request: String,
        target: String,
        closed: bool,
    },
    Saved {
        object: Object,
        change: Change,
        /// Empty for a permission, which has no name.
        name: String,
        id: String,
    },
    RoleGranted {
        role: String,
        user: String,
    },
    RoleRevoked {
        role: String,
        user: String,
    },
    SecretBound {
        secret: String,
        target: String,
    },
    SecretUnbound {
        secret: String,
        target: String,
    },
    MemberAdded {
        kind: MemberKind,
        member: String,
        group: String,
    },
    MemberRemoved {
        kind: MemberKind,
        member: String,
        group: String,
    },
    SftpStarted {
        target: String,
    },
    /// The policy refused the sftp subsystem outright.
    SftpRefused {
        target: String,
    },
    SftpEnded {
        files_read: u64,
        bytes_read: u64,
        files_written: u64,
        bytes_written: u64,
        not_closed: u64,
    },
    SftpDenied {
        op: String,
        paths: Vec<String>,
    },
    /// One per file handle. The verb follows the mode the file was opened in,
    /// not the bytes that moved, so a file opened for writing and never
    /// written still says it was written.
    SftpFile {
        path: String,
        read: bool,
        write: bool,
        bytes_read: u64,
        bytes_written: u64,
        closed: bool,
    },
    /// `attrs` is what was set, `uid=0 mode=0644`; empty for nothing.
    SftpSetstat {
        path: String,
        attrs: String,
        /// `fsetstat`: through an open handle rather than a path.
        handle: bool,
    },
    SftpMkdir {
        path: String,
    },
    SftpRemove {
        path: String,
    },
    SftpRmdir {
        path: String,
    },
    SftpRename {
        from: String,
        to: String,
    },
    SftpSymlink {
        link: String,
        target: String,
    },
}

/// `name(id)`, the way rows name things.
pub(crate) fn labelled(name: &str, id: impl std::fmt::Display) -> String {
    format!("{name}({id})")
}

impl Audit {
    pub(crate) fn saved(
        object: Object,
        change: Change,
        name: &str,
        id: impl std::fmt::Display,
    ) -> Self {
        Audit::Saved {
            object,
            change,
            name: name.to_string(),
            id: id.to_string(),
        }
    }

    /// The stored form: JSON, within [`DETAIL_MAX`] characters.
    ///
    /// Postgres and MySQL reject an over-long value, and the insert's error is
    /// logged and swallowed, so a long path would silently cost its audit row.
    /// Cutting the JSON would leave a row nothing can read, so the text fields
    /// are cut instead, each around a `…` that keeps its head and tail. They
    /// are cut to one common length, the longest that fits, so a long source
    /// does not push the destination of a `rename` out. The bound is on the
    /// JSON, escapes included: a control byte takes six characters there.
    pub(crate) fn encode(&self) -> String {
        let text = serde_json::to_string(self).expect("an audit event is plain data");
        let len = text.chars().count();
        if len <= DETAIL_MAX {
            return text;
        }
        let mut value = serde_json::to_value(self).expect("an audit event is plain data");
        let mut fields = text_fields(&mut value);
        let costs: Vec<usize> = fields.iter().map(|f| json_cost(f)).collect();
        let budget = DETAIL_MAX.saturating_sub(len - costs.iter().sum::<usize>());
        let fits = |cap: usize| costs.iter().map(|c| (*c).min(cap)).sum::<usize>() <= budget;
        let (mut lo, mut hi) = (0, costs.iter().copied().max().unwrap_or(0));
        while lo < hi {
            let mid = (lo + hi).div_ceil(2);
            if fits(mid) {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        for (field, cost) in fields.iter_mut().zip(costs) {
            if cost > lo {
                **field = cut_to_cost(field, lo);
            }
        }
        // Back through the type, so a cut row keeps the field order of an
        // uncut one (a `Value` sorts its keys).
        match serde_json::from_value::<Audit>(value) {
            Ok(cut) => serde_json::to_string(&cut).expect("an audit event is plain data"),
            Err(_) => text,
        }
    }

    /// The row as a sentence in `tr`'s language.
    pub(crate) fn text(&self, tr: &Strings) -> String {
        use crate::fill;
        match self {
            Audit::LoginPassword => tr.a_login_password.to_string(),
            Audit::LoginPublicKey => tr.a_login_public_key.to_string(),
            Audit::Logout => tr.a_logout.to_string(),
            Audit::Admin => tr.a_admin.to_string(),
            Audit::Player => tr.a_player.to_string(),
            Audit::PasswordChanged => tr.a_password_changed.to_string(),
            Audit::TargetRequest {
                request,
                target,
                closed,
            } => {
                let t = if *closed {
                    tr.a_target_request_closed
                } else {
                    tr.a_target_request
                };
                fill!(t, request = plain(request), target = plain(target))
            }
            Audit::Saved {
                object,
                change,
                name,
                id,
            } => {
                use {Change::*, Object::*};
                let t = match (object, change) {
                    (User, Added) => tr.a_user_added,
                    (User, Updated) => tr.a_user_updated,
                    (User, Deleted) => tr.a_user_deleted,
                    (Target, Added) => tr.a_target_added,
                    (Target, Updated) => tr.a_target_updated,
                    (Target, Deleted) => tr.a_target_deleted,
                    (Secret, Added) => tr.a_secret_added,
                    (Secret, Updated) => tr.a_secret_updated,
                    (Secret, Deleted) => tr.a_secret_deleted,
                    (Permission, Added) => tr.a_permission_added,
                    (Permission, Updated) => tr.a_permission_updated,
                    (Permission, Deleted) => tr.a_permission_deleted,
                    (Group, Added) => tr.a_group_added,
                    (Group, Updated) => tr.a_group_updated,
                    (Group, Deleted) => tr.a_group_deleted,
                };
                fill!(t, name = plain(&labelled(name, id)), id = plain(id))
            }
            Audit::RoleGranted { role, user } => {
                fill!(tr.a_role_granted, role = plain(role), user = plain(user))
            }
            Audit::RoleRevoked { role, user } => {
                fill!(tr.a_role_revoked, role = plain(role), user = plain(user))
            }
            Audit::SecretBound { secret, target } => fill!(
                tr.a_secret_bound,
                secret = plain(secret),
                target = plain(target)
            ),
            Audit::SecretUnbound { secret, target } => fill!(
                tr.a_secret_unbound,
                secret = plain(secret),
                target = plain(target)
            ),
            Audit::MemberAdded {
                kind,
                member,
                group,
            } => fill!(
                tr.a_member_added,
                kind = kind.text(tr),
                member = plain(member),
                group = plain(group)
            ),
            Audit::MemberRemoved {
                kind,
                member,
                group,
            } => fill!(
                tr.a_member_removed,
                kind = kind.text(tr),
                member = plain(member),
                group = plain(group)
            ),
            Audit::SftpStarted { target } => fill!(tr.a_sftp_started, target = plain(target)),
            Audit::SftpRefused { target } => fill!(tr.a_sftp_refused, target = plain(target)),
            Audit::SftpEnded {
                files_read,
                bytes_read,
                files_written,
                bytes_written,
                not_closed,
            } => fill!(
                tr.a_sftp_ended,
                files_read = files_read,
                bytes_read = bytes_read,
                files_written = files_written,
                bytes_written = bytes_written,
                not_closed = not_closed
            ),
            Audit::SftpDenied { op, paths } => {
                let paths: Vec<String> = paths.iter().map(|p| quoted(p)).collect();
                fill!(tr.a_sftp_denied, op = plain(op), paths = paths.join(" -> "))
            }
            Audit::SftpFile {
                path,
                read,
                write,
                bytes_read,
                bytes_written,
                closed,
            } => {
                let path = quoted(path);
                match (read, write, closed) {
                    (true, true, true) => fill!(
                        tr.a_sftp_read_wrote,
                        path = path,
                        read = bytes_read,
                        written = bytes_written
                    ),
                    (true, true, false) => fill!(
                        tr.a_sftp_read_wrote_open,
                        path = path,
                        read = bytes_read,
                        written = bytes_written
                    ),
                    (false, true, true) => {
                        fill!(tr.a_sftp_wrote, path = path, bytes = bytes_written)
                    }
                    (false, true, false) => {
                        fill!(tr.a_sftp_wrote_open, path = path, bytes = bytes_written)
                    }
                    (_, false, true) => fill!(tr.a_sftp_read, path = path, bytes = bytes_read),
                    (_, false, false) => {
                        fill!(tr.a_sftp_read_open, path = path, bytes = bytes_read)
                    }
                }
            }
            Audit::SftpSetstat {
                path,
                attrs,
                handle,
            } => {
                let attrs = if attrs.is_empty() {
                    tr.a_sftp_no_attrs.to_string()
                } else {
                    plain(attrs)
                };
                let t = if *handle {
                    tr.a_sftp_fsetstat
                } else {
                    tr.a_sftp_setstat
                };
                fill!(t, path = quoted(path), attrs = attrs)
            }
            Audit::SftpMkdir { path } => fill!(tr.a_sftp_mkdir, path = quoted(path)),
            Audit::SftpRemove { path } => fill!(tr.a_sftp_remove, path = quoted(path)),
            Audit::SftpRmdir { path } => fill!(tr.a_sftp_rmdir, path = quoted(path)),
            Audit::SftpRename { from, to } => {
                fill!(tr.a_sftp_rename, from = quoted(from), to = quoted(to))
            }
            Audit::SftpSymlink { link, target } => fill!(
                tr.a_sftp_symlink,
                link = quoted(link),
                target = quoted(target)
            ),
        }
    }
}

impl Audit {
    /// What a dialog tells the operator who did it: the row's sentence
    /// without the ids, which mean nothing to a person. Events with ids only
    /// in the log have the same text as the log row.
    pub(crate) fn notice(&self, tr: &Strings) -> String {
        use crate::fill;
        match self {
            Audit::Saved {
                object: Object::Permission,
                change,
                ..
            } => match change {
                Change::Added => tr.permission_added,
                Change::Updated => tr.permission_updated,
                Change::Deleted => tr.permission_deleted,
            }
            .to_string(),
            Audit::Saved {
                object,
                change,
                name,
                ..
            } => {
                use {Change::*, Object::*};
                let t = match (object, change) {
                    (User, Added) => tr.a_user_added,
                    (User, Updated) => tr.a_user_updated,
                    (User, Deleted) => tr.a_user_deleted,
                    (Target, Added) => tr.a_target_added,
                    (Target, Updated) => tr.a_target_updated,
                    (Target, Deleted) => tr.a_target_deleted,
                    (Secret, Added) => tr.a_secret_added,
                    (Secret, Updated) => tr.a_secret_updated,
                    (Secret, Deleted) => tr.a_secret_deleted,
                    (Group, Added) => tr.a_group_added,
                    (Group, Updated) => tr.a_group_updated,
                    (Group, Deleted) => tr.a_group_deleted,
                    (Permission, _) => unreachable!("matched above"),
                };
                fill!(t, name = plain(name))
            }
            other => other.text(tr),
        }
    }
}

impl MemberKind {
    pub(crate) fn text(self, tr: &Strings) -> &'static str {
        match self {
            MemberKind::User => tr.kind_user,
            MemberKind::Target => tr.kind_target,
            MemberKind::Action => tr.kind_action,
            MemberKind::Group => tr.kind_group,
        }
    }
}

/// A stored `detail` as a sentence in `tr`'s language. A row that is not an
/// [`Audit`] predates them, and is English text already.
pub(crate) fn render(detail: &str, tr: &Strings) -> String {
    match serde_json::from_str::<Audit>(detail) {
        Ok(event) => event.text(tr),
        Err(_) => detail.to_string(),
    }
}

/// A client's path, quoted and escaped, so a crafted name cannot break the
/// row it is shown in or pass for another one.
fn quoted(path: &str) -> String {
    format!("{path:?}")
}

/// Text with its control characters escaped: a name or a command, shown
/// without quotes.
fn plain(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// The free-text fields of a serialised event: every string but the tag and
/// the enum values, which have to survive whole for the row to read back.
fn text_fields(value: &mut serde_json::Value) -> Vec<&mut String> {
    use serde_json::Value;
    fn walk<'a>(v: &'a mut Value, out: &mut Vec<&'a mut String>) {
        match v {
            Value::String(s) => out.push(s),
            Value::Array(a) => a.iter_mut().for_each(|v| walk(v, out)),
            Value::Object(o) => o
                .iter_mut()
                .filter(|(k, _)| !matches!(k.as_str(), "event" | "object" | "change" | "kind"))
                .for_each(|(_, v)| walk(v, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(value, &mut out);
    out
}

/// The characters `c` takes inside a JSON string.
fn char_cost(c: char) -> usize {
    match c {
        '"' | '\\' | '\n' | '\r' | '\t' | '\u{8}' | '\u{c}' => 2,
        c if (c as u32) < 0x20 => 6,
        _ => 1,
    }
}

fn json_cost(s: &str) -> usize {
    s.chars().map(char_cost).sum()
}

/// `s` cut to take at most `cap` characters of JSON: its head and tail either
/// side of a `…`, each character kept or dropped whole.
fn cut_to_cost(s: &str, cap: usize) -> String {
    if cap == 0 {
        return String::new();
    }
    let room = cap - 1;
    let mut head = String::new();
    let mut used = 0;
    for c in s.chars() {
        if used + char_cost(c) > room / 2 {
            break;
        }
        used += char_cost(c);
        head.push(c);
    }
    let mut tail = Vec::new();
    for c in s.chars().rev() {
        if used + char_cost(c) > room {
            break;
        }
        used += char_cost(c);
        tail.push(c);
    }
    head.push('…');
    head.extend(tail.into_iter().rev());
    head
}

impl<B> EventLogger<B>
where
    B: 'static + super::HandlerBackend + Send + Sync,
{
    pub(crate) fn new(
        backend: Arc<B>,
        connection_id: Uuid,
        user_id: Uuid,
        kind: EventKind,
    ) -> Self {
        Self {
            backend,
            connection_id,
            user_id,
            kind,
        }
    }

    /// Same connection and user, different subsystem. Used when handing a
    /// logger to a module that audits under its own [`EventKind`].
    pub(crate) fn scoped(&self, kind: EventKind) -> Self {
        Self {
            kind,
            ..self.clone()
        }
    }

    /// Write one event. Best-effort; see the module docs.
    pub(crate) async fn record(&self, event: Audit) {
        self.backend
            .insert_log(Event {
                connection_id: self.connection_id,
                user_id: self.user_id,
                kind: self.kind,
                detail: event.encode(),
            })
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Lang;

    fn en(event: &Audit) -> String {
        event.text(Lang::En.strings())
    }

    /// The stored form is the on-disk format: pin it, so a renamed variant or
    /// field fails here rather than turning old rows back into raw JSON.
    #[test]
    fn the_stored_form_is_stable() {
        assert_eq!(Audit::Logout.encode(), r#"{"event":"logout"}"#);
        assert_eq!(
            Audit::saved(Object::User, Change::Deleted, "bob", 7).encode(),
            r#"{"event":"saved","object":"user","change":"deleted","name":"bob","id":"7"}"#
        );
        assert_eq!(
            Audit::SftpRename {
                from: "/a".into(),
                to: "/b".into()
            }
            .encode(),
            r#"{"event":"sftp_rename","from":"/a","to":"/b"}"#
        );
    }

    #[test]
    fn a_row_reads_back_in_every_language() {
        let row = Audit::saved(Object::Target, Change::Added, "web1", "id1").encode();
        assert_eq!(render(&row, Lang::En.strings()), "Target 'web1(id1)' added");
        assert_eq!(
            render(&row, Lang::Ja.strings()),
            "ターゲット 'web1(id1)' を追加しました"
        );
        for lang in Lang::ALL {
            let text = render(&row, lang.strings());
            assert!(text.contains("web1(id1)"), "{lang}: {text}");
            assert!(!text.contains('{'), "{lang}: {text}");
        }
    }

    /// The log names what changed by `name(id)`; the dialog the operator
    /// sees by name alone.
    #[test]
    fn a_dialog_leaves_the_ids_out() {
        let id = "01a03223-0883-7f03-b0a5-4e536cfa092f";
        let user = Audit::saved(Object::User, Change::Added, "sad", id);
        assert_eq!(en(&user), format!("User 'sad({id})' added"));
        assert_eq!(user.notice(Lang::En.strings()), "User 'sad' added");
        let rule = Audit::saved(Object::Permission, Change::Deleted, "", id);
        assert_eq!(en(&rule), format!("Permission '({id})' deleted"));
        assert_eq!(rule.notice(Lang::En.strings()), "Permission deleted");
        for lang in Lang::ALL {
            for event in [&user, &rule] {
                let shown = event.notice(lang.strings());
                assert!(
                    !shown.contains(id) && !shown.contains('{'),
                    "{lang}: {shown}"
                );
            }
        }
    }

    #[test]
    fn rows_from_before_are_shown_as_they_are() {
        for legacy in ["logout", "User 'bob(1)' deleted", "", "{not json"] {
            assert_eq!(render(legacy, Lang::Ja.strings()), legacy);
        }
    }

    #[test]
    fn file_rows_follow_the_open_mode() {
        let file = |read, write, bytes_read, bytes_written, closed| Audit::SftpFile {
            path: "/a".into(),
            read,
            write,
            bytes_read,
            bytes_written,
            closed,
        };
        assert_eq!(
            en(&file(true, false, 10, 0, true)),
            r#"sftp read "/a" (10 bytes)"#
        );
        assert_eq!(
            en(&file(false, true, 0, 0, true)),
            r#"sftp wrote "/a" (0 bytes)"#
        );
        assert_eq!(
            en(&file(true, true, 0, 64, true)),
            r#"sftp read+wrote "/a" (r 0, w 64)"#
        );
        assert_eq!(
            en(&file(false, true, 0, 5, false)),
            r#"sftp wrote "/a" (5 bytes, not closed)"#
        );
    }

    #[test]
    fn a_short_row_is_untouched() {
        let event = Audit::SftpMkdir {
            path: "/srv/a b".into(),
        };
        let row = event.encode();
        assert_eq!(serde_json::from_str::<Audit>(&row).unwrap(), event);
    }

    /// The column is `varchar(512)` in characters; Postgres and MySQL reject a
    /// longer value, and `insert_log` swallows that error. The cut row must
    /// still read back.
    #[test]
    fn a_long_row_is_cut_to_fit_and_still_reads() {
        let long = "/".to_string() + &"é".repeat(2000) + "/end";
        let row = Audit::SftpMkdir { path: long.clone() }.encode();
        let len = row.chars().count();
        assert!(len <= DETAIL_MAX && len > DETAIL_MAX - 4, "{len}");
        let Audit::SftpMkdir { path } = serde_json::from_str(&row).unwrap() else {
            panic!("{row}")
        };
        assert!(path.starts_with("/éé"));
        assert!(path.ends_with("é/end"));
        assert!(path.contains('…'));
    }

    /// Cutting the longest path first keeps both ends of both paths: the
    /// destination of a `rename` survives a long source.
    #[test]
    fn a_long_source_does_not_cost_the_destination() {
        let row = Audit::SftpRename {
            from: "/".to_string() + &"s".repeat(4000) + "/src-end",
            to: "/home/u/dest".into(),
        }
        .encode();
        assert!(row.chars().count() <= DETAIL_MAX);
        let Audit::SftpRename { from, to } = serde_json::from_str(&row).unwrap() else {
            panic!("{row}")
        };
        assert_eq!(to, "/home/u/dest");
        assert!(from.ends_with("/src-end"));

        let both = Audit::SftpRename {
            from: "f".repeat(3000),
            to: "t".repeat(3000) + "/to-end",
        }
        .encode();
        assert!(both.chars().count() <= DETAIL_MAX);
        let Audit::SftpRename { from, to } = serde_json::from_str(&both).unwrap() else {
            panic!("{both}")
        };
        assert!(from.len() > 100 && to.len() > 100, "{from} {to}");
        assert!(to.ends_with("/to-end"));
    }

    /// Escaping can make a path several times longer in JSON (a control byte
    /// is `\u0001`), so the bound has to be on the JSON.
    #[test]
    fn the_bound_is_on_the_escaped_row() {
        let row = Audit::SftpMkdir {
            path: "\u{1}".repeat(600) + "/end",
        }
        .encode();
        assert!(row.chars().count() <= DETAIL_MAX, "{}", row.chars().count());
        let Audit::SftpMkdir { path } = serde_json::from_str(&row).unwrap() else {
            panic!("{row}")
        };
        assert!(path.ends_with("/end"));
    }

    #[test]
    fn client_text_cannot_forge_a_row() {
        let shown = en(&Audit::SftpMkdir {
            path: "/a\nsftp mkdir \"/fake\"".into(),
        });
        assert!(!shown.contains('\n'));
        assert!(shown.contains(r"\n"));
        let shown = en(&Audit::TargetRequest {
            request: "exec: ls\n\u{1b}[2J".into(),
            target: "web1".into(),
            closed: false,
        });
        assert!(
            !shown.contains('\n') && !shown.contains('\u{1b}'),
            "{shown}"
        );
    }
}
