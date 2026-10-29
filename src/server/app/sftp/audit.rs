//! Pieces of what the proxy reports: paths for its log lines, and the
//! attributes a `setstat` sets for its audit rows. The rows themselves are
//! `event_log::Audit` events, worded when they are shown.
//!
//! Paths are client-controlled and always formatted through [`path`], which
//! uses `{:?}` to escape newlines and control characters so a crafted name
//! cannot forge a log line.

use russh_sftp::protocol::FileAttributes;

/// The most characters of one escaped path a log line shows, quotes excluded.
pub(super) const PATH_MAX: usize = 240;
/// How much of [`PATH_MAX`] goes to the head; the tail gets the rest after `…`.
const HEAD_MAX: usize = 120;

/// A path for a log line: quoted and escaped, and at most [`PATH_MAX`]
/// characters between the quotes, keeping its head and tail around a `…`, so
/// a client cannot fill the log with one name and both ends of a `rename`
/// stay in view.
///
/// The bound is on the *escaped* text. Escaping can multiply a path's length
/// (a control byte becomes `\u{1}`), so cutting the raw path first would let a
/// name made of control bytes overflow the row anyway. Each character is
/// escaped on its own and kept or dropped whole, so a cut never splits an
/// escape sequence.
pub(super) fn path(p: &str) -> String {
    // `{:?}` of a one-character string, minus its quotes: the same escaping as
    // the whole string, one character at a time.
    let units: Vec<String> = p
        .chars()
        .map(|c| {
            let q = format!("{:?}", c.to_string());
            q[1..q.len() - 1].to_string()
        })
        .collect();
    let len = |u: &String| u.chars().count();
    let total: usize = units.iter().map(len).sum();
    if total <= PATH_MAX {
        return format!("\"{}\"", units.concat());
    }

    let mut head = String::new();
    let mut used = 0;
    for u in &units {
        if used + len(u) > HEAD_MAX {
            break;
        }
        used += len(u);
        head.push_str(u);
    }
    // One character for the `…`.
    let tail_max = PATH_MAX - used - 1;
    let mut tail: Vec<&str> = Vec::new();
    let mut used = 0;
    for u in units.iter().rev() {
        if used + len(u) > tail_max {
            break;
        }
        used += len(u);
        tail.push(u);
    }
    tail.reverse();
    format!("\"{head}…{}\"", tail.concat())
}

/// The attributes a `setstat`/`fsetstat` sets, e.g. `uid=0 mode=0644`; empty
/// when it sets none, which the row words in the reader's language.
pub(super) fn attrs(a: &FileAttributes) -> String {
    let mut out = Vec::new();
    if let Some(v) = a.size {
        out.push(format!("size={v}"));
    }
    if let Some(v) = a.uid {
        out.push(format!("uid={v}"));
    }
    if let Some(v) = a.gid {
        out.push(format!("gid={v}"));
    }
    if let Some(v) = a.permissions {
        out.push(format!("mode={:04o}", v & 0o7777));
    }
    if let Some(v) = a.atime {
        out.push(format!("atime={v}"));
    }
    if let Some(v) = a.mtime {
        out.push(format!("mtime={v}"));
    }
    out.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attrs_lists_only_what_is_set() {
        let a = FileAttributes {
            permissions: Some(0o100644),
            uid: Some(0),
            ..Default::default()
        };
        assert_eq!(attrs(&a), "uid=0 mode=0644");
        assert_eq!(attrs(&FileAttributes::default()), "");
    }

    #[test]
    fn a_long_path_keeps_both_ends() {
        let head = "/".to_string() + &"h".repeat(199);
        let tail = "t".repeat(399);
        let long = head.clone() + "/" + &tail;
        assert_eq!(long.chars().count(), 600);
        let out = path(&long);
        let inner = out.strip_prefix('"').unwrap().strip_suffix('"').unwrap();
        assert_eq!(inner.chars().count(), PATH_MAX);
        assert!(inner.starts_with(&long[..120]));
        assert!(inner.ends_with(&long[long.len() - 119..]));
        assert!(inner.contains('…'));
    }

    #[test]
    fn a_short_path_is_only_quoted() {
        assert_eq!(path("/srv/a b"), r#""/srv/a b""#);
        let exact = "x".repeat(PATH_MAX);
        assert_eq!(path(&exact), format!("{exact:?}"));
    }

    /// Escaping can make a path several times longer. The bound must hold on
    /// what is written, or a name of control bytes floods the log line.
    #[test]
    fn the_bound_is_on_the_escaped_path() {
        let raw = "\u{1}".repeat(600) + "/end";
        let out = path(&raw);
        let inner = out.strip_prefix('"').unwrap().strip_suffix('"').unwrap();
        assert!(
            inner.chars().count() <= PATH_MAX,
            "{}",
            inner.chars().count()
        );
        assert!(inner.starts_with(r"\u{1}"));
        assert!(inner.ends_with(r"\u{1}/end"));
        // No escape sequence is cut in half on either side of the `…`.
        let (head, tail) = inner.split_once('…').unwrap();
        assert_eq!(head.len() % r"\u{1}".len(), 0);
        assert!(tail.strip_suffix("/end").unwrap().len() % r"\u{1}".len() == 0);

        // Short but escape-heavy: under the raw bound, over the escaped one.
        let out = path(&"\u{1}".repeat(200));
        assert!(out.chars().count() <= PATH_MAX + 2);
    }

    #[test]
    fn path_escapes_newlines() {
        let out = path("/a\nb");
        assert!(!out.contains('\n'));
        assert!(out.contains(r"\n"));
    }
}
