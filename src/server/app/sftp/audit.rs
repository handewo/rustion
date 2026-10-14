//! Wording of the `event_log` details the proxy writes. Pure, so the exact text
//! is tested here rather than through a proxy session.
//!
//! Paths are client-controlled and always formatted through [`path`], which
//! uses `{:?}` to escape newlines and control characters so a crafted name
//! cannot forge a row.

use russh_sftp::protocol::FileAttributes;

/// The most characters of one escaped path a row shows, quotes excluded.
pub(super) const PATH_MAX: usize = 240;
/// How much of [`PATH_MAX`] goes to the head; the tail gets the rest after `…`.
const HEAD_MAX: usize = 120;

/// A path for an audit row: quoted and escaped, and at most [`PATH_MAX`]
/// characters between the quotes, keeping its head and tail around a `…`.
///
/// `EventLogger::record` cuts a whole row to `event_log`'s 512 characters,
/// which would drop the destination of a `rename` or `symlink` behind a long
/// source; bounding each path keeps both ends of every path in the row, and
/// the row within 512.
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

/// The attributes a `setstat`/`fsetstat` sets, e.g. `uid=0 mode=0644`.
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
    if out.is_empty() {
        "no attributes".to_string()
    } else {
        out.join(" ")
    }
}

/// One row per file handle: `sftp read "/p" (10 bytes)`. The verb follows the
/// mode the file was opened in, not the bytes that moved, so a file opened for
/// writing and never written still says `wrote`.
pub(super) fn file_row(
    p: &str,
    read: bool,
    write: bool,
    bytes_read: u64,
    bytes_written: u64,
    closed: bool,
) -> String {
    let tail = if closed { "" } else { ", not closed" };
    let p = path(p);
    match (read, write) {
        (true, true) => {
            format!("sftp read+wrote {p} (r {bytes_read}, w {bytes_written}{tail})")
        }
        (false, true) => format!("sftp wrote {p} ({bytes_written} bytes{tail})"),
        _ => format!("sftp read {p} ({bytes_read} bytes{tail})"),
    }
}

pub(super) fn session_end(
    files_read: u64,
    bytes_read: u64,
    files_written: u64,
    bytes_written: u64,
    not_closed: u64,
) -> String {
    format!(
        "sftp session ended: {files_read} read ({bytes_read} bytes), \
         {files_written} written ({bytes_written} bytes), {not_closed} not closed"
    )
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
        assert_eq!(attrs(&FileAttributes::default()), "no attributes");
    }

    #[test]
    fn file_rows_follow_the_open_mode() {
        assert_eq!(
            file_row("/a", true, false, 10, 0, true),
            r#"sftp read "/a" (10 bytes)"#
        );
        assert_eq!(
            file_row("/b", false, true, 0, 0, true),
            r#"sftp wrote "/b" (0 bytes)"#
        );
        assert_eq!(
            file_row("/c", true, true, 0, 64, true),
            r#"sftp read+wrote "/c" (r 0, w 64)"#
        );
        assert_eq!(
            file_row("/d", false, true, 0, 5, false),
            r#"sftp wrote "/d" (5 bytes, not closed)"#
        );
    }

    #[test]
    fn session_end_summary() {
        assert_eq!(
            session_end(3, 12, 1, 512, 2),
            "sftp session ended: 3 read (12 bytes), 1 written (512 bytes), 2 not closed"
        );
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
    /// what is written, or a name of control bytes pushes the rest of the row
    /// (a `rename` destination) past `event_log`'s 512.
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

        let row = format!(
            "sftp rename {} -> {}",
            path(&"\u{1}".repeat(4000)),
            path("/home/u/dest")
        );
        assert!(row.chars().count() <= 512);
        assert!(row.ends_with(r#"-> "/home/u/dest""#));
    }

    #[test]
    fn path_escapes_newlines() {
        let out = path("/a\nb");
        assert!(!out.contains('\n'));
        assert!(out.contains(r"\n"));
    }

    #[test]
    fn paths_cannot_forge_a_row() {
        let row = file_row("/a\nsftp mkdir \"/fake\"", true, false, 0, 0, true);
        assert!(!row.contains('\n'));
        assert!(row.contains(r"\n"));
    }
}
