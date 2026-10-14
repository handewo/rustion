//! The handles this proxy has handed out, and what each was authorized for.
//!
//! `read`, `write`, `readdir`, `fstat` and `close` carry only a handle, so the
//! permission they ride on is the one checked at `open`/`opendir`. This table
//! is what ties them back to it: a handle the proxy did not issue, or one used
//! for something it was not opened for, is refused without reaching the target.
//! It also counts bytes for the audit rows.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HandleKind {
    File { read: bool, write: bool },
    Dir,
}

/// What a handle-only request needs the handle to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Use {
    /// `fstat`, `fsetstat`, `close`: any handle this proxy issued.
    Any,
    Dir,
    Read,
    Write,
}

impl HandleKind {
    pub(super) fn allows(self, u: Use) -> bool {
        match (u, self) {
            (Use::Any, _) | (Use::Dir, HandleKind::Dir) => true,
            (Use::Read, HandleKind::File { read, .. }) => read,
            (Use::Write, HandleKind::File { write, .. }) => write,
            _ => false,
        }
    }
}

#[derive(Debug)]
pub(super) struct HandleInfo {
    /// Resolved, as it was checked and sent to the target.
    pub path: String,
    pub kind: HandleKind,
    pub bytes_read: u64,
    pub bytes_written: u64,
}

/// Per-session sums for the session-end row. A file opened for both counts
/// as read and as written.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct Totals {
    pub files_read: u64,
    pub bytes_read: u64,
    pub files_written: u64,
    pub bytes_written: u64,
    pub not_closed: u64,
}

#[derive(Debug, Default)]
pub(super) struct HandleTable {
    open: HashMap<String, HandleInfo>,
    totals: Totals,
}

impl HandleTable {
    pub(super) fn insert(&mut self, handle: String, path: String, kind: HandleKind) {
        self.open.insert(
            handle,
            HandleInfo {
                path,
                kind,
                bytes_read: 0,
                bytes_written: 0,
            },
        );
    }

    pub(super) fn get(&self, handle: &str) -> Option<&HandleInfo> {
        self.open.get(handle)
    }

    pub(super) fn add_read(&mut self, handle: &str, n: u64) {
        if let Some(h) = self.open.get_mut(handle) {
            h.bytes_read += n;
        }
    }

    pub(super) fn add_written(&mut self, handle: &str, n: u64) {
        if let Some(h) = self.open.get_mut(handle) {
            h.bytes_written += n;
        }
    }

    /// Forget a handle on `close`, adding it to the totals.
    pub(super) fn remove(&mut self, handle: &str) -> Option<HandleInfo> {
        let h = self.open.remove(handle)?;
        self.tally(&h, true);
        Some(h)
    }

    /// Every handle still open when the session ends, added to the totals
    /// as not closed.
    pub(super) fn drain_open(&mut self) -> Vec<HandleInfo> {
        let open: Vec<HandleInfo> = self.open.drain().map(|(_, h)| h).collect();
        for h in &open {
            self.tally(h, false);
        }
        open
    }

    pub(super) fn totals(&self) -> Totals {
        self.totals
    }

    fn tally(&mut self, h: &HandleInfo, closed: bool) {
        let HandleKind::File { read, write } = h.kind else {
            return;
        };
        let t = &mut self.totals;
        if read {
            t.files_read += 1;
        }
        if write {
            t.files_written += 1;
        }
        t.bytes_read += h.bytes_read;
        t.bytes_written += h.bytes_written;
        if !closed {
            t.not_closed += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const R: HandleKind = HandleKind::File {
        read: true,
        write: false,
    };
    const W: HandleKind = HandleKind::File {
        read: false,
        write: true,
    };
    const RW: HandleKind = HandleKind::File {
        read: true,
        write: true,
    };

    #[test]
    fn a_handle_allows_what_it_was_opened_for() {
        assert!(R.allows(Use::Read) && !R.allows(Use::Write) && !R.allows(Use::Dir));
        assert!(W.allows(Use::Write) && !W.allows(Use::Read));
        assert!(RW.allows(Use::Read) && RW.allows(Use::Write));
        assert!(HandleKind::Dir.allows(Use::Dir) && !HandleKind::Dir.allows(Use::Read));
        for k in [R, W, RW, HandleKind::Dir] {
            assert!(k.allows(Use::Any));
        }
    }

    #[test]
    fn bytes_accumulate_and_close_tallies() {
        let mut t = HandleTable::default();
        t.insert("h1".into(), "/a".into(), RW);
        t.add_read("h1", 10);
        t.add_read("h1", 5);
        t.add_written("h1", 3);
        t.add_read("nope", 99);
        let h = t.remove("h1").unwrap();
        assert_eq!((h.bytes_read, h.bytes_written), (15, 3));
        assert!(t.get("h1").is_none() && t.remove("h1").is_none());
        assert_eq!(
            t.totals(),
            Totals {
                files_read: 1,
                bytes_read: 15,
                files_written: 1,
                bytes_written: 3,
                not_closed: 0,
            }
        );
    }

    #[test]
    fn drain_counts_open_files_as_not_closed_and_skips_dirs() {
        let mut t = HandleTable::default();
        t.insert("f".into(), "/up".into(), W);
        t.insert("d".into(), "/dir".into(), HandleKind::Dir);
        t.add_written("f", 7);
        let open = t.drain_open();
        assert_eq!(open.len(), 2);
        assert!(t.get("f").is_none());
        assert_eq!(
            t.totals(),
            Totals {
                files_written: 1,
                bytes_written: 7,
                not_closed: 1,
                ..Totals::default()
            }
        );
    }
}
