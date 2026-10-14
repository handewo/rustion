//! Audit-trail events written to the `event_log` table.
//!
//! Distinct from the `log` crate's tracing output: these rows record what a
//! *user* did, are queried by administrators, and are part of the security
//! surface. Tracing output records what the *program* did.
//!
//! Call sites go through [`EventLogger`], which carries the connection and user
//! identity so a call site only has to supply the detail:
//!
//! ```ignore
//! self.log.record(format!("User '{}({})' deleted", u.username, u.id)).await;
//! ```
//!
//! Writes are best-effort. A failed insert is reported by the backend at
//! `error!` level and does not propagate — an audit write must not be able to
//! fail an administrative action that already succeeded.

use crate::database::Uuid;
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

/// Cut `detail` to [`DETAIL_MAX`] characters, ending in `…` when cut.
///
/// Postgres and MySQL reject an over-long value, and the insert's error is
/// logged and swallowed, so without this a long path would silently cost its
/// audit row.
pub(crate) fn bound_detail(detail: String) -> String {
    if detail.chars().count() <= DETAIL_MAX {
        return detail;
    }
    let mut cut: String = detail.chars().take(DETAIL_MAX - 1).collect();
    cut.push('…');
    cut
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
    pub(crate) async fn record(&self, detail: impl Into<String>) {
        self.backend
            .insert_log(Event {
                connection_id: self.connection_id,
                user_id: self.user_id,
                kind: self.kind,
                detail: bound_detail(detail.into()),
            })
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_detail_is_untouched() {
        assert_eq!(bound_detail("abc".into()), "abc");
        let exact = "x".repeat(DETAIL_MAX);
        assert_eq!(bound_detail(exact.clone()), exact);
    }

    /// The column is `varchar(512)` in characters; Postgres and MySQL reject a
    /// longer value, and `insert_log` swallows that error.
    #[test]
    fn long_detail_is_cut_on_a_char_boundary() {
        let long = "é".repeat(DETAIL_MAX + 10);
        let cut = bound_detail(long);
        assert_eq!(cut.chars().count(), DETAIL_MAX);
        assert!(cut.ends_with('…'));
        assert!(cut.starts_with("éé"));
    }
}
