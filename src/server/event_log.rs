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

/// Which subsystem an event came from — the `log_type` column.
///
/// One variant per module that audits, replacing the per-module
/// `const LOG_TYPE: &str` these used to be. Being a closed set means the
/// vocabulary is greppable, a typo is a compile error, and a filter UI can
/// enumerate it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum EventKind {
    /// Connection lifecycle: authentication and logout.
    Server,
    /// Entering the admin TUI.
    Admin,
    /// CRUD inside the admin TUI.
    Manage,
    /// Target connections and channel requests.
    Target,
    /// Forced and voluntary password changes.
    Password,
    /// Entering the session player.
    Player,
}

impl EventKind {
    /// The stored `log_type` value. Existing rows depend on these strings, so
    /// they are not derived from the variant names.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Admin => "admin",
            Self::Manage => "manage",
            Self::Target => "target",
            Self::Password => "password",
            Self::Player => "player",
        }
    }
}

impl std::fmt::Display for EventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

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
                detail: detail.into(),
            })
            .await;
    }
}
