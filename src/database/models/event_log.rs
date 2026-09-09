use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub(crate) use crate::database::entity::event_log::EventKind;

/// A user's successful operation, as read back for the admin log view.
///
/// Read-only: writes go through `insert_log` as an
/// `entity::event_log::ActiveModel`, so there is no conversion in this direction.
#[derive(Debug, Clone, Serialize, Deserialize, sea_orm::FromQueryResult)]
pub struct EventLog {
    /// The surrogate key, assigned by the database on insert.
    ///
    /// Carried through to the admin view because it is the only stable way to name
    /// one row: `created_at` collides within a millisecond, and the rest of the
    /// columns repeat freely.
    pub id: i64,
    pub connection_id: Uuid,
    pub log_type: EventKind,
    pub user_id: Uuid,
    pub detail: String,
    pub created_at: i64,
}

impl From<crate::database::entity::event_log::Model> for EventLog {
    fn from(m: crate::database::entity::event_log::Model) -> Self {
        Self {
            id: m.id,
            connection_id: m.connection_id,
            log_type: m.log_type,
            user_id: m.user_id,
            detail: m.detail,
            created_at: m.created_at,
        }
    }
}
