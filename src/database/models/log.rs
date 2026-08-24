use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A user's successful operation, as read back for the admin log view.
///
/// Read-only: writes go through `insert_log` as an `entity::logs::ActiveModel`,
/// so there is no conversion in this direction.
#[derive(Debug, Clone, Serialize, Deserialize, sea_orm::FromQueryResult)]
pub struct Log {
    pub connection_id: Uuid,
    pub log_type: String,
    pub user_id: Uuid,
    pub detail: String,
    pub created_at: i64,
}

impl From<crate::database::entity::event_log::Model> for Log {
    fn from(m: crate::database::entity::event_log::Model) -> Self {
        Self {
            connection_id: m.connection_id,
            log_type: m.log_type,
            user_id: m.user_id,
            detail: m.detail,
            created_at: m.created_at,
        }
    }
}
