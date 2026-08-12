use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Log model for database storage
/// Just record user's successful operation
#[derive(Debug, Clone, Serialize, Deserialize, sea_orm::FromQueryResult)]
pub struct Log {
    pub connection_id: Uuid,
    pub log_type: String,
    pub user_id: Uuid,
    pub detail: String,
    pub created_at: i64,
}

impl From<crate::database::entity::logs::Model> for Log {
    fn from(m: crate::database::entity::logs::Model) -> Self {
        Self {
            connection_id: m.connection_id,
            log_type: m.log_type,
            user_id: m.user_id,
            detail: m.detail,
            created_at: m.created_at,
        }
    }
}

impl Log {
    pub(in crate::database) fn into_active_model(
        self,
    ) -> crate::database::entity::logs::ActiveModel {
        use sea_orm::ActiveValue::Set;
        crate::database::entity::logs::ActiveModel {
            created_at: Set(self.created_at),
            connection_id: Set(self.connection_id),
            detail: Set(self.detail),
            log_type: Set(self.log_type),
            user_id: Set(self.user_id),
        }
    }
}
