use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Log model for database storage
/// Just record user's successful operation
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Log {
    pub connection_id: Uuid,
    pub log_type: String,
    pub user_id: Uuid,
    pub detail: String,
    pub created_at: i64,
}
