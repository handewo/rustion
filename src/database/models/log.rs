use serde::{Deserialize, Serialize};
/// Log model for database storage
/// Just record user's successful operation
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Log {
    pub connection_id: String,
    pub log_type: String,
    pub user_id: String,
    pub detail: String,
    pub created_at: i64,
}
