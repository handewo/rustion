use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Session recording metadata for database storage
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SessionRecording {
    pub id: Uuid,
    pub user_id: Uuid,
    pub target_id: Uuid,
    pub target_secret_id: Uuid,
    pub file_path: String,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub connection_id: Uuid,
    pub status: String,
}

impl SessionRecording {
    pub fn new(
        user_id: Uuid,
        target_id: Uuid,
        target_secret_id: Uuid,
        file_save_path: String,
        connection_id: Uuid,
    ) -> Self {
        let id = Uuid::new_v4();
        Self {
            id,
            user_id,
            target_id,
            target_secret_id,
            file_path: format!("{}/{}.cast", file_save_path, id),
            started_at: chrono::Utc::now().timestamp_millis(),
            ended_at: None,
            connection_id,
            status: "active".to_string(),
        }
    }
}
