use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Session recording metadata for database storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecording {
    pub id: Uuid,
    pub user_id: Uuid,
    pub target_id: Uuid,
    pub secret_id: Uuid,
    pub file_path: String,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub connection_id: Uuid,
    //TODO:Using enum instead
    pub status: String,
}

impl SessionRecording {
    pub fn new(user_id: Uuid, target_id: Uuid, secret_id: Uuid, connection_id: Uuid) -> Self {
        let id = Uuid::new_v4();
        Self {
            id,
            user_id,
            target_id,
            secret_id,
            file_path: generate_path(id),
            started_at: chrono::Utc::now().timestamp_millis(),
            ended_at: None,
            connection_id,
            status: "active".to_string(),
        }
    }
}

pub fn generate_path(id: Uuid) -> String {
    format!("{}.cast", id)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingView {
    pub id: Uuid,
    pub target_secret: String,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub status: String,
}

impl RecordingView {
    pub fn generate_path(&self) -> String {
        generate_path(self.id)
    }
}

impl From<crate::database::entity::session_recordings::Model> for SessionRecording {
    fn from(m: crate::database::entity::session_recordings::Model) -> Self {
        Self {
            id: m.id,
            user_id: m.user_id,
            target_id: m.target_id,
            secret_id: m.secret_id,
            file_path: m.file_path,
            started_at: m.started_at,
            ended_at: m.ended_at,
            connection_id: m.connection_id,
            status: m.status,
        }
    }
}

impl SessionRecording {
    pub(in crate::database) fn into_active_model(
        self,
    ) -> crate::database::entity::session_recordings::ActiveModel {
        use sea_orm::ActiveValue::Set;
        crate::database::entity::session_recordings::ActiveModel {
            id: Set(self.id),
            user_id: Set(self.user_id),
            target_id: Set(self.target_id),
            secret_id: Set(self.secret_id),
            file_path: Set(self.file_path),
            started_at: Set(self.started_at),
            ended_at: Set(self.ended_at),
            connection_id: Set(self.connection_id),
            status: Set(self.status),
        }
    }
}
