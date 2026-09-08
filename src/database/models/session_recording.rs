use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub(crate) use crate::database::entity::session_recording::RecordingStatus;

/// Session recording metadata, as read back from storage.
///
/// Read-only, like [`super::Log`]: writes go through the repository as an
/// `entity::session_recordings::ActiveModel`.
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
    pub status: RecordingStatus,
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
    pub status: RecordingStatus,
}

impl RecordingView {
    pub fn generate_path(&self) -> String {
        generate_path(self.id)
    }
}

impl From<crate::database::entity::session_recording::Model> for SessionRecording {
    fn from(m: crate::database::entity::session_recording::Model) -> Self {
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
