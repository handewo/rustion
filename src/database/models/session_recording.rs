use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub(crate) use crate::database::entity::session_recording::RecordingStatus;

/// Session recording metadata, as read back from storage.
///
/// Read-only, like [`super::EventLog`]: writes go through the repository as an
/// `entity::session_recordings::ActiveModel`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecording {
    pub id: Uuid,
    pub user_id: Uuid,
    pub target_id: Uuid,
    pub secret_id: Uuid,
    /// See [`entity::session_recording::Model::target_label`]: the label as it
    /// read when the recording was made, not as the target reads now.
    ///
    /// [`entity::session_recording::Model::target_label`]: crate::database::entity::session_recording::Model::target_label
    pub target_label: String,
    pub file_path: String,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub connection_id: Uuid,
    pub status: RecordingStatus,
}

pub fn generate_path(id: Uuid) -> String {
    format!("{}.cast", id)
}

/// How a recording is labelled: `secret_user@target_name:port`.
///
/// The one spelling of this format. The write site in `connect_target` calls it,
/// and `migrations/002-recording-target-label.sql` reproduces it in SQL to
/// backfill rows written before the column existed — if this changes, that file
/// is already-written history and does not follow.
pub fn compose_label(secret_user: &str, target_name: &str) -> String {
    format!("{}@{}", secret_user, target_name,)
}

#[derive(Debug, Clone, Serialize, Deserialize, sea_orm::FromQueryResult)]
pub struct RecordingView {
    pub id: Uuid,
    /// Query the name of target and secret from database each time
    pub current_label: String,
    /// Read straight off the row now, not composed from a join — so it says what
    /// the target was called at the time, and survives the target's deletion.
    pub target_label: String,
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
            target_label: m.target_label,
            file_path: m.file_path,
            started_at: m.started_at,
            ended_at: m.ended_at,
            connection_id: m.connection_id,
            status: m.status,
        }
    }
}
