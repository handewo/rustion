//! Session recordings: the asciicast writer and the database row that
//! names it. Both ways onto a target — the bridge (`connect_target`) and
//! the limited shell — record what the user does through this one type.

use crate::asciinema;
use crate::database::Uuid;
use crate::database::entity::session_recording as session_recording_entity;
use crate::database::error::DatabaseError;
use crate::database::models::TargetSecretName;
use crate::database::models::session_recording;
use crate::server::HandlerBackend;
use crate::server::app::error::AppError;
use sea_orm::ActiveValue::{Set, Unchanged};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

/// Why a session recording could not be started. Each says so in its own
/// words, so a log line the error reaches names the recording, which the
/// bare io or database error below it does not.
#[derive(Debug, Error)]
pub enum RecordingError {
    #[error("Failed to open the recording's cast file: {0}")]
    CastFile(#[source] asciinema::Error),

    #[error("Failed to create the session recording row: {0}")]
    Row(#[source] DatabaseError),
}

/// One recording in progress: the cast writer, and the row that names it.
/// Every task that writes to it holds it as a [`SharedRecording`], and
/// [`Recording::finish`] closes it.
///
/// TODO: A recorder that fails while the session runs — no space on disk,
/// say — is not noticed: the session continues and the recording is lost.
pub(super) struct Recording {
    /// What everything the user sees is written to.
    pub(super) session: asciinema::Session,
    id: Uuid,
}

/// A session's recording slot, shared by every task that writes to it:
/// `None` until a recording starts and once it has finished.
pub(super) type SharedRecording = Arc<Mutex<Option<Recording>>>;

/// The slot a session starts with: no recording yet.
pub(super) fn no_recording() -> SharedRecording {
    Arc::new(Mutex::new(None))
}

impl Recording {
    /// Open the cast file and write the row that names it. The id is
    /// minted here rather than by the database: it names the `.cast` file
    /// the recorder opens before the row is written. A failure is the
    /// caller's to stop the session with: one that cannot be recorded
    /// must not run unrecorded.
    pub(super) async fn start<B: 'static + HandlerBackend + Send + Sync>(
        backend: &B,
        handler_id: Uuid,
        user_id: Uuid,
        binding: &TargetSecretName,
        term: Option<String>,
        size: (u16, u16),
    ) -> Result<Recording, AppError> {
        let id = Uuid::now_v7();
        let file_path = session_recording::generate_path(id);
        let session = asciinema::new_recorder(
            term,
            std::path::PathBuf::from(backend.record_path()).join(&file_path),
            size,
            None,
            backend.record_input(),
        )
        .await
        .map_err(RecordingError::CastFile)?;
        backend
            .db_repository()
            .create_session_recording(session_recording_entity::ActiveModel {
                id: Set(id),
                user_id: Set(user_id),
                target_id: Set(binding.target_id),
                secret_id: Set(binding.secret_id),
                // Frozen here, not composed at read time: this is what the
                // user connected to, whatever the target is later renamed
                // to or whether it still exists.
                target_label: Set(session_recording::compose_label(
                    &binding.secret_user,
                    &binding.target_name,
                )),
                file_path: Set(file_path),
                connection_id: Set(handler_id),
                status: Set(session_recording::RecordingStatus::Active),
                ..Default::default()
            })
            .await
            .map_err(RecordingError::Row)?;
        Ok(Recording { session, id })
    }

    /// End the recording: close the cast writer, then mark the row
    /// Completed. Only the two columns that move are `Set`, so this needs
    /// no read of the existing row.
    pub(super) async fn finish<B: 'static + HandlerBackend + Send + Sync>(
        self,
        backend: &B,
        handler_id: Uuid,
    ) {
        // Drop the writer first: that ends the event stream it serves, and
        // the row must not say Completed of a recording still taking
        // events.
        let Self { session, id } = self;
        drop(session);
        if let Err(e) = backend
            .db_repository()
            .update_session_recording(session_recording_entity::ActiveModel {
                id: Unchanged(id),
                ended_at: Set(Some(chrono::Utc::now().timestamp_millis())),
                status: Set(session_recording::RecordingStatus::Completed),
                ..Default::default()
            })
            .await
        {
            log::error!("[{}] Failed to update session recording: {}", handler_id, e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A start failure says "recording" in the log lines it reaches, which
    /// the io error inside it does not.
    #[test]
    fn a_start_failure_names_the_recording() {
        let e = AppError::Recording(RecordingError::CastFile(asciinema::Error::Io(
            std::io::Error::from_raw_os_error(13),
        )));
        assert_eq!(
            e.to_string(),
            "Failed to open the recording's cast file: I/O error: Permission denied (os error 13)"
        );
    }
}
