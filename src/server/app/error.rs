use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error(transparent)]
    ConnectTarget(#[from] super::connect_target::ConnectTargetError),

    #[error(transparent)]
    Recording(#[from] super::recording::RecordingError),

    #[error("No target available for connection")]
    NoTargetAvailable,

    // Admin errors
    #[error(transparent)]
    Admin(#[from] super::admin::error::AdminError),
}
