use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error(transparent)]
    ConnectTarget(#[from] super::connect_target::ConnectTargetError),

    #[error("No target available for connection")]
    NoTargetAvailable,

    // Admin errors
    #[error(transparent)]
    Admin(#[from] super::admin::error::AdminError),
}
