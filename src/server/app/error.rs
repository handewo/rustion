use thiserror::Error;

/// What the application layer — the panels, shells and players a connected
/// user runs — can fail with. Composed of the dialects below it: each
/// application speaks its own error, and this is where they meet on the way
/// up to the process boundary's error, in `crate::error`.
#[derive(Debug, Error)]
pub enum AppError {
    #[error(transparent)]
    ConnectTarget(#[from] super::connect_target::ConnectTargetError),

    #[error(transparent)]
    Recording(#[from] super::recording::RecordingError),

    #[error(transparent)]
    Player(#[from] super::player::PlayerError),

    #[error("No target available for connection")]
    NoTargetAvailable,

    /// A database call the application depended on.
    #[error(transparent)]
    Database(#[from] crate::database::error::DatabaseError),

    /// A server operation the application asked for: a permission check, a
    /// connection, an encryption.
    #[error(transparent)]
    Server(#[from] crate::server::error::ServerError),

    // Admin errors
    #[error(transparent)]
    Admin(#[from] super::admin::error::AdminError),
}

