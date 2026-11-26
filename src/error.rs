use thiserror::Error;

/// The process boundary's error: what `main` and the russh connection handler
/// speak. It is pure composition — each layer's own dialect
/// ([`ConfigError`](crate::config::error::ConfigError),
/// [`DatabaseError`](crate::database::error::DatabaseError),
/// [`ServerError`](crate::server::error::ServerError),
/// [`AppError`](crate::server::app::error::AppError)) reaches it through
/// `#[from]`, plus the externals only this boundary deals in directly: the
/// SSH wire (`russh`) and the socket. Nothing below the boundary names this
/// type.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Pty window is zero-sized")]
    ZeroWindow,

    #[error(transparent)]
    Russh(#[from] russh::Error),

    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[error(transparent)]
    Config(#[from] crate::config::error::ConfigError),

    #[error(transparent)]
    Database(#[from] crate::database::error::DatabaseError),

    #[error(transparent)]
    Server(#[from] crate::server::error::ServerError),

    #[error(transparent)]
    App(#[from] crate::server::app::error::AppError),
}
