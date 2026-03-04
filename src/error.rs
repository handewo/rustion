use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    // External library errors (keep transparent)
    #[error(transparent)]
    Russh(#[from] russh::Error),

    #[error(transparent)]
    RusshKey(#[from] russh::keys::Error),

    #[error(transparent)]
    RusshForkedKey(#[from] russh::keys::ssh_key::Error),

    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    // Module-level errors
    #[error(transparent)]
    Config(#[from] crate::config::error::ConfigError),

    #[error(transparent)]
    Database(#[from] crate::database::error::DatabaseError),

    #[error(transparent)]
    Server(#[from] crate::server::error::ServerError),

    #[error(transparent)]
    App(#[from] crate::server::app::error::AppError),

    #[error(transparent)]
    Record(#[from] crate::asciinema::Error),
}