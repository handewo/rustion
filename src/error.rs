use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Russh(#[from] russh::Error),

    #[error(transparent)]
    RusshKey(#[from] russh::keys::Error),

    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[error("{0}")]
    Handler(String),

    #[error("Server error: {0}")]
    Server(String),

    #[error("Casbin error: {0}")]
    Casbin(String),

    #[error("App error: {0}")]
    App(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Database error: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Record(#[from] crate::asciinema::Error),
}
