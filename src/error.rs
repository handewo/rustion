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
    Db(#[from] sea_orm::DbErr),

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

    #[error(transparent)]
    Utils(#[from] crate::utils::HttpProxyError),
}

impl Error {
    /// Whether this error is a unique/primary-key constraint violation.
    ///
    /// Lets callers distinguish "already exists" from a genuine failure without
    /// naming a driver type. `DbErr::sql_err()` maps the per-backend error codes,
    /// so this behaves the same on SQLite, PostgreSQL and MySQL.
    pub fn is_unique_violation(&self) -> bool {
        let db_err = match self {
            Error::Db(e) => e,
            Error::Database(crate::database::error::DatabaseError::Db(e)) => e,
            _ => return false,
        };
        matches!(
            db_err.sql_err(),
            Some(sea_orm::SqlErr::UniqueConstraintViolation(_))
        )
    }
}