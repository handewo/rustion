use thiserror::Error;

/// What the admin TUI can fail with: the gates its entry points check, its
/// editors' save semantics, the terminal the panels draw on, and the server
/// and database calls every panel makes. Each panel speaks this; [`AppError`](crate::server::app::error::AppError)
/// carries it up.
#[derive(Debug, Error)]
pub enum AdminError {
    #[error("Target '{target}' already has a bound secret with user '{user}'")]
    DuplicateTargetUser { target: String, user: String },

    /// An entry gate said no: the session may not open this application.
    #[error("Permission deny")]
    Permission,

    #[error(transparent)]
    Validate(#[from] super::validate::ValidateError),

    /// Drawing a frame or reading a key.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// A database call the panel depended on.
    #[error(transparent)]
    Database(#[from] crate::database::error::DatabaseError),

    /// A server operation the panel asked for: a permission check, an
    /// encryption.
    #[error(transparent)]
    Server(#[from] crate::server::error::ServerError),
}

impl AdminError {
    /// Whether this error is a unique-constraint violation from a save. The
    /// admin editors read it as "that name is taken"; the check itself lives
    /// on [`DatabaseError`](crate::database::error::DatabaseError).
    pub fn is_unique_violation(&self) -> bool {
        match self {
            AdminError::Database(e) => e.is_unique_violation(),
            _ => false,
        }
    }
}
