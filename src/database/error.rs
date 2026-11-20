use thiserror::Error;

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error(transparent)]
    Db(#[from] sea_orm::DbErr),

    /// The one rule the repository enforces itself. Field validation lives in
    /// the admin editors (`server::app::admin::validate`), but this guards rows
    /// the RBAC engine depends on by name, so it has to hold for every caller.
    #[error("cannot modify internal types")]
    InternalTypeModification,
}

impl DatabaseError {
    /// Whether this error is a unique-constraint violation, which the admin
    /// editors read as "that name is taken". Once the repository spoke this
    /// type, a database error could reach a caller only one way, so the check
    /// lives here; every layer above carries it inside its own variant.
    pub fn is_unique_violation(&self) -> bool {
        matches!(
            self,
            DatabaseError::Db(e)
                if matches!(
                    e.sql_err(),
                    Some(sea_orm::SqlErr::UniqueConstraintViolation(_))
                )
        )
    }
}
