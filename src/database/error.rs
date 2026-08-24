use thiserror::Error;

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error(transparent)]
    Db(#[from] sea_orm::DbErr),

    #[error("invalid proxy URI")]
    InvalidProxy,

    /// The one rule the repository enforces itself. Field validation lives in
    /// the admin editors (`server::app::admin::validate`), but this guards rows
    /// the RBAC engine depends on by name, so it has to hold for every caller.
    #[error("cannot modify internal types")]
    InternalTypeModification,
}
