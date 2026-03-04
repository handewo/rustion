use thiserror::Error;

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),

    #[error(transparent)]
    UserValidation(#[from] super::models::user::ValidateError),

    #[error(transparent)]
    TargetValidation(#[from] super::models::target::ValidateError),

    #[error(transparent)]
    SecretValidation(#[from] super::models::target_secret::ValidateError),

    #[error(transparent)]
    PermissionPolicyValidation(#[from] super::models::casbin_rule::PermissionPolicyEmptyError),
}