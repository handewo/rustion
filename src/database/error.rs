use thiserror::Error;

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error(transparent)]
    Db(#[from] sea_orm::DbErr),

    #[error(transparent)]
    TargetValidation(#[from] super::models::target::ValidateError),

    #[error(transparent)]
    ProxyParseError(#[from] super::models::target::ProxyParseError),

    #[error("invalid proxy URI")]
    InvalidProxy,

    #[error(transparent)]
    SecretValidation(#[from] super::models::target_secret::ValidateError),

    #[error(transparent)]
    PermissionPolicyValidation(#[from] super::models::casbin_rule::PermissionPolicyEmptyError),

    #[error(transparent)]
    CasbinNameValidation(#[from] super::models::casbin_rule::ValidateError),
}
