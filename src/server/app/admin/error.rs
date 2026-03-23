use thiserror::Error;

#[derive(Debug, Error)]
pub enum AdminError {
    #[error("Target '{target}' already has a bound secret with user '{user}'")]
    DuplicateTargetUser { target: String, user: String },
}
