use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("No target available for connection")]
    NoTargetAvailable,

    #[error("Channel record already exists")]
    ChannelRecordExists,

    #[error("Channel notify already exists")]
    ChannelNotifyExists,

    // Admin errors
    #[error(transparent)]
    Admin(#[from] super::admin::error::AdminError),
}

