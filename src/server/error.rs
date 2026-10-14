use base64::DecodeError;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum ExtendPolicyError {
    #[error("Invalid single time")]
    InvalidSingleTime,

    #[error("End time absent")]
    EndTimeAbsent,

    #[error("Start time absent")]
    StartTimeAbsent,

    #[error("Start time and end time have different timezone")]
    DifferentTimezone,

    #[error("Invalid sftp_path regex '{pattern}': {reason}")]
    InvalidPathRegex { pattern: String, reason: String },
}

#[derive(Debug, Error)]
pub enum ServerError {
    // Secret token errors
    #[error("Invalid secret token: secret token is missing")]
    MissingSecretToken,

    #[error("Failed to decode secret token: {source}")]
    SecretTokenDecode {
        #[source]
        source: DecodeError,
    },

    #[error("Failed to create encryption key: {reason}")]
    EncryptionKeyError { reason: String },

    // Encryption/Decryption errors
    #[error("Failed to decode base64 text: {source}")]
    Base64Decode {
        #[source]
        source: DecodeError,
    },

    #[error("Permission deny")]
    PermissionDeny,

    #[error("Failed to decrypt secret: {reason}")]
    DecryptionFailed { reason: String },

    #[error("Failed to encrypt plain text: {reason}")]
    EncryptionFailed { reason: String },

    // Password errors
    #[error("Failed to hash password")]
    PasswordHashFailed,

    // Casbin errors
    #[error("Internal object '{name}' not found")]
    InternalObjectNotFound { name: String },

    #[error("Invalid Casbin rule group structure")]
    InvalidRuleGroup,

    // ExtendPolicy errors
    #[error(transparent)]
    ExtendPolicy(#[from] ExtendPolicyError),

    // Handler errors
    #[error("Invalid login name format")]
    InvalidLoginMode,

    #[error(transparent)]
    Russh(#[from] russh::Error),

    #[error(transparent)]
    RusshKey(#[from] russh::keys::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("Event log doesn't init")]
    EventLogNotInit,

    #[error("User doesn't init")]
    UserNotInit,

    #[error("Pty term not exist")]
    PtyTermNotExist,

    #[error("Pty modes not exist")]
    PtyModesNotExist,

    #[error("Window size not exist")]
    WindowSizeNotExist,

    #[error("Exec not init")]
    ExecNotInit,

    #[error("Tty not init")]
    TtyNotInit,

    #[error("Invalid proxy URL")]
    InvalidProxyUrl,

    #[error("Duplicate channel ID")]
    DuplicateChannelId,

    #[error("Channel not exist")]
    ChannelNotExist,
}
