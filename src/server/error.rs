use thiserror::Error;
use base64::DecodeError;

#[derive(Debug, Error)]
pub enum ExtendPolicyParseError {
    #[error("Invalid IP policy format: {0}")]
    InvalidIpPolicy(String),

    #[error("Invalid time format: {0}")]
    InvalidTimeFormat(String),

    #[error("Time consistency error: {0}")]
    TimeConsistencyError(String),

    #[error("Invalid expire date format: {0}")]
    InvalidExpireDateFormat(String),
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

    #[error("Action '{name}' not found")]
    ActionNotFound { name: String },

    #[error("Invalid Casbin rule group structure")]
    InvalidRuleGroup,

    // ExtendPolicy errors
    #[error(transparent)]
    ExtendPolicyParse(#[from] ExtendPolicyParseError),

    #[error("Rule ID is none for bound role")]
    MissingRuleId,

    // Handler errors
    #[error("Invalid login name format")]
    InvalidLoginName,

    #[error(transparent)]
    Russh(#[from] russh::Error),

    #[error(transparent)]
    RusshKey(#[from] russh::keys::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}