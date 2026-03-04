use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Invalid log level '{level}'. Valid levels are: error, warn, info, debug, trace")]
    InvalidLogLevel { level: String },

    #[error("Failed to parse TOML configuration: {source}")]
    TomlParse {
        #[source]
        source: toml::de::Error,
    },

    #[error("Failed to serialize TOML configuration: {source}")]
    TomlSerialize {
        #[source]
        source: toml::ser::Error,
    },

    #[error("Failed to resolve address '{addr}': {reason}")]
    AddressResolutionFailed { addr: String, reason: String },

    #[error("No address resolved for '{addr}'")]
    NoAddressResolved { addr: String },

    #[error("Invalid listen address '{addr}': {reason}")]
    InvalidListenAddress { addr: String, reason: String },

    #[error("max_auth_attempts must be greater than 0")]
    MaxAuthAttemptsZero,

    #[error("No secret token configured")]
    MissingSecretToken,

    #[error("Secret token is empty")]
    EmptySecretToken,

    #[error("Failed to decode secret token: {source}")]
    SecretTokenDecode {
        #[source]
        source: base64::DecodeError,
    },

    #[error("Failed to create encryption key from secret token: {reason}")]
    SecretTokenKeyError { reason: String },

    #[error(transparent)]
    Io(#[from] std::io::Error),
}