use crate::database::DatabaseConfig;
use crate::error::Error;
use aes_gcm::KeyInit;
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Error => write!(f, "error"),
            LogLevel::Warn => write!(f, "warn"),
            LogLevel::Info => write!(f, "info"),
            LogLevel::Debug => write!(f, "debug"),
            LogLevel::Trace => write!(f, "trace"),
        }
    }
}

impl std::str::FromStr for LogLevel {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "error" => Ok(LogLevel::Error),
            "warn" => Ok(LogLevel::Warn),
            "info" => Ok(LogLevel::Info),
            "debug" => Ok(LogLevel::Debug),
            "trace" => Ok(LogLevel::Trace),
            _ => Err(Error::Config(format!(
                "Invalid log level '{}'. Valid levels are: error, warn, info, debug, trace",
                s
            ))),
        }
    }
}

fn default_unban_duration() -> Duration {
    Duration::from_secs(900)
}

fn default_cache_idle_time() -> Duration {
    Duration::from_secs(1800)
}

fn default_record_path() -> String {
    "./record".to_string()
}

fn default_max_auth_attempts_per_conn() -> u32 {
    5
}

fn default_max_ip_attempts() -> u32 {
    100
}

fn default_max_user_attempts() -> u32 {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub listen: ListenConfig,
    pub server_key: String,
    secret_key: Option<String>,
    #[serde(default = "default_max_auth_attempts_per_conn")]
    pub max_auth_attempts_per_conn: u32,
    // Global ip attempts count
    #[serde(default = "default_max_ip_attempts")]
    pub max_ip_attempts: u32,
    // Global user attempts count
    #[serde(default = "default_max_user_attempts")]
    pub max_user_attempts: u32,
    // Used to unban global ip and user
    #[serde(default = "default_unban_duration")]
    #[serde(with = "humantime_serde")]
    pub unban_duration: Duration,
    pub reuse_target_connection: bool,
    #[serde(default = "default_cache_idle_time")]
    #[serde(with = "humantime_serde")]
    pub target_cache_duration: Duration,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub inactivity_timeout: Option<Duration>,
    #[serde(default)]
    pub log_level: LogLevel,
    #[serde(default)]
    pub database: DatabaseConfig,
    pub enable_record: bool,
    pub record_input: bool,
    #[serde(default = "default_record_path")]
    pub record_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ListenConfig {
    SocketAddr(SocketAddr),
    String(String),
}

impl std::fmt::Display for ListenConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ListenConfig::SocketAddr(addr) => {
                write!(f, "{}", addr)
            }
            ListenConfig::String(s) => {
                write!(f, "{}", s)
            }
        }
    }
}

impl Config {
    /// Load configuration from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)
            .map_err(|e| Error::Config(format!("Failed to parse TOML: {}", e)))?;
        Ok(config)
    }

    /// Create a default configuration
    pub fn default() -> Self {
        Config {
            listen: ListenConfig::String("0.0.0.0:2222".to_string()),
            server_key: "server_key.pem".to_string(),
            secret_key: None,
            max_auth_attempts_per_conn: default_max_auth_attempts_per_conn(),
            max_ip_attempts: default_max_ip_attempts(),
            max_user_attempts: default_max_user_attempts(),
            unban_duration: default_unban_duration(),
            reuse_target_connection: false,
            target_cache_duration: default_cache_idle_time(),
            inactivity_timeout: None,
            log_level: LogLevel::default(),
            database: DatabaseConfig::default(),
            enable_record: false,
            record_input: false,
            record_path: default_record_path(),
        }
    }

    pub fn take_secret_token(&mut self) -> Option<String> {
        self.secret_key.take()
    }

    pub fn gen_secret_token(mut self) -> Self {
        let key = aes_gcm::Aes256Gcm::generate_key(aes_gcm::aead::OsRng);
        let encoded = general_purpose::STANDARD.encode(key);
        self.secret_key = Some(encoded);
        self
    }

    /// Save configuration to a TOML file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| Error::Config(format!("Failed to serialize TOML: {}", e)))?;
        fs::write(path, content)?;
        Ok(())
    }

    /// Parse the listen configuration into a SocketAddr
    pub fn parse_listen_addr(&self) -> Result<SocketAddr, Error> {
        match &self.listen {
            ListenConfig::SocketAddr(addr) => Ok(*addr),
            ListenConfig::String(s) => {
                // Handle various formats:
                // - "localhost:2222"
                // - "*:2222" -> "0.0.0.0:2222"
                // - "2222" -> "0.0.0.0:2222"
                // - "192.168.1.1:2222"

                let addr_str = if s.starts_with('*') {
                    s.replace('*', "0.0.0.0")
                } else if !s.contains(':') {
                    // Just a port number
                    format!("0.0.0.0:{}", s)
                } else {
                    s.clone()
                };

                addr_str
                    .parse::<SocketAddr>()
                    .or_else(|_| {
                        // Try to resolve hostname if direct parsing fails
                        use std::net::ToSocketAddrs;
                        addr_str
                            .to_socket_addrs()
                            .map_err(|e| {
                                Error::Config(format!(
                                    "Failed to resolve address '{}': {}",
                                    addr_str, e
                                ))
                            })?
                            .next()
                            .ok_or_else(|| {
                                Error::Config(format!("No address resolved for '{}'", addr_str))
                            })
                    })
                    .map_err(|e| Error::Config(format!("Invalid listen address '{}': {}", s, e)))
            }
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), Error> {
        // Validate listen address
        self.parse_listen_addr()?;

        // Validate max_auth_attempts
        if self.max_auth_attempts_per_conn == 0 {
            return Err(Error::Config(
                "max_auth_attempts must be greater than 0".to_string(),
            ));
        }

        let sk = match self.secret_key.as_ref() {
            Some(token) => token,
            None => return Err(Error::Config("No secret token".to_string())),
        };
        if sk.is_empty() {
            return Err(Error::Config("Secret token is empty".to_string()));
        }
        let key = general_purpose::STANDARD
            .decode(sk)
            .map_err(|e| Error::Config(format!("Failed to parse secret token: {}", e)))?;
        aes_gcm::Aes256Gcm::new_from_slice(&key)
            .map_err(|e| Error::Config(format!("Failed to parse secret token: {}", e)))?;

        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::default()
    }
}

impl std::fmt::Display for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "listen: {}\r
            server_key: {}\r
            secret_key: {}...\r
            max_auth_attempts_per_conn: {}\r
            max_ip_attempts: {}\r
            max_user_attempts: {}\r
            unban_duration: {}\r
            reuse_target_connection: {}\r
            target_cache_duration: {}\r
            inactivity_timeout: {}\r
            log_level: {}\r
            database: {}\r
            enable_record: {}\r
            record_input: {}\r
            record_path: {}\r",
            self.listen,
            self.server_key,
            self.secret_key
                .as_ref()
                .map_or("None", |v| v.as_str().split_at(10).0),
            self.max_auth_attempts_per_conn,
            self.max_ip_attempts,
            self.max_user_attempts,
            humantime::format_duration(self.unban_duration),
            self.reuse_target_connection,
            humantime::format_duration(self.target_cache_duration),
            self.inactivity_timeout
                .map_or("None".to_string(), |v| humantime::format_duration(v)
                    .to_string()),
            self.log_level,
            self.database,
            self.enable_record,
            self.record_input,
            self.record_path,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_listen_addr() {
        let config = Config {
            listen: ListenConfig::String("localhost:2222".to_string()),
            server_key: "test.pem".to_string(),
            secret_key: None,
            max_auth_attempts_per_conn: 3,
            max_ip_attempts: 100,
            max_user_attempts: 100,
            unban_duration: Duration::from_secs(600),
            reuse_target_connection: false,
            target_cache_duration: Duration::from_secs(600),
            inactivity_timeout: None,
            log_level: LogLevel::Info,
            database: DatabaseConfig::default(),
            enable_record: false,
            record_input: false,
            record_path: default_record_path(),
        };
        assert!(config.parse_listen_addr().is_ok());

        let config = Config {
            listen: ListenConfig::String("*:2222".to_string()),
            server_key: "test.pem".to_string(),
            secret_key: None,
            max_auth_attempts_per_conn: 3,
            max_ip_attempts: 100,
            max_user_attempts: 100,
            unban_duration: Duration::from_secs(600),
            reuse_target_connection: false,
            target_cache_duration: Duration::from_secs(600),
            inactivity_timeout: None,
            log_level: LogLevel::Info,
            database: DatabaseConfig::default(),
            enable_record: false,
            record_input: false,
            record_path: default_record_path(),
        };
        let addr = config.parse_listen_addr().unwrap();
        assert_eq!(addr.port(), 2222);

        let config = Config {
            listen: ListenConfig::String("2222".to_string()),
            server_key: "test.pem".to_string(),
            secret_key: None,
            max_auth_attempts_per_conn: 3,
            max_ip_attempts: 100,
            max_user_attempts: 100,
            unban_duration: Duration::from_secs(600),
            reuse_target_connection: false,
            target_cache_duration: Duration::from_secs(600),
            inactivity_timeout: None,
            log_level: LogLevel::Info,
            database: DatabaseConfig::default(),
            enable_record: false,
            record_input: false,
            record_path: default_record_path(),
        };
        let addr = config.parse_listen_addr().unwrap();
        assert_eq!(addr.port(), 2222);
    }

    #[test]
    fn test_config_validation() {
        let config = Config::default().gen_secret_token();
        assert!(config.validate().is_ok());

        let invalid_config = Config {
            listen: ListenConfig::String("invalid".to_string()),
            server_key: "test.pem".to_string(),
            secret_key: None,
            max_auth_attempts_per_conn: 3,
            max_ip_attempts: 100,
            max_user_attempts: 100,
            unban_duration: Duration::from_secs(600),
            reuse_target_connection: false,
            target_cache_duration: Duration::from_secs(600),
            inactivity_timeout: None,
            log_level: LogLevel::Info,
            database: DatabaseConfig::default(),
            enable_record: false,
            record_input: false,
            record_path: default_record_path(),
        };
        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn test_log_level_parsing() {
        assert_eq!("error".parse::<LogLevel>().unwrap(), LogLevel::Error);
        assert_eq!("warn".parse::<LogLevel>().unwrap(), LogLevel::Warn);
        assert_eq!("info".parse::<LogLevel>().unwrap(), LogLevel::Info);
        assert_eq!("debug".parse::<LogLevel>().unwrap(), LogLevel::Debug);
        assert_eq!("trace".parse::<LogLevel>().unwrap(), LogLevel::Trace);

        // Test case insensitive parsing
        assert_eq!("ERROR".parse::<LogLevel>().unwrap(), LogLevel::Error);
        assert_eq!("Info".parse::<LogLevel>().unwrap(), LogLevel::Info);

        // Test invalid log level
        assert!("invalid".parse::<LogLevel>().is_err());
    }
}
