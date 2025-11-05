use crate::config::{Config, LogLevel};
use crate::error::Error;
use clap::Parser;
use log::info;

#[derive(Parser)]
#[command(name = "rustion")]
#[command(version = "0.1.0")]
#[command(about = "A Rust-based bastion server")]
pub struct Cli {
    /// Configuration file path
    #[arg(
        short = 'c',
        long = "config",
        value_name = "FILE",
        default_value = "rustion.toml"
    )]
    pub config: String,

    /// Generate a default configuration file
    #[arg(long = "generate-config")]
    pub generate_config: bool,

    /// Initial service and create admin user
    #[arg(long = "init")]
    pub init_service: bool,

    /// Listen address (overrides config file)
    #[arg(short = 'l', long = "listen", value_name = "ADDRESS")]
    pub listen: Option<String>,

    /// Server key file path (overrides config file)
    #[arg(short = 'k', long = "server-key", value_name = "PATH")]
    pub server_key: Option<String>,

    /// Log level (overrides config file)
    #[arg(
        long = "log-level",
        value_name = "LEVEL",
        help = "Set log level (error, warn, info, debug, trace)"
    )]
    pub log_level: Option<String>,
}

pub async fn handle_cli_args() -> Result<Option<Config>, Error> {
    let cli = Cli::parse();

    // Generate config file if requested
    if cli.generate_config {
        let default_config = Config::default().gen_secret_token();
        default_config.save_to_file(&cli.config)?;
        info!("Generated default configuration file: {}", cli.config);
        return Ok(None);
    }

    // Load configuration from file
    let mut config = match Config::from_file(&cli.config) {
        Ok(config) => config,
        Err(e) => {
            panic!("Configuration file load error '{}'", e);
        }
    };

    if cli.init_service {
        crate::server::init_service::init_service(config).await;
        return Ok(None);
    }

    // Override with command line arguments
    if let Some(listen) = cli.listen {
        config.listen = crate::config::ListenConfig::String(listen);
    }

    if let Some(server_key) = cli.server_key {
        config.server_key = server_key;
    }

    if let Some(log_level_str) = cli.log_level {
        config.log_level = log_level_str.parse::<LogLevel>()?;
    }

    // Validate the final configuration
    config.validate()?;

    Ok(Some(config))
}
