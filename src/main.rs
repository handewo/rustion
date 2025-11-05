mod asciinema;
mod cli;
mod common;
mod config;
pub mod database;
pub mod error;
mod server;
mod terminal;

use log::{debug, error, info, LevelFilter};

fn log_level_to_filter(level: &config::LogLevel) -> LevelFilter {
    match level {
        config::LogLevel::Error => LevelFilter::Error,
        config::LogLevel::Warn => LevelFilter::Warn,
        config::LogLevel::Info => LevelFilter::Info,
        config::LogLevel::Debug => LevelFilter::Debug,
        config::LogLevel::Trace => LevelFilter::Trace,
    }
}

#[tokio::main]
async fn main() {
    // Handle CLI arguments and configuration first to get log level
    let config = match cli::handle_cli_args().await {
        Ok(Some(config)) => config,
        Ok(None) => {
            // CLI handled the request (e.g., generated config file)
            return;
        }
        Err(e) => {
            // Initialize basic logger for error reporting
            env_logger::init();
            error!("{}", e);
            std::process::exit(1);
        }
    };

    // Initialize logger with configured level
    env_logger::Builder::from_default_env()
        .filter_level(log_level_to_filter(&config.log_level))
        .init();

    info!("Starting rustion application");
    debug!("Config: {}", config);

    // Create server with the resolved configuration
    let mut server = match server::BastionServer::with_config(config).await {
        Ok(server) => server,
        Err(e) => {
            error!("Server error: {}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = server.run().await {
        error!("Server error: {}", e);
        std::process::exit(1);
    }
}
