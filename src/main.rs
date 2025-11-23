// src/main.rs
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use log::info;

mod blocker;
mod cli;
mod config;
mod cookie;
mod db;
mod proxy;
mod randomizer;

// Export modules for examples and tests
pub use config::FingerprintConfig;
pub use randomizer::Randomizer;

use crate::cli::{handle_management_cmd, Cli};
use crate::config::load;
use crate::cookie::CookieHandler;
use crate::db::spawn_logger;
use crate::proxy::{run_proxy, ProxyState};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    // Parse CLI arguments (may contain subcommands for management)
    let cli = Cli::parse();

    // Load configuration (default path)
    let config_path = "config.yaml";
    let cfg = load(config_path)?;

    // If a management subcommand was provided, handle it and exit
    if let Some(command) = cli.command {
        handle_management_cmd(command, cfg.db_path.clone()).await?;
        return Ok(());
    }

    // Set up async logger channel
    let (db_tx, db_rx) = tokio::sync::mpsc::channel(1024);
    tokio::spawn(spawn_logger(cfg.db_path.clone(), db_rx));

    // Shared state components
    let db = Arc::new(tokio::sync::Mutex::new(db::Database::new(&cfg.db_path)?));
    let randomizer = Arc::new(tokio::sync::Mutex::new(randomizer::Randomizer::new(
        &cfg.fingerprint,
    )));
    let cookie_handler = Arc::new(CookieHandler::new(cfg.clone()));
    let blocker = Arc::new(blocker::Blocker::new(&cfg, db.clone(), db_tx.clone()));

    let state = ProxyState {
        randomizer,
        cookie_handler,
        blocker,
        db_logger: db_tx,
    };

    // Spawn cleanup task
    if cfg.cleanup.enabled {
        let db_clone = db.clone();
        let retention_days = cfg.cleanup.retention_days;
        let interval_seconds = cfg.cleanup.interval_seconds;
        
        tokio::spawn(async move {
            info!("Starting cleanup task (retention: {} days, interval: {}s)", retention_days, interval_seconds);
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_seconds));
            loop {
                interval.tick().await;
                match db_clone.lock().await.cleanup_old_data(retention_days).await {
                    Ok(count) => {
                        if count > 0 {
                            info!("Cleaned up {} old records from database", count);
                        }
                    }
                    Err(e) => {
                        log::error!("Database cleanup failed: {}", e);
                    }
                }
            }
        });
    }

    let port = cfg.port.unwrap_or(8080);
    info!("Starting proxy on 127.0.0.1:{}", port);
    run_proxy(state, port).await?;

    Ok(())
}
