// src/config.rs
use serde::Deserialize;
use std::fs::File;
use std::io::BufReader;

/// Configuration for fingerprint randomization.
#[derive(Debug, Deserialize, Clone)]
pub struct FingerprintConfig {
    /// Rotation mode: "every_request", "interval", or "launch".
    pub rotation_mode: String,
    /// Interval in seconds for "interval" rotation mode.
    pub rotation_interval: u64,
    /// Whether to randomize the User-Agent header.
    pub randomize_user_agent: bool,
    /// Whether to randomize the Accept-Language header.
    pub randomize_accept_language: bool,
    /// Whether to strip the Referer header.
    pub strip_referer: bool,
    /// List of Accept-Language values to choose from.
    #[serde(default = "default_accept_languages")]
    pub accept_languages: Vec<String>,
}

fn default_accept_languages() -> Vec<String> {
    vec!["en-US,en;q=0.9".to_string(), "en-GB,en;q=0.8".to_string()]
}

/// Configuration for cookie management.
#[derive(Debug, Deserialize, Clone)]
pub struct CookiesConfig {
    /// Whether to block all cookies by default.
    pub block_all: bool,
    /// Whether to log cookie attempts (even if blocked).
    pub log_attempts: bool,
    /// List of domains to allow cookies for (overrides block_all).
    #[serde(default)]
    pub allow_list: Vec<String>,
    /// List of domains to explicitly block cookies for.
    #[serde(default)]
    pub block_list: Vec<String>,
}

/// Configuration for domain blocking.
#[derive(Debug, Deserialize, Clone)]
pub struct BlockingConfig {
    /// Whether to automatically block domains after a threshold of hits.
    pub auto_block: bool,
    /// Number of hits before auto-blocking a domain.
    pub auto_block_threshold: usize,
    /// Regex patterns for identifying tracking domains.
    pub block_patterns: Vec<String>,
}

/// Configuration for periodic database cleanup.
#[derive(Debug, Deserialize, Clone)]
pub struct CleanupConfig {
    /// Whether periodic cleanup is enabled.
    #[serde(default = "default_cleanup_enabled")]
    pub enabled: bool,
    /// Number of days to retain data.
    #[serde(default = "default_retention_days")]
    pub retention_days: u64,
    /// Interval in seconds between cleanup runs.
    #[serde(default = "default_cleanup_interval")]
    pub interval_seconds: u64,
}

fn default_cleanup_enabled() -> bool { true }
fn default_retention_days() -> u64 { 7 }
fn default_cleanup_interval() -> u64 { 3600 }

/// Main configuration struct for BlankTrace.
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// Fingerprint randomization settings.
    pub fingerprint: FingerprintConfig,
    /// Cookie management settings.
    pub cookies: CookiesConfig,
    /// Domain blocking settings.
    pub blocking: BlockingConfig,
    /// Database cleanup settings.
    #[serde(default)]
    pub cleanup: CleanupConfig,
    /// Port to listen on (default: 8080).
    pub port: Option<u16>,
    /// Path to the SQLite database file.
    pub db_path: String,
}

impl Default for CleanupConfig {
    fn default() -> Self {
        Self {
            enabled: default_cleanup_enabled(),
            retention_days: default_retention_days(),
            interval_seconds: default_cleanup_interval(),
        }
    }
}

/// Loads configuration from a YAML file.
///
/// # Arguments
///
/// * `path` - Path to the configuration file.
pub fn load(path: &str) -> anyhow::Result<Config> {
    let file = File::open(path)?;
    let cfg: Config = serde_yaml::from_reader(BufReader::new(file))?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_cleanup_config() {
        let cleanup = CleanupConfig::default();
        assert!(cleanup.enabled);
        assert_eq!(cleanup.retention_days, 7);
        assert_eq!(cleanup.interval_seconds, 3600);
    }

    #[test]
    fn test_default_accept_languages() {
        let langs = default_accept_languages();
        assert!(!langs.is_empty());
        assert!(langs.contains(&"en-US,en;q=0.9".to_string()));
    }
}
