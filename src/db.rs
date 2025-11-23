use anyhow::Result;
use rusqlite::{params, Connection};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

/// Represents a loggable event in the proxy.
#[derive(Debug)]
pub enum LogEvent {
    /// A cookie was processed (and potentially blocked).
    Cookie {
        domain: String,
        cookie: String,
        blocked: bool,
    },
    /// A fingerprint rotation occurred.
    Fingerprint {
        user_agent: String,
        accept_language: String,
        mode: String,
    },
    /// A request was proxied.
    Request {
        domain: String,
        path: String,
        user_agent: String,
        client_ip: String,
    },
    /// A tracking domain was hit.
    TrackerHit {
        domain: String,
        category: Option<String>,
    },
}

/// Thread-safe wrapper around the SQLite database connection.
#[derive(Clone)]
pub struct Database {
    pub(crate) conn: Arc<Mutex<Connection>>, // protect with async mutex
}

impl Database {
    /// Opens a new database connection and initializes the schema.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the SQLite database file.
    pub fn new(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        // Execute schema (assumes schema.sql is placed next to Cargo.toml)
        conn.execute_batch(include_str!("../schema.sql"))?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Public accessor for the underlying connection (used by CLI).
    pub fn get_conn(&self) -> &Arc<Mutex<Connection>> {
        &self.conn
    }

    /// Logs a cookie event.
    pub async fn log_cookie(&self, domain: String, cookie: String, blocked: bool) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO cookie_traffic (domain, cookie, blocked) VALUES (?1, ?2, ?3)",
            params![domain, cookie, blocked],
        )?;
        Ok(())
    }

    /// Logs a fingerprint rotation event.
    pub async fn log_fingerprint(&self, ua: String, lang: String, mode: String) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO fingerprint_rotations (user_agent, accept_language, mode) VALUES (?1, ?2, ?3)",
            params![ua, lang, mode],
        )?;
        Ok(())
    }

    /// Logs a proxied request.
    pub async fn log_request(
        &self,
        domain: String,
        path: String,
        ua: String,
        client_ip: String,
    ) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO request_log (domain, path, user_agent, client_ip) VALUES (?1, ?2, ?3, ?4)",
            params![domain, path, ua, client_ip],
        )?;
        Ok(())
    }

    /// Increments the hit count for a tracking domain.
    ///
    /// Returns a tuple containing the new hit count and whether the domain is currently blocked.
    pub async fn increment_tracker(
        &self,
        domain: &str,
        category: Option<&str>,
    ) -> Result<(i32, bool)> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT OR IGNORE INTO tracking_domains (domain, category) VALUES (?1, ?2)",
            params![domain, category],
        )?;
        let hit_count: i32 = conn.query_row(
            "UPDATE tracking_domains SET hit_count = hit_count + 1 WHERE domain = ?1 RETURNING hit_count",
            [domain],
            |row| row.get(0),
        )?;
        let blocked: bool = conn.query_row(
            "SELECT blocked FROM tracking_domains WHERE domain = ?1",
            [domain],
            |row| row.get(0),
        )?;
        Ok((hit_count, blocked))
    }

    /// Checks if a domain is whitelisted.
    pub async fn is_whitelisted(&self, domain: &str) -> Result<bool> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare("SELECT 1 FROM whitelist WHERE domain = ?1")?;
        Ok(stmt.exists(params![domain])?)
    }

    /// Sets the blocked status for a domain.
    pub async fn set_blocked(&self, domain: &str, blocked: bool) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE tracking_domains SET blocked = ?2 WHERE domain = ?1",
            params![domain, blocked],
        )?;
        Ok(())
    }

    /// Adds a domain to the whitelist.
    pub async fn add_whitelist(&self, domain: &str, reason: Option<&str>) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT OR REPLACE INTO whitelist (domain, reason) VALUES (?1, ?2)",
            params![domain, reason],
        )?;
        Ok(())
    }

    /// Manually blocks a domain.
    pub async fn manual_block(&self, domain: &str) -> Result<()> {
        self.set_blocked(domain, true).await
    }

    /// Retrieves the top tracking domains by hit count.
    pub async fn get_top_domains(&self, limit: usize) -> Result<Vec<(String, i32)>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT domain, hit_count FROM tracking_domains ORDER BY hit_count DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit as i64], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let mut vec = Vec::new();
        for r in rows {
            vec.push(r?);
        }
        Ok(vec)
    }

    /// Cleans up old data from the database based on retention policy.
    ///
    /// # Arguments
    ///
    /// * `retention_days` - Number of days to retain data.
    ///
    /// Returns the total number of deleted records.
    pub async fn cleanup_old_data(&self, retention_days: u64) -> Result<usize> {
        let conn = self.conn.lock().await;
        let days_str = format!("-{} days", retention_days);
        
        let mut total_deleted = 0;

        // Cleanup request_log
        total_deleted += conn.execute(
            "DELETE FROM request_log WHERE timestamp < datetime('now', ?1)",
            params![days_str],
        )?;

        // Cleanup cookie_traffic
        total_deleted += conn.execute(
            "DELETE FROM cookie_traffic WHERE timestamp < datetime('now', ?1)",
            params![days_str],
        )?;

        // Cleanup fingerprint_rotations
        total_deleted += conn.execute(
            "DELETE FROM fingerprint_rotations WHERE timestamp < datetime('now', ?1)",
            params![days_str],
        )?;

        Ok(total_deleted)
    }
}

/// Spawns a background task to handle database logging events.
///
/// # Arguments
///
/// * `db_path` - Path to the database file.
/// * `rx` - Receiver for log events.
pub async fn spawn_logger(db_path: String, mut rx: mpsc::Receiver<LogEvent>) {
    let db = match Database::new(&db_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to open DB for logger: {}", e);
            return;
        }
    };
    while let Some(event) = rx.recv().await {
        match event {
            LogEvent::Cookie {
                domain,
                cookie,
                blocked,
            } => {
                let _ = db.log_cookie(domain, cookie, blocked).await;
            }
            LogEvent::Fingerprint {
                user_agent,
                accept_language,
                mode,
            } => {
                let _ = db.log_fingerprint(user_agent, accept_language, mode).await;
            }
            LogEvent::Request {
                domain,
                path,
                user_agent,
                client_ip,
            } => {
                let _ = db.log_request(domain, path, user_agent, client_ip).await;
            }
            LogEvent::TrackerHit { domain, category } => {
                let _ = db.increment_tracker(&domain, category.as_deref()).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_db_logging_and_retrieval() {
        let db = Database::new(":memory:").unwrap();
        
        // Test request logging
        db.log_request(
            "example.com".to_string(),
            "/".to_string(),
            "Mozilla/5.0".to_string(),
            "127.0.0.1".to_string()
        ).await.unwrap();

        let conn = db.conn.lock().await;
        let count: i32 = conn.query_row(
            "SELECT count(*) FROM request_log",
            [],
            |row| row.get(0)
        ).unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_tracker_increment() {
        let db = Database::new(":memory:").unwrap();
        
        let (hits, blocked) = db.increment_tracker("tracker.com", Some("ads")).await.unwrap();
        assert_eq!(hits, 1);
        assert!(!blocked);

        let (hits2, _) = db.increment_tracker("tracker.com", Some("ads")).await.unwrap();
        assert_eq!(hits2, 2);
    }

    #[tokio::test]
    async fn test_whitelist_operations() {
        let db = Database::new(":memory:").unwrap();
        
        assert!(!db.is_whitelisted("good.com").await.unwrap());
        
        db.add_whitelist("good.com", Some("trusted")).await.unwrap();
        assert!(db.is_whitelisted("good.com").await.unwrap());
    }

    #[tokio::test]
    async fn test_cleanup() {
        let db = Database::new(":memory:").unwrap();
        
        // Insert old record manually
        {
            let conn = db.conn.lock().await;
            conn.execute(
                "INSERT INTO request_log (domain, path, user_agent, client_ip, timestamp) 
                 VALUES ('old.com', '/', 'ua', '1.1.1.1', datetime('now', '-10 days'))",
                [],
            ).unwrap();
            
            conn.execute(
                "INSERT INTO request_log (domain, path, user_agent, client_ip, timestamp) 
                 VALUES ('new.com', '/', 'ua', '1.1.1.1', datetime('now'))",
                [],
            ).unwrap();
        }

        let deleted = db.cleanup_old_data(7).await.unwrap();
        assert_eq!(deleted, 1); // Should delete the old one

        let conn = db.conn.lock().await;
        let count: i32 = conn.query_row(
            "SELECT count(*) FROM request_log",
            [],
            |row| row.get(0)
        ).unwrap();
        assert_eq!(count, 1); // Only new one remains
    }
}
