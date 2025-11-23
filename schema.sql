-- schema.sql
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS tracking_domains (
    domain TEXT PRIMARY KEY,
    hit_count INTEGER DEFAULT 0,
    blocked BOOLEAN DEFAULT FALSE,
    category TEXT
);

CREATE TABLE IF NOT EXISTS tracking_ips (
    ip TEXT PRIMARY KEY,
    hit_count INTEGER DEFAULT 0,
    blocked BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS cookie_traffic (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT,
    cookie TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    blocked BOOLEAN
);

CREATE TABLE IF NOT EXISTS fingerprint_rotations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    user_agent TEXT,
    accept_language TEXT,
    mode TEXT
);

CREATE TABLE IF NOT EXISTS request_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT,
    path TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    user_agent TEXT,
    client_ip TEXT
);

CREATE TABLE IF NOT EXISTS whitelist (
    domain TEXT PRIMARY KEY,
    reason TEXT
);
