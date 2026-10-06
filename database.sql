-- SQLite schema used by app.py. The application also initializes these tables on startup.
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL,
    email TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email
ON users(email COLLATE NOCASE) WHERE email IS NOT NULL;

CREATE TABLE IF NOT EXISTS otp_challenges (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    code_hash TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    ip_address TEXT,
    status TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type TEXT NOT NULL,
    target TEXT NOT NULL,
    result TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    score INTEGER NOT NULL,
    status TEXT NOT NULL,
    solution TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
