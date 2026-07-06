pub mod models;
pub mod queries;

use rusqlite::{Connection, Result as SqliteResult};
use std::path::PathBuf;
use std::sync::Mutex;

pub struct Database {
    pub conn: Mutex<Connection>,
}

impl Database {
    pub fn new(app_data_dir: &PathBuf) -> SqliteResult<Self> {
        std::fs::create_dir_all(app_data_dir).ok();
        let db_path = app_data_dir.join("nullthreat.db");
        let conn = Connection::open(&db_path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        let db = Database {
            conn: Mutex::new(conn),
        };
        db.run_migrations()?;
        Ok(db)
    }

    fn column_exists(conn: &Connection, table: &str, column: &str) -> SqliteResult<bool> {
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
        for name in rows.flatten() {
            if name == column {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn run_migrations(&self) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS scan_history (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                filename        TEXT NOT NULL,
                filepath        TEXT NOT NULL,
                sha256          TEXT NOT NULL,
                timestamp       TEXT NOT NULL DEFAULT (datetime('now')),
                risk_score      INTEGER NOT NULL DEFAULT 0,
                verdict         TEXT NOT NULL DEFAULT 'clean',
                threat_name     TEXT,
                action_taken    TEXT NOT NULL DEFAULT 'none',
                engine_results  TEXT NOT NULL DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS quarantine_entries (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                original_path   TEXT NOT NULL,
                quarantine_path TEXT NOT NULL,
                threat_name     TEXT NOT NULL,
                risk_score      INTEGER NOT NULL DEFAULT 0,
                scan_date       TEXT NOT NULL DEFAULT (datetime('now')),
                file_size       INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS watched_folders (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                path    TEXT NOT NULL UNIQUE,
                enabled INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS whitelist (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                path        TEXT NOT NULL,
                sha256      TEXT NOT NULL,
                added_date  TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_scan_history_sha256 ON scan_history(sha256);
            CREATE INDEX IF NOT EXISTS idx_scan_history_timestamp ON scan_history(timestamp);
            CREATE INDEX IF NOT EXISTS idx_whitelist_sha256 ON whitelist(sha256);

            CREATE TABLE IF NOT EXISTS nsrl (
                sha256 TEXT PRIMARY KEY,
                product_name TEXT
            );

            CREATE TABLE IF NOT EXISTS malwarebazaar (
                sha256      TEXT PRIMARY KEY,
                threat_name TEXT NOT NULL,
                first_seen  TEXT
            );
            ",
        )?;

        if !Self::column_exists(&conn, "scan_history", "report_json")? {
            conn.execute(
                "ALTER TABLE scan_history ADD COLUMN report_json TEXT",
                [],
            )?;
        }

        Ok(())
    }
}
