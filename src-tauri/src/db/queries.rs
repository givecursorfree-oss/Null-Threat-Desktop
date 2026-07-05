use super::models::*;
use super::Database;
use chrono::Utc;
use rusqlite::{params, Result as SqliteResult};

impl Database {
    // ── Scan History ──────────────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    pub fn insert_scan_record(
        &self,
        filename: &str,
        filepath: &str,
        sha256: &str,
        risk_score: u32,
        verdict: &str,
        threat_name: Option<&str>,
        action_taken: &str,
        engine_results: &str,
    ) -> SqliteResult<i64> {
        let conn = self.conn.lock().unwrap();
        let timestamp = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO scan_history (filename, filepath, sha256, timestamp, risk_score, verdict, threat_name, action_taken, engine_results)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![filename, filepath, sha256, timestamp, risk_score, verdict, threat_name, action_taken, engine_results],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_scan_history(&self, limit: u32) -> SqliteResult<Vec<ScanRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, filename, filepath, sha256, timestamp, risk_score, verdict, threat_name, action_taken, engine_results
             FROM scan_history ORDER BY timestamp DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            Ok(ScanRecord {
                id: row.get(0)?,
                filename: row.get(1)?,
                filepath: row.get(2)?,
                sha256: row.get(3)?,
                timestamp: row.get(4)?,
                risk_score: row.get(5)?,
                verdict: row.get(6)?,
                threat_name: row.get(7)?,
                action_taken: row.get(8)?,
                engine_results: row.get(9)?,
            })
        })?;
        rows.collect()
    }

    /// Permanently delete all scan history rows and reclaim disk space.
    pub fn clear_scan_history(&self) -> SqliteResult<u64> {
        let conn = self.conn.lock().unwrap();
        let deleted = conn.execute("DELETE FROM scan_history", [])?;
        conn.execute("VACUUM", [])?;
        Ok(deleted as u64)
    }

    // ── Quarantine ────────────────────────────────────────────────

    pub fn insert_quarantine_entry(
        &self,
        original_path: &str,
        quarantine_path: &str,
        threat_name: &str,
        risk_score: u32,
        file_size: u64,
    ) -> SqliteResult<i64> {
        let conn = self.conn.lock().unwrap();
        let scan_date = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO quarantine_entries (original_path, quarantine_path, threat_name, risk_score, file_size, scan_date)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![original_path, quarantine_path, threat_name, risk_score, file_size as i64, scan_date],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_quarantine_list(&self) -> SqliteResult<Vec<QuarantineEntry>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, original_path, quarantine_path, threat_name, risk_score, scan_date, file_size
             FROM quarantine_entries ORDER BY scan_date DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            let size: i64 = row.get(6)?;
            Ok(QuarantineEntry {
                id: row.get(0)?,
                original_path: row.get(1)?,
                quarantine_path: row.get(2)?,
                threat_name: row.get(3)?,
                risk_score: row.get(4)?,
                scan_date: row.get(5)?,
                file_size: size as u64,
            })
        })?;
        rows.collect()
    }

    pub fn get_quarantine_entry(&self, id: i64) -> SqliteResult<QuarantineEntry> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, original_path, quarantine_path, threat_name, risk_score, scan_date, file_size
             FROM quarantine_entries WHERE id = ?1",
            params![id],
            |row| {
                let size: i64 = row.get(6)?;
                Ok(QuarantineEntry {
                    id: row.get(0)?,
                    original_path: row.get(1)?,
                    quarantine_path: row.get(2)?,
                    threat_name: row.get(3)?,
                    risk_score: row.get(4)?,
                    scan_date: row.get(5)?,
                    file_size: size as u64,
                })
            },
        )
    }

    pub fn delete_quarantine_entry(&self, id: i64) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM quarantine_entries WHERE id = ?1", params![id])?;
        Ok(())
    }

    // ── Watched Folders ───────────────────────────────────────────

    pub fn add_watched_folder(&self, path: &str) -> SqliteResult<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO watched_folders (path) VALUES (?1)",
            params![path],
        )?;
        let id = conn.last_insert_rowid();
        if id == 0 {
            conn.query_row(
                "SELECT id FROM watched_folders WHERE path = ?1",
                params![path],
                |row| row.get(0),
            )
        } else {
            Ok(id)
        }
    }

    pub fn remove_watched_folder(&self, id: i64) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM watched_folders WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn get_watched_folders(&self) -> SqliteResult<Vec<WatchedFolder>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id, path, enabled FROM watched_folders ORDER BY id")?;
        let rows = stmt.query_map([], |row| {
            Ok(WatchedFolder {
                id: row.get(0)?,
                path: row.get(1)?,
                enabled: row.get::<_, i64>(2)? != 0,
            })
        })?;
        rows.collect()
    }

    pub fn get_enabled_watched_folders(&self) -> SqliteResult<Vec<WatchedFolder>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, path, enabled FROM watched_folders WHERE enabled = 1 ORDER BY id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(WatchedFolder {
                id: row.get(0)?,
                path: row.get(1)?,
                enabled: row.get::<_, i64>(2)? != 0,
            })
        })?;
        rows.collect()
    }

    // ── Whitelist ─────────────────────────────────────────────────

    pub fn add_to_whitelist(&self, path: &str, sha256: &str) -> SqliteResult<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM whitelist WHERE sha256 = ?1", params![sha256])?;
        conn.execute(
            "INSERT INTO whitelist (path, sha256) VALUES (?1, ?2)",
            params![path, sha256],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn remove_from_whitelist(&self, id: i64) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM whitelist WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn get_whitelist(&self) -> SqliteResult<Vec<WhitelistEntry>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT id, path, sha256, added_date FROM whitelist ORDER BY added_date DESC")?;
        let rows = stmt.query_map([], |row| {
            Ok(WhitelistEntry {
                id: row.get(0)?,
                path: row.get(1)?,
                sha256: row.get(2)?,
                added_date: row.get(3)?,
            })
        })?;
        rows.collect()
    }

    pub fn is_whitelisted(&self, sha256: &str) -> SqliteResult<bool> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM whitelist WHERE sha256 = ?1",
            params![sha256],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    // ── Hash Lookup ───────────────────────────────────────────────

    pub fn lookup_nsrl(&self, sha256: &str) -> SqliteResult<bool> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM nsrl WHERE sha256 = ?1",
            params![sha256],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    pub fn lookup_malwarebazaar(&self, sha256: &str) -> SqliteResult<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let result = conn.query_row(
            "SELECT threat_name FROM malwarebazaar WHERE sha256 = ?1",
            params![sha256],
            |row| row.get::<_, String>(0),
        );
        match result {
            Ok(name) => Ok(Some(name)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn count_malwarebazaar(&self) -> SqliteResult<u64> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM malwarebazaar", [], |row| row.get(0))
    }

    pub fn upsert_malwarebazaar_entries(&self, entries: &[(String, String)]) -> SqliteResult<usize> {
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction()?;
        let mut imported = 0usize;

        for (sha256, threat_name) in entries {
            tx.execute(
                "INSERT INTO malwarebazaar (sha256, threat_name, first_seen)
                 VALUES (?1, ?2, datetime('now'))
                 ON CONFLICT(sha256) DO UPDATE SET threat_name = excluded.threat_name",
                params![sha256, threat_name],
            )?;
            imported += 1;
        }

        tx.commit()?;
        Ok(imported)
    }

    // ── Statistics ─────────────────────────────────────────────────

    pub fn get_dashboard_stats(&self) -> SqliteResult<DashboardStats> {
        let conn = self.conn.lock().unwrap();

        let total_scans: u64 = conn.query_row(
            "SELECT COUNT(*) FROM scan_history",
            [],
            |row| row.get(0),
        )?;

        let threats_found: u64 = conn.query_row(
            "SELECT COUNT(*) FROM scan_history WHERE verdict != 'clean'",
            [],
            |row| row.get(0),
        )?;

        let files_quarantined: u64 = conn.query_row(
            "SELECT COUNT(*) FROM quarantine_entries",
            [],
            |row| row.get(0),
        )?;

        let scans_today: u64 = conn.query_row(
            "SELECT COUNT(*) FROM scan_history WHERE date(timestamp) = date('now')",
            [],
            |row| row.get(0),
        )?;

        let threats_today: u64 = conn.query_row(
            "SELECT COUNT(*) FROM scan_history WHERE date(timestamp) = date('now') AND verdict != 'clean'",
            [],
            |row| row.get(0),
        )?;

        let avg_risk_score: f64 = conn
            .query_row(
                "SELECT COALESCE(AVG(risk_score), 0.0) FROM scan_history",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0.0);

        Ok(DashboardStats {
            total_scans,
            threats_found,
            files_quarantined,
            scans_today,
            threats_today,
            avg_risk_score,
            last_scan_at: conn
                .query_row(
                    "SELECT timestamp FROM scan_history ORDER BY timestamp DESC LIMIT 1",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .ok(),
        })
    }

    pub fn get_verdict_breakdown(&self) -> SqliteResult<VerdictBreakdown> {
        let conn = self.conn.lock().unwrap();

        let clean: u64 = conn.query_row(
            "SELECT COUNT(*) FROM scan_history WHERE risk_score <= 20 OR verdict = 'clean'",
            [],
            |row| row.get(0),
        )?;

        let suspicious: u64 = conn.query_row(
            "SELECT COUNT(*) FROM scan_history WHERE risk_score BETWEEN 21 AND 50",
            [],
            |row| row.get(0),
        )?;

        let detected: u64 = conn.query_row(
            "SELECT COUNT(*) FROM scan_history WHERE risk_score BETWEEN 51 AND 80",
            [],
            |row| row.get(0),
        )?;

        let critical: u64 = conn.query_row(
            "SELECT COUNT(*) FROM scan_history WHERE risk_score >= 81 OR verdict IN ('malware', 'high_risk')",
            [],
            |row| row.get(0),
        )?;

        Ok(VerdictBreakdown {
            clean,
            suspicious,
            detected,
            critical,
        })
    }

    pub fn set_watched_folder_enabled(&self, id: i64, enabled: bool) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE watched_folders SET enabled = ?1 WHERE id = ?2",
            params![enabled as i64, id],
        )?;
        Ok(())
    }

    // ── Settings ──────────────────────────────────────────────────

    pub fn get_setting(&self, key: &str) -> SqliteResult<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let result = conn.query_row(
            "SELECT value FROM settings WHERE key = ?1",
            params![key],
            |row| row.get::<_, String>(0),
        );
        match result {
            Ok(val) => Ok(Some(val)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn set_setting(&self, key: &str, value: &str) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    // ── CSV Export ─────────────────────────────────────────────────

    pub fn export_scan_history_csv(&self) -> SqliteResult<String> {
        let records = self.get_scan_history(u32::MAX)?;
        let mut wtr = csv::Writer::from_writer(Vec::new());
        wtr.write_record([
            "id",
            "filename",
            "filepath",
            "sha256",
            "timestamp",
            "risk_score",
            "verdict",
            "threat_name",
            "action_taken",
        ])
        .ok();
        for r in &records {
            wtr.write_record([
                &r.id.to_string(),
                &r.filename,
                &r.filepath,
                &r.sha256,
                &r.timestamp,
                &r.risk_score.to_string(),
                &r.verdict,
                r.threat_name.as_deref().unwrap_or(""),
                &r.action_taken,
            ])
            .ok();
        }
        let data = wtr.into_inner().unwrap_or_default();
        Ok(String::from_utf8(data).unwrap_or_default())
    }
}
