use crate::db::Database;
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use std::io::Cursor;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::{AppHandle, Emitter};

const LAST_UPDATED_KEY: &str = "hash_intel_last_updated";
const UPDATE_INTERVAL_HOURS: i64 = 24;
const MALWAREBAZAAR_CSV_URL: &str = "https://bazaar.abuse.ch/export/csv/recent/";
const MALWAREBAZAAR_TXT_URL: &str = "https://bazaar.abuse.ch/export/txt/sha256/recent/";

static UPDATE_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Serialize)]
pub struct HashIntelUpdateEvent {
    pub status: String,
    pub message: String,
    pub progress: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct HashIntelStatus {
    pub updating: bool,
    pub last_updated: Option<String>,
    pub hash_count: u64,
    pub update_due: bool,
    pub message: String,
}

fn emit_update(app: &AppHandle, status: &str, message: &str, progress: u32) {
    let payload = HashIntelUpdateEvent {
        status: status.to_string(),
        message: message.to_string(),
        progress,
    };
    if let Err(e) = app.emit("hash-intel-update", &payload) {
        log::warn!("Failed to emit hash-intel-update: {e}");
    }
}

fn parse_last_updated(db: &Database) -> Option<DateTime<Utc>> {
    db.get_setting(LAST_UPDATED_KEY)
        .ok()
        .flatten()
        .and_then(|raw| DateTime::parse_from_rfc3339(&raw).ok())
        .map(|dt| dt.with_timezone(&Utc))
}

pub fn is_update_due(db: &Database) -> bool {
    match parse_last_updated(db) {
        Some(ts) => Utc::now().signed_duration_since(ts) >= Duration::hours(UPDATE_INTERVAL_HOURS),
        None => true,
    }
}

pub fn get_hash_intel_status(db: &Database) -> HashIntelStatus {
    let last_updated = db.get_setting(LAST_UPDATED_KEY).ok().flatten();
    let hash_count = db.count_malwarebazaar().unwrap_or(0);
    let update_due = is_update_due(db);
    let updating = UPDATE_IN_PROGRESS.load(Ordering::SeqCst);

    let message = if updating {
        "Downloading MalwareBazaar hash intelligence...".to_string()
    } else if hash_count == 0 {
        "No malware hashes loaded yet. Null Threat still works offline — update when online for stronger hash detection.".to_string()
    } else if update_due {
        format!(
            "{hash_count} recent malware hashes cached locally. Daily refresh recommended when you have internet."
        )
    } else {
        format!("{hash_count} recent malware hashes cached. Hash lookup works fully offline.")
    };

    HashIntelStatus {
        updating,
        last_updated,
        hash_count,
        update_due,
        message,
    }
}

fn parse_csv_entries(body: &str) -> Vec<(String, String)> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(Cursor::new(body.as_bytes()));

    let headers = match reader.headers() {
        Ok(h) => h.clone(),
        Err(_) => return vec![],
    };

    let sha_idx = headers
        .iter()
        .position(|h| h.eq_ignore_ascii_case("sha256_hash") || h.eq_ignore_ascii_case("sha256"));
    let malware_idx = headers.iter().position(|h| {
        h.eq_ignore_ascii_case("malware")
            || h.eq_ignore_ascii_case("malware_printable")
            || h.eq_ignore_ascii_case("signature")
    });

    let Some(sha_idx) = sha_idx else {
        return vec![];
    };

    let mut entries = Vec::new();
    for row in reader.records().flatten() {
        let sha = row.get(sha_idx).unwrap_or("").trim().to_lowercase();
        if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        let threat = malware_idx
            .and_then(|i| row.get(i))
            .filter(|s| !s.is_empty())
            .unwrap_or("MalwareBazaar.sample")
            .to_string();
        entries.push((sha, threat));
    }
    entries
}

fn parse_txt_entries(body: &str) -> Vec<(String, String)> {
    body.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let sha = line.to_lowercase();
            if sha.len() == 64 && sha.chars().all(|c| c.is_ascii_hexdigit()) {
                Some((sha, "MalwareBazaar.sample".to_string()))
            } else {
                None
            }
        })
        .collect()
}

fn download_malwarebazaar_entries() -> Result<Vec<(String, String)>, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(120))
        .build();

    match agent.get(MALWAREBAZAAR_CSV_URL).call() {
        Ok(response) => {
            let body = response
                .into_string()
                .map_err(|e| format!("Failed to read MalwareBazaar CSV: {e}"))?;
            let entries = parse_csv_entries(&body);
            if !entries.is_empty() {
                return Ok(entries);
            }
        }
        Err(e) => log::warn!("MalwareBazaar CSV download failed: {e}"),
    }

    let response = agent
        .get(MALWAREBAZAAR_TXT_URL)
        .call()
        .map_err(|e| format!("Failed to download MalwareBazaar feed: {e}"))?;
    let body = response
        .into_string()
        .map_err(|e| format!("Failed to read MalwareBazaar feed: {e}"))?;
    let entries = parse_txt_entries(&body);
    if entries.is_empty() {
        return Err("MalwareBazaar feed contained no valid hashes".to_string());
    }
    Ok(entries)
}

pub async fn run_hash_intel_update(
    app: AppHandle,
    db: Arc<Database>,
    force: bool,
) -> Result<HashIntelStatus, String> {
    if UPDATE_IN_PROGRESS
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Ok(get_hash_intel_status(&db));
    }

    let result: Result<HashIntelStatus, String> = async {
        if !force && !is_update_due(&db) {
            emit_update(
                &app,
                "idle",
                "Malware hash database is already current",
                100,
            );
            return Ok(get_hash_intel_status(&db));
        }

        emit_update(
            &app,
            "checking",
            "Connecting to MalwareBazaar (internet required)...",
            15,
        );

        let entries = tokio::task::spawn_blocking(download_malwarebazaar_entries)
            .await
            .map_err(|e| format!("Task join error: {e}"))??;

        emit_update(
            &app,
            "downloading",
            &format!("Importing {} malware hashes locally...", entries.len()),
            60,
        );

        let imported = db
            .upsert_malwarebazaar_entries(&entries)
            .map_err(|e| format!("Database import error: {e}"))?;

        let now = Utc::now().to_rfc3339();
        db.set_setting(LAST_UPDATED_KEY, &now)
            .map_err(|e| format!("DB error: {e}"))?;

        emit_update(
            &app,
            "complete",
            &format!("Imported {imported} hashes — offline hash lookup is ready"),
            100,
        );

        Ok(get_hash_intel_status(&db))
    }
    .await;

    UPDATE_IN_PROGRESS.store(false, Ordering::SeqCst);

    if let Err(ref err) = result {
        emit_update(&app, "failed", err.as_str(), 0);
    }

    result
}
