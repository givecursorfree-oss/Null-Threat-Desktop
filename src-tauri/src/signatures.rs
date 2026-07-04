use crate::db::Database;
use crate::process_util;
use crate::scanner::clamav;
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::{AppHandle, Emitter};

const LAST_UPDATED_KEY: &str = "signatures_last_updated";
const UPDATE_INTERVAL_HOURS: i64 = 24;

static UPDATE_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Serialize)]
pub struct SignatureUpdateEvent {
    pub status: String,
    pub message: String,
    pub progress: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignatureStatus {
    pub updating: bool,
    pub last_updated: Option<String>,
    pub database_complete: bool,
    pub update_due: bool,
    pub message: String,
}

fn emit_update(app: &AppHandle, status: &str, message: &str, progress: u32) {
    let payload = SignatureUpdateEvent {
        status: status.to_string(),
        message: message.to_string(),
        progress,
    };
    if let Err(e) = app.emit("signature-update", &payload) {
        log::warn!("Failed to emit signature-update: {e}");
    }
}

fn write_freshclam_config(runtime_dir: &Path, db_dir: &Path) -> PathBuf {
    let conf_path = runtime_dir.join("freshclam.conf");
    let content = format!(
        "DatabaseDirectory {}\nDNSDatabaseInfo current.cvd.clamav.net\nDatabaseMirror database.clamav.net\n",
        db_dir.display()
    );
    let _ = std::fs::write(&conf_path, content);
    conf_path
}

fn resolve_freshclam(runtime_dir: &Path) -> Option<PathBuf> {
    crate::scanner::clamav::resolve_freshclam_binary(runtime_dir)
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

pub fn get_signature_status(
    db: &Database,
    db_dir: &Path,
    _runtime_dir: &Path,
) -> SignatureStatus {
    let last_updated = db
        .get_setting(LAST_UPDATED_KEY)
        .ok()
        .flatten();

    let database_complete = clamav::has_complete_virus_database(db_dir);
    let update_due = is_update_due(db);
    let updating = UPDATE_IN_PROGRESS.load(Ordering::SeqCst);

    let message = if updating {
        "Signature update in progress".to_string()
    } else if !database_complete {
        "Virus database incomplete — update recommended".to_string()
    } else if update_due {
        "Daily signature refresh is due".to_string()
    } else if let Some(ref ts) = last_updated {
        format!("Signatures up to date (last checked {ts})")
    } else {
        "Signatures ready".to_string()
    };

    SignatureStatus {
        updating,
        last_updated,
        database_complete,
        update_due,
        message,
    }
}

pub async fn run_signature_update(
    app: AppHandle,
    db: Arc<Database>,
    db_dir: PathBuf,
    runtime_dir: PathBuf,
    force: bool,
) -> Result<SignatureStatus, String> {
    if UPDATE_IN_PROGRESS
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Ok(get_signature_status(&db, &db_dir, &runtime_dir));
    }

    let result = async {
        if !force && !is_update_due(&db) && clamav::has_complete_virus_database(&db_dir) {
            emit_update(&app, "idle", "Signatures are already current", 100);
            return Ok(get_signature_status(&db, &db_dir, &runtime_dir));
        }

        emit_update(
            &app,
            "checking",
            "Checking for malware signature updates...",
            10,
        );

        std::fs::create_dir_all(&db_dir).map_err(|e| format!("Failed to create DB dir: {e}"))?;
        std::fs::create_dir_all(&runtime_dir)
            .map_err(|e| format!("Failed to create runtime dir: {e}"))?;

        let freshclam = resolve_freshclam(&runtime_dir).ok_or_else(|| {
            emit_update(
                &app,
                "failed",
                "freshclam not found — run the platform ClamAV setup script first",
                0,
            );
            "freshclam not available".to_string()
        })?;

        let conf_path = write_freshclam_config(&runtime_dir, &db_dir);
        let runtime_root = freshclam
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or(runtime_dir.clone());

        emit_update(
            &app,
            "downloading",
            "Downloading latest ClamAV signatures...",
            35,
        );

        let app_emit = app.clone();
        let output = tokio::task::spawn_blocking(move || {
            let mut cmd = Command::new(&freshclam);
            cmd.current_dir(&runtime_root)
                .arg(format!("--config-file={}", conf_path.display()))
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            clamav::configure_runtime_env(&mut cmd, &runtime_root);
            process_util::configure_hidden_subprocess(&mut cmd);
            cmd.output()
        })
        .await
        .map_err(|e| format!("Task join error: {e}"))?
        .map_err(|e| format!("Failed to run freshclam: {e}"))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{stdout}\n{stderr}");

        for line in combined.lines().map(str::trim).filter(|l| !l.is_empty()) {
            log::info!("freshclam: {line}");
            let progress = if line.to_lowercase().contains("download") {
                65
            } else if line.to_lowercase().contains("updated") {
                90
            } else {
                50
            };
            emit_update(&app_emit, "downloading", line, progress);
        }

        if clamav::has_complete_virus_database(&db_dir) {
            let now = Utc::now().to_rfc3339();
            db.set_setting(LAST_UPDATED_KEY, &now)
                .map_err(|e| format!("DB error: {e}"))?;
            emit_update(
                &app,
                "complete",
                "Malware signatures updated successfully",
                100,
            );
            Ok(get_signature_status(&db, &db_dir, &runtime_dir))
        } else if output.status.success() {
            let now = Utc::now().to_rfc3339();
            let _ = db.set_setting(LAST_UPDATED_KEY, &now);
            emit_update(
                &app,
                "complete",
                "Signature check finished",
                100,
            );
            Ok(get_signature_status(&db, &db_dir, &runtime_dir))
        } else {
            let err = if stderr.trim().is_empty() {
                format!("freshclam exited with status {}", output.status)
            } else {
                stderr.trim().to_string()
            };
            emit_update(&app, "failed", &err, 0);
            Err(err)
        }
    }
    .await;

    UPDATE_IN_PROGRESS.store(false, Ordering::SeqCst);
    result
}

pub async fn schedule_startup_update(
    app: AppHandle,
    db: Arc<Database>,
    db_dir: PathBuf,
    runtime_dir: PathBuf,
) {
    if !is_update_due(&db) && clamav::has_complete_virus_database(&db_dir) {
        return;
    }

    let _ = run_signature_update(app, db, db_dir, runtime_dir, false).await;
}
