use crate::db::models::*;
use crate::db::Database;
use crate::quarantine;
use crate::scanner::{self, ScanResult};
use crate::watcher::FileWatcher;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::State;
use tauri_plugin_dialog::DialogExt;

pub struct AppState {
    pub db: Arc<Database>,
    pub watcher: Arc<FileWatcher>,
    pub app_data_dir: PathBuf,
    pub rules_dir: PathBuf,
    pub clamav_db_dir: PathBuf,
    pub clamav_runtime_dir: PathBuf,
    pub resource_dir: Option<PathBuf>,
}

fn ensure_watcher_running(state: &AppState, app: &tauri::AppHandle) -> Result<(), String> {
    let enabled = state
        .db
        .get_setting("realtime_protection")
        .ok()
        .flatten()
        .map(|v| v == "true")
        .unwrap_or(false);

    if enabled && !state.watcher.is_enabled() {
        state.watcher.start(
            app.clone(),
            state.db.clone(),
            state.rules_dir.clone(),
            state.clamav_db_dir.clone(),
            state.clamav_runtime_dir.clone(),
            state.resource_dir.clone(),
        )?;
    }
    Ok(())
}

// ── Scanning ─────────────────────────────────────────────────────

#[tauri::command]
pub async fn pick_scan_file(app: tauri::AppHandle) -> Result<Option<String>, String> {
    let app = app.clone();
    tokio::task::spawn_blocking(move || {
        app.dialog()
            .file()
            .set_title("Select file to scan")
            .blocking_pick_file()
            .map(|p| p.to_string())
    })
    .await
    .map_err(|e| format!("Dialog error: {e}"))
}

#[tauri::command]
pub async fn scan_file(
    path: String,
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<ScanResult, String> {
    let result = scanner::run_scan_pipeline(
        &app,
        &path,
        &state.db,
        &state.rules_dir,
        &state.clamav_db_dir,
        Some(&state.clamav_runtime_dir),
        "manual",
    )
    .await?;

    let engine_json = serde_json::to_string(&result.engine_results).unwrap_or_default();
    state
        .db
        .insert_scan_record(
            &result.filename,
            &result.filepath,
            &result.sha256,
            result.risk_score,
            &result.verdict,
            result.threat_name.as_deref(),
            "manual_scan",
            &engine_json,
        )
        .map_err(|e| format!("DB error: {e}"))?;

    Ok(result)
}

#[tauri::command]
pub async fn get_scan_history(
    limit: u32,
    state: State<'_, AppState>,
) -> Result<Vec<ScanRecord>, String> {
    state
        .db
        .get_scan_history(limit)
        .map_err(|e| format!("DB error: {e}"))
}

#[tauri::command]
pub async fn get_dashboard_stats(state: State<'_, AppState>) -> Result<DashboardStats, String> {
    state
        .db
        .get_dashboard_stats()
        .map_err(|e| format!("DB error: {e}"))
}

// ── Quarantine ───────────────────────────────────────────────────

#[tauri::command]
pub async fn quarantine_file(
    path: String,
    threat: String,
    score: u32,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let app_data = state.app_data_dir.clone();
    let db = state.db.clone();
    tokio::task::spawn_blocking(move || {
        quarantine::quarantine_file(&app_data, &db, &path, &threat, score)
    })
    .await
    .map_err(|e| format!("Task error: {e}"))?
}

#[tauri::command]
pub async fn restore_file(id: u32, state: State<'_, AppState>) -> Result<String, String> {
    let db = state.db.clone();
    tokio::task::spawn_blocking(move || quarantine::restore_file(&db, id as i64))
        .await
        .map_err(|e| format!("Task error: {e}"))?
}

#[tauri::command]
pub async fn delete_quarantined(id: u32, state: State<'_, AppState>) -> Result<(), String> {
    let db = state.db.clone();
    tokio::task::spawn_blocking(move || quarantine::delete_quarantined(&db, id as i64))
        .await
        .map_err(|e| format!("Task error: {e}"))?
}

#[tauri::command]
pub async fn get_quarantine_list(
    state: State<'_, AppState>,
) -> Result<Vec<QuarantineEntry>, String> {
    quarantine::list_quarantined(&state.db)
}

#[tauri::command]
pub async fn pick_watched_folder(app: tauri::AppHandle) -> Result<Option<String>, String> {
    let app = app.clone();
    tokio::task::spawn_blocking(move || {
        app.dialog()
            .file()
            .set_title("Select folder to watch")
            .blocking_pick_folder()
            .map(|p| p.to_string())
    })
    .await
    .map_err(|e| format!("Dialog error: {e}"))
}

// ── Watched Folders ──────────────────────────────────────────────

#[tauri::command]
pub async fn add_watched_folder(
    path: String,
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<i64, String> {
    let id = state
        .db
        .add_watched_folder(&path)
        .map_err(|e| format!("DB error: {e}"))?;

    ensure_watcher_running(&state, &app)?;
    state
        .watcher
        .add_path(&PathBuf::from(&path))
        .map_err(|e| format!("Watcher error: {e}"))?;

    Ok(id)
}

#[tauri::command]
pub async fn remove_watched_folder(
    id: u32,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let folders = state.db.get_watched_folders().unwrap_or_default();
    if let Some(folder) = folders.iter().find(|f| f.id == id as i64) {
        state
            .watcher
            .remove_path(&PathBuf::from(&folder.path))
            .ok();
    }

    state
        .db
        .remove_watched_folder(id as i64)
        .map_err(|e| format!("DB error: {e}"))
}

#[tauri::command]
pub async fn toggle_watched_folder(
    id: u32,
    enabled: bool,
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    let folders = state.db.get_watched_folders().unwrap_or_default();
    let folder = folders
        .iter()
        .find(|f| f.id == id as i64)
        .ok_or_else(|| format!("Folder id {id} not found"))?;

    state
        .db
        .set_watched_folder_enabled(id as i64, enabled)
        .map_err(|e| format!("DB error: {e}"))?;

    let path = PathBuf::from(&folder.path);
    if enabled {
        ensure_watcher_running(&state, &app)?;
        state.watcher.add_path(&path)?;
    } else {
        state.watcher.remove_path(&path).ok();
    }

    Ok(())
}

#[tauri::command]
pub async fn get_watched_folders(
    state: State<'_, AppState>,
) -> Result<Vec<WatchedFolder>, String> {
    state
        .db
        .get_watched_folders()
        .map_err(|e| format!("DB error: {e}"))
}

// ── Real-time Protection ─────────────────────────────────────────

#[tauri::command]
pub fn get_realtime_protection(state: State<'_, AppState>) -> Result<bool, String> {
    Ok(state
        .db
        .get_setting("realtime_protection")
        .map_err(|e| format!("DB error: {e}"))?
        .map(|v| v == "true")
        .unwrap_or(false))
}

#[tauri::command]
pub async fn toggle_realtime_protection(
    enabled: bool,
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    if enabled {
        state.watcher.start(
            app,
            state.db.clone(),
            state.rules_dir.clone(),
            state.clamav_db_dir.clone(),
            state.clamav_runtime_dir.clone(),
            state.resource_dir.clone(),
        )?;
    } else {
        state.watcher.stop()?;
    }

    state
        .db
        .set_setting("realtime_protection", if enabled { "true" } else { "false" })
        .map_err(|e| format!("DB error: {e}"))?;

    Ok(())
}

// ── Whitelist ────────────────────────────────────────────────────

#[tauri::command]
pub async fn add_to_whitelist(
    path: String,
    sha256: String,
    state: State<'_, AppState>,
) -> Result<i64, String> {
    state
        .db
        .add_to_whitelist(&path, &sha256)
        .map_err(|e| format!("DB error: {e}"))
}

#[tauri::command]
pub async fn remove_from_whitelist(
    id: u32,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state
        .db
        .remove_from_whitelist(id as i64)
        .map_err(|e| format!("DB error: {e}"))
}

#[tauri::command]
pub async fn get_whitelist(state: State<'_, AppState>) -> Result<Vec<WhitelistEntry>, String> {
    state
        .db
        .get_whitelist()
        .map_err(|e| format!("DB error: {e}"))
}

// ── Utilities ────────────────────────────────────────────────────

#[tauri::command]
pub async fn export_history_csv(state: State<'_, AppState>) -> Result<String, String> {
    state
        .db
        .export_scan_history_csv()
        .map_err(|e| format!("Export error: {e}"))
}

#[tauri::command]
pub fn get_verdict_breakdown(state: State<'_, AppState>) -> Result<VerdictBreakdown, String> {
    state
        .db
        .get_verdict_breakdown()
        .map_err(|e| format!("DB error: {e}"))
}

#[tauri::command]
pub async fn update_hash_intel(
    force: bool,
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<crate::hash_intel::HashIntelStatus, String> {
    crate::hash_intel::run_hash_intel_update(app, state.db.clone(), force).await
}

#[tauri::command]
pub fn get_hash_intel_status(
    state: State<'_, AppState>,
) -> Result<crate::hash_intel::HashIntelStatus, String> {
    Ok(crate::hash_intel::get_hash_intel_status(&state.db))
}

#[tauri::command]
pub fn get_signature_status(state: State<'_, AppState>) -> Result<crate::signatures::SignatureStatus, String> {
    Ok(crate::signatures::get_signature_status(
        &state.db,
        &state.clamav_db_dir,
        &state.clamav_runtime_dir,
    ))
}

#[tauri::command]
pub async fn update_signatures(
    force: bool,
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<crate::signatures::SignatureStatus, String> {
    crate::signatures::run_signature_update(
        app,
        state.db.clone(),
        state.clamav_db_dir.clone(),
        state.clamav_runtime_dir.clone(),
        force,
    )
    .await
}

#[tauri::command]
pub async fn check_dependencies(
    state: State<'_, AppState>,
) -> Result<DependencyStatus, String> {
    let clamav_available =
        crate::scanner::clamav::is_clamav_available(
            &state.clamav_db_dir,
            Some(&state.clamav_runtime_dir),
        );
    let runtime = Some(state.clamav_runtime_dir.as_path());
    let yara_available = crate::scanner::yara::is_yara_available(runtime);
    let ffprobe_available = crate::scanner::video::is_ffprobe_available(runtime);
    let yara_rules_found = crate::scanner::yara::count_yara_rules(&state.rules_dir);
    let db_connected = state.db.conn.lock().is_ok();
    let malwarebazaar_hash_count = state.db.count_malwarebazaar().unwrap_or(0);

    Ok(DependencyStatus {
        clamav_available,
        yara_available,
        ffprobe_available,
        yara_rules_found,
        db_connected,
        malwarebazaar_hash_count,
    })
}
