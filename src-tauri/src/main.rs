#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use null_threat::commands::{self, AppState};
use null_threat::db::Database;
use null_threat::setup;
use null_threat::watcher::FileWatcher;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::Manager;
use tauri_plugin_notification::NotificationExt;

fn main() {
    env_logger::init();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            let app_data_dir = app
                .path()
                .app_data_dir()
                .unwrap_or_else(|_| PathBuf::from("."));

            let db = Arc::new(
                Database::new(&app_data_dir).expect("Failed to initialize database"),
            );

            setup::ensure_first_run_setup(&db).expect("First-run setup failed");

            let rules_dir = app_data_dir.join("yara_rules");
            let resource_rules = app.path().resource_dir().ok().map(|r| r.join("rules"));
            setup::copy_bundled_rules(&rules_dir, resource_rules);

            let clamav_db_dir = app_data_dir.join("clamav_db");
            let clamav_runtime_dir = app_data_dir.join("clamav_runtime");
            let resource_dir = app.path().resource_dir().ok();
            let resource_clamav = resource_dir.as_ref().map(|r| r.join("clamav"));

            setup::ensure_clamav_runtime(&clamav_runtime_dir, resource_dir.as_deref());
            setup::copy_bundled_clamav_db(&clamav_db_dir, resource_clamav);

            let _ = app.notification().request_permission();

            let watcher = Arc::new(FileWatcher::new());

            let realtime_enabled = db
                .get_setting("realtime_protection")
                .ok()
                .flatten()
                .map(|v| v == "true")
                .unwrap_or(true);

            if realtime_enabled {
                let app_handle = app.handle().clone();
                let db_clone = db.clone();
                let rules_clone = rules_dir.clone();
                let clamav_db_clone = clamav_db_dir.clone();
                let clamav_runtime_clone = clamav_runtime_dir.clone();
                let resource_clone = resource_dir.clone();
                let watcher_clone = watcher.clone();
                if let Err(e) = watcher_clone.start(
                    app_handle,
                    db_clone,
                    rules_clone,
                    clamav_db_clone,
                    clamav_runtime_clone,
                    resource_clone,
                ) {
                    log::error!("Failed to start file watcher: {e}");
                }
            }

            app.manage(AppState {
                db: db.clone(),
                watcher,
                app_data_dir,
                rules_dir: rules_dir.clone(),
                clamav_db_dir: clamav_db_dir.clone(),
                clamav_runtime_dir: clamav_runtime_dir.clone(),
                resource_dir,
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::pick_scan_file,
            commands::pick_watched_folder,
            commands::scan_file,
            commands::get_scan_history,
            commands::get_dashboard_stats,
            commands::get_verdict_breakdown,
            commands::get_realtime_protection,
            commands::quarantine_file,
            commands::restore_file,
            commands::delete_quarantined,
            commands::get_quarantine_list,
            commands::add_watched_folder,
            commands::remove_watched_folder,
            commands::toggle_watched_folder,
            commands::get_watched_folders,
            commands::toggle_realtime_protection,
            commands::add_to_whitelist,
            commands::remove_from_whitelist,
            commands::get_whitelist,
            commands::export_history_csv,
            commands::check_dependencies,
            commands::get_signature_status,
            commands::update_signatures,
            commands::get_hash_intel_status,
            commands::update_hash_intel,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Null Threat");
}
