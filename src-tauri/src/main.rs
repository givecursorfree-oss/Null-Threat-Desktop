#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use null_threat::app_paths::AppPaths;
use null_threat::commands::{self, AppState};
use null_threat::db::Database;
use null_threat::setup;
use null_threat::tray;
use null_threat::watcher::FileWatcher;
use std::sync::Arc;
use tauri::Manager;
use tauri_plugin_notification::NotificationExt;

fn main() {
    env_logger::init();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            let paths = AppPaths::resolve(app).expect("Failed to resolve application paths");

            let db = Arc::new(
                Database::new(&paths.app_data_dir).expect("Failed to initialize database"),
            );

            setup::ensure_first_run_setup(&db).expect("First-run setup failed");

            setup::ensure_yara_rules(&paths.rules_dir, paths.resource_dir.as_deref());

            setup::ensure_clamav_runtime(
                &paths.clamav_runtime_dir,
                paths.resource_dir.as_deref(),
                &paths.clamav_db_dir,
            );
            setup::copy_bundled_clamav_db(&paths.clamav_db_dir, paths.resource_clamav());

            #[cfg(windows)]
            null_threat::notifications::configure_windows(app.config().identifier.as_str());

            let _ = app.notification().request_permission();

            let watcher = Arc::new(FileWatcher::new());

            let realtime_enabled = db
                .get_setting("realtime_protection")
                .ok()
                .flatten()
                .map(|v| v == "true")
                .unwrap_or(false);

            if realtime_enabled {
                let app_handle = app.handle().clone();
                let db_clone = db.clone();
                let rules_clone = paths.rules_dir.clone();
                let clamav_db_clone = paths.clamav_db_dir.clone();
                let clamav_runtime_clone = paths.clamav_runtime_dir.clone();
                let resource_clone = paths.resource_dir.clone();
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
                app_data_dir: paths.app_data_dir,
                rules_dir: paths.rules_dir,
                clamav_db_dir: paths.clamav_db_dir,
                clamav_runtime_dir: paths.clamav_runtime_dir,
                resource_dir: paths.resource_dir,
            });

            tray::setup(app)?;

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
            commands::export_scan_report_json,
            commands::export_scan_report_pdf,
            commands::save_scan_report_json,
            commands::save_scan_report_pdf,
            commands::clear_scan_history,
            commands::check_dependencies,
            commands::get_signature_status,
            commands::update_signatures,
            commands::get_hash_intel_status,
            commands::update_hash_intel,
            commands::sync_yara_rules,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Null Threat");
}
