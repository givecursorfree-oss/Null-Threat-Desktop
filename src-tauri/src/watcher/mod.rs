use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter};
use tokio::sync::mpsc;

use crate::db::Database;
use crate::scanner;

pub struct FileWatcher {
    watcher: Mutex<Option<RecommendedWatcher>>,
    watched_paths: Mutex<Vec<PathBuf>>,
    enabled: Mutex<bool>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct FileDetectedEvent {
    path: String,
    event_type: String,
}

impl FileWatcher {
    pub fn new() -> Self {
        FileWatcher {
            watcher: Mutex::new(None),
            watched_paths: Mutex::new(Vec::new()),
            enabled: Mutex::new(false),
        }
    }

    pub fn is_enabled(&self) -> bool {
        *self.enabled.lock().unwrap()
    }

    pub fn start(
        &self,
        app: AppHandle,
        db: Arc<Database>,
        rules_dir: PathBuf,
        clamav_db_dir: PathBuf,
        clamav_runtime_dir: PathBuf,
        _resource_dir: Option<PathBuf>,
    ) -> Result<(), String> {
        {
            let mut enabled = self.enabled.lock().unwrap();
            if *enabled {
                return Ok(());
            }
            *enabled = true;
        }

        let (tx, mut rx) = mpsc::channel::<PathBuf>(256);

        let tx_clone = tx.clone();
        let watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    let dominated_kinds = matches!(
                        event.kind,
                        EventKind::Create(_) | EventKind::Modify(_)
                    );
                    if dominated_kinds {
                        for path in event.paths {
                            if path.is_file() {
                                let _ = tx_clone.blocking_send(path);
                            }
                        }
                    }
                }
            },
            Config::default(),
        )
        .map_err(|e| format!("Failed to create file watcher: {e}"))?;

        *self.watcher.lock().unwrap() = Some(watcher);

        let paths = db
            .get_enabled_watched_folders()
            .unwrap_or_default();

        for folder in &paths {
            self.add_path_internal(&PathBuf::from(&folder.path))?;
        }

        let app_handle = app.clone();
        let db_clone = db.clone();

        let debounce: Arc<Mutex<std::collections::HashSet<String>>> =
            Arc::new(Mutex::new(std::collections::HashSet::new()));

        tauri::async_runtime::spawn(async move {
            while let Some(path) = rx.recv().await {
                let path_str = path.to_string_lossy().to_string();

                {
                    let set = debounce.lock().unwrap();
                    if set.contains(&path_str) {
                        continue;
                    }
                }
                debounce.lock().unwrap().insert(path_str.clone());

                if let Err(e) = app_handle.emit(
                    "file-detected",
                    FileDetectedEvent {
                        path: path_str.clone(),
                        event_type: "auto_scan".into(),
                    },
                ) {
                    log::warn!("Failed to emit file-detected: {e}");
                }

                let app_for_scan = app_handle.clone();
                let db_for_scan = db_clone.clone();
                let rules = rules_dir.clone();
                let clamav_db = clamav_db_dir.clone();
                let clamav_runtime = clamav_runtime_dir.clone();
                let p = path_str.clone();

                tauri::async_runtime::spawn(async move {
                    match scanner::run_scan_pipeline(
                        &app_for_scan,
                        &p,
                        &db_for_scan,
                        &rules,
                        &clamav_db,
                        Some(&clamav_runtime),
                        "auto_scan",
                    )
                    .await
                    {
                        Ok(result) => {
                            let filename = &result.filename;
                            let _ = db_for_scan.insert_scan_record(
                                filename,
                                &result.filepath,
                                &result.sha256,
                                result.risk_score,
                                &result.verdict,
                                result.threat_name.as_deref(),
                                "auto_scan",
                                &serde_json::to_string(&result.engine_results).unwrap_or_default(),
                            );
                        }
                        Err(e) => {
                            log::error!("Auto-scan failed for {p}: {e}");
                        }
                    }
                });

                let debounce_clone = debounce.clone();
                let debounce_path = path_str;
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                    debounce_clone.lock().unwrap().remove(&debounce_path);
                });
            }
        });

        Ok(())
    }

    pub fn stop(&self) -> Result<(), String> {
        let mut enabled = self.enabled.lock().unwrap();
        *enabled = false;
        let mut watcher = self.watcher.lock().unwrap();
        *watcher = None;
        let mut paths = self.watched_paths.lock().unwrap();
        paths.clear();
        Ok(())
    }

    fn add_path_internal(&self, path: &Path) -> Result<(), String> {
        let mut watcher_guard = self.watcher.lock().unwrap();
        if let Some(ref mut w) = *watcher_guard {
            w.watch(path, RecursiveMode::Recursive)
                .map_err(|e| format!("Failed to watch path {}: {e}", path.display()))?;
            let mut paths = self.watched_paths.lock().unwrap();
            if !paths.contains(&path.to_path_buf()) {
                paths.push(path.to_path_buf());
            }
            Ok(())
        } else {
            Err("File watcher is not running".into())
        }
    }

    pub fn add_path(&self, path: &Path) -> Result<(), String> {
        if !self.is_enabled() {
            return Ok(());
        }
        self.add_path_internal(path)
    }

    pub fn remove_path(&self, path: &Path) -> Result<(), String> {
        let mut watcher_guard = self.watcher.lock().unwrap();
        if let Some(ref mut w) = *watcher_guard {
            w.unwatch(path)
                .map_err(|e| format!("Failed to unwatch path {}: {e}", path.display()))?;
        }
        let mut paths = self.watched_paths.lock().unwrap();
        paths.retain(|p| p != path);
        Ok(())
    }
}
