use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter};
use tokio::sync::mpsc;

use crate::db::Database;
use crate::scanner;

const SCAN_DEBOUNCE: Duration = Duration::from_secs(5);
const SCAN_COOLDOWN: Duration = Duration::from_secs(60);

pub struct FileWatcher {
    watcher: Mutex<Option<RecommendedWatcher>>,
    watched_paths: Mutex<Vec<PathBuf>>,
    enabled: Mutex<bool>,
    /// Held while the consumer loop is active; dropping it closes the channel and ends the task.
    event_tx: Mutex<Option<mpsc::Sender<PathBuf>>>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct FileDetectedEvent {
    path: String,
    event_type: String,
}

struct ScanCoordinator {
    generations: HashMap<String, u64>,
    in_flight: HashSet<String>,
    last_scanned: HashMap<String, Instant>,
}

impl ScanCoordinator {
    fn new() -> Self {
        Self {
            generations: HashMap::new(),
            in_flight: HashSet::new(),
            last_scanned: HashMap::new(),
        }
    }

    fn bump_generation(&mut self, path: &str) -> u64 {
        let next = self.generations.get(path).copied().unwrap_or(0) + 1;
        self.generations.insert(path.to_string(), next);
        next
    }

    fn should_skip_after_debounce(&self, path: &str, generation: u64) -> bool {
        self.generations.get(path).copied() != Some(generation)
            || self.in_flight.contains(path)
            || self
                .last_scanned
                .get(path)
                .is_some_and(|scanned_at| scanned_at.elapsed() < SCAN_COOLDOWN)
    }

    fn mark_scan_started(&mut self, path: &str) {
        self.in_flight.insert(path.to_string());
    }

    fn mark_scan_finished(&mut self, path: &str) {
        self.in_flight.remove(path);
        self.last_scanned.insert(path.to_string(), Instant::now());
    }
}

impl Default for FileWatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl FileWatcher {
    pub fn new() -> Self {
        FileWatcher {
            watcher: Mutex::new(None),
            watched_paths: Mutex::new(Vec::new()),
            enabled: Mutex::new(false),
            event_tx: Mutex::new(None),
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
        *self.event_tx.lock().unwrap() = Some(tx.clone());

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
        let coordinator = Arc::new(Mutex::new(ScanCoordinator::new()));

        tauri::async_runtime::spawn(async move {
            while let Some(path) = rx.recv().await {
                let path_str = path.to_string_lossy().to_string();
                let generation = {
                    let mut state = coordinator.lock().unwrap();
                    state.bump_generation(&path_str)
                };

                let app_for_scan = app_handle.clone();
                let db_for_scan = db_clone.clone();
                let rules = rules_dir.clone();
                let clamav_db = clamav_db_dir.clone();
                let clamav_runtime = clamav_runtime_dir.clone();
                let coordinator_for_scan = coordinator.clone();
                let scan_path = path_str.clone();

                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(SCAN_DEBOUNCE).await;

                    let should_scan = {
                        let state = coordinator_for_scan.lock().unwrap();
                        !state.should_skip_after_debounce(&scan_path, generation)
                    };

                    if !should_scan {
                        return;
                    }

                    coordinator_for_scan
                        .lock()
                        .unwrap()
                        .mark_scan_started(&scan_path);

                    if let Err(e) = app_for_scan.emit(
                        "file-detected",
                        FileDetectedEvent {
                            path: scan_path.clone(),
                            event_type: "auto_scan".into(),
                        },
                    ) {
                        log::warn!("Failed to emit file-detected: {e}");
                    }

                    let scan_result = scanner::run_scan_pipeline(
                        &app_for_scan,
                        &scan_path,
                        &db_for_scan,
                        &rules,
                        &clamav_db,
                        Some(&clamav_runtime),
                        "auto_scan",
                    )
                    .await;

                    match scan_result {
                        Ok(result) => {
                            let filename = &result.filename;
                            let engine_json =
                                serde_json::to_string(&result.engine_results).unwrap_or_default();
                            let report_json = crate::report::stored_report_json(&result);
                            let _ = db_for_scan.insert_scan_record(
                                filename,
                                &result.filepath,
                                &result.sha256,
                                result.risk_score,
                                &result.verdict,
                                result.threat_name.as_deref(),
                                "auto_scan",
                                &engine_json,
                                Some(&report_json),
                            );
                        }
                        Err(e) => {
                            log::error!("Auto-scan failed for {scan_path}: {e}");
                        }
                    }

                    coordinator_for_scan
                        .lock()
                        .unwrap()
                        .mark_scan_finished(&scan_path);
                });
            }
        });

        Ok(())
    }

    pub fn stop(&self) -> Result<(), String> {
        let mut enabled = self.enabled.lock().unwrap();
        *enabled = false;
        // Drop the stored sender and notify watcher so the consumer loop exits cleanly.
        *self.event_tx.lock().unwrap() = None;
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
