//! Per-machine paths for an installed Null Threat instance.
//!
//! All writable state lives under the OS app-data directory for the current user.
//! Bundled scanners and rules are read once from the installer resource directory,
//! then copied into app data on first run.

use std::path::{Path, PathBuf};
use tauri::{App, Manager};

#[derive(Clone, Debug)]
pub struct AppPaths {
    /// Writable root, e.g. `%APPDATA%\dev.nullthreat.desktop` on Windows.
    pub app_data_dir: PathBuf,
    /// Read-only bundle from the installer (Tauri `resource_dir`).
    pub resource_dir: Option<PathBuf>,
    pub rules_dir: PathBuf,
    pub clamav_db_dir: PathBuf,
    pub clamav_runtime_dir: PathBuf,
}

impl AppPaths {
    pub fn resolve(app: &App) -> Result<Self, String> {
        let app_data_dir = app.path().app_data_dir().map_err(|e| {
            format!(
                "Could not resolve application data directory for this user account: {e}"
            )
        })?;

        std::fs::create_dir_all(&app_data_dir).map_err(|e| {
            format!(
                "Could not create application data directory {}: {e}",
                app_data_dir.display()
            )
        })?;

        let resource_dir = app.path().resource_dir().ok();

        Ok(Self {
            rules_dir: app_data_dir.join("yara_rules"),
            clamav_db_dir: app_data_dir.join("clamav_db"),
            clamav_runtime_dir: app_data_dir.join("clamav_runtime"),
            app_data_dir,
            resource_dir,
        })
    }

    pub fn resource_clamav(&self) -> Option<PathBuf> {
        self.resource_dir.as_ref().map(|r| r.join("clamav"))
    }

    pub fn quarantine_dir(&self) -> PathBuf {
        self.app_data_dir.join("quarantine")
    }
}

/// Remove any stale bundled `freshclam.conf` and write one that points at this user's DB dir.
pub fn ensure_freshclam_config(runtime_dir: &Path, db_dir: &Path) {
    let conf_path = runtime_dir.join("freshclam.conf");
    let _ = std::fs::remove_file(&conf_path);
    let content = format!(
        "DatabaseDirectory {}\nDNSDatabaseInfo current.cvd.clamav.net\nDatabaseMirror database.clamav.net\n",
        db_dir.display()
    );
    let _ = std::fs::write(&conf_path, content);
}
