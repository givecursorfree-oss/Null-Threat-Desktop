use crate::process_util;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ClamResult {
    Clean,
    Detected(String),
    Unavailable(String),
}

const DB_EXTENSIONS: &[&str] = &["cvd", "cld", "cvdb"];

#[cfg(debug_assertions)]
const CLAMAV_MISSING_MSG: &str =
    "Bundled ClamAV not found — run the platform setup script and rebuild";

#[cfg(not(debug_assertions))]
const CLAMAV_MISSING_MSG: &str =
    "Bundled ClamAV not found — restart the app or reinstall from the official installer";

#[cfg(debug_assertions)]
const CLAMAV_CERTS_MISSING_MSG: &str =
    "Bundled ClamAV certificates missing — run setup-clamav and rebuild";

#[cfg(not(debug_assertions))]
const CLAMAV_CERTS_MISSING_MSG: &str =
    "Bundled ClamAV certificates missing — reinstall from the official installer";

fn clamscan_binary_name() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "clamscan.exe"
    }
    #[cfg(not(target_os = "windows"))]
    {
        "clamscan"
    }
}

fn freshclam_binary_name() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "freshclam.exe"
    }
    #[cfg(not(target_os = "windows"))]
    {
        "freshclam"
    }
}

pub fn has_virus_database(db_dir: &Path) -> bool {
    if !db_dir.is_dir() {
        return false;
    }

    std::fs::read_dir(db_dir)
        .map(|entries| {
            entries.filter_map(|e| e.ok()).any(|entry| {
                entry
                    .path()
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| DB_EXTENSIONS.contains(&ext))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

pub fn has_complete_virus_database(db_dir: &Path) -> bool {
    db_dir.join("main.cvd").is_file()
        && (db_dir.join("daily.cvd").is_file()
            || db_dir.join("daily.cld").is_file()
            || db_dir.join("bytecode.cvd").is_file())
}

fn runtime_is_valid(dir: &Path) -> bool {
    let scan_bin = dir.join(clamscan_binary_name());
    if !scan_bin.is_file() {
        return false;
    }

    #[cfg(target_os = "windows")]
    {
        dir.join("certs").is_dir()
    }
    #[cfg(not(target_os = "windows"))]
    {
        true
    }
}

fn bundled_runtime_candidates(runtime_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    if let Some(rt) = runtime_dir {
        dirs.push(rt.to_path_buf());
    }

    #[cfg(debug_assertions)]
    if let Some(manifest) = crate::bundle_paths::dev_manifest_root() {
        dirs.push(manifest.join(crate::bundle_paths::platform_binaries_dir()));
    }

    dirs
}

pub fn resolve_clamscan_binary(runtime_dir: Option<&Path>) -> Option<PathBuf> {
    for dir in bundled_runtime_candidates(runtime_dir) {
        if runtime_is_valid(&dir) {
            return Some(dir.join(clamscan_binary_name()));
        }
    }

    which::which(clamscan_binary_name()).ok()
}

pub fn resolve_freshclam_binary(runtime_dir: &Path) -> Option<PathBuf> {
    let bundled = runtime_dir.join(freshclam_binary_name());
    if bundled.is_file() {
        return Some(bundled);
    }
    which::which(freshclam_binary_name()).ok()
}

pub fn is_clamav_available(db_dir: &Path, runtime_dir: Option<&Path>) -> bool {
    resolve_clamscan_binary(runtime_dir).is_some() && has_complete_virus_database(db_dir)
}

/// Ensures bundled ClamAV shared libraries are visible to clamscan/freshclam on Unix.
pub fn configure_runtime_env(cmd: &mut Command, runtime_root: &Path) {
    #[cfg(target_os = "linux")]
    {
        let lib_dir = runtime_root.join("lib");
        if lib_dir.is_dir() {
            let lib_path = lib_dir.to_string_lossy().to_string();
            let merged = match std::env::var("LD_LIBRARY_PATH") {
                Ok(existing) if !existing.is_empty() => format!("{lib_path}:{existing}"),
                _ => lib_path,
            };
            cmd.env("LD_LIBRARY_PATH", merged);
        }
    }

    #[cfg(target_os = "macos")]
    {
        let lib_dir = runtime_root.join("lib");
        if lib_dir.is_dir() {
            let lib_path = lib_dir.to_string_lossy().to_string();
            let merged = match std::env::var("DYLD_LIBRARY_PATH") {
                Ok(existing) if !existing.is_empty() => format!("{lib_path}:{existing}"),
                _ => lib_path,
            };
            cmd.env("DYLD_LIBRARY_PATH", merged);
        }
    }

    // On platforms without bundled shared libs (e.g. Windows) the params are unused.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = (cmd, runtime_root);
}

fn normalize_scan_path(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn clamscan_exit_message(code: i32) -> String {
    match code {
        50 => "ClamAV database error — update signatures in Settings".to_string(),
        52 => "ClamAV does not support this file type".to_string(),
        53 => "ClamAV could not open the path — select a file (not a folder) you can read"
            .to_string(),
        54 => "ClamAV could not open the file — it may be locked or blocked".to_string(),
        55 => "ClamAV could not read the file".to_string(),
        56 => "ClamAV could not access the file — check permissions".to_string(),
        57 => "ClamAV working directory error — restart the app".to_string(),
        _ => format!("clamscan exited with status {code}"),
    }
}

pub async fn scan_with_clamav(
    file_path: &Path,
    db_dir: &Path,
    runtime_dir: Option<&Path>,
) -> ClamResult {
    if file_path.is_dir() {
        return ClamResult::Unavailable(
            "ClamAV scans files only — choose a file, not a folder".into(),
        );
    }

    if !file_path.is_file() {
        return ClamResult::Unavailable(format!(
            "File not found or not readable: {}",
            file_path.display()
        ));
    }

    let binary = match resolve_clamscan_binary(runtime_dir) {
        Some(p) => p,
        None => {
            return ClamResult::Unavailable(CLAMAV_MISSING_MSG.into());
        }
    };

    if !has_complete_virus_database(db_dir) {
        return ClamResult::Unavailable(
            "ClamAV virus database incomplete — update signatures in Settings".into(),
        );
    }

    let runtime_root = binary
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));

    #[cfg(target_os = "windows")]
    if !runtime_root.join("certs").is_dir() {
        return ClamResult::Unavailable(CLAMAV_CERTS_MISSING_MSG.into());
    }

    let scan_path = normalize_scan_path(file_path);
    let path_str = scan_path.to_string_lossy().to_string();
    let db_str = db_dir.to_string_lossy().to_string();

    let output = tokio::task::spawn_blocking(move || {
        let mut cmd = Command::new(&binary);
        cmd.current_dir(&runtime_root)
            .arg("--no-summary")
            .arg(format!("--database={db_str}"))
            .arg(&path_str);

        configure_runtime_env(&mut cmd, &runtime_root);
        process_util::configure_hidden_subprocess(&mut cmd);

        cmd.output()
    })
    .await;

    let output = match output {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return ClamResult::Unavailable(format!("Failed to run clamscan: {e}")),
        Err(e) => return ClamResult::Unavailable(format!("Task join error: {e}")),
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if stdout.contains("FOUND") {
        let virus_name = stdout
            .lines()
            .find(|l| l.contains("FOUND"))
            .and_then(|line| {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 2 {
                    Some(parts[1].trim().replace(" FOUND", "").trim().to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "Unknown Virus".to_string());
        ClamResult::Detected(virus_name)
    } else if stdout.contains("OK") {
        ClamResult::Clean
    } else if !stderr.is_empty() {
        ClamResult::Unavailable(format!("clamscan: {}", stderr.trim()))
    } else if !output.status.success() {
        let code = output.status.code().unwrap_or(-1);
        ClamResult::Unavailable(clamscan_exit_message(code))
    } else {
        ClamResult::Clean
    }
}
