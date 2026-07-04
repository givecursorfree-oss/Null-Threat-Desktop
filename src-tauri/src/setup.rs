use crate::db::Database;
use std::path::{Path, PathBuf};

pub fn default_watch_folders() -> Vec<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        if let Ok(home) = std::env::var("USERPROFILE") {
            let base = PathBuf::from(home);
            return vec![base.join("Downloads"), base.join("Desktop")];
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            let base = PathBuf::from(home);
            return vec![base.join("Downloads"), base.join("Desktop")];
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(home) = std::env::var("HOME") {
            let base = PathBuf::from(home);
            return vec![base.join("Downloads"), base.join("Desktop")];
        }
    }

    vec![]
}

pub fn ensure_first_run_setup(db: &Database) -> Result<(), String> {
    if db
        .get_setting("setup_complete")
        .map_err(|e| format!("DB error: {e}"))?
        .is_some()
    {
        return Ok(());
    }

    db.set_setting("realtime_protection", "true")
        .map_err(|e| format!("DB error: {e}"))?;

    for folder in default_watch_folders() {
        if folder.exists() {
            let _ = db.add_watched_folder(&folder.to_string_lossy());
        }
    }

    db.set_setting("setup_complete", "true")
        .map_err(|e| format!("DB error: {e}"))?;

    log::info!("First-run setup complete: real-time protection enabled");
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

fn clamav_runtime_sources(resource_dir: Option<&Path>) -> Vec<PathBuf> {
    let platform_dir = {
        #[cfg(target_os = "windows")]
        {
            "binaries/windows"
        }
        #[cfg(target_os = "macos")]
        {
            "binaries/macos"
        }
        #[cfg(target_os = "linux")]
        {
            "binaries/linux"
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            "binaries/linux"
        }
    };

    let mut sources = vec![PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(platform_dir)];
    if let Some(res) = resource_dir {
        sources.push(res.join(platform_dir));
    }
    sources
}

fn clamscan_name() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "clamscan.exe"
    }
    #[cfg(not(target_os = "windows"))]
    {
        "clamscan"
    }
}

/// Installs a complete ClamAV runtime into app data.
pub fn ensure_clamav_runtime(dest: &Path, resource_dir: Option<&Path>) -> bool {
    std::fs::create_dir_all(dest).ok();

    let already_valid = {
        let has_bin = dest.join(clamscan_name()).is_file();
        #[cfg(target_os = "windows")]
        {
            has_bin && dest.join("certs").is_dir()
        }
        #[cfg(not(target_os = "windows"))]
        {
            has_bin
        }
    };
    if already_valid {
        return true;
    }

    for source in clamav_runtime_sources(resource_dir) {
        if !source.join(clamscan_name()).is_file() {
            continue;
        }
        #[cfg(target_os = "windows")]
        if !source.join("certs").is_dir() {
            continue;
        }
        if copy_dir_recursive(&source, dest).is_ok() {
            log::info!("Installed ClamAV runtime at {}", dest.display());
            let valid = dest.join(clamscan_name()).is_file();
            #[cfg(target_os = "windows")]
            {
                return valid && dest.join("certs").is_dir();
            }
            #[cfg(not(target_os = "windows"))]
            {
                return valid;
            }
        }
    }

    false
}

pub fn copy_bundled_clamav_db(dest: &Path, resource_clamav: Option<PathBuf>) {
    std::fs::create_dir_all(dest).ok();

    if crate::scanner::clamav::has_complete_virus_database(dest) {
        return;
    }

    let mut sources: Vec<PathBuf> = Vec::new();
    if let Some(r) = resource_clamav {
        sources.push(r);
    }
    sources.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources/clamav"));

    for source in sources {
        if !source.exists() {
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(&source) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext == "cvd" || ext == "cld" || ext == "cvdb" {
                    if let Some(name) = path.file_name() {
                        let _ = std::fs::copy(&path, dest.join(name));
                    }
                }
            }
        }
        log::info!("Copied ClamAV database from {}", source.display());
        break;
    }
}

pub fn copy_bundled_rules(dest: &Path, resource_dir: Option<&Path>) {
    std::fs::create_dir_all(dest).ok();

    let mut sources: Vec<PathBuf> = Vec::new();
    sources.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../rules"));

    if let Some(res) = resource_dir {
        sources.push(res.join("rules"));
        sources.push(res.to_path_buf());
    }

    sources.push(PathBuf::from("rules"));
    sources.push(PathBuf::from("../rules"));

    let mut copied_files = 0u32;
    let source_count = sources.len();
    for source in &sources {
        if !source.is_dir() {
            continue;
        }
        copied_files += copy_yara_rule_files(source, dest);
    }

    let rule_count = crate::scanner::yara::count_yara_rules(dest);
    if rule_count == 0 {
        log::warn!(
            "No YARA rules available at {} (checked {source_count} source paths)",
            dest.display()
        );
    } else {
        log::info!(
            "YARA rules ready at {} ({rule_count} rules from {copied_files} files)",
            dest.display()
        );
    }
}

fn copy_yara_rule_files(source: &Path, dest: &Path) -> u32 {
    let mut copied = 0u32;
    let Ok(entries) = std::fs::read_dir(source) else {
        return 0;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let is_rule = path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("yar") || ext.eq_ignore_ascii_case("yara"))
            .unwrap_or(false);
        if !is_rule {
            continue;
        }
        if let Some(name) = path.file_name() {
            if std::fs::copy(&path, dest.join(name)).is_ok() {
                copied += 1;
            }
        }
    }

    copied
}

/// Re-install bundled YARA rules when the app data folder is empty.
pub fn ensure_yara_rules(dest: &Path, resource_dir: Option<&Path>) -> u32 {
    let existing = crate::scanner::yara::count_yara_rules(dest);
    if existing > 0 {
        return existing;
    }
    copy_bundled_rules(dest, resource_dir);
    crate::scanner::yara::count_yara_rules(dest)
}
