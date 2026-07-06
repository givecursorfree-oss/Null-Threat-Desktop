use crate::app_paths;
use crate::bundle_paths;
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

    db.set_setting("realtime_protection", "false")
        .map_err(|e| format!("DB error: {e}"))?;

    db.set_setting("setup_complete", "true")
        .map_err(|e| format!("DB error: {e}"))?;

    log::info!("First-run setup complete: real-time protection disabled until user opts in");
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        if bundle_paths::is_excluded_bundle_file(&name) {
            continue;
        }
        let src_path = entry.path();
        let dst_path = dst.join(&file_name);
        if entry.file_type()?.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

fn scanner_tool_name(base: &str) -> String {
    #[cfg(target_os = "windows")]
    {
        format!("{base}.exe")
    }
    #[cfg(not(target_os = "windows"))]
    {
        base.to_string()
    }
}

fn exiftool_support_dir() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "exiftool_files"
    }
    #[cfg(not(target_os = "windows"))]
    {
        "exiftool_lib"
    }
}

/// Copy bundled scanner tools into app data when missing (yara, ffprobe, ffmpeg, exiftool).
/// Runs on every startup so upgrades pick up newly bundled tools without reinstall.
fn sync_scanner_tools(dest: &Path, resource_dir: Option<&Path>) {
    let Some(source) = clamav_runtime_sources(resource_dir)
        .into_iter()
        .find(|s| s.is_dir())
    else {
        return;
    };

    std::fs::create_dir_all(dest).ok();

    for tool in ["yara", "ffprobe", "ffmpeg", "exiftool"] {
        let name = scanner_tool_name(tool);
        let src = source.join(&name);
        let dst = dest.join(&name);
        if src.is_file() && !dst.is_file() {
            if std::fs::copy(&src, &dst).is_ok() {
                log::info!("Installed bundled {tool} at {}", dst.display());
            }
        }
    }

    let support = exiftool_support_dir();
    let src_support = source.join(support);
    let dst_support = dest.join(support);
    if src_support.is_dir() && !dst_support.is_dir() {
        if copy_dir_recursive(&src_support, &dst_support).is_ok() {
            log::info!("Installed bundled {support} at {}", dst_support.display());
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let src_lib = source.join("lib");
        let dst_lib = dest.join("lib");
        if src_lib.is_dir() && !dst_lib.is_dir() {
            let _ = copy_dir_recursive(&src_lib, &dst_lib);
        }
    }
}

fn clamav_runtime_sources(resource_dir: Option<&Path>) -> Vec<PathBuf> {
    bundle_paths::bundled_binaries_dirs(resource_dir)
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

/// Installs bundled scanner runtimes (ClamAV + YARA/ffprobe/ffmpeg/exiftool) into app data.
pub fn ensure_clamav_runtime(dest: &Path, resource_dir: Option<&Path>, db_dir: &Path) -> bool {
    std::fs::create_dir_all(dest).ok();

    // Always merge newly bundled tools (exiftool, ffmpeg, etc.) even when ClamAV already exists.
    sync_scanner_tools(dest, resource_dir);

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
        app_paths::ensure_freshclam_config(dest, db_dir);
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
            app_paths::ensure_freshclam_config(dest, db_dir);
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

    app_paths::ensure_freshclam_config(dest, db_dir);
    false
}

pub fn copy_bundled_clamav_db(dest: &Path, resource_clamav: Option<PathBuf>) {
    std::fs::create_dir_all(dest).ok();

    if crate::scanner::clamav::has_complete_virus_database(dest) {
        return;
    }

    let sources = bundle_paths::clamav_db_sources(resource_clamav);

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

pub fn copy_bundled_rules(dest: &Path, resource_dir: Option<&Path>) -> u32 {
    std::fs::create_dir_all(dest).ok();

    let sources = yara_rule_sources(resource_dir);
    let mut copied_files = 0u32;

    for source in &sources {
        if !source.is_dir() {
            continue;
        }
        copied_files += copy_yara_rule_files(source, dest);
    }

    let rule_count = crate::scanner::yara::count_yara_rules(dest);
    if rule_count == 0 {
        let checked: Vec<String> = sources.iter().map(|p| p.display().to_string()).collect();
        log::warn!(
            "No YARA rules available at {}. Checked paths: {}",
            dest.display(),
            checked.join("; ")
        );
    } else {
        log::info!(
            "YARA rules ready at {} ({rule_count} rules from {copied_files} files)",
            dest.display()
        );
    }

    rule_count
}

fn yara_rule_sources(resource_dir: Option<&Path>) -> Vec<PathBuf> {
    bundle_paths::yara_rule_sources(resource_dir)
}

fn copy_yara_rule_files(source: &Path, dest: &Path) -> u32 {
    let mut copied = 0u32;

    for entry in walkdir::WalkDir::new(source)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        let is_rule = path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("yar") || ext.eq_ignore_ascii_case("yara"))
            .unwrap_or(false);
        if !is_rule {
            continue;
        }
        let file_name = match path.file_name() {
            Some(name) => name,
            None => continue,
        };
        if std::fs::copy(path, dest.join(file_name)).is_ok() {
            copied += 1;
        }
    }

    copied
}

const MIN_YARA_RULES: u32 = 20;

/// Install bundled YARA rules into app data when missing or incomplete.
pub fn ensure_yara_rules(dest: &Path, resource_dir: Option<&Path>) -> u32 {
    let existing = crate::scanner::yara::count_yara_rules(dest);
    if existing >= MIN_YARA_RULES {
        return existing;
    }
    copy_bundled_rules(dest, resource_dir)
}

/// Force a fresh install of bundled YARA rules.
pub fn sync_yara_rules(dest: &Path, resource_dir: Option<&Path>) -> u32 {
    copy_bundled_rules(dest, resource_dir)
}
