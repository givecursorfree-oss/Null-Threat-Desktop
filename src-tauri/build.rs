use std::fs;
use std::path::PathBuf;

fn copy_yara_rules_for_bundle() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = manifest_dir.join("../rules");
    let dest = manifest_dir.join("resources/yara_rules");

    if !source.is_dir() {
        return;
    }

    fs::create_dir_all(&dest).ok();

    let Ok(entries) = fs::read_dir(&source) else {
        return;
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
            let _ = fs::copy(&path, dest.join(name));
        }
    }
}

fn ensure_exiftool_bundle_dirs() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    #[cfg(target_os = "windows")]
    let dir = manifest_dir.join("binaries/windows/exiftool_files");
    #[cfg(target_os = "linux")]
    let dir = manifest_dir.join("binaries/linux/exiftool_lib");
    #[cfg(target_os = "macos")]
    let dir = manifest_dir.join("binaries/macos/exiftool_lib");
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    return;

    if dir.is_dir() {
        return;
    }

    // Tauri resource globs must match at least one file; create a placeholder when
    // scanner setup has not been run yet (local dev). CI runs setup before build.
    fs::create_dir_all(&dir).ok();
    let _ = fs::write(dir.join(".gitkeep"), b"");
}

fn main() {
    copy_yara_rules_for_bundle();
    ensure_exiftool_bundle_dirs();
    tauri_build::build();
}
