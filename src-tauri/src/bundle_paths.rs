use std::path::{Path, PathBuf};

pub fn platform_binaries_dir() -> &'static str {
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
}

/// Dev-only: compile-time manifest root. Not linked into release binaries.
#[cfg(debug_assertions)]
pub fn dev_manifest_root() -> Option<PathBuf> {
    Some(PathBuf::from(env!("CARGO_MANIFEST_DIR")))
}

#[cfg(not(debug_assertions))]
pub fn dev_manifest_root() -> Option<PathBuf> {
    None
}

/// Install layout: resources next to the running executable.
fn exe_resource_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            roots.push(exe_dir.to_path_buf());
            roots.push(exe_dir.join("resources"));
        }
    }
    roots
}

/// Roots that may contain bundled files on an end-user machine (installer resources only).
fn install_resource_roots(resource_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut roots = Vec::new();

    if let Some(res) = resource_dir {
        roots.push(res.to_path_buf());
    }

    for root in exe_resource_roots() {
        if !roots.iter().any(|r| r == &root) {
            roots.push(root);
        }
    }

    roots
}

fn push_unique(dir: &mut Vec<PathBuf>, candidate: PathBuf) {
    if !dir.iter().any(|d| d == &candidate) {
        dir.push(candidate);
    }
}

/// Bundled scanner binary directories (installer resources; dev tree in debug builds only).
pub fn bundled_binaries_dirs(resource_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    for root in install_resource_roots(resource_dir) {
        push_unique(&mut dirs, root.join(platform_binaries_dir()));
    }

    #[cfg(debug_assertions)]
    if let Some(manifest) = dev_manifest_root() {
        push_unique(&mut dirs, manifest.join(platform_binaries_dir()));
    }

    dirs
}

/// Sources for copying ClamAV virus DB into the current user's app data.
pub fn clamav_db_sources(resource_clamav: Option<PathBuf>) -> Vec<PathBuf> {
    let mut sources = Vec::new();

    if let Some(r) = resource_clamav.clone() {
        push_unique(&mut sources, r);
    }

    let resource_dir = resource_clamav.as_ref().and_then(|p| p.parent());
    for root in install_resource_roots(resource_dir) {
        let candidate = root.join("clamav");
        if candidate.is_dir() {
            push_unique(&mut sources, candidate);
        }
    }

    #[cfg(debug_assertions)]
    if let Some(manifest) = dev_manifest_root() {
        push_unique(&mut sources, manifest.join("resources/clamav"));
    }

    sources
}

/// Sources for YARA rules bundled with the installer.
pub fn yara_rule_sources(resource_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut sources = Vec::new();

    for root in install_resource_roots(resource_dir) {
        for sub in ["yara_rules", "rules", "_up_/rules"] {
            let candidate = root.join(sub);
            if candidate.is_dir() {
                push_unique(&mut sources, candidate);
            }
        }
    }

    #[cfg(debug_assertions)]
    if let Some(manifest) = dev_manifest_root() {
        for sub in ["../rules", "resources/yara_rules"] {
            let candidate = manifest.join(sub);
            if candidate.is_dir() {
                push_unique(&mut sources, candidate);
            }
        }
    }

    sources
}

/// Files that must never ship in installers or app data copies.
pub fn is_excluded_bundle_file(file_name: &str) -> bool {
    matches!(
        file_name.to_ascii_lowercase().as_str(),
        "freshclam.conf" | ".ds_store" | "thumbs.db"
    )
}
