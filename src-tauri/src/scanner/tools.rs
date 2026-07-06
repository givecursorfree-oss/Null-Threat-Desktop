use crate::bundle_paths;
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn platform_binaries_dir() -> &'static str {
    bundle_paths::platform_binaries_dir()
}

fn tool_filename(base: &str) -> String {
    #[cfg(target_os = "windows")]
    {
        format!("{base}.exe")
    }
    #[cfg(not(target_os = "windows"))]
    {
        base.to_string()
    }
}

fn bundled_runtime_candidates(runtime_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(rt) = runtime_dir {
        dirs.push(rt.to_path_buf());
    }
    #[cfg(debug_assertions)]
    if let Some(manifest) = bundle_paths::dev_manifest_root() {
        dirs.push(manifest.join(bundle_paths::platform_binaries_dir()));
    }
    dirs
}

pub fn resolve_tool_binary(tool: &str, runtime_dir: Option<&Path>) -> Option<PathBuf> {
    let filename = tool_filename(tool);
    for dir in bundled_runtime_candidates(runtime_dir) {
        let bundled = dir.join(&filename);
        if bundled.is_file() {
            return Some(bundled);
        }
    }
    which::which(&filename).ok()
}

pub fn is_yara_available(runtime_dir: Option<&Path>) -> bool {
    resolve_tool_binary("yara", runtime_dir).is_some()
}

pub fn is_ffprobe_available(runtime_dir: Option<&Path>) -> bool {
    resolve_tool_binary("ffprobe", runtime_dir).is_some()
}

pub fn is_ffmpeg_available(runtime_dir: Option<&Path>) -> bool {
    resolve_tool_binary("ffmpeg", runtime_dir).is_some()
}

/// Ensures bundled shared libraries are visible to subprocesses on Unix.
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

pub fn configure_exiftool_env(cmd: &mut Command, runtime_root: &Path) {
    configure_runtime_env(cmd, runtime_root);

    #[cfg(target_os = "windows")]
    {
        // Windows portable ExifTool expects exiftool_files/ next to exiftool.exe.
        // cwd is set to runtime_root in metadata.rs so relative lookup works.
        let _ = runtime_root.join("exiftool_files");
    }

    #[cfg(not(target_os = "windows"))]
    {
        let perl_lib = runtime_root.join("exiftool_lib");
        if perl_lib.is_dir() {
            cmd.env("PERL5LIB", perl_lib);
        }
    }
}

pub fn is_exiftool_available(runtime_dir: Option<&Path>) -> bool {
    let Some(bin) = resolve_tool_binary("exiftool", runtime_dir) else {
        return false;
    };
    let root = runtime_root_for(&bin);
    #[cfg(target_os = "windows")]
    {
        return root.join("exiftool_files").is_dir();
    }
    #[cfg(not(target_os = "windows"))]
    {
        return root.join("exiftool_lib").is_dir() || bin.is_file();
    }
}

pub fn runtime_root_for(binary: &Path) -> PathBuf {
    binary
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}
