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

fn main() {
    copy_yara_rules_for_bundle();
    tauri_build::build();
}
