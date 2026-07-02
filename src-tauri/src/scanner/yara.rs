use std::path::Path;
use walkdir::WalkDir;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct YaraResult {
    pub matched_rules: Vec<String>,
}

/// Load all .yar/.yara files from the rules directory and scan file bytes.
/// Uses subprocess call to `yara` CLI since yara-rust has complex build deps.
pub async fn scan_with_yara(file_path: &Path, rules_dir: &Path) -> YaraResult {
    if !rules_dir.exists() {
        log::warn!("YARA rules directory does not exist: {}", rules_dir.display());
        return YaraResult { matched_rules: vec![] };
    }

    let rule_files: Vec<String> = WalkDir::new(rules_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy();
            name.ends_with(".yar") || name.ends_with(".yara")
        })
        .map(|e| e.path().to_string_lossy().to_string())
        .collect();

    if rule_files.is_empty() {
        return YaraResult { matched_rules: vec![] };
    }

    let yara_bin = match which::which("yara") {
        Ok(p) => p,
        Err(_) => {
            log::warn!("YARA binary not found in PATH, skipping YARA scan");
            return YaraResult { matched_rules: vec![] };
        }
    };

    let file_str = file_path.to_string_lossy().to_string();
    let mut matched = Vec::new();

    for rule_file in rule_files {
        let yara_path = yara_bin.clone();
        let target = file_str.clone();
        let rule = rule_file.clone();

        let result = tokio::task::spawn_blocking(move || {
            std::process::Command::new(yara_path)
                .arg(&rule)
                .arg(&target)
                .output()
        })
        .await;

        match result {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if let Some(rule_name) = line.split_whitespace().next() {
                        if !rule_name.is_empty() {
                            matched.push(rule_name.to_string());
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                log::warn!("YARA scan error for {}: {}", rule_file, e);
            }
            Err(e) => {
                log::warn!("YARA task join error: {}", e);
            }
        }
    }

    YaraResult { matched_rules: matched }
}

pub fn count_yara_rules(rules_dir: &Path) -> u32 {
    if !rules_dir.exists() {
        return 0;
    }
    WalkDir::new(rules_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy();
            name.ends_with(".yar") || name.ends_with(".yara")
        })
        .count() as u32
}
