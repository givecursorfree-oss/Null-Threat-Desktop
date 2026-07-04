use crate::process_util;
use crate::scanner::tools::{self, configure_runtime_env, resolve_tool_binary, runtime_root_for};
use std::path::Path;
use walkdir::WalkDir;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct YaraResult {
    pub matched_rules: Vec<String>,
}

pub fn is_yara_available(runtime_dir: Option<&Path>) -> bool {
    tools::is_yara_available(runtime_dir)
}

/// Scan with bundled or system YARA using all rules in one invocation.
pub async fn scan_with_yara(file_path: &Path, rules_dir: &Path, runtime_dir: Option<&Path>) -> YaraResult {
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

    let yara_bin = match resolve_tool_binary("yara", runtime_dir) {
        Some(p) => p,
        None => {
            log::warn!("YARA binary not found — run scripts/setup-scanner-tools");
            return YaraResult { matched_rules: vec![] };
        }
    };

    let runtime_root = runtime_root_for(&yara_bin);
    let file_str = file_path.to_string_lossy().to_string();

    let result = tokio::task::spawn_blocking(move || {
        let mut cmd = std::process::Command::new(&yara_bin);
        cmd.current_dir(&runtime_root);
        for rule in &rule_files {
            cmd.arg(rule);
        }
        cmd.arg(&file_str);
        configure_runtime_env(&mut cmd, &runtime_root);
        process_util::configure_hidden_subprocess(&mut cmd);
        cmd.output()
    })
    .await;

    let mut matched = Vec::new();

    match result {
        Ok(Ok(output)) => {
            if !output.status.success() && output.status.code() != Some(1) {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.trim().is_empty() {
                    log::warn!("YARA scan stderr: {}", stderr.trim());
                }
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if let Some(rule_name) = line.split_whitespace().next() {
                    if !rule_name.is_empty() {
                        matched.push(rule_name.to_string());
                    }
                }
            }
        }
        Ok(Err(e)) => log::warn!("YARA scan error: {e}"),
        Err(e) => log::warn!("YARA task join error: {e}"),
    }

    matched.sort();
    matched.dedup();
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
