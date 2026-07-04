pub mod clamav;
pub mod deep;
pub mod entropy;
pub mod hash;
pub mod tools;
pub mod video;
pub mod yara;

use crate::db::Database;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tauri::{AppHandle, Emitter};

use clamav::ClamResult;
use deep::DeepAnalysisResult;
use hash::HashResult;
use yara::YaraResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub filepath: String,
    pub filename: String,
    pub file_size: u64,
    pub sha256: String,
    pub risk_score: u32,
    pub verdict: String,
    pub threat_name: Option<String>,
    pub hash_result: HashResult,
    pub clam_result: ClamResult,
    pub yara_result: YaraResult,
    pub deep_analysis: DeepAnalysisResult,
    pub engine_results: EngineResults,
    pub findings: Vec<String>,
    pub scan_source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineResults {
    pub hash_score: u32,
    pub clam_score: u32,
    pub yara_score: u32,
    pub magic_score: u32,
    pub entropy_score: u32,
    pub video_score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScanProgress {
    stage: String,
    progress: u32,
    detail: String,
}

fn emit_progress(app: &AppHandle, stage: &str, progress: u32, detail: &str) {
    let payload = ScanProgress {
        stage: stage.to_string(),
        progress,
        detail: detail.to_string(),
    };
    if let Err(e) = app.emit("scan-progress", &payload) {
        log::warn!("Failed to emit scan progress: {}", e);
    }
}

pub async fn run_scan_pipeline(
    app: &AppHandle,
    file_path: &str,
    db: &Arc<Database>,
    rules_dir: &Path,
    clamav_db_dir: &Path,
    clamav_runtime_dir: Option<&Path>,
    scan_source: &str,
) -> Result<ScanResult, String> {
    let path = PathBuf::from(file_path);
    if !path.exists() {
        return Err(format!("File not found: {file_path}"));
    }

    let filename = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| file_path.to_string());

    let file_size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);

    // ── Stage 1: Hash check ──────────────────────────────────────
    emit_progress(app, "hash", 10, "Computing SHA-256 hash...");

    let sha256 = {
        let p = path.clone();
        tokio::task::spawn_blocking(move || hash::compute_sha256(&p))
            .await
            .map_err(|e| format!("Hash computation failed: {e}"))?
            .map_err(|e| format!("Hash I/O error: {e}"))?
    };

    if db.is_whitelisted(&sha256).unwrap_or(false) {
        emit_progress(app, "complete", 100, "File is whitelisted");
        let empty_deep = DeepAnalysisResult {
            entropy: 0.0,
            high_entropy: false,
            magic_bytes: deep::MagicByteCheck {
                expected_extension: String::new(),
                detected_type: String::new(),
                mismatch: false,
            },
            video_analysis: video::VideoAnalysisResult {
                is_video: false,
                anomalies: vec![],
            },
        };
        return Ok(ScanResult {
            filepath: file_path.to_string(),
            filename,
            file_size,
            sha256,
            risk_score: 0,
            verdict: "whitelisted".into(),
            threat_name: None,
            hash_result: HashResult::Clean,
            clam_result: ClamResult::Clean,
            yara_result: YaraResult {
                matched_rules: vec![],
                skipped: None,
            },
            deep_analysis: empty_deep,
            engine_results: EngineResults {
                hash_score: 0,
                clam_score: 0,
                yara_score: 0,
                magic_score: 0,
                entropy_score: 0,
                video_score: 0,
            },
            findings: vec![],
            scan_source: scan_source.to_string(),
        });
    }

    let hash_result = hash::check_hash(db, &sha256);
    emit_progress(app, "hash", 25, "Hash check complete");

    // ── Stage 2: ClamAV scan ─────────────────────────────────────
    emit_progress(app, "clamav", 30, "Running ClamAV scan...");
    let clam_result = clamav::scan_with_clamav(&path, clamav_db_dir, clamav_runtime_dir).await;
    emit_progress(app, "clamav", 50, "ClamAV scan complete");

    // ── Stage 3: YARA scan ───────────────────────────────────────
    emit_progress(app, "yara", 55, "Running YARA rule scan...");
    let yara_result = yara::scan_with_yara(&path, rules_dir, clamav_runtime_dir).await;
    emit_progress(app, "yara", 70, "YARA scan complete");

    // ── Stage 4: Deep analysis ───────────────────────────────────
    emit_progress(app, "deep", 75, "Running deep analysis...");
    let deep_analysis = deep::run_deep_analysis(&path, clamav_runtime_dir).await;
    emit_progress(app, "deep", 90, "Deep analysis complete");

    // ── Score calculation ────────────────────────────────────────
    let mut hash_score: u32 = 0;
    let mut clam_score: u32 = 0;
    let yara_score: u32;
    let mut magic_score: u32 = 0;
    let mut entropy_score: u32 = 0;
    let mut video_score: u32 = 0;
    let mut threat_name: Option<String> = None;
    let mut findings: Vec<String> = Vec::new();

    match &hash_result {
        HashResult::KnownMalware(name) => {
            hash_score = 80;
            threat_name = Some(name.clone());
            findings.push(format!(
                "SHA256 lookup: file hash matches known malware signature ({name})"
            ));
        }
        _ => {}
    }

    match &clam_result {
        ClamResult::Detected(name) => {
            clam_score = 70;
            if threat_name.is_none() {
                threat_name = Some(name.clone());
            }
            findings.push(format!(
                "ClamAV: known virus/malware signature detected ({name})"
            ));
        }
        ClamResult::Unavailable(reason) => {
            findings.push(format!("ClamAV skipped: {reason}"));
        }
        _ => {}
    }

    let yara_contribution = (yara_result.matched_rules.len() as u32 * 40).min(80);
    yara_score = yara_contribution;
    if let Some(reason) = &yara_result.skipped {
        findings.push(format!("YARA skipped: {reason}"));
    }
    for rule in &yara_result.matched_rules {
        findings.push(format!("YARA rule matched: {rule}"));
    }
    if threat_name.is_none() && !yara_result.matched_rules.is_empty() {
        threat_name = Some(format!("YARA: {}", yara_result.matched_rules.join(", ")));
    }

    if deep_analysis.magic_bytes.mismatch {
        magic_score = 30;
        findings.push(format!(
            "File type mismatch: extension '.{}' but content looks like {} — file may be disguised",
            deep_analysis.magic_bytes.expected_extension,
            deep_analysis.magic_bytes.detected_type
        ));
    }

    if deep_analysis.high_entropy {
        entropy_score = 20;
        findings.push(format!(
            "High entropy ({:.2}): content may be encrypted, compressed, or packed to hide malicious code",
            deep_analysis.entropy
        ));
    }

    for anomaly in &deep_analysis.video_analysis.anomalies {
        findings.push(format!("Deep analysis: {anomaly}"));
    }
    if !deep_analysis.video_analysis.anomalies.is_empty() {
        video_score = 35;
    }

    let total_raw = hash_score + clam_score + yara_score + magic_score + entropy_score + video_score;
    let risk_score = total_raw.min(100);

    let verdict = if risk_score >= 81 {
        "malware"
    } else if risk_score >= 51 {
        "high_risk"
    } else if risk_score >= 21 {
        "suspicious"
    } else {
        "clean"
    };

    let engine_results = EngineResults {
        hash_score,
        clam_score,
        yara_score,
        magic_score,
        entropy_score,
        video_score,
    };

    emit_progress(app, "complete", 100, &format!("Scan complete – {verdict}"));

    let result = ScanResult {
        filepath: file_path.to_string(),
        filename,
        file_size,
        sha256,
        risk_score,
        verdict: verdict.to_string(),
        threat_name,
        hash_result,
        clam_result,
        yara_result,
        deep_analysis,
        engine_results,
        findings,
        scan_source: scan_source.to_string(),
    };

    if let Err(e) = app.emit("scan-complete", &result) {
        log::warn!("Failed to emit scan-complete: {}", e);
    }

    crate::notifications::notify_auto_scan_complete(app, &result);

    Ok(result)
}
