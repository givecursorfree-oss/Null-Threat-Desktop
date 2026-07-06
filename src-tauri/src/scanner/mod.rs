pub mod clamav;
pub mod deep;
pub mod entropy;
pub mod hash;
pub mod metadata;
pub mod scoring;
pub mod steg;
pub mod structure;
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineResults {
    pub hash_score: u32,
    pub clam_score: u32,
    pub yara_score: u32,
    pub magic_score: u32,
    pub entropy_score: u32,
    pub video_score: u32,
    pub structure_score: u32,
    pub metadata_score: u32,
    pub steg_score: u32,
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
            structure: structure::StructureAnalysis {
                applicable: false,
                container: "none".into(),
                anomalies: vec![],
            },
            metadata: metadata::MetadataAnalysis {
                scanned: false,
                tool: "native".into(),
                anomalies: vec![],
            },
            steganalysis: steg::StegAnalysis {
                analyzed: false,
                method: "none".into(),
                suspicious: false,
                chi_square_p: None,
                rs_rate: None,
                details: vec![],
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
                structure_score: 0,
                metadata_score: 0,
                steg_score: 0,
            },
            findings: vec![],
            scan_source: scan_source.to_string(),
            scan_id: None,
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
    let scoring = scoring::compute_risk_scores(
        &hash_result,
        &clam_result,
        &yara_result,
        &deep_analysis,
    );
    let risk_score = scoring.risk_score;
    let verdict = scoring.verdict;
    let threat_name = scoring.threat_name;
    let findings = scoring.findings;
    let engine_results = scoring.engine_results;

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
        scan_id: None,
    };

    if let Err(e) = app.emit("scan-complete", &result) {
        log::warn!("Failed to emit scan-complete: {}", e);
    }

    crate::notifications::notify_auto_scan_complete(app, &result);

    Ok(result)
}
