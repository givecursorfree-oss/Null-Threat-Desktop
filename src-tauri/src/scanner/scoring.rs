//! Risk score aggregation with separate caps for signature vs heuristic engines.
//!
//! Signature engines (hash, ClamAV, YARA) may drive scores into the critical range.
//! Heuristic deep-analysis signals are capped when no signature hit is present so
//! benign media or noisy structure checks cannot reach 100/100 alone.

use crate::scanner::clamav::ClamResult;
use crate::scanner::deep::DeepAnalysisResult;
use crate::scanner::hash::HashResult;
use crate::scanner::yara::YaraResult;
use crate::scanner::EngineResults;

/// Maximum combined heuristic contribution without a hash / ClamAV / YARA hit.
pub const HEURISTIC_CAP_NO_SIGNATURE: u32 = 48;

#[derive(Debug, Clone)]
pub struct ScoringOutput {
    pub engine_results: EngineResults,
    pub risk_score: u32,
    pub verdict: String,
    pub threat_name: Option<String>,
    pub findings: Vec<String>,
}

pub fn compute_risk_scores(
    hash_result: &HashResult,
    clam_result: &ClamResult,
    yara_result: &YaraResult,
    deep: &DeepAnalysisResult,
) -> ScoringOutput {
    let mut hash_score: u32 = 0;
    let mut clam_score: u32 = 0;
    let mut magic_score: u32 = 0;
    let mut entropy_score: u32 = 0;
    let mut video_score: u32 = 0;
    let mut structure_score: u32 = 0;
    let mut metadata_score: u32 = 0;
    let mut steg_score: u32 = 0;
    let mut threat_name: Option<String> = None;
    let mut findings: Vec<String> = Vec::new();

    if let HashResult::KnownMalware(name) = hash_result {
        hash_score = 80;
        threat_name = Some(name.clone());
        findings.push(format!(
            "SHA256 lookup: file hash matches known malware signature ({name})"
        ));
    }

    match clam_result {
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

    let yara_score = (yara_result.matched_rules.len() as u32 * 40).min(80);
    if let Some(reason) = &yara_result.skipped {
        findings.push(format!("YARA skipped: {reason}"));
    }
    for rule in &yara_result.matched_rules {
        findings.push(format!("YARA rule matched: {rule}"));
    }
    if threat_name.is_none() && !yara_result.matched_rules.is_empty() {
        threat_name = Some(format!("YARA: {}", yara_result.matched_rules.join(", ")));
    }

    if deep.magic_bytes.mismatch {
        magic_score = 25;
        findings.push(format!(
            "File type mismatch: extension '.{}' but content looks like {} — file may be disguised",
            deep.magic_bytes.expected_extension,
            deep.magic_bytes.detected_type
        ));
    }

    if deep.high_entropy {
        entropy_score = 15;
        findings.push(format!(
            "High entropy ({:.2}): content may be encrypted, compressed, or packed to hide malicious code",
            deep.entropy
        ));
    }

    for anomaly in &deep.video_analysis.anomalies {
        findings.push(format!("Deep analysis: {anomaly}"));
    }
    if !deep.video_analysis.anomalies.is_empty() {
        video_score = 20;
    }

    if !deep.structure.anomalies.is_empty() {
        structure_score = 25;
        for anomaly in &deep.structure.anomalies {
            findings.push(format!("Structure ({}): {anomaly}", deep.structure.container));
        }
    }

    if !deep.metadata.anomalies.is_empty() {
        let severe = deep.metadata.anomalies.iter().any(|a| {
            a.contains("executable") || a.contains("script/command") || a.contains("Shell/command")
        });
        metadata_score = if severe { 35 } else { 20 };
        for anomaly in &deep.metadata.anomalies {
            findings.push(format!("Metadata: {anomaly}"));
        }
    }

    if deep.steganalysis.suspicious {
        steg_score = 30;
        if threat_name.is_none() {
            threat_name = Some("Possible steganography (hidden payload)".into());
        }
    }
    for detail in &deep.steganalysis.details {
        if deep.steganalysis.suspicious || detail.contains("skipped") {
            findings.push(format!("Steganalysis: {detail}"));
        }
    }

    let signature_total = hash_score + clam_score + yara_score;
    let has_signature_hit = signature_total > 0;

    let heuristic_total =
        magic_score + entropy_score + video_score + structure_score + metadata_score + steg_score;
    let capped_heuristic = if has_signature_hit {
        heuristic_total
    } else {
        heuristic_total.min(HEURISTIC_CAP_NO_SIGNATURE)
    };

    let risk_score = (signature_total + capped_heuristic).min(100);
    let verdict = verdict_from_score(risk_score);

    let engine_results = EngineResults {
        hash_score,
        clam_score,
        yara_score,
        magic_score,
        entropy_score,
        video_score,
        structure_score,
        metadata_score,
        steg_score,
    };

    ScoringOutput {
        engine_results,
        risk_score,
        verdict,
        threat_name,
        findings,
    }
}

pub fn verdict_from_score(risk_score: u32) -> String {
    if risk_score >= 81 {
        "malware".into()
    } else if risk_score >= 51 {
        "high_risk".into()
    } else if risk_score >= 21 {
        "suspicious".into()
    } else {
        "clean".into()
    }
}

pub fn cap_heuristic_total(raw_heuristic: u32, has_signature_hit: bool) -> u32 {
    if has_signature_hit {
        raw_heuristic
    } else {
        raw_heuristic.min(HEURISTIC_CAP_NO_SIGNATURE)
    }
}

pub fn aggregate_risk_score(signature_total: u32, heuristic_total: u32, has_signature_hit: bool) -> u32 {
    let capped = cap_heuristic_total(heuristic_total, has_signature_hit);
    (signature_total + capped).min(100)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::deep::MagicByteCheck;
    use crate::scanner::metadata::MetadataAnalysis;
    use crate::scanner::steg::StegAnalysis;
    use crate::scanner::structure::StructureAnalysis;
    use crate::scanner::video::VideoAnalysisResult;

    fn empty_deep() -> DeepAnalysisResult {
        DeepAnalysisResult {
            entropy: 0.0,
            high_entropy: false,
            magic_bytes: MagicByteCheck {
                expected_extension: String::new(),
                detected_type: String::new(),
                mismatch: false,
            },
            video_analysis: VideoAnalysisResult {
                is_video: false,
                anomalies: vec![],
            },
            structure: StructureAnalysis {
                applicable: false,
                container: "none".into(),
                anomalies: vec![],
            },
            metadata: MetadataAnalysis {
                scanned: false,
                tool: "native".into(),
                anomalies: vec![],
            },
            steganalysis: StegAnalysis {
                analyzed: false,
                method: "none".into(),
                suspicious: false,
                chi_square_p: None,
                rs_rate: None,
                details: vec![],
            },
        }
    }

    #[test]
    fn heuristics_alone_cannot_reach_critical_without_signature() {
        let mut deep = empty_deep();
        deep.magic_bytes.mismatch = true;
        deep.high_entropy = true;
        deep.video_analysis.anomalies = vec!["suspicious codec".into()];
        deep.structure.anomalies = vec!["bad box".into()];
        deep.metadata.anomalies = vec!["encoded executable".into()];
        deep.steganalysis.suspicious = true;

        let out = compute_risk_scores(
            &HashResult::Clean,
            &ClamResult::Clean,
            &YaraResult {
                matched_rules: vec![],
                skipped: None,
            },
            &deep,
        );

        assert!(
            out.risk_score <= 48,
            "heuristic-only score should cap at 48, got {}",
            out.risk_score
        );
        assert_eq!(out.verdict, "suspicious");
    }

    #[test]
    fn signature_hit_allows_full_stack_to_critical() {
        let mut deep = empty_deep();
        deep.magic_bytes.mismatch = true;

        let out = compute_risk_scores(
            &HashResult::KnownMalware("Emotet".into()),
            &ClamResult::Clean,
            &YaraResult {
                matched_rules: vec![],
                skipped: None,
            },
            &deep,
        );

        assert!(out.risk_score >= 81);
        assert_eq!(out.verdict, "malware");
    }

    #[test]
    fn clamav_plus_yara_can_reach_high_risk() {
        let out = compute_risk_scores(
            &HashResult::Clean,
            &ClamResult::Detected("Eicar".into()),
            &YaraResult {
                matched_rules: vec!["rule_a".into()],
                skipped: None,
            },
            &empty_deep(),
        );

        assert!(out.risk_score >= 51);
    }

    #[test]
    fn cap_heuristic_helper() {
        assert_eq!(cap_heuristic_total(120, false), 48);
        assert_eq!(cap_heuristic_total(120, true), 120);
    }

    #[test]
    fn aggregate_risk_score_helper() {
        assert_eq!(aggregate_risk_score(0, 90, false), 48);
        assert_eq!(aggregate_risk_score(80, 30, true), 100);
        assert_eq!(aggregate_risk_score(0, 0, false), 0);
    }

    #[test]
    fn verdict_thresholds() {
        assert_eq!(verdict_from_score(0), "clean");
        assert_eq!(verdict_from_score(21), "suspicious");
        assert_eq!(verdict_from_score(51), "high_risk");
        assert_eq!(verdict_from_score(81), "malware");
    }
}
