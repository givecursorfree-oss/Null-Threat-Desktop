use crate::db::models::ScanRecord;
use crate::scanner::ScanResult;
use chrono::Utc;
use printpdf::{BuiltinFont, Mm, PdfDocument, PdfDocumentReference, PdfLayerReference};
use serde::Serialize;
use std::io::BufWriter;

pub const REPORT_VERSION: &str = "1.0";

#[derive(Debug, Serialize)]
pub struct ItScanReport {
    pub report_version: &'static str,
    pub generator: &'static str,
    pub generated_at: String,
    pub scan: ScanReportBody,
}

#[derive(Debug, Serialize)]
pub struct ScanReportBody {
    pub id: i64,
    pub timestamp: String,
    pub scan_source: String,
    pub action_taken: String,
    pub file: ScanReportFile,
    pub verdict: String,
    pub risk_score: u32,
    pub threat_name: Option<String>,
    pub findings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_result: Option<ScanResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_scores: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct ScanReportFile {
    pub filename: String,
    pub filepath: String,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_size: Option<u64>,
}

pub fn stored_report_json(result: &ScanResult) -> String {
    serde_json::to_string(result).unwrap_or_else(|_| "{}".into())
}

pub fn build_report_from_record(record: &ScanRecord) -> ItScanReport {
    let full_result = record
        .report_json
        .as_deref()
        .and_then(|raw| serde_json::from_str::<ScanResult>(raw).ok());

    let engine_scores = if full_result.is_none() {
        serde_json::from_str(&record.engine_results).ok()
    } else {
        None
    };

    let scan_source = full_result
        .as_ref()
        .map(|r| r.scan_source.clone())
        .unwrap_or_else(|| "unknown".into());

    let findings = full_result
        .as_ref()
        .map(|r| r.findings.clone())
        .unwrap_or_default();

    let file_size = full_result.as_ref().map(|r| r.file_size);

    ItScanReport {
        report_version: REPORT_VERSION,
        generator: "Null Threat",
        generated_at: Utc::now().to_rfc3339(),
        scan: ScanReportBody {
            id: record.id,
            timestamp: record.timestamp.clone(),
            scan_source,
            action_taken: record.action_taken.clone(),
            file: ScanReportFile {
                filename: record.filename.clone(),
                filepath: record.filepath.clone(),
                sha256: record.sha256.clone(),
                file_size,
            },
            verdict: record.verdict.clone(),
            risk_score: record.risk_score,
            threat_name: record.threat_name.clone(),
            findings,
            full_result,
            engine_scores,
        },
    }
}

pub fn export_json(record: &ScanRecord) -> Result<String, String> {
    let report = build_report_from_record(record);
    serde_json::to_string_pretty(&report).map_err(|e| format!("JSON export failed: {e}"))
}

fn pdf_safe_text(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '\u{2014}' | '\u{2013}' => '-',
            '\u{2022}' => '*',
            c if c.is_ascii() => c,
            _ => '?',
        })
        .collect()
}

fn write_line(
    layer: &PdfLayerReference,
    font: &printpdf::IndirectFontRef,
    y: &mut f32,
    size: f32,
    text: &str,
) {
    let safe = pdf_safe_text(text);
    layer.use_text(&safe, size, Mm(18.0), Mm(*y), font);
    *y -= 6.5;
}

pub fn export_pdf(record: &ScanRecord) -> Result<Vec<u8>, String> {
    let report = build_report_from_record(record);
    let (doc, page1, layer1) =
        PdfDocument::new("Null Threat Scan Report", Mm(210.0), Mm(297.0), "Layer 1");
    let font = doc
        .add_builtin_font(BuiltinFont::Helvetica)
        .map_err(|e| format!("PDF font error: {e}"))?;
    let font_bold = doc
        .add_builtin_font(BuiltinFont::HelveticaBold)
        .map_err(|e| format!("PDF font error: {e}"))?;
    let layer = doc.get_page(page1).get_layer(layer1);

    let mut y = 280.0_f32;

    write_line(&layer, &font_bold, &mut y, 16.0, "Null Threat - Scan Report");
    write_line(&layer, &font, &mut y, 9.0, &format!("Report version: {}", REPORT_VERSION));
    write_line(&layer, &font, &mut y, 9.0, &format!("Generated: {}", report.generated_at));
    y -= 4.0;

    write_line(&layer, &font_bold, &mut y, 11.0, "Scan summary");
    write_line(
        &layer,
        &font,
        &mut y,
        9.0,
        &format!("Scan ID: {}", report.scan.id),
    );
    write_line(
        &layer,
        &font,
        &mut y,
        9.0,
        &format!("Timestamp: {}", report.scan.timestamp),
    );
    write_line(
        &layer,
        &font,
        &mut y,
        9.0,
        &format!("Source: {}", report.scan.scan_source),
    );
    write_line(
        &layer,
        &font,
        &mut y,
        9.0,
        &format!("Verdict: {}", report.scan.verdict.to_uppercase()),
    );
    write_line(
        &layer,
        &font,
        &mut y,
        9.0,
        &format!("Risk score: {}/100", report.scan.risk_score),
    );
    if let Some(threat) = &report.scan.threat_name {
        write_line(&layer, &font, &mut y, 9.0, &format!("Threat: {threat}"));
    }
    y -= 4.0;

    write_line(&layer, &font_bold, &mut y, 11.0, "File");
    write_line(
        &layer,
        &font,
        &mut y,
        9.0,
        &format!("Name: {}", report.scan.file.filename),
    );
    write_line(
        &layer,
        &font,
        &mut y,
        9.0,
        &truncate_line(&format!("Path: {}", report.scan.file.filepath), 88),
    );
    write_line(
        &layer,
        &font,
        &mut y,
        9.0,
        &truncate_line(&format!("SHA-256: {}", report.scan.file.sha256), 88),
    );
    if let Some(size) = report.scan.file.file_size {
        write_line(&layer, &font, &mut y, 9.0, &format!("Size: {size} bytes"));
    }
    y -= 4.0;

    if !report.scan.findings.is_empty() {
        write_line(&layer, &font_bold, &mut y, 11.0, "Findings");
        for finding in report.scan.findings.iter().take(18) {
            if y < 22.0 {
                break;
            }
            write_line(
                &layer,
                &font,
                &mut y,
                8.5,
                &truncate_line(&format!("* {finding}"), 92),
            );
        }
        y -= 4.0;
    }

    if let Some(result) = &report.scan.full_result {
        write_line(&layer, &font_bold, &mut y, 11.0, "Engine results");
        write_engine_pdf(&layer, &font, &mut y, "Hash lookup", &format!("{:?}", result.hash_result));
        write_engine_pdf(&layer, &font, &mut y, "ClamAV", &format!("{:?}", result.clam_result));
        if !result.yara_result.matched_rules.is_empty() {
            write_engine_pdf(
                &layer,
                &font,
                &mut y,
                "YARA",
                &result.yara_result.matched_rules.join(", "),
            );
        } else {
            write_engine_pdf(&layer, &font, &mut y, "YARA", "No rule matches");
        }
        write_engine_pdf(
            &layer,
            &font,
            &mut y,
            "Deep analysis",
            &format!(
                "entropy={:.2}, structure={}, metadata anomalies={}",
                result.deep_analysis.entropy,
                result.deep_analysis.structure.container,
                result.deep_analysis.metadata.anomalies.len()
            ),
        );
    } else if let Some(scores) = &report.scan.engine_scores {
        write_line(&layer, &font_bold, &mut y, 11.0, "Engine scores (summary)");
        write_line(
            &layer,
            &font,
            &mut y,
            8.5,
            &truncate_line(&scores.to_string(), 92),
        );
    }

    write_line(
        &layer,
        &font,
        &mut y,
        7.5,
        "Null Threat — local scan only. No telemetry. Report generated on this device.",
    );

    save_pdf(doc)
}

fn write_engine_pdf(
    layer: &PdfLayerReference,
    font: &printpdf::IndirectFontRef,
    y: &mut f32,
    name: &str,
    detail: &str,
) {
    if *y < 22.0 {
        return;
    }
    write_line(
        layer,
        font,
        y,
        8.5,
        &truncate_line(&format!("{name}: {detail}"), 92),
    );
}

fn truncate_line(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let truncated: String = text.chars().take(max_chars.saturating_sub(1)).collect();
    format!("{truncated}…")
}

fn save_pdf(doc: PdfDocumentReference) -> Result<Vec<u8>, String> {
    let mut buffer = Vec::new();
    {
        let mut writer = BufWriter::new(&mut buffer);
        doc.save(&mut writer)
            .map_err(|e| format!("PDF save failed: {e}"))?;
    }
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::models::ScanRecord;

    fn sample_record() -> ScanRecord {
        ScanRecord {
            id: 1,
            filename: "test.exe".into(),
            filepath: r"C:\Users\test\file.exe".into(),
            sha256: "abc".repeat(8),
            timestamp: "2026-07-06T12:00:00Z".into(),
            risk_score: 12,
            verdict: "clean".into(),
            threat_name: None,
            action_taken: "manual_scan".into(),
            engine_results: r#"{"hash_score":0,"clam_score":0,"yara_score":0,"magic_score":0,"entropy_score":0,"video_score":0,"structure_score":0,"metadata_score":0,"steg_score":0}"#.into(),
            report_json: None,
        }
    }

    #[test]
    fn export_json_roundtrip() {
        let json = export_json(&sample_record()).expect("json export");
        assert!(json.contains("\"report_version\""));
        assert!(json.contains("test.exe"));
    }

    #[test]
    fn export_pdf_non_empty() {
        let pdf = export_pdf(&sample_record()).expect("pdf export");
        assert!(pdf.starts_with(b"%PDF"));
        assert!(pdf.len() > 200);
    }

    #[test]
    fn pdf_safe_text_strips_non_ascii() {
        assert_eq!(pdf_safe_text("caf\u{e9}"), "caf?");
        assert_eq!(pdf_safe_text("a\u{2014}b"), "a-b");
    }
}
