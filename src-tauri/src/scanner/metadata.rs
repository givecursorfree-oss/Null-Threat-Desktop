//! Stage 2 — Metadata Scanner.
//!
//! Extracts file metadata and inspects every field value for indicators of
//! abuse: URLs, base64/encoded payloads, OS command syntax, and abnormally
//! long fields.
//!
//! Two backends:
//! - **exiftool** (preferred) when the binary is bundled or on PATH. We run
//!   `exiftool -j -a -u -G1` and iterate the JSON key/value pairs.
//! - **native** fallback that locates common metadata regions (EXIF, XMP, ID3,
//!   PDF Info, OLE) and extracts printable strings for the same heuristics.

use crate::process_util;
use crate::scanner::tools::{configure_exiftool_env, resolve_tool_binary, runtime_root_for};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::Path;
use std::process::Command;

const MAX_ANOMALIES: usize = 24;
const MAX_NATIVE_BYTES: u64 = 4 * 1024 * 1024;
const LONG_FIELD_THRESHOLD: usize = 2048;
const MIN_BASE64_RUN: usize = 40;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataAnalysis {
    pub scanned: bool,
    /// "exiftool" or "native".
    pub tool: String,
    pub anomalies: Vec<String>,
}

pub fn analyze_metadata(path: &Path, runtime_dir: Option<&Path>) -> MetadataAnalysis {
    if let Some(result) = analyze_with_exiftool(path, runtime_dir) {
        return result;
    }
    analyze_native(path)
}

// ── exiftool backend ──────────────────────────────────────────────────────

fn analyze_with_exiftool(path: &Path, runtime_dir: Option<&Path>) -> Option<MetadataAnalysis> {
    let bin = resolve_tool_binary("exiftool", runtime_dir)?;
    let runtime_root = runtime_root_for(&bin);
    let path_str = path.to_string_lossy().to_string();

    let mut cmd = Command::new(&bin);
    cmd.current_dir(&runtime_root).args([
        "-j", // JSON output
        "-a", // allow duplicate tags
        "-u", // unknown tags
        "-G1", // group names
        "-q", // quiet
        &path_str,
    ]);
    configure_exiftool_env(&mut cmd, &runtime_root);
    process_util::configure_hidden_subprocess(&mut cmd);

    let output = cmd.output().ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(stdout.trim()).ok()?;

    let mut anomalies = Vec::new();
    if let Some(entries) = json.as_array() {
        for entry in entries {
            if let Some(obj) = entry.as_object() {
                for (key, value) in obj {
                    if key == "SourceFile" {
                        continue;
                    }
                    if let Some(s) = value.as_str() {
                        inspect_value(key, s, &mut anomalies);
                    }
                }
            }
        }
    }

    Some(MetadataAnalysis {
        scanned: true,
        tool: "exiftool".into(),
        anomalies: cap(anomalies),
    })
}

// ── native backend ────────────────────────────────────────────────────────

fn analyze_native(path: &Path) -> MetadataAnalysis {
    let mut buf = Vec::new();
    let read_ok = std::fs::File::open(path)
        .and_then(|mut f| f.by_ref().take(MAX_NATIVE_BYTES).read_to_end(&mut buf))
        .is_ok();
    if !read_ok {
        return MetadataAnalysis {
            scanned: false,
            tool: "native".into(),
            anomalies: vec![],
        };
    }

    let mut anomalies = Vec::new();

    for (marker, label) in [
        (&b"Exif"[..], "EXIF"),
        (&b"<x:xmpmeta"[..], "XMP"),
        (&b"http://ns.adobe.com/xap"[..], "XMP"),
        (&b"ID3"[..], "ID3"),
        (&b"8BIM"[..], "IPTC/Photoshop"),
        (&b"/Author"[..], "PDF Info"),
        (&b"/Creator"[..], "PDF Info"),
        (&b"/Producer"[..], "PDF Info"),
        (&b"\x05SummaryInformation"[..], "OLE"),
    ] {
        for region in find_regions(&buf, marker, 2048) {
            for value in printable_runs(region, 8) {
                inspect_value(label, &value, &mut anomalies);
            }
        }
    }

    MetadataAnalysis {
        scanned: true,
        tool: "native".into(),
        anomalies: cap(anomalies),
    }
}

/// Returns byte slices of `window` bytes following each occurrence of `marker`.
fn find_regions<'a>(haystack: &'a [u8], marker: &[u8], window: usize) -> Vec<&'a [u8]> {
    let mut regions = Vec::new();
    if marker.is_empty() || haystack.len() < marker.len() {
        return regions;
    }
    let mut i = 0;
    while i + marker.len() <= haystack.len() {
        if &haystack[i..i + marker.len()] == marker {
            let start = i + marker.len();
            let end = (start + window).min(haystack.len());
            regions.push(&haystack[start..end]);
            i = end;
            if regions.len() >= 32 {
                break;
            }
        } else {
            i += 1;
        }
    }
    regions
}

/// Splits a byte region into printable ASCII runs of at least `min_len`.
fn printable_runs(region: &[u8], min_len: usize) -> Vec<String> {
    let mut runs = Vec::new();
    let mut cur = String::new();
    for &b in region {
        if (0x20..=0x7E).contains(&b) {
            cur.push(b as char);
        } else {
            if cur.len() >= min_len {
                runs.push(std::mem::take(&mut cur));
            } else {
                cur.clear();
            }
        }
    }
    if cur.len() >= min_len {
        runs.push(cur);
    }
    runs
}

fn cap(mut anomalies: Vec<String>) -> Vec<String> {
    anomalies.sort();
    anomalies.dedup();
    if anomalies.len() > MAX_ANOMALIES {
        let extra = anomalies.len() - MAX_ANOMALIES;
        anomalies.truncate(MAX_ANOMALIES);
        anomalies.push(format!("... and {extra} more metadata anomalies"));
    }
    anomalies
}

// ── value heuristics ──────────────────────────────────────────────────────

fn inspect_value(field: &str, value: &str, anomalies: &mut Vec<String>) {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return;
    }
    let lower = trimmed.to_lowercase();

    // URLs / C2-style indicators.
    if lower.contains("http://")
        || lower.contains("https://")
        || lower.contains("ftp://")
        || lower.contains(".onion")
    {
        anomalies.push(format!("URL in metadata field '{field}': {}", clip(trimmed)));
    }

    // OS command / download tooling syntax.
    let cmd_tokens = [
        "powershell", "cmd.exe", "/bin/sh", "bash -c", "wscript", "cscript",
        "certutil", "curl ", "wget ", "invoke-expression", "iex(", "$(", "&&",
        "|", ";", "`", "system(", "eval(", "exec(",
    ];
    if let Some(tok) = cmd_tokens.iter().find(|t| lower.contains(**t)) {
        anomalies.push(format!(
            "Shell/command syntax in metadata field '{field}' (token '{tok}')"
        ));
    }

    // Base64-looking payloads — try to decode and classify.
    if let Some(run) = longest_base64_run(trimmed) {
        if run.len() >= MIN_BASE64_RUN {
            if let Some(kind) = classify_base64_payload(&run) {
                anomalies.push(format!(
                    "Encoded payload in metadata field '{field}': base64 decodes to {kind}"
                ));
            } else {
                anomalies.push(format!(
                    "Large base64-looking blob ({} chars) in metadata field '{field}'",
                    run.len()
                ));
            }
        }
    }

    // Abnormally long fields.
    if trimmed.len() > LONG_FIELD_THRESHOLD {
        anomalies.push(format!(
            "Abnormally long metadata field '{field}' ({} chars)",
            trimmed.len()
        ));
    }

    // Embedded NUL/control characters in a text field.
    if value.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t') {
        anomalies.push(format!(
            "Control characters embedded in metadata field '{field}'"
        ));
    }
}

fn clip(s: &str) -> String {
    if s.len() > 120 {
        format!("{}…", &s[..120])
    } else {
        s.to_string()
    }
}

/// Extracts the longest contiguous base64-alphabet substring.
fn longest_base64_run(s: &str) -> Option<String> {
    let mut best: &str = "";
    let bytes = s.as_bytes();
    let mut start = 0usize;
    let mut i = 0usize;
    while i <= bytes.len() {
        let is_b64 = i < bytes.len()
            && (bytes[i].is_ascii_alphanumeric()
                || bytes[i] == b'+'
                || bytes[i] == b'/'
                || bytes[i] == b'=');
        if !is_b64 {
            if i - start > best.len() {
                best = &s[start..i];
            }
            start = i + 1;
        }
        i += 1;
    }
    if best.is_empty() {
        None
    } else {
        Some(best.to_string())
    }
}

/// Decodes a base64 run and reports what it looks like, if recognizable.
fn classify_base64_payload(run: &str) -> Option<&'static str> {
    let decoded = base64_decode(run)?;
    if decoded.len() < 4 {
        return None;
    }
    if decoded.starts_with(&[0x4D, 0x5A]) {
        return Some("a Windows PE/EXE executable");
    }
    if decoded.starts_with(&[0x7F, 0x45, 0x4C, 0x46]) {
        return Some("an ELF executable");
    }
    if decoded.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
        return Some("a ZIP/Office archive");
    }
    let text = String::from_utf8_lossy(&decoded).to_lowercase();
    if text.contains("powershell")
        || text.contains("<script")
        || text.contains("cmd.exe")
        || text.contains("invoke-")
        || text.contains("/bin/sh")
    {
        return Some("a script/command string");
    }
    None
}

/// Minimal, dependency-free standard base64 decoder. Ignores whitespace,
/// returns None on invalid input.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let cleaned: Vec<u8> = input
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'=')
        .collect();
    if cleaned.len() < 4 {
        return None;
    }

    let mut out = Vec::with_capacity(cleaned.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &c in &cleaned {
        let v = val(c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
        // Cap decode work; we only need a prefix to classify.
        if out.len() >= 512 {
            break;
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}
