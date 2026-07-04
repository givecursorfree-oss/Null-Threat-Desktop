//! Stage 1 — Structure Parser.
//!
//! Strict, non-rendering structural validation of container formats.
//! - MP4/MOV/3GP: ISO-BMFF box (atom) walker that validates that box sizes add
//!   up, are not oversized/recursive, and that atom type codes are sane.
//! - MKV/WebM: EBML element walker that validates element sizes fit their parent.
//! - SRT/ASS/SSA/VTT: subtitle content is extracted and scanned for scripting /
//!   injection patterns (ASS override tags, HTML/JS, URLs, encoded blobs).
//!
//! Nothing here decodes or renders media; it only parses structure.

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Hard caps to keep parsing cheap and safe against hostile inputs.
const MAX_BOX_DEPTH: u32 = 8;
const MAX_BOXES: u32 = 4096;
const MAX_EBML_ELEMENTS: u32 = 8192;
const MAX_SUBTITLE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ANOMALIES: usize = 24;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructureAnalysis {
    /// Whether a structural parser applied to this file type.
    pub applicable: bool,
    /// Detected container family: "mp4", "mkv", "subtitle", or "none".
    pub container: String,
    pub anomalies: Vec<String>,
}

impl StructureAnalysis {
    fn none() -> Self {
        Self {
            applicable: false,
            container: "none".into(),
            anomalies: vec![],
        }
    }
}

pub fn analyze_structure(path: &Path) -> StructureAnalysis {
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    match ext.as_str() {
        "mp4" | "m4v" | "mov" | "3gp" | "m4a" => {
            let mut anomalies = Vec::new();
            parse_iso_bmff(path, &mut anomalies);
            StructureAnalysis {
                applicable: true,
                container: "mp4".into(),
                anomalies: cap(anomalies),
            }
        }
        "mkv" | "webm" | "mka" => {
            let mut anomalies = Vec::new();
            parse_ebml(path, &mut anomalies);
            StructureAnalysis {
                applicable: true,
                container: "mkv".into(),
                anomalies: cap(anomalies),
            }
        }
        "srt" | "vtt" | "ass" | "ssa" | "sub" | "sbv" => {
            let mut anomalies = Vec::new();
            scan_subtitle(path, &ext, &mut anomalies);
            StructureAnalysis {
                applicable: true,
                container: "subtitle".into(),
                anomalies: cap(anomalies),
            }
        }
        _ => StructureAnalysis::none(),
    }
}

fn cap(mut anomalies: Vec<String>) -> Vec<String> {
    if anomalies.len() > MAX_ANOMALIES {
        let extra = anomalies.len() - MAX_ANOMALIES;
        anomalies.truncate(MAX_ANOMALIES);
        anomalies.push(format!("... and {extra} more structural anomalies"));
    }
    anomalies
}

// ── ISO Base Media File Format (MP4/MOV) ──────────────────────────────────

/// Container boxes whose children are themselves boxes.
const CONTAINER_BOXES: &[&str] = &[
    "moov", "trak", "mdia", "minf", "stbl", "dinf", "edts", "udta", "mvex",
    "moof", "traf", "mfra", "skip", "meta", "ipro", "sinf", "stsd",
];

fn parse_iso_bmff(path: &Path, anomalies: &mut Vec<String>) {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            anomalies.push(format!("Unable to open file for structural parsing: {e}"));
            return;
        }
    };
    let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
    if file_len < 8 {
        anomalies.push("File too small to be a valid MP4 container".into());
        return;
    }

    let mut counter: u32 = 0;
    let mut saw_ftyp = false;
    walk_boxes(
        &mut file,
        0,
        file_len,
        0,
        &mut counter,
        &mut saw_ftyp,
        anomalies,
    );

    if !saw_ftyp {
        anomalies.push("Missing 'ftyp' box — not a well-formed MP4/MOV file".into());
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_boxes(
    file: &mut File,
    start: u64,
    end: u64,
    depth: u32,
    counter: &mut u32,
    saw_ftyp: &mut bool,
    anomalies: &mut Vec<String>,
) {
    if depth > MAX_BOX_DEPTH {
        anomalies.push(format!(
            "Box nesting exceeds safe depth ({MAX_BOX_DEPTH}) — possible crafted recursion"
        ));
        return;
    }

    let mut pos = start;
    while pos + 8 <= end {
        if *counter >= MAX_BOXES {
            anomalies.push("Excessive number of boxes — aborting structural walk".into());
            return;
        }
        *counter += 1;

        let mut header = [0u8; 8];
        if file.seek(SeekFrom::Start(pos)).is_err() || file.read_exact(&mut header).is_err() {
            anomalies.push(format!("Truncated box header at offset {pos}"));
            return;
        }

        let size32 = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as u64;
        let box_type = &header[4..8];

        if !is_sane_atom_type(box_type) {
            anomalies.push(format!(
                "Non-printable/garbage atom type at offset {pos}: {}",
                escape_type(box_type)
            ));
            return;
        }
        let type_str = String::from_utf8_lossy(box_type).to_string();
        let mut header_size = 8u64;

        let box_size = match size32 {
            0 => end - pos, // extends to end of container
            1 => {
                // 64-bit largesize follows the 8-byte header.
                let mut large = [0u8; 8];
                if file.read_exact(&mut large).is_err() {
                    anomalies.push(format!("Truncated 64-bit box size for '{type_str}'"));
                    return;
                }
                header_size = 16;
                u64::from_be_bytes(large)
            }
            s => s,
        };

        if box_size < header_size {
            anomalies.push(format!(
                "Box '{type_str}' declares size {box_size} smaller than its header ({header_size}) — malformed"
            ));
            return;
        }
        if pos + box_size > end {
            anomalies.push(format!(
                "Box '{type_str}' size {box_size} overruns its container by {} bytes — possible hidden appended data",
                (pos + box_size).saturating_sub(end)
            ));
            return;
        }

        if type_str == "ftyp" {
            *saw_ftyp = true;
        }

        // 'mdat' can legitimately be huge; only sanity-check the others.
        if type_str != "mdat" && box_size > end.saturating_sub(start) {
            anomalies.push(format!(
                "Box '{type_str}' larger than its parent container — structural inconsistency"
            ));
        }

        if CONTAINER_BOXES.contains(&type_str.as_str()) {
            let child_start = pos + header_size;
            let child_end = pos + box_size;
            // 'meta' has a 4-byte version/flags prelude before its children.
            let adjusted_start = if type_str == "meta" {
                (child_start + 4).min(child_end)
            } else {
                child_start
            };
            walk_boxes(
                file,
                adjusted_start,
                child_end,
                depth + 1,
                counter,
                saw_ftyp,
                anomalies,
            );
        }

        pos += box_size;
    }

    if depth == 0 && pos != end {
        anomalies.push(format!(
            "Trailing data after last top-level box: {} unexplained bytes",
            end.saturating_sub(pos)
        ));
    }
}

fn is_sane_atom_type(t: &[u8]) -> bool {
    t.iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b' ' || b == b'-' || b == b'_' || b == 0xA9)
}

fn escape_type(t: &[u8]) -> String {
    t.iter()
        .map(|&b| {
            if b.is_ascii_graphic() {
                (b as char).to_string()
            } else {
                format!("\\x{b:02x}")
            }
        })
        .collect()
}

// ── EBML (Matroska / WebM) ────────────────────────────────────────────────

fn parse_ebml(path: &Path, anomalies: &mut Vec<String>) {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            anomalies.push(format!("Unable to open file for EBML parsing: {e}"));
            return;
        }
    };
    let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);

    let mut magic = [0u8; 4];
    if file.read_exact(&mut magic).is_err() {
        anomalies.push("File too small to be a valid Matroska/WebM container".into());
        return;
    }
    if magic != [0x1A, 0x45, 0xDF, 0xA3] {
        anomalies.push("Missing EBML magic (0x1A45DFA3) — not a valid Matroska/WebM header".into());
        return;
    }

    if file.seek(SeekFrom::Start(0)).is_err() {
        return;
    }

    let mut elements: u32 = 0;
    walk_ebml(&mut file, 0, file_len, 0, &mut elements, anomalies);
}

fn walk_ebml(
    file: &mut File,
    start: u64,
    end: u64,
    depth: u32,
    elements: &mut u32,
    anomalies: &mut Vec<String>,
) {
    if depth > MAX_BOX_DEPTH {
        anomalies.push("EBML nesting exceeds safe depth — possible crafted recursion".into());
        return;
    }

    let mut pos = start;
    while pos < end {
        if *elements >= MAX_EBML_ELEMENTS {
            anomalies.push("Excessive number of EBML elements — aborting walk".into());
            return;
        }
        *elements += 1;

        if file.seek(SeekFrom::Start(pos)).is_err() {
            return;
        }

        let (id_len, _id_val, id_ok) = match read_vint(file, true) {
            Some(v) => v,
            None => return,
        };
        if !id_ok || id_len == 0 {
            anomalies.push(format!("Malformed EBML element ID at offset {pos}"));
            return;
        }

        let (size_len, size_val, size_ok) = match read_vint(file, false) {
            Some(v) => v,
            None => {
                anomalies.push(format!("Truncated EBML size field at offset {pos}"));
                return;
            }
        };
        if !size_ok {
            // "Unknown size" is legal for some streaming elements; stop descending.
            return;
        }

        let header = id_len + size_len;
        let elem_end = pos + header + size_val;
        if elem_end > end {
            anomalies.push(format!(
                "EBML element at offset {pos} declares size {size_val} that overruns its parent — malformed or hidden data"
            ));
            return;
        }

        // The two top-level container elements worth descending into are the
        // EBML header (small) and Segment; nested containers get generic depth checks.
        // We recurse conservatively into everything with plausible size.
        if size_val > 0 && size_val <= (end - start) && depth < MAX_BOX_DEPTH {
            let child_start = pos + header;
            // Only descend when the payload plausibly contains sub-elements.
            if looks_like_container(file, child_start, size_val) {
                walk_ebml(file, child_start, elem_end, depth + 1, elements, anomalies);
            }
        }

        pos = elem_end;
    }
}

/// Peek whether an EBML payload begins with a plausible sub-element ID.
fn looks_like_container(file: &mut File, start: u64, size: u64) -> bool {
    if size < 2 {
        return false;
    }
    if file.seek(SeekFrom::Start(start)).is_err() {
        return false;
    }
    let mut b = [0u8; 1];
    if file.read_exact(&mut b).is_err() {
        return false;
    }
    // A leading byte with a set high nibble marks a short EBML ID (container-ish).
    b[0] >= 0x10
}

/// Reads an EBML variable-length integer. When `keep_marker` is true the length
/// descriptor bit is retained (used for element IDs). Returns
/// (byte_length, value, ok). `ok` is false when the value is the "unknown size".
fn read_vint(file: &mut File, keep_marker: bool) -> Option<(u64, u64, bool)> {
    let mut first = [0u8; 1];
    file.read_exact(&mut first).ok()?;
    let b0 = first[0];
    if b0 == 0 {
        return Some((0, 0, false));
    }
    let length = b0.leading_zeros() as u64 + 1;
    if length > 8 {
        return Some((0, 0, false));
    }

    let mut value: u64 = if keep_marker {
        b0 as u64
    } else {
        (b0 as u64) & (0xFF >> length)
    };

    let mut all_ones = ((b0 as u64) & (0xFF >> length)) == (0xFF >> length);
    for _ in 1..length {
        let mut next = [0u8; 1];
        file.read_exact(&mut next).ok()?;
        value = (value << 8) | next[0] as u64;
        if next[0] != 0xFF {
            all_ones = false;
        }
    }

    // A size field with all data bits set signals "unknown size".
    let ok = keep_marker || !all_ones;
    Some((length, value, ok))
}

// ── Subtitle / sidecar text tracks ────────────────────────────────────────

fn scan_subtitle(path: &Path, ext: &str, anomalies: &mut Vec<String>) {
    let file_len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if file_len > MAX_SUBTITLE_BYTES {
        anomalies.push(format!(
            "Subtitle file unusually large ({file_len} bytes) — possible payload padding"
        ));
    }

    let mut buf = Vec::new();
    let read_ok = File::open(path)
        .and_then(|mut f| f.by_ref().take(MAX_SUBTITLE_BYTES).read_to_end(&mut buf))
        .is_ok();
    if !read_ok {
        anomalies.push("Unable to read subtitle content".into());
        return;
    }

    let text = String::from_utf8_lossy(&buf);
    let lower = text.to_lowercase();

    // Script / markup injection (players that render HTML are the risk here).
    let script_markers = [
        ("<script", "embedded <script> tag"),
        ("javascript:", "javascript: URI"),
        ("onload=", "HTML onload handler"),
        ("onerror=", "HTML onerror handler"),
        ("onclick=", "HTML onclick handler"),
        ("<iframe", "embedded <iframe>"),
        ("<object", "embedded <object> tag"),
        ("<embed", "embedded <embed> tag"),
        ("data:text/html", "data: HTML URI"),
        ("vbscript:", "vbscript: URI"),
    ];
    for (needle, label) in script_markers {
        if lower.contains(needle) {
            anomalies.push(format!("Subtitle contains {label}"));
        }
    }

    // Command / download indicators.
    let cmd_markers = [
        "powershell", "cmd.exe", "/bin/sh", "bash -c", "wscript", "cscript",
        "curl ", "wget ", "certutil", "invoke-expression", "iex(", "$(",
    ];
    for needle in cmd_markers {
        if lower.contains(needle) {
            anomalies.push(format!("Subtitle contains command-like token '{needle}'"));
        }
    }

    // URLs (informational — legitimate subtitles rarely embed live links).
    let url_count = lower.matches("http://").count() + lower.matches("https://").count();
    if url_count > 0 {
        anomalies.push(format!("Subtitle embeds {url_count} URL(s)"));
    }

    // ASS/SSA-specific: override blocks and embedded fonts/graphics.
    if ext == "ass" || ext == "ssa" {
        if lower.contains("[fonts]") || lower.contains("[graphics]") {
            anomalies.push(
                "ASS/SSA file embeds a [Fonts]/[Graphics] section — carries binary payload".into(),
            );
        }
        // Drawing mode (\p) with very large coordinate blobs can smuggle data.
        for line in text.lines() {
            if let Some(idx) = line.to_lowercase().find("\\p") {
                let tail = &line[idx..];
                if tail.len() > 512 {
                    anomalies.push(
                        "ASS drawing (\\p) command with abnormally large payload".into(),
                    );
                    break;
                }
            }
        }
    }

    // Base64-looking blobs anywhere in the file.
    if let Some(sample) = find_base64_blob(&text) {
        anomalies.push(format!(
            "Subtitle contains a large base64-looking blob ({} chars) — possible hidden payload",
            sample
        ));
    }

    // Abnormally long lines (encoded payloads masquerading as dialogue).
    if let Some(len) = text.lines().map(|l| l.len()).max() {
        if len > 4096 {
            anomalies.push(format!(
                "Subtitle has an abnormally long line ({len} chars)"
            ));
        }
    }
}

/// Returns the length of the longest contiguous base64-charset run over 120 chars.
fn find_base64_blob(text: &str) -> Option<usize> {
    let mut best = 0usize;
    let mut cur = 0usize;
    for ch in text.chars() {
        let is_b64 = ch.is_ascii_alphanumeric() || ch == '+' || ch == '/' || ch == '=';
        if is_b64 {
            cur += 1;
            best = best.max(cur);
        } else {
            cur = 0;
        }
    }
    if best >= 120 {
        Some(best)
    } else {
        None
    }
}
