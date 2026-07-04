use serde::{Deserialize, Serialize};
use std::path::Path;

use super::entropy;
use super::metadata::{self, MetadataAnalysis};
use super::steg::{self, StegAnalysis};
use super::structure::{self, StructureAnalysis};
use super::video::{self, VideoAnalysisResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MagicByteCheck {
    pub expected_extension: String,
    pub detected_type: String,
    pub mismatch: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepAnalysisResult {
    pub entropy: f64,
    pub high_entropy: bool,
    pub magic_bytes: MagicByteCheck,
    pub video_analysis: VideoAnalysisResult,
    pub structure: StructureAnalysis,
    pub metadata: MetadataAnalysis,
    pub steganalysis: StegAnalysis,
}

struct MagicSignature {
    bytes: &'static [u8],
    file_type: &'static str,
    extensions: &'static [&'static str],
}

const SIGNATURES: &[MagicSignature] = &[
    MagicSignature { bytes: &[0x89, 0x50, 0x4E, 0x47], file_type: "PNG", extensions: &["png"] },
    MagicSignature { bytes: &[0xFF, 0xD8, 0xFF], file_type: "JPEG", extensions: &["jpg", "jpeg"] },
    MagicSignature { bytes: &[0x47, 0x49, 0x46, 0x38], file_type: "GIF", extensions: &["gif"] },
    MagicSignature { bytes: &[0x25, 0x50, 0x44, 0x46], file_type: "PDF", extensions: &["pdf"] },
    MagicSignature { bytes: &[0x50, 0x4B, 0x03, 0x04], file_type: "ZIP/Office", extensions: &["zip", "docx", "xlsx", "pptx", "jar", "apk"] },
    MagicSignature { bytes: &[0x4D, 0x5A], file_type: "PE/EXE", extensions: &["exe", "dll", "sys"] },
    MagicSignature { bytes: &[0x7F, 0x45, 0x4C, 0x46], file_type: "ELF", extensions: &["elf", "so", "o"] },
    MagicSignature { bytes: &[0x52, 0x61, 0x72, 0x21], file_type: "RAR", extensions: &["rar"] },
    MagicSignature { bytes: &[0x1F, 0x8B], file_type: "GZIP", extensions: &["gz", "tgz"] },
    MagicSignature { bytes: &[0x42, 0x5A, 0x68], file_type: "BZIP2", extensions: &["bz2"] },
    MagicSignature { bytes: &[0xCA, 0xFE, 0xBA, 0xBE], file_type: "Java Class/Mach-O", extensions: &["class"] },
    MagicSignature { bytes: &[0x00, 0x00, 0x00, 0x1C, 0x66, 0x74, 0x79, 0x70], file_type: "MP4/MOV", extensions: &["mp4", "m4v", "mov"] },
    MagicSignature { bytes: &[0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70], file_type: "MP4/MOV", extensions: &["mp4", "m4v", "mov"] },
    MagicSignature { bytes: &[0x1A, 0x45, 0xDF, 0xA3], file_type: "MKV/WebM", extensions: &["mkv", "webm"] },
    MagicSignature { bytes: &[0x52, 0x49, 0x46, 0x46], file_type: "RIFF (AVI/WAV/WEBP)", extensions: &["avi", "wav", "webp"] },
    MagicSignature { bytes: &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], file_type: "7-Zip", extensions: &["7z"] },
    MagicSignature { bytes: &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00], file_type: "XZ", extensions: &["xz"] },
    MagicSignature { bytes: &[0x49, 0x49, 0x2A, 0x00], file_type: "TIFF", extensions: &["tif", "tiff"] },
    MagicSignature { bytes: &[0x4D, 0x4D, 0x00, 0x2A], file_type: "TIFF", extensions: &["tif", "tiff"] },
    MagicSignature { bytes: &[0x42, 0x4D], file_type: "BMP", extensions: &["bmp"] },
    MagicSignature { bytes: &[0x00, 0x00, 0x01, 0xBA], file_type: "MPEG-PS", extensions: &["mpg", "mpeg", "vob"] },
    MagicSignature { bytes: &[0x00, 0x00, 0x01, 0xB3], file_type: "MPEG-Video", extensions: &["mpg", "mpeg"] },
];

/// Extensions we treat as passive media/images/documents. When one of these
/// carries executable or script content, that is a strong disguise signal.
const PASSIVE_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "bmp", "tif", "tiff", "webp", "svg", "ico",
    "mp4", "m4v", "mov", "mkv", "webm", "avi", "wav", "mp3", "flac", "m4a",
    "pdf", "txt", "srt", "vtt", "ass", "ssa", "doc", "docx", "csv",
];

fn detect_magic_type(header: &[u8]) -> Option<&'static str> {
    for sig in SIGNATURES {
        if header.len() >= sig.bytes.len() && header[..sig.bytes.len()] == *sig.bytes {
            return Some(sig.file_type);
        }
    }

    // ftyp box at variable offsets for MP4
    if header.len() >= 12 {
        for offset in [4usize, 8] {
            if offset + 4 <= header.len() && &header[offset..offset + 4] == b"ftyp" {
                return Some("MP4/MOV");
            }
        }
    }

    None
}

fn check_extension_match(ext: &str, detected_type: &str) -> bool {
    for sig in SIGNATURES {
        if sig.file_type == detected_type {
            return sig.extensions.contains(&ext);
        }
    }
    true
}

/// Classifies header bytes that don't match a known binary signature as
/// executable/script/markup content. Used to catch passive files (images,
/// media, documents) that actually contain code.
fn classify_content(header: &[u8]) -> Option<&'static str> {
    if header.len() >= 2 && &header[..2] == b"MZ" {
        return Some("Windows executable (PE)");
    }
    if header.len() >= 4 && &header[..4] == [0x7F, 0x45, 0x4C, 0x46] {
        return Some("ELF executable");
    }
    if header.len() >= 2 && &header[..2] == b"#!" {
        return Some("shell script (shebang)");
    }

    // Text/markup sniffing over a printable prefix.
    let prefix_len = header.len().min(256);
    let text = String::from_utf8_lossy(&header[..prefix_len]).to_lowercase();
    let markers = [
        ("<?php", "PHP script"),
        ("<script", "HTML/JavaScript"),
        ("<html", "HTML document"),
        ("<!doctype html", "HTML document"),
        ("powershell", "PowerShell script"),
        ("import os", "Python script"),
        ("#!/bin/", "shell script"),
        ("@echo off", "Windows batch script"),
    ];
    for (needle, label) in markers {
        if text.contains(needle) {
            return Some(label);
        }
    }
    None
}

pub fn check_magic_bytes(path: &Path) -> MagicByteCheck {
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    let header = {
        use std::io::Read;
        let mut buf = vec![0u8; 256];
        match std::fs::File::open(path).and_then(|mut f| f.read(&mut buf).map(|n| { buf.truncate(n); buf })) {
            Ok(data) => data,
            Err(_) => {
                return MagicByteCheck {
                    expected_extension: ext,
                    detected_type: "unreadable".into(),
                    mismatch: false,
                };
            }
        }
    };

    let detected = detect_magic_type(&header).unwrap_or("unknown");

    if detected == "unknown" {
        // A passive-looking extension hiding executable/script content is a
        // strong disguise signal, even without a fixed binary signature.
        if PASSIVE_EXTENSIONS.contains(&ext.as_str()) {
            if let Some(content) = classify_content(&header) {
                return MagicByteCheck {
                    expected_extension: ext,
                    detected_type: content.to_string(),
                    mismatch: true,
                };
            }
        }
        return MagicByteCheck {
            expected_extension: ext,
            detected_type: "unknown".into(),
            mismatch: false,
        };
    }

    let mismatch = if ext.is_empty() {
        false
    } else {
        !check_extension_match(&ext, detected)
    };

    MagicByteCheck {
        expected_extension: ext,
        detected_type: detected.to_string(),
        mismatch,
    }
}

pub async fn run_deep_analysis(path: &Path, runtime_dir: Option<&Path>) -> DeepAnalysisResult {
    let path_owned = path.to_path_buf();

    let entropy_val = tokio::task::spawn_blocking({
        let p = path_owned.clone();
        move || entropy::calculate_entropy(&p).unwrap_or(0.0)
    })
    .await
    .unwrap_or(0.0);

    let magic = check_magic_bytes(path);
    let video_result = video::analyze_video(path, runtime_dir).await;

    // Stages 1–3 are CPU/IO-bound and independent of the async video probe.
    let structure_result = tokio::task::spawn_blocking({
        let p = path_owned.clone();
        move || structure::analyze_structure(&p)
    })
    .await
    .unwrap_or_else(|_| structure::analyze_structure(path));

    let metadata_result = tokio::task::spawn_blocking({
        let p = path_owned.clone();
        let rt = runtime_dir.map(|r| r.to_path_buf());
        move || metadata::analyze_metadata(&p, rt.as_deref())
    })
    .await
    .unwrap_or_else(|_| metadata::analyze_metadata(path, runtime_dir));

    let steg_result = tokio::task::spawn_blocking({
        let p = path_owned.clone();
        let rt = runtime_dir.map(|r| r.to_path_buf());
        move || steg::analyze_steg(&p, rt.as_deref())
    })
    .await
    .unwrap_or_else(|_| steg::analyze_steg(path, runtime_dir));

    DeepAnalysisResult {
        entropy: entropy_val,
        high_entropy: entropy::is_high_entropy_for_file(path, entropy_val),
        magic_bytes: magic,
        video_analysis: video_result,
        structure: structure_result,
        metadata: metadata_result,
        steganalysis: steg_result,
    }
}
