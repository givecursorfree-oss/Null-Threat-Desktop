use serde::{Deserialize, Serialize};
use std::path::Path;

use super::entropy;
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
    MagicSignature { bytes: &[0x52, 0x49, 0x46, 0x46], file_type: "RIFF (AVI/WAV)", extensions: &["avi", "wav"] },
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

pub fn check_magic_bytes(path: &Path) -> MagicByteCheck {
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    let header = {
        use std::io::Read;
        let mut buf = vec![0u8; 32];
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
    let mismatch = if detected == "unknown" || ext.is_empty() {
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

pub async fn run_deep_analysis(path: &Path) -> DeepAnalysisResult {
    let path_owned = path.to_path_buf();

    let entropy_val = tokio::task::spawn_blocking({
        let p = path_owned.clone();
        move || entropy::calculate_entropy(&p).unwrap_or(0.0)
    })
    .await
    .unwrap_or(0.0);

    let magic = check_magic_bytes(path);
    let video_result = video::analyze_video(path).await;

    DeepAnalysisResult {
        entropy: entropy_val,
        high_entropy: entropy::is_high_entropy(entropy_val),
        magic_bytes: magic,
        video_analysis: video_result,
    }
}
