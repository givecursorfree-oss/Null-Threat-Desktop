use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VideoAnalysisResult {
    pub is_video: bool,
    pub anomalies: Vec<String>,
}

const VIDEO_EXTENSIONS: &[&str] = &[
    "mp4", "avi", "mkv", "mov", "wmv", "flv", "webm", "m4v", "mpeg", "mpg", "3gp",
];

pub async fn analyze_video(file_path: &Path) -> VideoAnalysisResult {
    let ext = file_path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    if !VIDEO_EXTENSIONS.contains(&ext.as_str()) {
        return VideoAnalysisResult {
            is_video: false,
            anomalies: vec![],
        };
    }

    let ffprobe = match which::which("ffprobe") {
        Ok(p) => p,
        Err(_) => {
            log::warn!("ffprobe not found in PATH, skipping video analysis");
            return VideoAnalysisResult {
                is_video: true,
                anomalies: vec!["ffprobe unavailable – could not analyze".into()],
            };
        }
    };

    let path_str = file_path.to_string_lossy().to_string();
    let probe_path = ffprobe.clone();

    let output = tokio::task::spawn_blocking(move || {
        Command::new(probe_path)
            .args([
                "-v", "quiet",
                "-print_format", "json",
                "-show_format",
                "-show_streams",
                &path_str,
            ])
            .output()
    })
    .await;

    let output = match output {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            return VideoAnalysisResult {
                is_video: true,
                anomalies: vec![format!("ffprobe execution failed: {e}")],
            };
        }
        Err(e) => {
            return VideoAnalysisResult {
                is_video: true,
                anomalies: vec![format!("Task join error: {e}")],
            };
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let mut anomalies = Vec::new();

    check_polyglot_indicators(file_path, &mut anomalies);
    check_ffprobe_output(&stdout, &mut anomalies);

    VideoAnalysisResult {
        is_video: true,
        anomalies,
    }
}

fn check_polyglot_indicators(path: &Path, anomalies: &mut Vec<String>) {
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return,
    };

    use std::io::Read;
    let mut header = vec![0u8; 4096.min(path.metadata().map(|m| m.len() as usize).unwrap_or(4096))];
    if file.read_exact(&mut header).is_err() {
        return;
    }

    // PE header: MZ magic bytes
    if header.len() >= 2 && header[0] == 0x4D && header[1] == 0x5A {
        anomalies.push("PE (MZ) header detected in video container".into());
    }

    // ZIP header: PK magic bytes
    if header.len() >= 4 && header[0] == 0x50 && header[1] == 0x4B && header[2] == 0x03 && header[3] == 0x04 {
        anomalies.push("ZIP (PK) header detected in video container".into());
    }

    let header_str = String::from_utf8_lossy(&header);

    let suspicious_strings = [
        "powershell",
        "cmd.exe",
        "WScript.Shell",
        "CreateObject",
        "<script",
        "eval(",
        "exec(",
        "system(",
    ];

    for pattern in &suspicious_strings {
        if header_str.to_lowercase().contains(&pattern.to_lowercase()) {
            anomalies.push(format!("Suspicious string found in video header: {pattern}"));
        }
    }
}

fn check_ffprobe_output(stdout: &str, anomalies: &mut Vec<String>) {
    let json: serde_json::Value = match serde_json::from_str(stdout) {
        Ok(v) => v,
        Err(_) => {
            if !stdout.trim().is_empty() {
                anomalies.push("ffprobe output is not valid JSON".into());
            }
            return;
        }
    };

    if let Some(format) = json.get("format") {
        if let Some(name) = format.get("format_name").and_then(|v| v.as_str()) {
            let suspicious_formats = ["concat", "data", "image2pipe"];
            for sf in &suspicious_formats {
                if name.contains(sf) {
                    anomalies.push(format!("Suspicious container format: {name}"));
                }
            }
        }

        if let Some(nb_streams) = format.get("nb_streams").and_then(|v| v.as_i64()) {
            if nb_streams == 0 {
                anomalies.push("Video container has zero streams".into());
            }
        }

        if let Some(tags) = format.get("tags").and_then(|v| v.as_object()) {
            for (key, value) in tags {
                let val_str = value.as_str().unwrap_or_default();
                if val_str.contains("http://") || val_str.contains("https://") {
                    anomalies.push(format!("URL found in metadata tag '{key}': {val_str}"));
                }
            }
        }
    }

    if let Some(streams) = json.get("streams").and_then(|v| v.as_array()) {
        let has_video = streams
            .iter()
            .any(|s| s.get("codec_type").and_then(|v| v.as_str()) == Some("video"));
        let has_data = streams
            .iter()
            .any(|s| s.get("codec_type").and_then(|v| v.as_str()) == Some("data"));

        if !has_video {
            anomalies.push("No video stream found in video container".into());
        }
        if has_data {
            anomalies.push("Data stream detected – possible embedded payload".into());
        }
    }
}
