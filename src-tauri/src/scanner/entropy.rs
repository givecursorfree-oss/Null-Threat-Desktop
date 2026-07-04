use std::io::Read;
use std::path::Path;

const CHUNK_SIZE: usize = 8192;

/// Calculate Shannon entropy of a file's contents.
/// Returns a value between 0.0 (completely uniform) and 8.0 (maximum entropy for byte data).
pub fn calculate_entropy(path: &Path) -> std::io::Result<f64> {
    let mut freq = [0u64; 256];
    let mut total: u64 = 0;
    let mut file = std::fs::File::open(path)?;
    let mut buf = vec![0u8; CHUNK_SIZE];

    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        for &byte in &buf[..n] {
            freq[byte as usize] += 1;
        }
        total += n as u64;
    }

    if total == 0 {
        return Ok(0.0);
    }

    let total_f = total as f64;
    let entropy = freq
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / total_f;
            -p * p.log2()
        })
        .sum::<f64>();

    Ok(entropy)
}

pub fn is_high_entropy(entropy: f64) -> bool {
    entropy > 7.2
}

/// Compressed audio/video/images are expected to have high Shannon entropy.
/// Flagging them produces false positives on every normal media file.
pub fn is_high_entropy_for_file(path: &Path, entropy: f64) -> bool {
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    const EXPECTED_HIGH_ENTROPY: &[&str] = &[
        // Video
        "mp4", "m4v", "mov", "mkv", "webm", "avi", "wmv", "flv", "mpeg", "mpg", "3gp", "m4a",
        // Audio
        "mp3", "aac", "ogg", "flac", "wav", "wma",
        // Compressed images
        "jpg", "jpeg", "png", "gif", "webp", "heic", "heif", "avif",
        // Archives (also high entropy)
        "zip", "gz", "bz2", "xz", "7z", "rar",
    ];

    if EXPECTED_HIGH_ENTROPY.contains(&ext.as_str()) {
        return false;
    }

    is_high_entropy(entropy)
}
