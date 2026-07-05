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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn high_entropy_threshold() {
        assert!(!is_high_entropy(7.0));
        assert!(is_high_entropy(7.3));
    }

    #[test]
    fn video_extensions_skip_entropy_flag() {
        let dir = std::env::temp_dir().join("null-threat-entropy-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("sample.mp4");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(&[0u8; 4096]).unwrap();
        }
        assert!(
            !is_high_entropy_for_file(&path, 7.9),
            "mp4 should not be flagged for high entropy"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn jpeg_extensions_skip_entropy_flag() {
        let dir = std::env::temp_dir().join("null-threat-entropy-jpeg");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("photo.jpeg");
        std::fs::write(&path, [0u8; 1024]).unwrap();
        assert!(!is_high_entropy_for_file(&path, 7.8));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn exe_high_entropy_is_flagged() {
        let dir = std::env::temp_dir().join("null-threat-entropy-exe");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("packed.exe");
        std::fs::write(&path, [0u8; 64]).unwrap();
        assert!(is_high_entropy_for_file(&path, 7.5));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn calculate_entropy_uniform_bytes() {
        let dir = std::env::temp_dir().join("null-threat-entropy-calc");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("uniform.bin");
        std::fs::write(&path, vec![0u8; 256]).unwrap();
        let e = calculate_entropy(&path).unwrap();
        assert!(e < 0.01, "single repeated byte should have ~0 entropy, got {e}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
