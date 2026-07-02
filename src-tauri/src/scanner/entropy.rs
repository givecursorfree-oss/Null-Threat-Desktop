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
