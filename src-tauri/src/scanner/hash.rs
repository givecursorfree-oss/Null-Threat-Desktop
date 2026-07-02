use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use crate::db::Database;

const CHUNK_SIZE: usize = 65536;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum HashResult {
    Clean,
    KnownMalware(String),
    Unknown,
}

pub fn compute_sha256(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK_SIZE];

    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

pub fn check_hash(db: &Arc<Database>, sha256: &str) -> HashResult {
    if let Ok(Some(threat)) = db.lookup_malwarebazaar(sha256) {
        return HashResult::KnownMalware(threat);
    }

    if let Ok(true) = db.lookup_nsrl(sha256) {
        return HashResult::Clean;
    }

    HashResult::Unknown
}
