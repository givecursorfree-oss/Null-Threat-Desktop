pub mod vault;

use crate::db::Database;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Derive a deterministic encryption key from a machine-specific seed.
/// In production, this should use a proper key management system.
fn get_vault_key() -> [u8; 32] {
    let seed = format!(
        "nullthreat-vault-{}",
        whoami()
    );
    let hash = Sha256::digest(seed.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    key
}

fn whoami() -> String {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "nullthreat-default".into())
}

fn quarantine_dir(app_data_dir: &Path) -> PathBuf {
    let dir = app_data_dir.join("quarantine");
    std::fs::create_dir_all(&dir).ok();
    dir
}

pub fn quarantine_file(
    app_data_dir: &Path,
    db: &Arc<Database>,
    file_path: &str,
    threat_name: &str,
    risk_score: u32,
) -> Result<String, String> {
    let source = PathBuf::from(file_path);
    if !source.exists() {
        return Err(format!("File not found: {file_path}"));
    }

    let file_size = source
        .metadata()
        .map(|m| m.len())
        .map_err(|e| format!("Cannot read file metadata: {e}"))?;

    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let filename = source
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".into());

    let quarantine_filename = format!("{timestamp}_{filename}.quarantine");
    let quarantine_path = quarantine_dir(app_data_dir).join(&quarantine_filename);

    let key = get_vault_key();
    vault::encrypt_file(&source, &quarantine_path, &key)?;

    std::fs::remove_file(&source)
        .map_err(|e| format!("Failed to remove original file: {e}"))?;

    let q_path_str = quarantine_path.to_string_lossy().to_string();
    db.insert_quarantine_entry(file_path, &q_path_str, threat_name, risk_score, file_size)
        .map_err(|e| format!("Database error: {e}"))?;

    Ok(q_path_str)
}

pub fn restore_file(
    db: &Arc<Database>,
    entry_id: i64,
) -> Result<String, String> {
    let entry = db
        .get_quarantine_entry(entry_id)
        .map_err(|e| format!("Quarantine entry not found: {e}"))?;

    let quarantine_path = PathBuf::from(&entry.quarantine_path);
    if !quarantine_path.exists() {
        return Err("Quarantine file no longer exists on disk".into());
    }

    let restore_path = PathBuf::from(&entry.original_path);
    let key = get_vault_key();

    vault::decrypt_file(&quarantine_path, &restore_path, &key)?;

    std::fs::remove_file(&quarantine_path).ok();

    db.delete_quarantine_entry(entry_id)
        .map_err(|e| format!("Failed to remove quarantine record: {e}"))?;

    Ok(entry.original_path)
}

pub fn delete_quarantined(
    db: &Arc<Database>,
    entry_id: i64,
) -> Result<(), String> {
    let entry = db
        .get_quarantine_entry(entry_id)
        .map_err(|e| format!("Quarantine entry not found: {e}"))?;

    let quarantine_path = PathBuf::from(&entry.quarantine_path);
    if quarantine_path.exists() {
        std::fs::remove_file(&quarantine_path)
            .map_err(|e| format!("Failed to delete quarantine file: {e}"))?;
    }

    db.delete_quarantine_entry(entry_id)
        .map_err(|e| format!("Failed to remove quarantine record: {e}"))?;

    Ok(())
}

pub fn list_quarantined(db: &Arc<Database>) -> Result<Vec<crate::db::models::QuarantineEntry>, String> {
    db.get_quarantine_list()
        .map_err(|e| format!("Failed to list quarantine entries: {e}"))
}
