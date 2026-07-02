use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use std::path::Path;

const NONCE_SIZE: usize = 12;

/// Encrypt file bytes with AES-256-GCM.
/// Output format: [12-byte nonce][ciphertext+tag]
pub fn encrypt_file(input_path: &Path, output_path: &Path, key: &[u8; 32]) -> Result<(), String> {
    let plaintext =
        std::fs::read(input_path).map_err(|e| format!("Failed to read file: {e}"))?;

    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| format!("Invalid encryption key: {e}"))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| format!("Encryption failed: {e}"))?;

    let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create quarantine directory: {e}"))?;
    }

    std::fs::write(output_path, &output)
        .map_err(|e| format!("Failed to write quarantine file: {e}"))?;

    Ok(())
}

/// Decrypt a .quarantine file back to original bytes.
pub fn decrypt_file(input_path: &Path, output_path: &Path, key: &[u8; 32]) -> Result<(), String> {
    let data =
        std::fs::read(input_path).map_err(|e| format!("Failed to read quarantine file: {e}"))?;

    if data.len() < NONCE_SIZE + 16 {
        return Err("Quarantine file too small to contain valid encrypted data".into());
    }

    let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| format!("Invalid decryption key: {e}"))?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed – file may be corrupt or key mismatch".to_string())?;

    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create restore directory: {e}"))?;
    }

    std::fs::write(output_path, &plaintext)
        .map_err(|e| format!("Failed to write restored file: {e}"))?;

    Ok(())
}
