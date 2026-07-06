use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

const KEYCHAIN_SERVICE: &str = "dev.nullthreat.desktop";
const KEYCHAIN_ACCOUNT: &str = "quarantine-vault-key-v1";
const FILE_KEY_NAME: &str = ".quarantine_vault_key";

fn decode_key_b64(encoded: &str) -> Result<[u8; 32], String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|e| format!("Invalid vault key encoding: {e}"))?;
    if bytes.len() != 32 {
        return Err("Vault key must be 32 bytes".into());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn encode_key_b64(key: &[u8; 32]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(key)
}

fn read_os_keychain() -> Result<Option<[u8; 32]>, String> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
        .map_err(|e| format!("Keychain entry error: {e}"))?;

    match entry.get_password() {
        Ok(value) => decode_key_b64(&value).map(Some),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("Keychain read failed: {e}")),
    }
}

fn write_os_keychain(key: &[u8; 32]) -> Result<(), String> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
        .map_err(|e| format!("Keychain entry error: {e}"))?;
    entry
        .set_password(&encode_key_b64(key))
        .map_err(|e| format!("Keychain write failed: {e}"))
}

fn file_key_path(app_data_dir: &Path) -> std::path::PathBuf {
    app_data_dir.join(FILE_KEY_NAME)
}

fn read_file_key(app_data_dir: &Path) -> Result<Option<[u8; 32]>, String> {
    let path = file_key_path(app_data_dir);
    if !path.is_file() {
        return Ok(None);
    }
    let encoded = fs::read_to_string(&path).map_err(|e| format!("Failed to read vault key file: {e}"))?;
    decode_key_b64(&encoded).map(Some)
}

fn write_file_key(app_data_dir: &Path, key: &[u8; 32]) -> Result<(), String> {
    fs::create_dir_all(app_data_dir).map_err(|e| format!("Failed to create app data dir: {e}"))?;
    let path = file_key_path(app_data_dir);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .map_err(|e| format!("Failed to open vault key file: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(app_data_dir, fs::Permissions::from_mode(0o700)).ok();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).ok();
    }

    file.write_all(encode_key_b64(key).as_bytes())
        .map_err(|e| format!("Failed to write vault key file: {e}"))?;
    Ok(())
}

fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Primary vault key: OS keychain first, then restricted local file, never username-derived.
pub fn get_vault_key(app_data_dir: &Path) -> Result<[u8; 32], String> {
    if let Ok(Some(key)) = read_os_keychain() {
        return Ok(key);
    }

    if let Ok(Some(key)) = read_file_key(app_data_dir) {
        if write_os_keychain(&key).is_ok() {
            log::info!("Migrated quarantine vault key into OS keychain");
        }
        return Ok(key);
    }

    let key = generate_key();

    if write_os_keychain(&key).is_ok() {
        log::info!("Stored quarantine vault key in OS keychain");
        return Ok(key);
    }

    write_file_key(app_data_dir, &key)?;
    log::warn!("OS keychain unavailable; quarantine key stored in app data (mode 0600)");
    Ok(key)
}

pub fn vault_keys_for_decrypt(app_data_dir: &Path) -> Vec<[u8; 32]> {
    get_vault_key(app_data_dir).into_iter().collect()
}
