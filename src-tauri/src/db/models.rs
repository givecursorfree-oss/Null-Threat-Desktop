use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    pub id: i64,
    pub filename: String,
    pub filepath: String,
    pub sha256: String,
    pub timestamp: String,
    pub risk_score: u32,
    pub verdict: String,
    pub threat_name: Option<String>,
    pub action_taken: String,
    pub engine_results: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: i64,
    pub original_path: String,
    pub quarantine_path: String,
    pub threat_name: String,
    pub risk_score: u32,
    pub scan_date: String,
    pub file_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchedFolder {
    pub id: i64,
    pub path: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistEntry {
    pub id: i64,
    pub path: String,
    pub sha256: String,
    pub added_date: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardStats {
    pub total_scans: u64,
    pub threats_found: u64,
    pub files_quarantined: u64,
    pub scans_today: u64,
    pub threats_today: u64,
    pub avg_risk_score: f64,
    pub last_scan_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictBreakdown {
    pub clean: u64,
    pub suspicious: u64,
    pub detected: u64,
    pub critical: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyStatus {
    pub clamav_available: bool,
    pub yara_available: bool,
    pub ffprobe_available: bool,
    pub ffmpeg_available: bool,
    pub exiftool_available: bool,
    pub yara_rules_found: u32,
    pub db_connected: bool,
    pub malwarebazaar_hash_count: u64,
}
