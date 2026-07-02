use crate::scanner::ScanResult;
use tauri::AppHandle;
use tauri_plugin_notification::NotificationExt;

pub fn notify_auto_scan_complete(app: &AppHandle, result: &ScanResult) {
    if result.scan_source != "auto_scan" {
        return;
    }

    let is_threat = result.risk_score >= 21
        || matches!(
            result.verdict.as_str(),
            "malware" | "high_risk" | "suspicious"
        );

    let title = if is_threat {
        "Null Threat — Threat Detected"
    } else {
        "Null Threat — Scan Complete"
    };

    let body = if is_threat {
        format!(
            "{} flagged ({}% risk). Open Null Threat to view the full report.",
            result.filename, result.risk_score
        )
    } else {
        format!(
            "{} scanned clean. Open Null Threat to view the latest report.",
            result.filename
        )
    };

    if let Err(e) = app
        .notification()
        .builder()
        .title(title)
        .body(body)
        .show()
    {
        log::warn!("Failed to show scan notification: {e}");
    }
}
