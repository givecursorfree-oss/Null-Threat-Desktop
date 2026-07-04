use crate::scanner::ScanResult;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tauri::AppHandle;
#[cfg(not(windows))]
use tauri_plugin_notification::NotificationExt;

const NOTIFICATION_DEDUP_WINDOW: Duration = Duration::from_secs(120);

fn recent_notifications() -> &'static Mutex<HashMap<String, Instant>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn should_notify(result: &ScanResult) -> bool {
    let key = format!("{}:{}", result.filepath, result.sha256);
    let now = Instant::now();
    let mut cache = recent_notifications().lock().unwrap();
    cache.retain(|_, sent_at| now.duration_since(*sent_at) < NOTIFICATION_DEDUP_WINDOW);

    if cache
        .get(&key)
        .is_some_and(|sent_at| now.duration_since(*sent_at) < NOTIFICATION_DEDUP_WINDOW)
    {
        return false;
    }

    cache.insert(key, now);
    true
}

pub fn notify_auto_scan_complete(app: &AppHandle, result: &ScanResult) {
    if result.scan_source != "auto_scan" {
        return;
    }

    if !should_notify(result) {
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

    if let Err(e) = show_scan_notification(app, title, &body) {
        log::warn!("Failed to show scan notification: {e}");
    }
}

fn show_scan_notification(app: &AppHandle, title: &str, body: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        show_windows_toast(app, title, body)
    }

    #[cfg(not(windows))]
    {
        app.notification()
            .builder()
            .title(title)
            .body(body)
            .show()
            .map_err(|e| e.to_string())
    }
}

#[cfg(windows)]
fn show_windows_toast(app: &AppHandle, title: &str, body: &str) -> Result<(), String> {
    use tauri::Emitter;
    use tauri_winrt_notification::{Duration as ToastDuration, Toast};

    let app_id = app.config().identifier.clone();
    let title = title.to_string();
    let body = body.to_string();
    let app_handle = app.clone();

    std::thread::spawn(move || {
        let app_for_activation = app_handle.clone();
        let toast = Toast::new(&app_id)
            .title(&title)
            .text1(&body)
            .duration(ToastDuration::Short)
            .on_activated(move |_action| {
                let app = app_for_activation.clone();
                let app_for_thread = app.clone();
                let _ = app.run_on_main_thread(move || {
                    crate::tray::show_main_window(&app_for_thread);
                    let _ = app_for_thread.emit("notification-opened", ());
                });
                Ok(())
            });

        if let Err(e) = toast.show() {
            log::warn!("Failed to show Windows toast: {e}");
        }
    });

    Ok(())
}

#[cfg(windows)]
pub fn configure_windows(app_id: &str) {
    use windows::core::HSTRING;
    use windows::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID;

    unsafe {
        let _ = SetCurrentProcessExplicitAppUserModelID(&HSTRING::from(app_id));
    }
}
