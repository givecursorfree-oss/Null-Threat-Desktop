import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { listen } from "@tauri-apps/api/event";
import { isTauri } from "@tauri-apps/api/core";
import {
  isPermissionGranted,
  requestPermission,
} from "@tauri-apps/plugin-notification";
import { useScanStore } from "../store/scanStore";
import {
  fetchDashboardStats,
  fetchRealtimeProtection,
  fetchScanHistory,
  mapScanResult,
  type ScanProgressEvent,
} from "../lib/api";

export function useAppInit() {
  const navigate = useNavigate();
  const {
    refreshStats,
    setRealtimeProtection,
    setRecentScans,
    addScanResult,
    setScanning,
    setCurrentFile,
    setReportToView,
  } = useScanStore();

  useEffect(() => {
    if (!isTauri()) return;

    const load = async () => {
      try {
        const granted = await isPermissionGranted();
        if (!granted) {
          await requestPermission();
        }
      } catch {
        /* notifications optional */
      }

      try {
        const [stats, realtime, history] = await Promise.all([
          fetchDashboardStats(),
          fetchRealtimeProtection(),
          fetchScanHistory(20),
        ]);
        refreshStats(stats);
        setRealtimeProtection(realtime);
        setRecentScans(
          history.map((h) => ({
            id: h.id,
            fileName: h.fileName,
            filePath: h.filePath,
            fileSize: 0,
            fileType: "unknown",
            sha256: "",
            timestamp: h.date,
            riskScore: h.riskScore,
            verdict: h.verdict,
            engines: [],
            deepChecks: [],
            findings: [],
          }))
        );
      } catch (err) {
        console.error("Failed to load app state:", err);
      }
    };

    void load();

    const unlistenComplete = listen<Parameters<typeof mapScanResult>[0]>(
      "scan-complete",
      async (event) => {
        const result = mapScanResult(event.payload);
        addScanResult(result);
        setScanning(false);
        setCurrentFile(null);

        if (result.scanSource === "auto_scan") {
          setReportToView(result);
        }

        try {
          refreshStats(await fetchDashboardStats());
        } catch {
          /* ignore */
        }
      }
    );

    const unlistenDetected = listen<{ path: string; event_type?: string }>(
      "file-detected",
      (event) => {
        setScanning(true);
        setCurrentFile(event.payload.path);
      }
    );

    const unlistenProgress = listen<ScanProgressEvent>("scan-progress", (event) => {
      if (event.payload.stage === "complete") {
        setScanning(false);
      }
    });

    const unlistenNotification = listen("notification-opened", () => {
      navigate("/scan");
    });

    return () => {
      unlistenComplete.then((fn) => fn());
      unlistenDetected.then((fn) => fn());
      unlistenProgress.then((fn) => fn());
      unlistenNotification.then((fn) => fn());
    };
  }, [
    navigate,
    refreshStats,
    setRealtimeProtection,
    setRecentScans,
    addScanResult,
    setScanning,
    setCurrentFile,
    setReportToView,
  ]);
}
