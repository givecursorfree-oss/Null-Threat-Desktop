import { useEffect, useCallback } from "react";
import { listen } from "@tauri-apps/api/event";
import { useScanStore } from "../store/scanStore";
import type { EngineName } from "../types";
import {
  mapProgressEvent,
  scanFile,
  type ScanProgressEvent,
} from "../lib/api";

const ENGINE_ORDER: EngineName[] = [
  "SHA256 Lookup",
  "ClamAV Engine",
  "YARA Rules",
  "Deep Analysis",
];

export function useScanner() {
  const {
    isScanning,
    currentFile,
    progress,
    setScanning,
    setCurrentFile,
    updateProgress,
    resetProgress,
  } = useScanStore();

  useEffect(() => {
    const unlistenProgress = listen<ScanProgressEvent>("scan-progress", (event) => {
      const mapped = mapProgressEvent(event.payload);
      if (!mapped) return;

      const idx = ENGINE_ORDER.indexOf(mapped.engineName);
      if (idx > 0) {
        for (let i = 0; i < idx; i++) {
          const name = ENGINE_ORDER[i];
          updateProgress(name, { status: "complete", progress: 100 });
        }
      }

      updateProgress(mapped.engineName, {
        status: mapped.status,
        progress: mapped.progress,
      });

      if (event.payload.stage === "complete") {
        ENGINE_ORDER.forEach((name) => {
          updateProgress(name, { status: "complete", progress: 100 });
        });
      }
    });

    return () => {
      unlistenProgress.then((fn) => fn());
    };
  }, [updateProgress]);

  const startScan = useCallback(
    async (filePath: string) => {
      resetProgress();
      setCurrentFile(filePath);
      setScanning(true);
      try {
        return await scanFile(filePath);
      } catch (error) {
        console.error("Scan failed:", error);
        throw error;
      } finally {
        setScanning(false);
        setCurrentFile(null);
      }
    },
    [resetProgress, setCurrentFile, setScanning]
  );

  return {
    startScan,
    isScanning,
    currentFile,
    progress,
  };
}
