import { useState, useCallback, useEffect } from "react";
import { Upload, FileSearch, File, AlertCircle, RotateCcw } from "lucide-react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { isTauri } from "@tauri-apps/api/core";
import { useScanner } from "../hooks/useScanner";
import ScanProgress from "./ScanProgress";
import ScanResult from "./ScanResult";
import { pickScanFile, quarantineFile, addToWhitelist, fetchDashboardStats } from "../lib/api";
import { useScanStore } from "../store/scanStore";
import PageHeader from "./PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { cn } from "@/lib/utils";
import type { ScanResult as ScanResultType } from "../types";

export default function ScanFile() {
  const { startScan, isScanning } = useScanner();
  const { refreshStats, reportToView, setReportToView } = useScanStore();
  const [selectedFile, setSelectedFile] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResultType | null>(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (reportToView) {
      setResult(reportToView);
      setSelectedFile(reportToView.filePath);
      setError(null);
      setReportToView(null);
    }
  }, [reportToView, setReportToView]);

  const runScan = useCallback(
    async (filePath: string) => {
      setError(null);
      setResult(null);
      setSelectedFile(filePath);
      try {
        const scanResult = await startScan(filePath);
        setResult(scanResult);
        refreshStats(await fetchDashboardStats());
      } catch (err) {
        const message =
          err instanceof Error ? err.message : String(err ?? "Scan failed");
        setError(message);
      }
    },
    [startScan, refreshStats]
  );

  const handleFilePick = async () => {
    if (!isTauri()) {
      setError("Run Null Threat with npm run dev (Tauri), not the browser-only dev server.");
      return;
    }

    setError(null);
    try {
      const file = await pickScanFile();
      if (file) {
        await runScan(file);
      }
    } catch (err) {
      const message =
        err instanceof Error ? err.message : String(err ?? "Could not open file picker");
      setError(message);
    }
  };

  useEffect(() => {
    if (!isTauri()) return;

    let unlisten: (() => void) | undefined;

    getCurrentWindow()
      .onDragDropEvent((event) => {
        const { type } = event.payload;
        if (type === "over") {
          setIsDragOver(true);
        } else if (type === "leave") {
          setIsDragOver(false);
        } else if (type === "drop") {
          setIsDragOver(false);
          const path = event.payload.paths[0];
          if (path) {
            void runScan(path);
          }
        }
      })
      .then((fn) => {
        unlisten = fn;
      })
      .catch((err) => {
        console.error("Drag-drop listener failed:", err);
      });

    return () => {
      unlisten?.();
    };
  }, [runScan]);

  const handleReset = () => {
    setResult(null);
    setSelectedFile(null);
    setError(null);
  };

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <PageHeader
        title="Scan"
        description="Analyze a single file with hash lookup, ClamAV, YARA rules, and structural checks."
      />

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Scan failed</AlertTitle>
          <AlertDescription className="break-words">{error}</AlertDescription>
        </Alert>
      )}

      {!isScanning && !result && (
        <div
          className={cn(
            "flex cursor-pointer flex-col items-center gap-4 rounded-lg border-2 border-dashed p-12 transition-colors",
            isDragOver
              ? "border-foreground bg-accent"
              : "border-border hover:border-muted-foreground"
          )}
          onClick={handleFilePick}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              void handleFilePick();
            }
          }}
        >
          <Upload
            className={cn(
              "h-10 w-10",
              isDragOver ? "text-foreground" : "text-muted-foreground"
            )}
          />
          <div className="text-center">
            <p className="font-medium text-foreground">
              Drop file here or click to browse
            </p>
            <p className="mt-1 text-xs text-muted-foreground">
              All file types supported — analysis runs locally
            </p>
          </div>
        </div>
      )}

      {selectedFile && !isScanning && !result && !error && (
        <Card>
          <CardContent className="flex items-center gap-3 p-4">
            <File className="h-5 w-5 shrink-0 text-muted-foreground" />
            <span className="flex-1 truncate text-sm text-foreground">
              {selectedFile}
            </span>
            <Button type="button" onClick={handleFilePick} size="sm">
              <FileSearch className="h-3 w-3" />
              Scan
            </Button>
          </CardContent>
        </Card>
      )}

      {isScanning && <ScanProgress />}

      {result && (
        <div className="space-y-4">
          <div className="flex justify-end">
            <Button type="button" onClick={handleReset} variant="outline" size="sm">
              <RotateCcw className="h-3 w-3" />
              Scan another file
            </Button>
          </div>
          <ScanResult
            result={result}
            onQuarantine={async () => {
              await quarantineFile(
                result.filePath,
                result.threatName || "Threat detected",
                result.riskScore
              );
              refreshStats(await fetchDashboardStats());
            }}
            onTrust={async () => {
              await addToWhitelist(result.filePath, result.sha256);
            }}
          />
        </div>
      )}
    </div>
  );
}
