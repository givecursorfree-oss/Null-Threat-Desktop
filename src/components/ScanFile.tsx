import { useState, useCallback, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Upload, FileSearch, File, AlertCircle, RotateCcw, CheckCircle2, ShieldAlert } from "lucide-react";
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

type ActionNotice =
  | { type: "success"; title: string; message: string }
  | { type: "error"; title: string; message: string };

export default function ScanFile() {
  const navigate = useNavigate();
  const { startScan, isScanning } = useScanner();
  const { refreshStats, reportToView, setReportToView } = useScanStore();
  const [selectedFile, setSelectedFile] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResultType | null>(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [actionNotice, setActionNotice] = useState<ActionNotice | null>(null);
  const [actionLoading, setActionLoading] = useState<"quarantine" | "trust" | null>(null);

  useEffect(() => {
    if (reportToView) {
      setResult(reportToView);
      setSelectedFile(reportToView.filePath);
      setError(null);
      setActionNotice(null);
      setReportToView(null);
    }
  }, [reportToView, setReportToView]);

  const runScan = useCallback(
    async (filePath: string) => {
      setError(null);
      setActionNotice(null);
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
    setActionNotice(null);
  };

  const handleQuarantine = async () => {
    if (!result) return;
    setActionNotice(null);
    setActionLoading("quarantine");
    try {
      await quarantineFile(
        result.filePath,
        result.threatName || "Threat detected",
        result.riskScore
      );
      refreshStats(await fetchDashboardStats());
      setActionNotice({
        type: "success",
        title: "File quarantined",
        message:
          "The file was encrypted and moved to the Quarantine vault. The original has been removed from disk.",
      });
      setResult(null);
      setSelectedFile(null);
    } catch (err) {
      const message =
        err instanceof Error ? err.message : String(err ?? "Quarantine failed");
      setActionNotice({
        type: "error",
        title: "Quarantine failed",
        message,
      });
    } finally {
      setActionLoading(null);
    }
  };

  const handleTrust = async () => {
    if (!result) return;
    if (!result.sha256) {
      setActionNotice({
        type: "error",
        title: "Cannot trust file",
        message: "No SHA-256 hash was recorded for this scan. Scan the file again and retry.",
      });
      return;
    }
    setActionNotice(null);
    setActionLoading("trust");
    try {
      await addToWhitelist(result.filePath, result.sha256);
      setActionNotice({
        type: "success",
        title: "File trusted",
        message:
          "This file is now on your trusted list. Future scans will skip it unless you remove it in Settings.",
      });
    } catch (err) {
      const message =
        err instanceof Error ? err.message : String(err ?? "Could not add to trusted list");
      setActionNotice({
        type: "error",
        title: "Trust failed",
        message,
      });
    } finally {
      setActionLoading(null);
    }
  };

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <PageHeader
        title="Scan"
        description="Analyze a single file with hash lookup, ClamAV, YARA rules, structural parsing, metadata inspection, and steganalysis."
      />

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Scan failed</AlertTitle>
          <AlertDescription className="break-words">{error}</AlertDescription>
        </Alert>
      )}

      {actionNotice && (
        <Alert variant={actionNotice.type === "error" ? "destructive" : "default"}>
          {actionNotice.type === "success" ? (
            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
          ) : (
            <AlertCircle className="h-4 w-4" />
          )}
          <AlertTitle>{actionNotice.title}</AlertTitle>
          <AlertDescription className="break-words">{actionNotice.message}</AlertDescription>
          {actionNotice.type === "success" && actionNotice.title === "File quarantined" && (
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="mt-3"
              onClick={() => navigate("/quarantine")}
            >
              <ShieldAlert className="h-3 w-3" />
              Open Quarantine
            </Button>
          )}
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
            actionLoading={actionLoading}
            onQuarantine={handleQuarantine}
            onTrust={handleTrust}
          />
        </div>
      )}
    </div>
  );
}
