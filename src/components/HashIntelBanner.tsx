import { useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { isTauri } from "@tauri-apps/api/core";
import { Loader2, Wifi, AlertCircle, RefreshCw } from "lucide-react";
import { fetchHashIntelStatus, updateHashIntel } from "@/lib/api";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import type { HashIntelStatus, HashIntelUpdateEvent } from "@/types";

function formatLastUpdated(iso: string | null): string {
  if (!iso) return "Never";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "Unknown";
  return date.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function HashIntelBanner() {
  const [status, setStatus] = useState<HashIntelStatus | null>(null);
  const [live, setLive] = useState<HashIntelUpdateEvent | null>(null);
  const [isUpdating, setIsUpdating] = useState(false);

  const refreshStatus = () => {
    fetchHashIntelStatus()
      .then(setStatus)
      .catch(() => {});
  };

  useEffect(() => {
    if (!isTauri()) return;
    refreshStatus();

    const unlisten = listen<HashIntelUpdateEvent>("hash-intel-update", (event) => {
      setLive(event.payload);
      if (event.payload.status === "complete" || event.payload.status === "failed") {
        refreshStatus();
        setIsUpdating(false);
        if (event.payload.status === "complete") {
          window.setTimeout(() => setLive(null), 5000);
        }
      }
    });

    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

  const handleUpdate = async () => {
    setIsUpdating(true);
    try {
      const next = await updateHashIntel(true);
      setStatus(next);
    } catch {
      setIsUpdating(false);
    }
  };

  const activeUpdate =
    isUpdating ||
    live?.status === "checking" ||
    live?.status === "downloading" ||
    status?.updating;

  if (activeUpdate) {
    const progress = live?.progress ?? 40;
    return (
      <div
        className={cn(
          "mb-4 rounded-lg border border-cyan-500/25 bg-cyan-500/10 px-4 py-3",
          "shadow-[inset_0_1px_0_rgba(255,255,255,0.05)]"
        )}
        role="status"
        aria-live="polite"
      >
        <div className="flex items-center gap-3">
          <Loader2 className="h-4 w-4 shrink-0 animate-spin text-cyan-200" />
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium text-foreground">
              Updating MalwareBazaar hash intelligence
            </p>
            <p className="mt-0.5 truncate text-xs text-muted-foreground">
              {live?.message ?? "Downloading latest known-malware hashes..."}
            </p>
          </div>
          <span className="font-mono text-xs text-cyan-200">{progress}%</span>
        </div>
        <Progress value={progress} className="mt-3 h-1.5" />
      </div>
    );
  }

  if (live?.status === "failed") {
    return (
      <div className="mb-4 flex items-start justify-between gap-3 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3">
        <div className="flex min-w-0 items-start gap-3">
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" />
          <div>
            <p className="text-sm font-medium text-foreground">Hash update failed</p>
            <p className="mt-0.5 text-xs text-muted-foreground">{live.message}</p>
          </div>
        </div>
        <Button type="button" size="sm" variant="outline" onClick={handleUpdate}>
          Retry
        </Button>
      </div>
    );
  }

  const showReminder =
    status && (status.hashCount === 0 || status.updateDue);

  if (!showReminder) {
    return null;
  }

  return (
    <div className="mb-4 flex flex-col gap-3 rounded-lg border border-white/[0.08] bg-card/70 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex min-w-0 items-start gap-3">
        <Wifi className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
        <div>
          <p className="text-sm font-medium text-foreground">
            {status.hashCount === 0
              ? "Null Threat works offline — hash database not loaded yet"
              : "Daily MalwareBazaar refresh recommended"}
          </p>
          <p className="mt-0.5 text-xs text-muted-foreground">
            Scanning, YARA, and deep analysis work without internet. Update malware hashes only when
            you are online to improve SHA256 detection.
            {status.hashCount > 0 && (
              <> Last updated: {formatLastUpdated(status.lastUpdated)}.</>
            )}
          </p>
        </div>
      </div>
      <Button type="button" size="sm" variant="outline" onClick={handleUpdate} className="shrink-0">
        <RefreshCw className="h-3 w-3" />
        Update hashes
      </Button>
    </div>
  );
}
