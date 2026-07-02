import { useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { isTauri } from "@tauri-apps/api/core";
import { Loader2, AlertCircle } from "lucide-react";
import { fetchSignatureStatus } from "@/lib/api";
import { Progress } from "@/components/ui/progress";
import { cn } from "@/lib/utils";
import type { SignatureStatus, SignatureUpdateEvent } from "@/types";

export default function SignatureUpdateBanner() {
  const [status, setStatus] = useState<SignatureStatus | null>(null);
  const [live, setLive] = useState<SignatureUpdateEvent | null>(null);

  useEffect(() => {
    if (!isTauri()) return;

    fetchSignatureStatus()
      .then(setStatus)
      .catch(() => {});

    const unlisten = listen<SignatureUpdateEvent>("signature-update", (event) => {
      setLive(event.payload);
      if (event.payload.status === "complete" || event.payload.status === "failed") {
        fetchSignatureStatus()
          .then(setStatus)
          .catch(() => {});
        if (event.payload.status === "complete") {
          window.setTimeout(() => setLive(null), 4000);
        }
      }
    });

    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

  const isUpdating =
    live?.status === "checking" ||
    live?.status === "downloading" ||
    status?.updating === true;

  if (!isUpdating && live?.status === "failed") {
    return (
      <div className="mb-4 flex items-start gap-3 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3">
        <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" />
        <div className="min-w-0">
          <p className="text-sm font-medium text-foreground">Signature update failed</p>
          <p className="mt-0.5 text-xs text-muted-foreground">{live.message}</p>
        </div>
      </div>
    );
  }

  if (!isUpdating) {
    return null;
  }

  const progress = live?.progress ?? 35;
  const message = live?.message ?? "Updating ClamAV virus definitions...";

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
          <p className="text-sm font-medium text-foreground">Signature update in progress</p>
          <p className="mt-0.5 truncate text-xs text-muted-foreground">{message}</p>
        </div>
        <span className="font-mono text-xs text-cyan-200">{progress}%</span>
      </div>
      <Progress value={progress} className="mt-3 h-1.5" />
    </div>
  );
}
