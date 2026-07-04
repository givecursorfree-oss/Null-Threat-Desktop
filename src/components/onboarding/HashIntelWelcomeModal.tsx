import { useEffect, useState } from "react";
import { Database, Loader2, Shield, Wifi, X } from "lucide-react";
import { isTauri } from "@tauri-apps/api/core";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { fetchHashIntelStatus, updateHashIntel } from "@/lib/api";
import {
  dismissHashIntro,
  hasSeenHashIntro,
  markHashIntroSeen,
} from "@/lib/consent";
import { cn } from "@/lib/utils";

const INTRO_DELAY_MS = 5000;

export default function HashIntelWelcomeModal() {
  const [visible, setVisible] = useState(false);
  const [isUpdating, setIsUpdating] = useState(false);
  const [progress, setProgress] = useState(0);
  const [hashCount, setHashCount] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isTauri() || hasSeenHashIntro()) return;

    const timer = window.setTimeout(() => {
      if (hasSeenHashIntro()) return;
      setVisible(true);
      fetchHashIntelStatus()
        .then((status) => setHashCount(status.hashCount))
        .catch(() => {});
    }, INTRO_DELAY_MS);

    return () => window.clearTimeout(timer);
  }, []);

  const close = (dismissed: boolean) => {
    if (dismissed) {
      dismissHashIntro();
    } else {
      markHashIntroSeen();
    }
    setVisible(false);
  };

  const handleUpdate = async () => {
    setError(null);
    setIsUpdating(true);
    setProgress(20);
    try {
      const status = await updateHashIntel(true);
      setHashCount(status.hashCount);
      setProgress(100);
      markHashIntroSeen();
      window.setTimeout(() => setVisible(false), 1200);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Hash update failed");
      setIsUpdating(false);
      setProgress(0);
    }
  };

  if (!visible) return null;

  return (
    <div
      className="fixed inset-0 z-[90] flex items-center justify-center bg-[#050505]/85 p-4 backdrop-blur-md"
      role="dialog"
      aria-modal="true"
      aria-labelledby="hash-intro-title"
    >
      <div
        className={cn(
          "relative w-full max-w-md rounded-xl border border-white/[0.08] bg-card/90 p-6",
          "shadow-[inset_0_1px_0_rgba(255,255,255,0.06)] backdrop-blur-xl",
          "animate-in fade-in zoom-in-95 duration-300"
        )}
      >
        <button
          type="button"
          onClick={() => close(true)}
          className="absolute right-4 top-4 rounded-md p-1 text-muted-foreground transition-colors hover:bg-white/[0.06] hover:text-foreground"
          aria-label="Close"
        >
          <X className="h-4 w-4" />
        </button>

        <div className="mb-5 flex items-start gap-3 pr-6">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-cyan-500/20 bg-cyan-500/10">
            <Database className="h-5 w-5 text-cyan-200" strokeWidth={1.75} />
          </div>
          <div>
            <h2
              id="hash-intro-title"
              className="font-display text-lg font-semibold tracking-tight text-foreground"
            >
              Update threat intelligence
            </h2>
            <p className="mt-1 text-sm text-muted-foreground">
              Null Threat scans offline by default. Downloading MalwareBazaar hashes
              improves SHA-256 detection when you are online.
            </p>
          </div>
        </div>

        <div className="space-y-3 rounded-lg border border-white/[0.06] bg-background/40 px-4 py-3 text-sm text-muted-foreground">
          <div className="flex items-start gap-2">
            <Shield className="mt-0.5 h-4 w-4 shrink-0 text-foreground/70" />
            <p>ClamAV, YARA, and deep analysis work without this update.</p>
          </div>
          <div className="flex items-start gap-2">
            <Wifi className="mt-0.5 h-4 w-4 shrink-0 text-foreground/70" />
            <p>
              {hashCount === null
                ? "Checking local hash database..."
                : hashCount === 0
                  ? "No malware hashes loaded yet — we recommend updating now."
                  : `${hashCount.toLocaleString()} hashes loaded — refresh for the latest signatures.`}
            </p>
          </div>
        </div>

        {isUpdating && (
          <div className="mt-4 space-y-2" role="status" aria-live="polite">
            <div className="flex items-center gap-2 text-sm text-foreground">
              <Loader2 className="h-4 w-4 animate-spin text-cyan-200" />
              Downloading MalwareBazaar intelligence...
            </div>
            <Progress value={progress} className="h-1.5" />
          </div>
        )}

        {error && (
          <p className="mt-3 text-xs text-destructive" role="alert">
            {error}
          </p>
        )}

        <div className="mt-6 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={() => close(true)}
            disabled={isUpdating}
          >
            Remind me later
          </Button>
          <Button
            type="button"
            size="sm"
            onClick={() => void handleUpdate()}
            disabled={isUpdating}
          >
            {isUpdating ? "Updating..." : "Update hashes now"}
          </Button>
        </div>

        <p className="mt-4 text-center text-[11px] text-muted-foreground/80">
          You can also update anytime from Settings or the banner at the top.
        </p>
      </div>
    </div>
  );
}
