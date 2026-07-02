import { Progress } from "@/components/ui/progress";
import { cn } from "@/lib/utils";
import type { EngineStatus, Verdict } from "../types";

interface EngineProgressBarProps {
  engineName: string;
  status: EngineStatus;
  progress: number;
  elapsed: number;
  verdict?: Verdict;
}

export default function EngineProgressBar({
  engineName,
  status,
  progress,
  elapsed,
  verdict,
}: EngineProgressBarProps) {
  const isClean = verdict === "clean";
  const isDetected = verdict === "detected" || verdict === "suspicious";

  const progressValue =
    status === "complete" ? 100 : status === "running" ? progress : 0;

  const textColor =
    status === "complete"
      ? isDetected
        ? "text-destructive"
        : "text-emerald-400"
      : status === "running"
        ? "text-foreground"
        : "text-muted-foreground";

  const statusText =
    status === "waiting"
      ? "Waiting"
      : status === "running"
        ? "Scanning..."
        : isClean
          ? "Clean"
          : isDetected
            ? "Detected"
            : "Complete";

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <span className={cn("text-sm font-medium", textColor)}>{engineName}</span>
        <div className="flex items-center gap-3">
          <span className="font-mono text-xs text-muted-foreground">
            {elapsed > 0 ? `${(elapsed / 1000).toFixed(1)}s` : "—"}
          </span>
          <span className={cn("text-xs font-medium", textColor)}>{statusText}</span>
        </div>
      </div>

      <Progress
        value={progressValue}
        className={cn(
          status === "complete" && isDetected && "[&>div]:bg-destructive",
          status === "complete" && !isDetected && "[&>div]:bg-emerald-400"
        )}
      />
    </div>
  );
}
