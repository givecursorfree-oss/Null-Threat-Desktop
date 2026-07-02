import { useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";

interface FeedEvent {
  id: string;
  timestamp: string;
  message: string;
  type: "info" | "clean" | "threat";
}

export default function LiveFeed({ className }: { className?: string }) {
  const [events, setEvents] = useState<FeedEvent[]>([
    {
      id: "init",
      timestamp: new Date().toISOString(),
      message: "Real-time protection initialized",
      type: "info",
    },
  ]);

  useEffect(() => {
    const unlistenScan = listen<{
      filename: string;
      verdict: string;
      risk_score: number;
      scan_source?: string;
    }>("scan-complete", (event) => {
      const { filename, verdict, risk_score, scan_source } = event.payload;
      const displayVerdict =
        verdict === "clean" || risk_score <= 20
          ? "clean"
          : risk_score >= 51
            ? "detected"
            : "suspicious";
      const newEvent: FeedEvent = {
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        message:
          scan_source === "auto_scan"
            ? `Auto-scanned ${filename} — ${displayVerdict}`
            : `${filename} — ${displayVerdict}`,
        type: displayVerdict === "clean" ? "clean" : "threat",
      };
      setEvents((prev) => [newEvent, ...prev].slice(0, 20));
    });

    const unlistenWatch = listen<{ path: string }>("file-detected", (event) => {
      const fileName = event.payload.path.split(/[\\/]/).pop() || "Unknown";
      setEvents((prev) =>
        [
          {
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            message: `Scanning ${fileName}`,
            type: "info" as const,
          },
          ...prev,
        ].slice(0, 20)
      );
    });

    return () => {
      unlistenScan.then((fn) => fn());
      unlistenWatch.then((fn) => fn());
    };
  }, []);

  return (
    <section className={cn("space-y-3", className)}>
      <div className="flex items-baseline justify-between">
        <h2 className="text-sm font-medium text-foreground">Activity</h2>
        <span className="text-xs text-muted-foreground">Live</span>
      </div>
      <ScrollArea className="h-[140px] rounded-lg border border-border bg-card/40">
        <ul className="divide-y divide-border/60">
          {events.map((event) => (
            <li
              key={event.id}
              className="flex items-center justify-between gap-3 px-3 py-2.5 text-sm"
            >
              <span
                className={cn(
                  "min-w-0 truncate",
                  event.type === "threat"
                    ? "text-foreground"
                    : "text-muted-foreground"
                )}
              >
                {event.message}
              </span>
              <time className="shrink-0 text-xs tabular-nums text-muted-foreground">
                {new Date(event.timestamp).toLocaleTimeString([], {
                  hour: "2-digit",
                  minute: "2-digit",
                })}
              </time>
            </li>
          ))}
        </ul>
      </ScrollArea>
    </section>
  );
}
