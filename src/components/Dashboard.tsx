import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowUpRight, FileSearch, AlertCircle } from "lucide-react";
import { useScanStore } from "../store/scanStore";
import { fetchDashboardStats, fetchVerdictBreakdown } from "../lib/api";
import ScanProgress from "./ScanProgress";
import VerdictBadge from "./VerdictBadge";
import PageHeader from "./PageHeader";
import LiveFeed from "./LiveFeed";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { cn } from "@/lib/utils";
import type { VerdictBreakdown } from "../types";

export default function Dashboard() {
  const navigate = useNavigate();
  const { stats, recentScans, realtimeProtection, refreshStats, isScanning } =
    useScanStore();
  const [breakdown, setBreakdown] = useState<VerdictBreakdown>({
    clean: 0,
    suspicious: 0,
    detected: 0,
    critical: 0,
  });
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    const loadDashboard = async () => {
      try {
        const [dashboardStats, verdictBreakdown] = await Promise.all([
          fetchDashboardStats(),
          fetchVerdictBreakdown(),
        ]);
        refreshStats(dashboardStats);
        setBreakdown(verdictBreakdown);
        setLoadError(null);
      } catch (err) {
        setLoadError(
          err instanceof Error ? err.message : "Could not load dashboard data"
        );
      }
    };
    void loadDashboard();
  }, [recentScans.length, stats.filesScanned, refreshStats]);

  const totalVerdicts =
    breakdown.clean + breakdown.suspicious + breakdown.detected + breakdown.critical;

  return (
    <div className="mx-auto max-w-5xl">
      <PageHeader
        title="Overview"
        description={
          realtimeProtection
            ? "Automatic scans run when files appear in watched folders."
            : "Turn on real-time protection in Settings to scan new downloads."
        }
        actions={
          <>
            <StatusPill active={realtimeProtection} />
            <Button variant="outline" size="sm" onClick={() => navigate("/scan")}>
              <FileSearch className="h-3.5 w-3.5" />
              Scan file
            </Button>
          </>
        }
      />

      {loadError && (
        <Alert variant="destructive" className="mb-6">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Dashboard unavailable</AlertTitle>
          <AlertDescription>{loadError}</AlertDescription>
        </Alert>
      )}

      <div className="mb-8 grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-border bg-border sm:grid-cols-4">
        <Metric label="Files scanned" value={stats.filesScanned.toLocaleString()} />
        <Metric label="Threats flagged" value={stats.threatsBlocked.toLocaleString()} />
        <Metric label="Quarantined" value={stats.filesQuarantined.toLocaleString()} />
        <Metric label="Last activity" value={formatTime(stats.lastUpdated)} />
      </div>

      {isScanning && (
        <div className="mb-8">
          <ScanProgress />
        </div>
      )}

      <div className="mb-8 grid gap-8 lg:grid-cols-[1.4fr_1fr]">
        <section>
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-medium text-foreground">Recent scans</h2>
            <Button
              variant="ghost"
              size="sm"
              className="h-8 text-xs text-muted-foreground"
              onClick={() => navigate("/history")}
            >
              View all
              <ArrowUpRight className="h-3 w-3" />
            </Button>
          </div>

          {recentScans.length === 0 ? (
            <p className="rounded-lg border border-dashed border-border px-4 py-10 text-center text-sm text-muted-foreground">
              No scans yet. Drop a file in Downloads or run a manual scan.
            </p>
          ) : (
            <div className="overflow-hidden rounded-lg border border-border">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border bg-white/[0.02] text-left text-xs text-muted-foreground">
                    <th className="px-4 py-2.5 font-normal">File</th>
                    <th className="hidden px-4 py-2.5 font-normal sm:table-cell">Risk</th>
                    <th className="px-4 py-2.5 text-right font-normal">Result</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/60">
                  {recentScans.slice(0, 8).map((scan) => (
                    <tr key={scan.id} className="hover:bg-white/[0.02]">
                      <td className="max-w-[200px] truncate px-4 py-3 text-foreground">
                        {scan.fileName}
                      </td>
                      <td className="hidden px-4 py-3 tabular-nums text-muted-foreground sm:table-cell">
                        {scan.riskScore}%
                      </td>
                      <td className="px-4 py-3 text-right">
                        <VerdictBadge verdict={scan.verdict} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section>
          <h2 className="mb-3 text-sm font-medium text-foreground">Verdict mix</h2>
          {totalVerdicts === 0 ? (
            <p className="text-sm text-muted-foreground">No verdict data yet.</p>
          ) : (
            <ul className="space-y-3">
              <BreakdownRow
                label="Clean"
                count={breakdown.clean}
                total={totalVerdicts}
                tone="neutral"
              />
              <BreakdownRow
                label="Suspicious"
                count={breakdown.suspicious}
                total={totalVerdicts}
                tone="warn"
              />
              <BreakdownRow
                label="Detected"
                count={breakdown.detected}
                total={totalVerdicts}
                tone="alert"
              />
              <BreakdownRow
                label="Critical"
                count={breakdown.critical}
                total={totalVerdicts}
                tone="critical"
              />
            </ul>
          )}
        </section>
      </div>

      <LiveFeed />
    </div>
  );
}

function StatusPill({ active }: { active: boolean }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs",
        active
          ? "border-border text-muted-foreground"
          : "border-amber-500/30 text-amber-400/90"
      )}
    >
      <span
        className={cn(
          "h-1.5 w-1.5 rounded-full",
          active ? "bg-foreground/70" : "bg-amber-400"
        )}
      />
      {active ? "Protection on" : "Protection off"}
    </span>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-card/60 px-4 py-4 sm:px-5">
      <p className="text-2xl font-medium tabular-nums tracking-tight text-foreground">
        {value}
      </p>
      <p className="mt-1 text-xs text-muted-foreground">{label}</p>
    </div>
  );
}

function BreakdownRow({
  label,
  count,
  total,
  tone,
}: {
  label: string;
  count: number;
  total: number;
  tone: "neutral" | "warn" | "alert" | "critical";
}) {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0;
  const barClass = {
    neutral: "bg-foreground/25",
    warn: "bg-amber-500/60",
    alert: "bg-orange-500/70",
    critical: "bg-red-500/80",
  }[tone];

  return (
    <li className="space-y-1.5">
      <div className="flex items-center justify-between text-xs">
        <span className="text-muted-foreground">{label}</span>
        <span className="tabular-nums text-foreground">
          {count}
          <span className="text-muted-foreground"> · {pct}%</span>
        </span>
      </div>
      <div className="h-1 overflow-hidden rounded-full bg-white/[0.06]">
        <div className={cn("h-full rounded-full transition-all", barClass)} style={{ width: `${pct}%` }} />
      </div>
    </li>
  );
}

function formatTime(iso: string): string {
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return "—";
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  } catch {
    return "—";
  }
}
