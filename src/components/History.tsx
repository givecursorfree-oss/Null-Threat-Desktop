import { useState, useEffect, useMemo } from "react";
import { Search, Download, ChevronLeft, ChevronRight, FileJson } from "lucide-react";
import { fetchScanHistory, saveScanReportJson, saveScanReportPdf } from "../lib/api";
import { formatSaveSuccess, isSaveCancelledError } from "../lib/exportReport";
import VerdictBadge from "./VerdictBadge";
import PageHeader from "./PageHeader";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { formatAppDate } from "../lib/datetime";
import { formatRiskScoreShort } from "../lib/riskScore";
import type { ScanHistoryEntry, Verdict } from "../types";

const PAGE_SIZE = 15;

export default function History() {
  const [entries, setEntries] = useState<ScanHistoryEntry[]>([]);
  const [search, setSearch] = useState("");
  const [verdictFilter, setVerdictFilter] = useState<Verdict | "all">("all");
  const [page, setPage] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [exportingId, setExportingId] = useState<string | null>(null);
  const [exportMessage, setExportMessage] = useState<string | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);

  const handleExportJson = async (entry: ScanHistoryEntry) => {
    setExportingId(`${entry.id}-json`);
    setExportError(null);
    setExportMessage(null);
    try {
      const path = await saveScanReportJson(entry.id);
      setExportMessage(formatSaveSuccess(path));
    } catch (e) {
      const message = e instanceof Error ? e.message : "JSON export failed";
      if (!isSaveCancelledError(message)) {
        setExportError(message);
      }
    } finally {
      setExportingId(null);
    }
  };

  const handleExportPdf = async (entry: ScanHistoryEntry) => {
    setExportingId(`${entry.id}-pdf`);
    setExportError(null);
    setExportMessage(null);
    try {
      const path = await saveScanReportPdf(entry.id);
      setExportMessage(formatSaveSuccess(path));
    } catch (e) {
      const message = e instanceof Error ? e.message : "PDF export failed";
      if (!isSaveCancelledError(message)) {
        setExportError(message);
      }
    } finally {
      setExportingId(null);
    }
  };

  useEffect(() => {
    fetchScanHistory(500)
      .then(setEntries)
      .catch(() => {})
      .finally(() => setIsLoading(false));
  }, []);

  const filtered = useMemo(() => {
    return entries.filter((e) => {
      const matchesSearch =
        !search ||
        e.fileName.toLowerCase().includes(search.toLowerCase()) ||
        e.filePath.toLowerCase().includes(search.toLowerCase());
      const matchesVerdict = verdictFilter === "all" || e.verdict === verdictFilter;
      return matchesSearch && matchesVerdict;
    });
  }, [entries, search, verdictFilter]);

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const pageData = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  const handleExportCsv = () => {
    const headers = "Filename,Path,Date,Risk Score,Verdict,Action Taken\n";
    const rows = filtered
      .map(
        (e) =>
          `"${e.fileName}","${e.filePath}","${e.date}",${e.riskScore},"${e.verdict}","${e.actionTaken}"`
      )
      .join("\n");
    const blob = new Blob([headers + rows], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "null-threat-history.csv";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <PageHeader
        title="History"
        description={`${filtered.length} scan${filtered.length !== 1 ? "s" : ""} on this device`}
        actions={
          <Button onClick={handleExportCsv} variant="outline" size="sm">
            <Download className="h-3 w-3" />
            Export CSV
          </Button>
        }
      />

      {exportMessage && (
        <p className="text-xs text-emerald-400/90">{exportMessage}</p>
      )}
      {exportError && <p className="text-xs text-destructive">{exportError}</p>}

      <div className="flex flex-col gap-3 sm:flex-row">
        <div className="relative min-w-0 flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            type="text"
            placeholder="Search files..."
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(0); }}
            className="pl-9"
          />
        </div>
        <div className="relative w-full shrink-0 sm:w-[160px]">
          <select
            value={verdictFilter}
            onChange={(e) => { setVerdictFilter(e.target.value as Verdict | "all"); setPage(0); }}
            className={cn(
              "verdict-filter-select flex h-10 w-full appearance-none rounded-md",
              "border border-white/[0.08] bg-card px-3 pr-9 text-sm text-foreground",
              "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            )}
            aria-label="Filter by verdict"
          >
            <option value="all">All Verdicts</option>
            <option value="clean">Clean</option>
            <option value="suspicious">Suspicious</option>
            <option value="detected">Detected</option>
            <option value="critical">Critical</option>
          </select>
          <span
            className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground"
            aria-hidden
          >
            ▾
          </span>
        </div>
      </div>

      {isLoading ? (
        <Card>
          <CardContent className="flex items-center justify-center py-12">
            <Skeleton className="h-5 w-5 rounded-full" />
          </CardContent>
        </Card>
      ) : pageData.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <p className="text-sm text-muted-foreground">No scan history found</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-1.5">
          <div className="hidden px-4 py-2.5 text-left text-xs text-muted-foreground sm:grid sm:grid-cols-[1fr_120px_80px_90px_100px_72px] sm:gap-3">
            <span>File</span>
            <span>Date</span>
            <span>Risk</span>
            <span>Verdict</span>
            <span>Action</span>
            <span>Report</span>
          </div>
          {pageData.map((entry) => (
            <div
              key={entry.id}
              className="rounded-md border border-border bg-card/80 px-3 py-3 sm:grid sm:grid-cols-[1fr_120px_80px_90px_100px_72px] sm:items-center sm:gap-3 sm:px-4 sm:py-2.5"
            >
              <div className="min-w-0 space-y-1 sm:space-y-0">
                <span className="block truncate text-sm text-foreground">
                  {entry.fileName || "Unknown file"}
                </span>
                <span className="block truncate text-[11px] text-muted-foreground sm:hidden">
                  {entry.filePath || "No path available"}
                </span>
              </div>

              <div className="mt-2 flex items-center justify-between gap-3 sm:mt-0 sm:contents">
                <span className="text-xs text-muted-foreground">
                  {formatAppDate(entry.date, { month: "short", day: "numeric" })}
                </span>
                <span
                  className={cn(
                    "text-xs font-medium",
                    entry.riskScore > 50
                      ? "text-destructive"
                      : entry.riskScore > 20
                        ? "text-amber-400"
                        : "text-muted-foreground"
                  )}
                >
                  {formatRiskScoreShort(entry.riskScore)}
                </span>
                <VerdictBadge verdict={entry.verdict} className="justify-self-start sm:justify-self-auto" />
                <span className="text-xs capitalize text-muted-foreground">
                  {entry.actionTaken || "none"}
                </span>
                <div className="flex gap-1 justify-self-start sm:justify-self-auto">
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7"
                    disabled={exportingId === `${entry.id}-json`}
                    onClick={() => void handleExportJson(entry)}
                    aria-label="Export JSON report"
                  >
                    <FileJson className="h-3.5 w-3.5" />
                  </Button>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7"
                    disabled={exportingId === `${entry.id}-pdf`}
                    onClick={() => void handleExportPdf(entry)}
                    aria-label="Export PDF report"
                  >
                    <Download className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-4">
          <Button
            onClick={() => setPage((p) => Math.max(0, p - 1))}
            disabled={page === 0}
            variant="ghost"
            size="icon"
          >
            <ChevronLeft className="h-4 w-4" />
          </Button>
          <span className="font-mono text-xs text-muted-foreground">
            Page {page + 1} of {totalPages}
          </span>
          <Button
            onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
            disabled={page >= totalPages - 1}
            variant="ghost"
            size="icon"
          >
            <ChevronRight className="h-4 w-4" />
          </Button>
        </div>
      )}
    </div>
  );
}
