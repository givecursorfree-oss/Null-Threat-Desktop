import { useState } from "react";
import {
  FileText,
  ShieldCheck,
  ShieldX,
  FolderOpen,
  Trash2,
  ShieldAlert,
  CheckCircle,
  ChevronDown,
  Download,
  FileJson,
} from "lucide-react";
import ConfidenceMeter from "./ConfidenceMeter";
import ThreatCard from "./ThreatCard";
import VerdictBadge from "./VerdictBadge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { formatRiskScore } from "@/lib/riskScore";
import { saveScanReportJson, saveScanReportPdf } from "../lib/api";
import { formatSaveSuccess, isSaveCancelledError } from "../lib/exportReport";
import type { DeepAnalysisCheck, ScanResult as ScanResultType, ThreatInfo, Verdict } from "../types";

interface ScanResultProps {
  result: ScanResultType;
  actionLoading?: "quarantine" | "trust" | null;
  onQuarantine?: () => void | Promise<void>;
  onDelete?: () => void;
  onTrust?: () => void | Promise<void>;
  onViewFolder?: () => void;
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function isDeepCheckFlagged(verdict: Verdict): boolean {
  return verdict === "detected" || verdict === "suspicious" || verdict === "critical";
}

function DeepCheckRow({ check }: { check: DeepAnalysisCheck }) {
  const [open, setOpen] = useState(isDeepCheckFlagged(check.verdict));
  const flagged = isDeepCheckFlagged(check.verdict);

  return (
    <div
      className={cn(
        "overflow-hidden rounded-md border",
        flagged ? "border-destructive/30 bg-destructive/5" : "border-border/60 bg-background/40"
      )}
    >
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-start justify-between gap-2 px-3 py-2 text-left transition-colors hover:bg-white/[0.03]"
        aria-expanded={open}
      >
        <div className="min-w-0 flex-1 space-y-0.5">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-medium text-foreground">{check.name}</span>
            {check.score > 0 && (
              <span className="font-mono text-[10px] text-muted-foreground">+{check.score}</span>
            )}
          </div>
          <p className="text-[11px] leading-snug text-muted-foreground">{check.summary}</p>
        </div>
        <div className="flex shrink-0 items-center gap-2 pt-0.5">
          <VerdictBadge verdict={check.verdict} />
          <ChevronDown
            className={cn(
              "h-3.5 w-3.5 text-muted-foreground transition-transform duration-200",
              open && "rotate-180"
            )}
          />
        </div>
      </button>

      {open && (
        <div className="border-t border-border/50 px-3 py-2">
          <ul className="space-y-1.5">
            {check.items.map((item, i) => (
              <li key={i} className="flex gap-2 text-[11px] leading-snug text-foreground">
                <span
                  className={cn(
                    "mt-1.5 h-1 w-1 shrink-0 rounded-full",
                    flagged ? "bg-destructive" : "bg-muted-foreground"
                  )}
                />
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export default function ScanResult({
  result,
  actionLoading,
  onQuarantine,
  onDelete,
  onTrust,
  onViewFolder,
}: ScanResultProps) {
  const deepHasFlags = result.deepChecks.some((c) => isDeepCheckFlagged(c.verdict));
  const [deepExpanded, setDeepExpanded] = useState(deepHasFlags);
  const [exporting, setExporting] = useState<"json" | "pdf" | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const [exportSuccess, setExportSuccess] = useState<string | null>(null);

  const canExportReport = /^\d+$/.test(result.id);

  const handleExportJson = async () => {
    if (!canExportReport) return;
    setExportError(null);
    setExportSuccess(null);
    setExporting("json");
    try {
      const path = await saveScanReportJson(result.id);
      setExportSuccess(formatSaveSuccess(path));
    } catch (e) {
      const message = e instanceof Error ? e.message : "JSON export failed";
      if (!isSaveCancelledError(message)) {
        setExportError(message);
      }
    } finally {
      setExporting(null);
    }
  };

  const handleExportPdf = async () => {
    if (!canExportReport) return;
    setExportError(null);
    setExportSuccess(null);
    setExporting("pdf");
    try {
      const path = await saveScanReportPdf(result.id);
      setExportSuccess(formatSaveSuccess(path));
    } catch (e) {
      const message = e instanceof Error ? e.message : "PDF export failed";
      if (!isSaveCancelledError(message)) {
        setExportError(message);
      }
    } finally {
      setExporting(null);
    }
  };

  const threatInfo: ThreatInfo | null =
    (result.verdict === "detected" ||
      result.verdict === "suspicious" ||
      result.verdict === "critical") &&
    (result.threatName || result.findings.length > 0)
      ? {
          name: result.threatName || "Suspicious file",
          family: (result.threatName || "Analysis").split(".")[0] || "Unknown",
          severity: result.riskScore > 80 ? "critical" : result.riskScore > 50 ? "high" : "medium",
          description:
            result.findings.filter((f) => !f.startsWith("ClamAV skipped:")).join(" ") ||
            formatRiskScore(result.riskScore),
          recommendedActions: [
            result.verdict === "detected" ? "Quarantine the file immediately" : "Review before opening",
            "Do not execute or open this file unless you trust the source",
            "Report to your security team if unexpected",
          ],
        }
      : null;

  return (
    <div className="animate-in fade-in-0 space-y-4 duration-300">
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center gap-2">
            <FileText className="h-4 w-4 text-muted-foreground" />
            <CardTitle>File Information</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-3 text-sm">
            <div>
              <span className="font-mono text-xs text-muted-foreground">Name</span>
              <p className="truncate text-foreground">{result.fileName}</p>
            </div>
            <div>
              <span className="font-mono text-xs text-muted-foreground">Size</span>
              <p className="text-foreground">{formatFileSize(result.fileSize)}</p>
            </div>
            <div>
              <span className="font-mono text-xs text-muted-foreground">Type</span>
              <p className="text-foreground">{result.fileType}</p>
            </div>
            <div>
              <span className="font-mono text-xs text-muted-foreground">Path</span>
              <p className="truncate text-foreground">{result.filePath}</p>
            </div>
            <div className="col-span-2">
              <span className="font-mono text-xs text-muted-foreground">SHA-256</span>
              <p className="break-all font-mono text-xs text-foreground">{result.sha256}</p>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle>Engine Results</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 gap-2">
            {result.engines.map((engine) => {
              const isDeep = engine.engineName === "Deep Analysis";

              if (isDeep && result.deepChecks.length > 0) {
                return (
                  <div key={engine.engineName} className="overflow-hidden rounded-md bg-secondary">
                    <button
                      type="button"
                      onClick={() => setDeepExpanded((v) => !v)}
                      className="flex w-full items-start justify-between gap-2 px-3 py-2 text-left transition-colors hover:bg-white/[0.03]"
                      aria-expanded={deepExpanded}
                    >
                      <div className="min-w-0 flex-1 space-y-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-xs font-medium text-foreground">
                            {engine.engineName}
                          </span>
                          {!deepExpanded && (
                            <span className="text-[10px] text-muted-foreground">
                              Tap to view breakdown
                            </span>
                          )}
                        </div>
                        {engine.details && (
                          <p className="text-[11px] leading-snug text-muted-foreground">
                            {engine.details}
                          </p>
                        )}
                      </div>
                      <div className="flex shrink-0 items-center gap-2 pt-0.5">
                        <VerdictBadge verdict={engine.verdict} />
                        <ChevronDown
                          className={cn(
                            "h-4 w-4 text-muted-foreground transition-transform duration-200",
                            deepExpanded && "rotate-180"
                          )}
                        />
                      </div>
                    </button>

                    {deepExpanded && (
                      <div className="space-y-2 border-t border-border/50 px-3 py-3">
                        <p className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
                          What we checked in this file
                        </p>
                        {result.deepChecks.map((check) => (
                          <DeepCheckRow key={check.name} check={check} />
                        ))}
                      </div>
                    )}
                  </div>
                );
              }

              return (
                <div
                  key={engine.engineName}
                  className="space-y-1 rounded-md bg-secondary px-3 py-2"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-foreground">{engine.engineName}</span>
                    <VerdictBadge verdict={engine.verdict} />
                  </div>
                  {engine.details && (
                    <p className="text-[11px] leading-snug text-muted-foreground">{engine.details}</p>
                  )}
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {result.findings.length > 0 && result.verdict !== "clean" && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle>
              {result.verdict === "suspicious" ? "Why This Is Suspicious" : "Why This Was Flagged"}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2">
              {result.findings
                .filter((f) => !f.startsWith("ClamAV skipped:"))
                .map((finding, i) => (
                  <li key={i} className="flex gap-2 text-xs text-foreground">
                    <span className="shrink-0 text-amber-400">•</span>
                    <span>{finding}</span>
                  </li>
                ))}
            </ul>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardContent className="flex items-center gap-6 p-4">
          <div className="relative">
            <ConfidenceMeter score={result.riskScore} size={120} />
          </div>
          <div className="flex-1 space-y-2">
            <div className="flex items-center gap-2">
              {result.verdict === "clean" ? (
                <ShieldCheck className="h-6 w-6 text-emerald-400" />
              ) : (
                <ShieldX className="h-6 w-6 text-destructive" />
              )}
              <span className="font-display text-lg font-bold uppercase text-foreground">
                {result.verdict === "clean" ? "No Threats Found" : result.threatName || "Threat Detected"}
              </span>
            </div>
            <p className="text-sm text-muted-foreground">
              {result.verdict === "clean"
                ? "All scan engines report this file as safe."
                : result.verdict === "suspicious"
                  ? `${formatRiskScore(result.riskScore)} — suspicious indicators found. See details below.`
                  : `${formatRiskScore(result.riskScore)} — malicious indicators identified.`}
            </p>
          </div>
        </CardContent>
      </Card>

      {threatInfo && (
        <ThreatCard
          threat={threatInfo}
          onQuarantine={onQuarantine}
          onDelete={onDelete}
        />
      )}

      <div className="flex flex-wrap gap-2">
        {canExportReport && (
          <>
            <Button
              type="button"
              variant="outline"
              onClick={() => void handleExportJson()}
              disabled={exporting !== null}
            >
              <FileJson className="h-4 w-4" />
              {exporting === "json" ? "Exporting…" : "Export JSON"}
            </Button>
            <Button
              type="button"
              variant="outline"
              onClick={() => void handleExportPdf()}
              disabled={exporting !== null}
            >
              <Download className="h-4 w-4" />
              {exporting === "pdf" ? "Exporting…" : "Export PDF"}
            </Button>
          </>
        )}
        {result.verdict !== "clean" && onQuarantine && (
          <Button
            onClick={() => void onQuarantine()}
            disabled={actionLoading === "quarantine"}
          >
            <ShieldAlert className="h-4 w-4" />
            {actionLoading === "quarantine" ? "Quarantining..." : "Quarantine"}
          </Button>
        )}
        {onDelete && (
          <Button onClick={onDelete} variant="destructive">
            <Trash2 className="h-4 w-4" />
            Delete
          </Button>
        )}
        {result.verdict === "clean" && onTrust && (
          <Button
            onClick={() => void onTrust()}
            disabled={actionLoading === "trust"}
          >
            <CheckCircle className="h-4 w-4" />
            {actionLoading === "trust" ? "Trusting..." : "Trust File"}
          </Button>
        )}
        {onViewFolder && (
          <Button onClick={onViewFolder} variant="outline">
            <FolderOpen className="h-4 w-4" />
            View in Folder
          </Button>
        )}
      </div>
      {exportSuccess && (
        <p className="text-xs text-emerald-400/90">{exportSuccess}</p>
      )}
      {exportError && (
        <p className="text-xs text-destructive">{exportError}</p>
      )}
    </div>
  );
}
