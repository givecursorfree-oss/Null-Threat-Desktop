import {
  FileText,
  ShieldCheck,
  ShieldX,
  FolderOpen,
  Trash2,
  ShieldAlert,
  CheckCircle,
} from "lucide-react";
import ConfidenceMeter from "./ConfidenceMeter";
import ThreatCard from "./ThreatCard";
import VerdictBadge from "./VerdictBadge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { ScanResult as ScanResultType, ThreatInfo } from "../types";

interface ScanResultProps {
  result: ScanResultType;
  onQuarantine?: () => void;
  onDelete?: () => void;
  onTrust?: () => void;
  onViewFolder?: () => void;
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export default function ScanResult({
  result,
  onQuarantine,
  onDelete,
  onTrust,
  onViewFolder,
}: ScanResultProps) {
  const threatInfo: ThreatInfo | null =
    (result.verdict === "detected" || result.verdict === "suspicious") &&
    (result.threatName || result.findings.length > 0)
      ? {
          name: result.threatName || "Suspicious file",
          family: (result.threatName || "Analysis").split(".")[0] || "Unknown",
          severity: result.riskScore > 80 ? "critical" : result.riskScore > 50 ? "high" : "medium",
          description:
            result.findings.filter((f) => !f.startsWith("ClamAV skipped:")).join(" ") ||
            `Analysis flagged this file with ${result.riskScore}% risk confidence.`,
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
            {result.engines.map((engine) => (
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
            ))}
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
                  ? `Suspicious indicators found with ${result.riskScore}% risk confidence. See details below.`
                  : `Malicious content identified with ${result.riskScore}% confidence.`}
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

      <div className="flex gap-2">
        {result.verdict !== "clean" && onQuarantine && (
          <Button onClick={onQuarantine}>
            <ShieldAlert className="h-4 w-4" />
            Quarantine
          </Button>
        )}
        {onDelete && (
          <Button onClick={onDelete} variant="destructive">
            <Trash2 className="h-4 w-4" />
            Delete
          </Button>
        )}
        {result.verdict === "clean" && onTrust && (
          <Button onClick={onTrust}>
            <CheckCircle className="h-4 w-4" />
            Trust File
          </Button>
        )}
        {onViewFolder && (
          <Button onClick={onViewFolder} variant="outline">
            <FolderOpen className="h-4 w-4" />
            View in Folder
          </Button>
        )}
      </div>
    </div>
  );
}
