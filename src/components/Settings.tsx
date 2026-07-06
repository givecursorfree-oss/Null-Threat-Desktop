import { useState, useEffect } from "react";
import { FolderPlus, Trash2, Download, Eye, EyeOff, AlertCircle, RefreshCw, DatabaseZap } from "lucide-react";
import {
  exportHistoryCsv,
  clearScanHistory,
  fetchDashboardStats,
  addToWhitelist,
  toggleRealtimeProtection,
  pickWatchedFolder,
  fetchDependencies,
  fetchWhitelist,
  removeFromWhitelist,
  pickScanFile,
  fetchSignatureStatus,
  updateSignatures,
  fetchHashIntelStatus,
  updateHashIntel,
  syncYaraRules,
} from "../lib/api";
import { useWatcher } from "../hooks/useWatcher";
import { useScanStore } from "../store/scanStore";
import { useConsent } from "@/components/onboarding/ConsentProvider";
import PageHeader from "./PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import type { DependencyStatus, HashIntelStatus, SignatureStatus } from "../types";

export default function Settings() {
  const { watchedFolders, addFolder, removeFolder, toggleFolder } = useWatcher();
  const { realtimeProtection, setRealtimeProtection, setRecentScans, refreshStats } = useScanStore();
  const { requestFolderWatchConsent } = useConsent();
  const [whitelist, setWhitelist] = useState<
    Array<{ id: number; path: string; sha256: string }>
  >([]);
  const [deps, setDeps] = useState<DependencyStatus | null>(null);
  const [signatureStatus, setSignatureStatus] = useState<SignatureStatus | null>(null);
  const [hashIntelStatus, setHashIntelStatus] = useState<HashIntelStatus | null>(null);
  const [isUpdatingSignatures, setIsUpdatingSignatures] = useState(false);
  const [isUpdatingHashIntel, setIsUpdatingHashIntel] = useState(false);
  const [isSyncingYaraRules, setIsSyncingYaraRules] = useState(false);
  const [showClearHistoryConfirm, setShowClearHistoryConfirm] = useState(false);
  const [isClearingHistory, setIsClearingHistory] = useState(false);
  const [clearHistorySuccess, setClearHistorySuccess] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchDependencies()
      .then(setDeps)
      .catch(() => {});
    fetchWhitelist()
      .then(setWhitelist)
      .catch(() => {});
    fetchSignatureStatus()
      .then(setSignatureStatus)
      .catch(() => {});
    fetchHashIntelStatus()
      .then(setHashIntelStatus)
      .catch(() => {});
  }, []);

  const handleSyncYaraRules = async () => {
    setError(null);
    setIsSyncingYaraRules(true);
    try {
      const count = await syncYaraRules();
      const next = await fetchDependencies();
      setDeps(next);
      if (count === 0) {
        setError("Could not install YARA rules from the bundled app files.");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setIsSyncingYaraRules(false);
    }
  };

  const handleAddFolder = async () => {
    setError(null);
    const granted = await requestFolderWatchConsent();
    if (!granted) return;

    try {
      const selected = await pickWatchedFolder();
      if (selected) {
        await addFolder(selected);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleAddWhitelist = async () => {
    setError(null);
    try {
      const path = await pickScanFile();
      if (path) {
        await addToWhitelist(path, "");
        const list = await fetchWhitelist();
        setWhitelist(list);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleRemoveWhitelist = async (id: number) => {
    await removeFromWhitelist(id);
    const list = await fetchWhitelist();
    setWhitelist(list);
  };

  const handleExportHistory = async () => {
    try {
      const csv = await exportHistoryCsv();
      const blob = new Blob([csv], { type: "text/csv" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `null-threat-history-${Date.now()}.csv`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleClearHistory = async () => {
    setError(null);
    setClearHistorySuccess(null);
    setIsClearingHistory(true);
    try {
      const deleted = await clearScanHistory();
      setRecentScans([]);
      refreshStats(await fetchDashboardStats());
      setShowClearHistoryConfirm(false);
      setClearHistorySuccess(
        deleted > 0
          ? `Permanently removed ${deleted.toLocaleString()} scan record${deleted === 1 ? "" : "s"} from the local database.`
          : "Scan history was already empty."
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setIsClearingHistory(false);
    }
  };

  const handleToggleProtection = async () => {
    const newState = !realtimeProtection;
    setError(null);

    if (newState) {
      const granted = await requestFolderWatchConsent();
      if (!granted) return;
    }

    try {
      await toggleRealtimeProtection(newState);
      setRealtimeProtection(newState);
    } catch (err) {
      setRealtimeProtection(!newState);
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleUpdateSignatures = async () => {
    setError(null);
    setIsUpdatingSignatures(true);
    try {
      const status = await updateSignatures(true);
      setSignatureStatus(status);
      const refreshed = await fetchDependencies();
      setDeps(refreshed);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setIsUpdatingSignatures(false);
    }
  };

  const handleUpdateHashIntel = async () => {
    setError(null);
    setIsUpdatingHashIntel(true);
    try {
      const status = await updateHashIntel(true);
      setHashIntelStatus(status);
      const refreshed = await fetchDependencies();
      setDeps(refreshed);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setIsUpdatingHashIntel(false);
    }
  };

  const formatSignatureDate = (iso: string | null) => {
    if (!iso) return "Never";
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return "Unknown";
    return date.toLocaleString();
  };

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <PageHeader
        title="Settings"
        description="Protection, watched folders, and engine dependencies."
      />

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {deps && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle>Engine Status</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-1.5 text-xs text-muted-foreground">
              <li>ClamAV: {deps.clamavAvailable ? "bundled" : "not found"}</li>
              <li>YARA: {deps.yaraAvailable ? "bundled" : "not found"}</li>
              <li>ffprobe: {deps.ffprobeAvailable ? "bundled" : "not found"}</li>
              <li>ffmpeg: {deps.ffmpegAvailable ? "bundled" : "not found"}</li>
              <li>exiftool: {deps.exiftoolAvailable ? "bundled" : "not found"}</li>
              <li className={deps.yaraRulesFound === 0 ? "text-amber-300" : undefined}>
                YARA rules loaded:{" "}
                {deps.yaraRulesFound > 0
                  ? deps.yaraRulesFound.toLocaleString()
                  : "none — restart the app or reinstall"}
              </li>
              <li>
                MalwareBazaar hashes (recent):{" "}
                {deps.malwarebazaarHashCount > 0
                  ? deps.malwarebazaarHashCount.toLocaleString()
                  : "none — update when online"}
              </li>
              <li>Database: {deps.dbConnected ? "connected" : "error"}</li>
            </ul>
            {deps.yaraRulesFound === 0 && deps.yaraAvailable && (
              <div className="mt-3 space-y-2">
                <p className="text-xs text-amber-300/90">
                  YARA is installed but rule files are missing from app data. Click below to
                  install the bundled rules — no restart required.
                </p>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  onClick={() => void handleSyncYaraRules()}
                  disabled={isSyncingYaraRules}
                >
                  <RefreshCw className={`h-3 w-3 ${isSyncingYaraRules ? "animate-spin" : ""}`} />
                  {isSyncingYaraRules ? "Installing rules..." : "Install YARA rules"}
                </Button>
              </div>
            )}
            {deps.malwarebazaarHashCount > 0 && deps.malwarebazaarHashCount < 2000 && (
              <p className="mt-3 text-xs text-muted-foreground">
                The free MalwareBazaar feed includes recent samples (last ~48 hours). Use
                &quot;Update hashes&quot; below when online to refresh this list daily.
              </p>
            )}
          </CardContent>
        </Card>
      )}

      <Card>
        <CardContent className="flex items-center justify-between gap-4 p-4">
          <div>
            <h3 className="font-display text-sm font-semibold text-foreground">
              MalwareBazaar Hash Intelligence
            </h3>
            <p className="mt-0.5 text-xs text-muted-foreground">
              Null Threat works fully offline. When you are online, refresh known-malware SHA256
              hashes daily for better detection. Internet is only needed for this step.
            </p>
            {hashIntelStatus && (
              <p className="mt-2 text-xs text-muted-foreground">
                {hashIntelStatus.hashCount > 0
                  ? `${hashIntelStatus.hashCount.toLocaleString()} hashes loaded`
                  : "No hashes loaded yet"}
                {" · "}
                Last updated: {formatSignatureDate(hashIntelStatus.lastUpdated)}
                {hashIntelStatus.updateDue ? " · refresh recommended" : ""}
              </p>
            )}
          </div>
          <Button
            type="button"
            onClick={handleUpdateHashIntel}
            variant="outline"
            size="sm"
            disabled={isUpdatingHashIntel || hashIntelStatus?.updating}
          >
            <RefreshCw className={isUpdatingHashIntel ? "h-3 w-3 animate-spin" : "h-3 w-3"} />
            {isUpdatingHashIntel ? "Updating..." : "Update hashes"}
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="flex items-center justify-between gap-4 p-4">
          <div>
            <h3 className="font-display text-sm font-semibold text-foreground">
              ClamAV Signatures (optional)
            </h3>
            <p className="mt-0.5 text-xs text-muted-foreground">
              Optional virus definitions for the ClamAV engine. Update manually when online — not
              required for offline scanning with bundled definitions.
            </p>
            {signatureStatus && (
              <p className="mt-2 text-xs text-muted-foreground">
                Last updated: {formatSignatureDate(signatureStatus.lastUpdated)}
                {signatureStatus.updateDue ? " · refresh due" : " · up to date"}
              </p>
            )}
          </div>
          <Button
            type="button"
            onClick={handleUpdateSignatures}
            variant="outline"
            size="sm"
            disabled={isUpdatingSignatures || signatureStatus?.updating}
          >
            <RefreshCw className={isUpdatingSignatures ? "h-3 w-3 animate-spin" : "h-3 w-3"} />
            {isUpdatingSignatures ? "Updating..." : "Update now"}
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="flex items-center justify-between p-4">
          <div>
            <Label htmlFor="realtime-protection" className="font-display text-sm font-semibold">
              Real-time Protection
            </Label>
            <p className="mt-0.5 text-xs text-muted-foreground">
              Scan new files in watched folders. You will be asked before monitoring starts.
            </p>
          </div>
          <Switch
            id="realtime-protection"
            checked={realtimeProtection}
            onCheckedChange={handleToggleProtection}
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle>Watched Folders</CardTitle>
            <Button type="button" onClick={handleAddFolder} variant="outline" size="sm">
              <FolderPlus className="h-3 w-3" />
              Add Folder
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {watchedFolders.length === 0 ? (
            <p className="py-2 text-xs text-muted-foreground">
              No folders watched. Add Downloads or Desktop to test real-time scanning.
            </p>
          ) : (
            <ul className="space-y-2">
              {watchedFolders.map((folder) => (
                <li
                  key={folder.id}
                  className="flex items-center gap-3 rounded-md bg-secondary px-3 py-2"
                >
                  <button
                    type="button"
                    onClick={() => toggleFolder(folder.id, !folder.enabled)}
                    className={folder.enabled ? "text-foreground" : "text-muted-foreground"}
                    title={folder.enabled ? "Disable" : "Enable"}
                    aria-label={folder.enabled ? "Disable folder" : "Enable folder"}
                  >
                    {folder.enabled ? <Eye className="h-4 w-4" /> : <EyeOff className="h-4 w-4" />}
                  </button>
                  <span className="flex-1 truncate text-sm text-foreground">{folder.path}</span>
                  <Button
                    type="button"
                    onClick={() => removeFolder(folder.id)}
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8 text-muted-foreground hover:text-destructive"
                    aria-label="Remove folder"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle>Whitelist</CardTitle>
            <Button type="button" onClick={handleAddWhitelist} variant="outline" size="sm">
              Add File
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {whitelist.length === 0 ? (
            <p className="py-2 text-xs text-muted-foreground">No whitelisted files</p>
          ) : (
            <ul className="space-y-1">
              {whitelist.map((entry) => (
                <li
                  key={entry.id}
                  className="flex items-center gap-2 rounded-md bg-secondary px-3 py-2"
                >
                  <span className="flex-1 truncate text-xs text-foreground">{entry.path}</span>
                  <Button
                    type="button"
                    onClick={() => handleRemoveWhitelist(entry.id)}
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7 text-muted-foreground hover:text-destructive"
                    aria-label="Remove from whitelist"
                  >
                    <Trash2 className="h-3 w-3" />
                  </Button>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle>Data &amp; Privacy</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="rounded-md border border-border/60 bg-secondary/40 px-3 py-3 text-xs leading-relaxed text-muted-foreground">
            <p className="font-medium text-foreground">Your data stays on this device</p>
            <ul className="mt-2 list-inside list-disc space-y-1.5">
              <li>
                Scans run locally. Null Threat does not upload files, scan results, or usage
                telemetry to our servers.
              </li>
              <li>
                Optional updates (malware hash lists, ClamAV signatures) download public threat
                feeds only when you click update in Settings. No personal data is sent.
              </li>
              <li>
                Quarantine encryption keys are stored in your OS keychain (Windows Credential
                Manager, macOS Keychain, Linux Secret Service) when available.
              </li>
              <li>
                Local SQLite database{" "}
                <span className="font-mono text-foreground">nullthreat.db</span> stores: scan
                history (file paths, SHA-256, verdicts, engine scores), quarantine records,
                watched folders, whitelist entries, and app settings. Nothing is synced to the
                cloud.
              </li>
            </ul>
          </div>

          <div className="flex items-center justify-between gap-4">
            <div>
              <h3 className="font-display text-sm font-semibold text-foreground">
                Export Scan History
              </h3>
              <p className="mt-0.5 text-xs text-muted-foreground">
                Download all scan records as CSV before clearing data.
              </p>
            </div>
            <Button type="button" onClick={handleExportHistory} variant="outline" size="sm">
              <Download className="h-3 w-3" />
              Export
            </Button>
          </div>

          <div className="border-t border-border/60 pt-4">
            <div className="flex items-center justify-between gap-4">
              <div>
                <h3 className="font-display text-sm font-semibold text-destructive">
                  Clear Scan History
                </h3>
                <p className="mt-0.5 text-xs text-muted-foreground">
                  Permanently delete every scan record from the local SQLite database on this
                  device. Quarantine, whitelist, and signature data are not affected. This cannot
                  be undone.
                </p>
              </div>
              <Button
                type="button"
                onClick={() => setShowClearHistoryConfirm(true)}
                variant="destructive"
                size="sm"
              >
                <DatabaseZap className="h-3 w-3" />
                Clear all
              </Button>
            </div>
            {clearHistorySuccess && (
              <p className="mt-2 text-xs text-emerald-400/90">{clearHistorySuccess}</p>
            )}
          </div>
        </CardContent>
      </Card>

      {showClearHistoryConfirm && (
        <div
          className="fixed inset-0 z-50 flex animate-in fade-in-0 items-center justify-center bg-background/80 duration-200"
          onClick={() => !isClearingHistory && setShowClearHistoryConfirm(false)}
        >
          <Card
            className="mx-4 w-full max-w-sm animate-in fade-in-0 zoom-in-95 duration-200"
            onClick={(e) => e.stopPropagation()}
          >
            <CardContent className="space-y-4 p-4">
              <h3 className="font-display text-sm font-semibold text-foreground">
                Clear scan history permanently?
              </h3>
              <p className="text-xs text-muted-foreground">
                All scan history rows will be deleted from{" "}
                <span className="font-mono text-foreground">nullthreat.db</span> and disk space
                will be reclaimed. Export first if you need a backup. Quarantined files and your
                whitelist will stay intact.
              </p>
              <div className="flex justify-end gap-2">
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  disabled={isClearingHistory}
                  onClick={() => setShowClearHistoryConfirm(false)}
                >
                  Cancel
                </Button>
                <Button
                  type="button"
                  variant="destructive"
                  size="sm"
                  disabled={isClearingHistory}
                  onClick={() => void handleClearHistory()}
                >
                  {isClearingHistory ? "Clearing..." : "Yes, delete permanently"}
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
