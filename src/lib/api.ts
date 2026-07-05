import { invoke } from "@tauri-apps/api/core";
import type {
  DashboardStats,
  DeepAnalysisCheck,
  DependencyStatus,
  EngineName,
  EngineResult,
  QuarantinedFile,
  ScanHistoryEntry,
  ScanResult,
  SignatureStatus,
  HashIntelStatus,
  Verdict,
  VerdictBreakdown,
  WatchedFolder,
} from "../types";

/** Raw scan result shape from Rust backend (snake_case). */
interface RustScanResult {
  filepath: string;
  filename: string;
  file_size: number;
  sha256: string;
  risk_score: number;
  verdict: string;
  threat_name?: string | null;
  hash_result: string | { KnownMalware?: string };
  clam_result: string | { Detected?: string; Unavailable?: string };
  yara_result: { matched_rules: string[]; skipped?: string | null };
  deep_analysis: {
    entropy: number;
    high_entropy: boolean;
    magic_bytes: { mismatch: boolean; detected_type: string; expected_extension?: string };
    video_analysis: { anomalies: string[] };
    structure: { applicable: boolean; container: string; anomalies: string[] };
    metadata: { scanned: boolean; tool: string; anomalies: string[] };
    steganalysis: {
      analyzed: boolean;
      method: string;
      suspicious: boolean;
      chi_square_p?: number | null;
      rs_rate?: number | null;
      details: string[];
    };
  };
  engine_results: {
    hash_score: number;
    clam_score: number;
    yara_score: number;
    magic_score: number;
    entropy_score: number;
    video_score: number;
    structure_score: number;
    metadata_score: number;
    steg_score: number;
  };
  findings: string[];
  scan_source?: string;
}

interface RustDashboardStats {
  total_scans: number;
  threats_found: number;
  files_quarantined: number;
  scans_today: number;
  threats_today: number;
  avg_risk_score: number;
  last_scan_at?: string | null;
}

interface RustVerdictBreakdown {
  clean: number;
  suspicious: number;
  detected: number;
  critical: number;
}

interface RustDependencyStatus {
  clamav_available: boolean;
  yara_available: boolean;
  ffprobe_available: boolean;
  ffmpeg_available: boolean;
  exiftool_available: boolean;
  yara_rules_found: number;
  db_connected: boolean;
  malwarebazaar_hash_count: number;
}

interface RustQuarantineEntry {
  id: number;
  original_path: string;
  quarantine_path: string;
  threat_name: string;
  risk_score: number;
  scan_date: string;
  file_size: number;
}

interface RustWatchedFolder {
  id: number;
  path: string;
  enabled: boolean;
}

interface RustScanRecord {
  id: number;
  filename: string;
  filepath: string;
  sha256: string;
  timestamp: string;
  risk_score: number;
  verdict: string;
  threat_name?: string | null;
  action_taken: string;
}

export interface ScanProgressEvent {
  stage: string;
  progress: number;
  detail: string;
}

const STAGE_TO_ENGINE: Record<string, EngineName> = {
  hash: "SHA256 Lookup",
  clamav: "ClamAV Engine",
  yara: "YARA Rules",
  deep: "Deep Analysis",
};

export function mapProgressEvent(payload: ScanProgressEvent): {
  engineName: EngineName;
  status: "waiting" | "running" | "complete";
  progress: number;
} | null {
  if (payload.stage === "complete") {
    return {
      engineName: "Deep Analysis",
      status: "complete",
      progress: 100,
    };
  }

  const engineName = STAGE_TO_ENGINE[payload.stage];
  if (!engineName) return null;

  return {
    engineName,
    status: payload.progress >= 50 ? "complete" : "running",
    progress: payload.progress,
  };
}

export function mapVerdict(rustVerdict: string, riskScore: number): Verdict {
  if (rustVerdict === "whitelisted" || rustVerdict === "clean" || riskScore <= 20) {
    return "clean";
  }
  if (rustVerdict === "malware" || riskScore >= 81) {
    return "critical";
  }
  if (rustVerdict === "high_risk" || rustVerdict === "malicious" || riskScore >= 51) {
    return "detected";
  }
  if (rustVerdict === "suspicious" || riskScore >= 21) {
    return "suspicious";
  }
  return "unknown";
}

function engineVerdict(score: number, detected?: boolean): Verdict {
  if (detected || score >= 40) return "detected";
  if (score > 0) return "suspicious";
  return "clean";
}

function buildDeepChecks(raw: RustScanResult): DeepAnalysisCheck[] {
  const identityParts: string[] = [];
  if (raw.deep_analysis.magic_bytes.mismatch) {
    identityParts.push(
      `Extension '.${raw.deep_analysis.magic_bytes.expected_extension ?? "unknown"}' vs content '${raw.deep_analysis.magic_bytes.detected_type}'`
    );
  } else if (raw.deep_analysis.magic_bytes.detected_type) {
    identityParts.push(`Content type: ${raw.deep_analysis.magic_bytes.detected_type}`);
  }
  if (raw.deep_analysis.high_entropy) {
    identityParts.push(`High entropy (${raw.deep_analysis.entropy.toFixed(2)})`);
  }
  const identityScore = raw.engine_results.magic_score + raw.engine_results.entropy_score;
  const identityDetected = raw.deep_analysis.magic_bytes.mismatch || raw.deep_analysis.high_entropy;

  const structureParts: string[] = [
    ...raw.deep_analysis.structure.anomalies,
    ...raw.deep_analysis.video_analysis.anomalies,
  ];
  const structureScore = raw.engine_results.structure_score + raw.engine_results.video_score;
  const structureDetected =
    (raw.deep_analysis.structure.anomalies.length ?? 0) > 0 ||
    raw.deep_analysis.video_analysis.anomalies.length > 0;

  const metadataParts = raw.deep_analysis.metadata.anomalies;
  const metadataScore = raw.engine_results.metadata_score;
  const metadataDetected = metadataParts.length > 0;

  const stegParts = raw.deep_analysis.steganalysis.details.filter(
    (d) => raw.deep_analysis.steganalysis.suspicious || d.includes("skipped") || d.includes("not scored")
  );
  const stegScore = raw.engine_results.steg_score;
  const stegDetected = raw.deep_analysis.steganalysis.suspicious;

  return [
    {
      name: "Identity",
      verdict: engineVerdict(identityScore, identityDetected),
      score: identityScore,
      details:
        identityParts.length > 0
          ? identityParts.join("; ")
          : "File type and entropy look normal",
    },
    {
      name: "Structure",
      verdict: engineVerdict(structureScore, structureDetected),
      score: structureScore,
      details:
        structureParts.length > 0
          ? structureParts.join("; ")
          : raw.deep_analysis.structure.applicable
            ? "Container structure validated"
            : "No structural parser applied for this file type",
    },
    {
      name: "Metadata",
      verdict: engineVerdict(metadataScore, metadataDetected),
      score: metadataScore,
      details:
        metadataParts.length > 0
          ? metadataParts.join("; ")
          : raw.deep_analysis.metadata.scanned
            ? `No suspicious metadata (${raw.deep_analysis.metadata.tool})`
            : "Metadata scan not applicable",
    },
    {
      name: "Steganography",
      verdict: engineVerdict(stegScore, stegDetected),
      score: stegScore,
      details:
        stegParts.length > 0
          ? stegParts.join("; ")
          : raw.deep_analysis.steganalysis.analyzed
            ? "No statistical signs of LSB steganography"
            : "Steganalysis not applicable for this file type",
    },
  ];
}

function buildEngineDetails(raw: RustScanResult): EngineResult[] {
  const hashDetected =
    typeof raw.hash_result === "object" && raw.hash_result !== null && "KnownMalware" in raw.hash_result;
  const hashName =
    hashDetected && typeof raw.hash_result === "object"
      ? (raw.hash_result as { KnownMalware: string }).KnownMalware
      : null;
  const clamDetected =
    typeof raw.clam_result === "object" && raw.clam_result !== null && "Detected" in raw.clam_result;
  const clamName =
    clamDetected && typeof raw.clam_result === "object"
      ? (raw.clam_result as { Detected: string }).Detected
      : null;
  const clamUnavailable =
    typeof raw.clam_result === "object" &&
    raw.clam_result !== null &&
    "Unavailable" in raw.clam_result;
  const clamUnavailableReason = clamUnavailable
    ? (raw.clam_result as { Unavailable: string }).Unavailable
    : null;

  const deepFlags: string[] = [];
  if (raw.deep_analysis.magic_bytes.mismatch) {
    deepFlags.push(
      `Extension '.${raw.deep_analysis.magic_bytes.expected_extension ?? "unknown"}' vs content '${raw.deep_analysis.magic_bytes.detected_type}'`
    );
  }
  if (raw.deep_analysis.high_entropy) {
    deepFlags.push(`High entropy ${raw.deep_analysis.entropy.toFixed(2)}`);
  }
  if (raw.deep_analysis.video_analysis.anomalies.length > 0) {
    deepFlags.push(...raw.deep_analysis.video_analysis.anomalies);
  }
  if (raw.deep_analysis.structure?.anomalies?.length > 0) {
    deepFlags.push(...raw.deep_analysis.structure.anomalies);
  }
  if (raw.deep_analysis.metadata?.anomalies?.length > 0) {
    deepFlags.push(...raw.deep_analysis.metadata.anomalies);
  }
  if (raw.deep_analysis.steganalysis?.suspicious) {
    deepFlags.push(...raw.deep_analysis.steganalysis.details);
  }

  const deepScore =
    raw.engine_results.magic_score +
    raw.engine_results.entropy_score +
    raw.engine_results.video_score +
    (raw.engine_results.structure_score ?? 0) +
    (raw.engine_results.metadata_score ?? 0) +
    (raw.engine_results.steg_score ?? 0);
  const deepDetected =
    raw.deep_analysis.magic_bytes.mismatch ||
    raw.deep_analysis.high_entropy ||
    raw.deep_analysis.video_analysis.anomalies.length > 0 ||
    (raw.deep_analysis.structure?.anomalies?.length ?? 0) > 0 ||
    (raw.deep_analysis.metadata?.anomalies?.length ?? 0) > 0 ||
    (raw.deep_analysis.steganalysis?.suspicious ?? false);

  return [
    {
      engineName: "SHA256 Lookup",
      status: "complete",
      verdict: engineVerdict(raw.engine_results.hash_score, hashDetected),
      elapsed: 0,
      details: hashDetected
        ? `Known malware hash: ${hashName}`
        : "Hash not in malware database",
    },
    {
      engineName: "ClamAV Engine",
      status: "complete",
      verdict: clamUnavailable
        ? "skipped"
        : engineVerdict(raw.engine_results.clam_score, clamDetected),
      elapsed: 0,
      details: clamDetected
        ? `Signature match: ${clamName}`
        : clamUnavailable
          ? clamUnavailableReason || "ClamAV not installed"
          : "No known virus signatures matched",
    },
    {
      engineName: "YARA Rules",
      status: "complete",
      verdict: raw.yara_result.skipped
        ? "skipped"
        : engineVerdict(raw.engine_results.yara_score, raw.yara_result.matched_rules.length > 0),
      elapsed: 0,
      details: raw.yara_result.skipped
        ? raw.yara_result.skipped
        : raw.yara_result.matched_rules.length > 0
          ? raw.yara_result.matched_rules.join(", ")
          : "No custom threat rules matched",
    },
    {
      engineName: "Deep Analysis",
      status: "complete",
      verdict: engineVerdict(deepScore, deepDetected),
      elapsed: 0,
      details: deepFlags.length > 0 ? deepFlags.join("; ") : "No structural anomalies",
    },
  ];
}

export function mapScanResult(raw: RustScanResult): ScanResult {
  const engines = buildEngineDetails(raw);
  const deepChecks = buildDeepChecks(raw);

  return {
    id: crypto.randomUUID(),
    fileName: raw.filename,
    filePath: raw.filepath,
    fileSize: raw.file_size ?? 0,
    fileType: raw.deep_analysis.magic_bytes.detected_type || "unknown",
    sha256: raw.sha256,
    timestamp: new Date().toISOString(),
    riskScore: raw.risk_score,
    verdict: mapVerdict(raw.verdict, raw.risk_score),
    threatName: raw.threat_name ?? undefined,
    engines,
    deepChecks,
    findings: raw.findings ?? [],
    scanSource: raw.scan_source,
  };
}

function mapDashboardStats(raw: RustDashboardStats): DashboardStats {
  return {
    filesScanned: raw.total_scans,
    threatsBlocked: raw.threats_found,
    filesQuarantined: raw.files_quarantined,
    lastUpdated: raw.last_scan_at ?? new Date().toISOString(),
  };
}

function mapVerdictBreakdown(raw: RustVerdictBreakdown): VerdictBreakdown {
  return {
    clean: raw.clean,
    suspicious: raw.suspicious,
    detected: raw.detected,
    critical: raw.critical,
  };
}

function mapDependencies(raw: RustDependencyStatus): DependencyStatus {
  return {
    clamavAvailable: raw.clamav_available,
    yaraAvailable: raw.yara_available,
    ffprobeAvailable: raw.ffprobe_available,
    ffmpegAvailable: raw.ffmpeg_available,
    exiftoolAvailable: raw.exiftool_available,
    yaraRulesFound: raw.yara_rules_found,
    dbConnected: raw.db_connected,
    malwarebazaarHashCount: raw.malwarebazaar_hash_count,
  };
}

function mapQuarantineEntry(raw: RustQuarantineEntry): QuarantinedFile {
  const fileName = raw.original_path.split(/[\\/]/).pop() || "Unknown";
  return {
    id: String(raw.id),
    fileName,
    filePath: raw.quarantine_path,
    originalPath: raw.original_path,
    threatName: raw.threat_name,
    riskScore: raw.risk_score,
    fileSize: raw.file_size,
    quarantinedAt: raw.scan_date,
  };
}

function mapWatchedFolder(raw: RustWatchedFolder): WatchedFolder {
  return {
    id: String(raw.id),
    path: raw.path,
    enabled: raw.enabled,
  };
}

function mapHistoryEntry(raw: RustScanRecord): ScanHistoryEntry {
  return {
    id: String(raw.id),
    fileName: raw.filename,
    filePath: raw.filepath,
    date: raw.timestamp,
    riskScore: raw.risk_score,
    verdict: mapVerdict(raw.verdict, raw.risk_score),
    actionTaken: raw.action_taken,
  };
}

export function mapHistoryToScanResult(entry: ScanHistoryEntry): ScanResult {
  return {
    id: entry.id,
    fileName: entry.fileName,
    filePath: entry.filePath,
    fileSize: 0,
    fileType: "unknown",
    sha256: "",
    timestamp: entry.date,
    riskScore: entry.riskScore,
    verdict: entry.verdict,
    engines: [],
    deepChecks: [],
    findings: [],
  };
}

export async function pickScanFile(): Promise<string | null> {
  return invoke<string | null>("pick_scan_file");
}

export async function pickWatchedFolder(): Promise<string | null> {
  return invoke<string | null>("pick_watched_folder");
}

export async function scanFile(path: string): Promise<ScanResult> {
  const raw = await invoke<RustScanResult>("scan_file", { path });
  return mapScanResult(raw);
}

export async function fetchDashboardStats(): Promise<DashboardStats> {
  const raw = await invoke<RustDashboardStats>("get_dashboard_stats");
  return mapDashboardStats(raw);
}

export async function fetchVerdictBreakdown(): Promise<VerdictBreakdown> {
  const raw = await invoke<RustVerdictBreakdown>("get_verdict_breakdown");
  return mapVerdictBreakdown(raw);
}

export async function fetchRealtimeProtection(): Promise<boolean> {
  return invoke<boolean>("get_realtime_protection");
}

export async function fetchDependencies(): Promise<DependencyStatus> {
  const raw = await invoke<RustDependencyStatus>("check_dependencies");
  return mapDependencies(raw);
}

export async function syncYaraRules(): Promise<number> {
  return invoke<number>("sync_yara_rules");
}

export async function fetchQuarantineList(): Promise<QuarantinedFile[]> {
  const raw = await invoke<RustQuarantineEntry[]>("get_quarantine_list");
  return raw.map(mapQuarantineEntry);
}

export async function quarantineFile(
  path: string,
  threat: string,
  score: number
): Promise<string> {
  return invoke<string>("quarantine_file", { path, threat, score });
}

export async function restoreQuarantinedFile(id: string): Promise<void> {
  await invoke("restore_file", { id: Number(id) });
}

export async function deleteQuarantinedFile(id: string): Promise<void> {
  await invoke("delete_quarantined", { id: Number(id) });
}

export async function fetchWatchedFolders(): Promise<WatchedFolder[]> {
  const raw = await invoke<RustWatchedFolder[]>("get_watched_folders");
  return raw.map(mapWatchedFolder);
}

export async function addWatchedFolder(path: string): Promise<WatchedFolder> {
  const id = await invoke<number>("add_watched_folder", { path });
  return { id: String(id), path, enabled: true };
}

export async function removeWatchedFolder(id: string): Promise<void> {
  await invoke("remove_watched_folder", { id: Number(id) });
}

export async function toggleWatchedFolder(id: string, enabled: boolean): Promise<void> {
  await invoke("toggle_watched_folder", { id: Number(id), enabled });
}

export async function toggleRealtimeProtection(enabled: boolean): Promise<void> {
  await invoke("toggle_realtime_protection", { enabled });
}

export async function addToWhitelist(path: string, sha256: string): Promise<void> {
  await invoke("add_to_whitelist", { path, sha256 });
}

export async function removeFromWhitelist(id: number): Promise<void> {
  await invoke("remove_from_whitelist", { id });
}

export async function exportHistoryCsv(): Promise<string> {
  return invoke<string>("export_history_csv");
}

export async function fetchScanHistory(limit = 100): Promise<ScanHistoryEntry[]> {
  const raw = await invoke<RustScanRecord[]>("get_scan_history", { limit });
  return raw.map(mapHistoryEntry);
}

export async function fetchWhitelist() {
  return invoke<Array<{ id: number; path: string; sha256: string; added_date: string }>>(
    "get_whitelist"
  );
}

interface RustSignatureStatus {
  updating: boolean;
  last_updated: string | null;
  database_complete: boolean;
  update_due: boolean;
  message: string;
}

function mapSignatureStatus(raw: RustSignatureStatus): SignatureStatus {
  return {
    updating: raw.updating,
    lastUpdated: raw.last_updated,
    databaseComplete: raw.database_complete,
    updateDue: raw.update_due,
    message: raw.message,
  };
}

export async function fetchSignatureStatus(): Promise<SignatureStatus> {
  const raw = await invoke<RustSignatureStatus>("get_signature_status");
  return mapSignatureStatus(raw);
}

export async function updateSignatures(force = true): Promise<SignatureStatus> {
  const raw = await invoke<RustSignatureStatus>("update_signatures", { force });
  return mapSignatureStatus(raw);
}

interface RustHashIntelStatus {
  updating: boolean;
  last_updated: string | null;
  hash_count: number;
  update_due: boolean;
  message: string;
}

function mapHashIntelStatus(raw: RustHashIntelStatus): HashIntelStatus {
  return {
    updating: raw.updating,
    lastUpdated: raw.last_updated,
    hashCount: raw.hash_count,
    updateDue: raw.update_due,
    message: raw.message,
  };
}

export async function fetchHashIntelStatus(): Promise<HashIntelStatus> {
  const raw = await invoke<RustHashIntelStatus>("get_hash_intel_status");
  return mapHashIntelStatus(raw);
}

export async function updateHashIntel(force = true): Promise<HashIntelStatus> {
  const raw = await invoke<RustHashIntelStatus>("update_hash_intel", { force });
  return mapHashIntelStatus(raw);
}
