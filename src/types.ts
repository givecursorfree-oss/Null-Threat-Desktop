export interface ScanResult {
  id: string;
  fileName: string;
  filePath: string;
  fileSize: number;
  fileType: string;
  sha256: string;
  timestamp: string;
  riskScore: number;
  verdict: Verdict;
  threatName?: string;
  engines: EngineResult[];
  findings: string[];
  scanSource?: string;
}

export interface EngineResult {
  engineName: EngineName;
  status: EngineStatus;
  verdict: Verdict;
  elapsed: number;
  details?: string;
}

export type EngineName = "SHA256 Lookup" | "ClamAV Engine" | "YARA Rules" | "Deep Analysis";

export type EngineStatus = "waiting" | "running" | "complete";

export type Verdict = "clean" | "detected" | "suspicious" | "critical" | "unknown" | "skipped";

export interface ScanProgress {
  engineName: EngineName;
  status: EngineStatus;
  progress: number;
  elapsed: number;
}

export interface QuarantinedFile {
  id: string;
  fileName: string;
  filePath: string;
  originalPath: string;
  threatName: string;
  riskScore: number;
  fileSize: number;
  quarantinedAt: string;
}

export interface DashboardStats {
  filesScanned: number;
  threatsBlocked: number;
  filesQuarantined: number;
  lastUpdated: string;
}

export interface VerdictBreakdown {
  clean: number;
  suspicious: number;
  detected: number;
  critical: number;
}

export interface DependencyStatus {
  clamavAvailable: boolean;
  yaraAvailable: boolean;
  ffprobeAvailable: boolean;
  yaraRulesFound: number;
  dbConnected: boolean;
  malwarebazaarHashCount: number;
}

export interface HashIntelStatus {
  updating: boolean;
  lastUpdated: string | null;
  hashCount: number;
  updateDue: boolean;
  message: string;
}

export interface HashIntelUpdateEvent {
  status: "idle" | "checking" | "downloading" | "complete" | "failed";
  message: string;
  progress: number;
}

export interface SignatureStatus {
  updating: boolean;
  lastUpdated: string | null;
  databaseComplete: boolean;
  updateDue: boolean;
  message: string;
}

export interface SignatureUpdateEvent {
  status: "idle" | "checking" | "downloading" | "complete" | "failed";
  message: string;
  progress: number;
}

export interface WatchedFolder {
  id: string;
  path: string;
  enabled: boolean;
}

export interface ThreatInfo {
  name: string;
  family: string;
  severity: "low" | "medium" | "high" | "critical";
  description: string;
  recommendedActions: string[];
}

export interface ScanHistoryEntry {
  id: string;
  fileName: string;
  filePath: string;
  date: string;
  riskScore: number;
  verdict: Verdict;
  actionTaken: string;
}
