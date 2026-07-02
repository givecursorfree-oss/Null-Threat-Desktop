import { create } from "zustand";
import type {
  ScanResult,
  ScanProgress,
  DashboardStats,
  EngineName,
} from "../types";

interface ScanState {
  isScanning: boolean;
  currentFile: string | null;
  progress: Record<EngineName, ScanProgress>;
  recentScans: ScanResult[];
  stats: DashboardStats;
  realtimeProtection: boolean;
  reportToView: ScanResult | null;

  setScanning: (scanning: boolean) => void;
  setCurrentFile: (file: string | null) => void;
  updateProgress: (engineName: EngineName, update: Partial<ScanProgress>) => void;
  resetProgress: () => void;
  addScanResult: (result: ScanResult) => void;
  setRecentScans: (scans: ScanResult[]) => void;
  refreshStats: (stats: DashboardStats) => void;
  setRealtimeProtection: (enabled: boolean) => void;
  setReportToView: (result: ScanResult | null) => void;
}

const defaultProgress: Record<EngineName, ScanProgress> = {
  "SHA256 Lookup": { engineName: "SHA256 Lookup", status: "waiting", progress: 0, elapsed: 0 },
  "ClamAV Engine": { engineName: "ClamAV Engine", status: "waiting", progress: 0, elapsed: 0 },
  "YARA Rules": { engineName: "YARA Rules", status: "waiting", progress: 0, elapsed: 0 },
  "Deep Analysis": { engineName: "Deep Analysis", status: "waiting", progress: 0, elapsed: 0 },
};

export const useScanStore = create<ScanState>((set) => ({
  isScanning: false,
  currentFile: null,
  progress: { ...defaultProgress },
  recentScans: [],
  stats: {
    filesScanned: 0,
    threatsBlocked: 0,
    filesQuarantined: 0,
    lastUpdated: new Date().toISOString(),
  },
  realtimeProtection: false,
  reportToView: null,

  setScanning: (scanning) => set({ isScanning: scanning }),

  setCurrentFile: (file) => set({ currentFile: file }),

  updateProgress: (engineName, update) =>
    set((state) => ({
      progress: {
        ...state.progress,
        [engineName]: { ...state.progress[engineName], ...update },
      },
    })),

  resetProgress: () => set({ progress: { ...defaultProgress } }),

  addScanResult: (result) =>
    set((state) => ({
      recentScans: [result, ...state.recentScans].slice(0, 50),
    })),

  setRecentScans: (scans) => set({ recentScans: scans }),

  refreshStats: (stats) => set({ stats }),

  setRealtimeProtection: (enabled) => set({ realtimeProtection: enabled }),

  setReportToView: (result) => set({ reportToView: result }),
}));
