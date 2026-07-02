import { useState, useEffect, useCallback } from "react";
import type { QuarantinedFile } from "../types";
import {
  deleteQuarantinedFile,
  fetchQuarantineList,
  quarantineFile,
  restoreQuarantinedFile,
} from "../lib/api";

export function useQuarantine() {
  const [quarantinedFiles, setQuarantinedFiles] = useState<QuarantinedFile[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  const loadQuarantinedFiles = useCallback(async () => {
    try {
      const files = await fetchQuarantineList();
      setQuarantinedFiles(files);
    } catch (error) {
      console.error("Failed to load quarantined files:", error);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadQuarantinedFiles();
  }, [loadQuarantinedFiles]);

  const quarantine = useCallback(
    async (filePath: string, threatName: string, riskScore: number) => {
      try {
        await quarantineFile(filePath, threatName, riskScore);
        await loadQuarantinedFiles();
      } catch (error) {
        console.error("Failed to quarantine file:", error);
        throw error;
      }
    },
    [loadQuarantinedFiles]
  );

  const restoreFile = useCallback(
    async (id: string) => {
      try {
        await restoreQuarantinedFile(id);
        setQuarantinedFiles((prev) => prev.filter((f) => f.id !== id));
      } catch (error) {
        console.error("Failed to restore file:", error);
        throw error;
      }
    },
    []
  );

  const deleteFile = useCallback(async (id: string) => {
    try {
      await deleteQuarantinedFile(id);
      setQuarantinedFiles((prev) => prev.filter((f) => f.id !== id));
    } catch (error) {
      console.error("Failed to delete file:", error);
      throw error;
    }
  }, []);

  return {
    quarantinedFiles,
    isLoading,
    quarantineFile: quarantine,
    restoreFile,
    deleteFile,
    refresh: loadQuarantinedFiles,
  };
}
