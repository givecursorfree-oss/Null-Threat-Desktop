import { useState, useEffect, useCallback } from "react";
import { listen } from "@tauri-apps/api/event";
import type { WatchedFolder } from "../types";
import {
  addWatchedFolder,
  fetchWatchedFolders,
  removeWatchedFolder,
  toggleWatchedFolder,
} from "../lib/api";

export function useWatcher() {
  const [watchedFolders, setWatchedFolders] = useState<WatchedFolder[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  const loadWatchedFolders = useCallback(async () => {
    try {
      const folders = await fetchWatchedFolders();
      setWatchedFolders(folders);
    } catch (error) {
      console.error("Failed to load watched folders:", error);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadWatchedFolders();

    const unlistenDetected = listen<{ path: string }>("file-detected", () => {
      void loadWatchedFolders();
    });

    return () => {
      unlistenDetected.then((fn) => fn());
    };
  }, [loadWatchedFolders]);

  const addFolder = useCallback(
    async (path: string) => {
      await addWatchedFolder(path);
      await loadWatchedFolders();
    },
    [loadWatchedFolders]
  );

  const removeFolder = useCallback(
    async (id: string) => {
      await removeWatchedFolder(id);
      await loadWatchedFolders();
    },
    [loadWatchedFolders]
  );

  const toggleFolder = useCallback(
    async (id: string, enabled: boolean) => {
      await toggleWatchedFolder(id, enabled);
      await loadWatchedFolders();
    },
    [loadWatchedFolders]
  );

  return {
    watchedFolders,
    isLoading,
    addFolder,
    removeFolder,
    toggleFolder,
    refresh: loadWatchedFolders,
  };
}
