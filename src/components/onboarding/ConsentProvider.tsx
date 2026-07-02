import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { grantFolderWatchConsent, hasFolderWatchConsent } from "@/lib/consent";
import FolderWatchConsentModal from "./FolderWatchConsentModal";

interface ConsentContextValue {
  requestFolderWatchConsent: () => Promise<boolean>;
}

const ConsentContext = createContext<ConsentContextValue | null>(null);

export function ConsentProvider({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const resolverRef = useRef<((granted: boolean) => void) | null>(null);

  const requestFolderWatchConsent = useCallback(async () => {
    if (hasFolderWatchConsent()) {
      return true;
    }

    return new Promise<boolean>((resolve) => {
      resolverRef.current = resolve;
      setOpen(true);
    });
  }, []);

  const handleAllow = useCallback(() => {
    grantFolderWatchConsent();
    resolverRef.current?.(true);
    resolverRef.current = null;
    setOpen(false);
  }, []);

  const handleDecline = useCallback(() => {
    resolverRef.current?.(false);
    resolverRef.current = null;
    setOpen(false);
  }, []);

  const value = useMemo(
    () => ({ requestFolderWatchConsent }),
    [requestFolderWatchConsent]
  );

  return (
    <ConsentContext.Provider value={value}>
      {children}
      <FolderWatchConsentModal open={open} onAllow={handleAllow} onDecline={handleDecline} />
    </ConsentContext.Provider>
  );
}

export function useConsent() {
  const context = useContext(ConsentContext);
  if (!context) {
    throw new Error("useConsent must be used within ConsentProvider");
  }
  return context;
}
