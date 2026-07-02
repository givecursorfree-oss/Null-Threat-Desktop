import { FolderSearch } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

interface FolderWatchConsentModalProps {
  open: boolean;
  onAllow: () => void;
  onDecline: () => void;
}

export default function FolderWatchConsentModal({
  open,
  onAllow,
  onDecline,
}: FolderWatchConsentModalProps) {
  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center bg-[#050505]/80 p-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-labelledby="folder-consent-title"
    >
      <div
        className={cn(
          "w-full max-w-md rounded-xl border border-white/[0.08] bg-card/80 p-6 shadow-[inset_0_1px_0_rgba(255,255,255,0.06)] backdrop-blur-xl"
        )}
      >
        <div className="mb-4 flex items-start gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-white/[0.08] bg-white/[0.04]">
            <FolderSearch className="h-5 w-5 text-foreground" strokeWidth={1.75} />
          </div>
          <div>
            <h2 id="folder-consent-title" className="font-display text-base font-semibold text-foreground">
              Allow folder monitoring?
            </h2>
            <p className="mt-1 text-sm text-muted-foreground">
              Null Threat will watch folders you choose and scan new files locally on this device.
            </p>
          </div>
        </div>

        <ul className="mb-5 space-y-2 text-sm text-muted-foreground">
          <li className="flex gap-2">
            <span className="text-foreground">-</span>
            <span>Only folders you add are monitored — nothing else on your system.</span>
          </li>
          <li className="flex gap-2">
            <span className="text-foreground">-</span>
            <span>Files are analyzed on your machine; paths are not sent to the cloud.</span>
          </li>
          <li className="flex gap-2">
            <span className="text-foreground">-</span>
            <span>You can remove folders or turn off protection anytime in Settings.</span>
          </li>
        </ul>

        <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
          <Button type="button" variant="outline" onClick={onDecline}>
            Not now
          </Button>
          <Button type="button" onClick={onAllow}>
            Allow folder monitoring
          </Button>
        </div>
      </div>
    </div>
  );
}
