import { Shield } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";

interface TermsAcceptanceModalProps {
  onAccept: () => void;
}

export default function TermsAcceptanceModal({ onAccept }: TermsAcceptanceModalProps) {
  return (
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center bg-[#050505]/90 p-4 backdrop-blur-md"
      role="dialog"
      aria-modal="true"
      aria-labelledby="terms-title"
      aria-describedby="terms-description"
    >
      <div
        className={cn(
          "w-full max-w-lg rounded-xl border border-white/[0.08] bg-card/80 p-6 shadow-[inset_0_1px_0_rgba(255,255,255,0.06)] backdrop-blur-xl",
          "animate-in fade-in zoom-in-95 duration-300"
        )}
      >
        <div className="mb-5 flex items-start gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-white/[0.08] bg-white/[0.04]">
            <Shield className="h-5 w-5 text-foreground" strokeWidth={1.75} />
          </div>
          <div>
            <h1 id="terms-title" className="font-display text-lg font-semibold tracking-tight text-foreground">
              Welcome to Null Threat
            </h1>
            <p id="terms-description" className="mt-1 text-sm text-muted-foreground">
              Local threat analysis on your device. Review these terms once before you continue.
            </p>
          </div>
        </div>

        <ScrollArea className="h-56 rounded-lg border border-white/[0.06] bg-background/50 px-4 py-3">
          <div className="space-y-4 pr-3 text-sm leading-relaxed text-muted-foreground">
            <section>
              <h2 className="mb-1 font-medium text-foreground">Offline-first scanning</h2>
              <p>
                Null Threat works without internet. File scanning, YARA rules, and deep analysis run
                locally on your device. When you are online, you can optionally refresh MalwareBazaar
                malware hashes from Settings for improved SHA256 detection — we recommend doing this
                daily if you want the latest threat intelligence.
              </p>
            </section>
            <section>
              <h2 className="mb-1 font-medium text-foreground">Local processing</h2>
              <p>
                Null Threat scans files on your computer using local engines (ClamAV, YARA, and
                built-in analysis). Scan data stays on your machine unless you export it.
              </p>
            </section>
            <section>
              <h2 className="mb-1 font-medium text-foreground">Your responsibility</h2>
              <p>
                You choose which files and folders to scan. Results are advisory — verify critical
                findings before taking action. Null Threat is not a replacement for professional
                security review.
              </p>
            </section>
            <section>
              <h2 className="mb-1 font-medium text-foreground">Folder monitoring</h2>
              <p>
                Real-time protection only watches folders you explicitly add. We will ask for your
                permission before enabling folder monitoring or adding a watched path.
              </p>
            </section>
            <section>
              <h2 className="mb-1 font-medium text-foreground">Open source</h2>
              <p>
                Null Threat is open source. You may inspect, modify, and run it under the project
                license. No account or cloud subscription is required for core scanning.
              </p>
            </section>
          </div>
        </ScrollArea>

        <p className="mt-4 text-xs text-muted-foreground">
          By selecting Accept, you agree to these terms. This prompt appears only on first launch.
        </p>

        <div className="mt-5 flex justify-end">
          <Button type="button" onClick={onAccept} className="min-w-[120px]">
            Accept and continue
          </Button>
        </div>
      </div>
    </div>
  );
}
