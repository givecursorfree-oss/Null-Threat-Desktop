import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { Verdict } from "@/types";

const verdictStyles: Record<Verdict, string> = {
  clean: "border-emerald-500/25 bg-emerald-500/10 text-emerald-200",
  detected: "border-red-500/40 bg-red-500/10 text-red-300",
  suspicious: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  skipped: "border-border bg-white/[0.03] text-muted-foreground",
  unknown: "border-border bg-white/[0.03] text-muted-foreground",
};

const verdictLabels: Record<Verdict, string> = {
  clean: "Clean",
  detected: "Detected",
  suspicious: "Suspicious",
  skipped: "Skipped",
  unknown: "Unknown",
};

interface VerdictBadgeProps {
  verdict: Verdict;
  className?: string;
}

export default function VerdictBadge({ verdict, className }: VerdictBadgeProps) {
  return (
    <Badge
      variant="outline"
      className={cn(
        "inline-flex min-w-[88px] justify-center rounded-md px-2 py-0.5 text-[11px] font-medium capitalize tracking-wide",
        verdictStyles[verdict],
        className
      )}
    >
      {verdictLabels[verdict]}
    </Badge>
  );
}
