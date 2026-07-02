import { AlertTriangle, ShieldX, Bug, Trash2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type { ThreatInfo } from "../types";

interface ThreatCardProps {
  threat: ThreatInfo;
  onQuarantine?: () => void;
  onDelete?: () => void;
}

const severityConfig = {
  low: { color: "text-amber-400", bg: "bg-amber-500/10", border: "border-amber-500/30" },
  medium: { color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30" },
  high: { color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/30" },
  critical: { color: "text-red-500", bg: "bg-red-600/10", border: "border-red-600/30" },
};

export default function ThreatCard({ threat, onQuarantine, onDelete }: ThreatCardProps) {
  const config = severityConfig[threat.severity];

  return (
    <Card className={cn("border", config.border, config.bg)}>
      <CardContent className="space-y-3 p-4">
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-2">
            {threat.severity === "critical" ? (
              <ShieldX className={cn("h-5 w-5", config.color)} />
            ) : threat.severity === "high" ? (
              <AlertTriangle className={cn("h-5 w-5", config.color)} />
            ) : (
              <Bug className={cn("h-5 w-5", config.color)} />
            )}
            <div>
              <h4 className={cn("font-display font-semibold", config.color)}>{threat.name}</h4>
              <p className="font-mono text-xs text-muted-foreground">Family: {threat.family}</p>
            </div>
          </div>
          <Badge variant="outline" className={cn(config.bg, config.color, config.border)}>
            {threat.severity}
          </Badge>
        </div>

        <p className="text-sm text-foreground/80">{threat.description}</p>

        <div className="space-y-1">
          <p className="font-mono text-xs font-medium uppercase tracking-wider text-muted-foreground">
            Recommended Actions
          </p>
          <ul className="space-y-1">
            {threat.recommendedActions.map((action, i) => (
              <li key={i} className="flex items-center gap-2 text-xs text-foreground/70">
                <span className={cn("h-1 w-1 rounded-full", config.color.replace("text-", "bg-"))} />
                {action}
              </li>
            ))}
          </ul>
        </div>

        <div className="flex gap-2 pt-1">
          {onQuarantine && (
            <Button onClick={onQuarantine} size="sm">
              Quarantine File
            </Button>
          )}
          {onDelete && (
            <Button onClick={onDelete} variant="destructive" size="sm">
              <Trash2 className="h-3 w-3" />
              Delete
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
