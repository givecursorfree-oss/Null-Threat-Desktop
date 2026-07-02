import EngineProgressBar from "./EngineProgressBar";
import { useScanStore } from "../store/scanStore";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { EngineName } from "../types";

const engineOrder: EngineName[] = [
  "SHA256 Lookup",
  "ClamAV Engine",
  "YARA Rules",
  "Deep Analysis",
];

export default function ScanProgress() {
  const { progress, currentFile } = useScanStore();

  return (
    <Card className="animate-in fade-in-0 duration-300">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle>Scan Engines</CardTitle>
          <div className="flex items-center gap-2">
            <div className="h-2 w-2 animate-pulse rounded-full bg-foreground" />
            <span className="font-mono text-xs text-muted-foreground">Scanning</span>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-5">
        {currentFile && (
          <p className="truncate text-xs text-muted-foreground">
            Analyzing: {currentFile.split(/[\\/]/).pop()}
          </p>
        )}

        <div className="space-y-4">
          {engineOrder.map((name) => {
            const engine = progress[name];
            return (
              <EngineProgressBar
                key={name}
                engineName={name}
                status={engine.status}
                progress={engine.progress}
                elapsed={engine.elapsed}
              />
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}
