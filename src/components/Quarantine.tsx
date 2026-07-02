import { useState } from "react";
import { ShieldAlert, RotateCcw, Trash2, FileText, Inbox } from "lucide-react";
import { useQuarantine } from "../hooks/useQuarantine";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";

export default function Quarantine() {
  const { quarantinedFiles, isLoading, restoreFile, deleteFile } = useQuarantine();
  const [confirmAction, setConfirmAction] = useState<{
    id: string;
    type: "restore" | "delete";
  } | null>(null);

  const handleRestore = async (id: string) => {
    await restoreFile(id);
    setConfirmAction(null);
  };

  const handleDelete = async (id: string) => {
    await deleteFile(id);
    setConfirmAction(null);
  };

  function formatFileSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  function formatDate(iso: string): string {
    return new Date(iso).toLocaleDateString(undefined, {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  }

  return (
    <div className="space-y-5">
      <div>
        <h1 className="font-display text-xl font-bold text-foreground">Quarantine Vault</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Isolated threats — files are encrypted and cannot execute
        </p>
      </div>

      {isLoading ? (
        <Card>
          <CardContent className="flex items-center justify-center py-12">
            <Skeleton className="h-5 w-5 rounded-full" />
          </CardContent>
        </Card>
      ) : quarantinedFiles.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center gap-3 py-12">
            <Inbox className="h-10 w-10 text-muted-foreground/50" />
            <p className="text-sm text-muted-foreground">No quarantined files</p>
            <p className="text-xs text-muted-foreground/70">
              Threats will appear here when detected and isolated
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          <div className="grid grid-cols-[1fr_140px_100px_80px_70px_100px] gap-3 px-4 py-2 font-mono text-xs uppercase tracking-wider text-muted-foreground">
            <span>File</span>
            <span>Threat</span>
            <span>Date</span>
            <span>Risk</span>
            <span>Size</span>
            <span>Actions</span>
          </div>

          {quarantinedFiles.map((file) => (
            <div
              key={file.id}
              className="grid grid-cols-[1fr_140px_100px_80px_70px_100px] items-center gap-3 rounded-md border border-border bg-card px-4 py-3"
            >
              <div className="flex min-w-0 items-center gap-2">
                <ShieldAlert className="h-4 w-4 shrink-0 text-destructive" />
                <span className="truncate text-sm text-foreground">
                  {file.fileName}
                </span>
              </div>
              <span className="truncate text-xs text-destructive">
                {file.threatName}
              </span>
              <span className="text-xs text-muted-foreground">
                {formatDate(file.quarantinedAt)}
              </span>
              <span className="text-xs font-medium text-destructive">
                {file.riskScore}%
              </span>
              <span className="text-xs text-muted-foreground">
                {formatFileSize(file.fileSize)}
              </span>
              <div className="flex gap-1">
                <Button
                  onClick={() => setConfirmAction({ id: file.id, type: "restore" })}
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8"
                  title="Restore"
                >
                  <RotateCcw className="h-3.5 w-3.5" />
                </Button>
                <Button
                  onClick={() => setConfirmAction({ id: file.id, type: "delete" })}
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8 text-muted-foreground hover:text-destructive"
                  title="Delete permanently"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </Button>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8"
                  title="View report"
                >
                  <FileText className="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}

      {confirmAction && (
        <div
          className="fixed inset-0 z-50 flex animate-in fade-in-0 items-center justify-center bg-background/80 duration-200"
          onClick={() => setConfirmAction(null)}
        >
          <Card
            className="mx-4 w-full max-w-sm animate-in fade-in-0 zoom-in-95 duration-200"
            onClick={(e) => e.stopPropagation()}
          >
            <CardContent className="space-y-4 p-4">
              <h3 className="font-display text-sm font-semibold text-foreground">
                {confirmAction.type === "restore"
                  ? "Restore File?"
                  : "Delete Permanently?"}
              </h3>
              <p className="text-xs text-muted-foreground">
                {confirmAction.type === "restore"
                  ? "This file was quarantined due to a threat detection. Restoring it could put your system at risk."
                  : "This action cannot be undone. The file will be permanently removed from the quarantine vault."}
              </p>
              <div className="flex justify-end gap-2">
                <Button
                  onClick={() => setConfirmAction(null)}
                  variant="outline"
                  size="sm"
                >
                  Cancel
                </Button>
                <Button
                  onClick={() =>
                    confirmAction.type === "restore"
                      ? handleRestore(confirmAction.id)
                      : handleDelete(confirmAction.id)
                  }
                  variant={confirmAction.type === "delete" ? "destructive" : "default"}
                  size="sm"
                >
                  {confirmAction.type === "restore" ? "Restore Anyway" : "Delete"}
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
