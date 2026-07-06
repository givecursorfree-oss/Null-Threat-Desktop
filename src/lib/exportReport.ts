const SAVE_CANCELLED = "SAVE_CANCELLED";

export function isSaveCancelledError(message: string): boolean {
  return message.includes(SAVE_CANCELLED);
}

export function formatSaveSuccess(path: string): string {
  const name = path.split(/[\\/]/).pop() || path;
  return `Saved ${name}`;
}
