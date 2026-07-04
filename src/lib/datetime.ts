/**
 * Parse timestamps from the Null Threat backend.
 * SQLite `datetime('now')` values are UTC but omit a timezone suffix;
 * JavaScript would otherwise treat them as local time.
 */
export function parseAppTimestamp(value: string): Date {
  if (!value) return new Date(NaN);

  const trimmed = value.trim();
  if (/[zZ]|[+-]\d{2}:\d{2}$/.test(trimmed)) {
    return new Date(trimmed);
  }

  const normalized = trimmed.includes("T") ? trimmed : trimmed.replace(" ", "T");
  return new Date(`${normalized}Z`);
}

export function formatAppTime(value: string): string {
  const date = parseAppTimestamp(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export function formatAppDate(
  value: string,
  options: Intl.DateTimeFormatOptions = {
    month: "short",
    day: "numeric",
    year: "numeric",
  }
): string {
  const date = parseAppTimestamp(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleDateString(undefined, options);
}

export function formatAppDateTime(value: string | null): string {
  if (!value) return "Never";
  const date = parseAppTimestamp(value);
  if (Number.isNaN(date.getTime())) return "Unknown";
  return date.toLocaleString();
}
