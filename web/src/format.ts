// Small formatting helpers shared by the views.

/// A short, human relative time: "2 hours ago", "yesterday".
///
/// Exact timestamps are noise on a dashboard — what matters is whether a
/// scan is fresh or stale, and a reader answers that faster from "3 days
/// ago" than from a date they have to subtract in their head.
export function relativeTime(iso: string, now: Date = new Date()): string {
  const then = new Date(iso);
  const seconds = Math.round((now.getTime() - then.getTime()) / 1000);

  if (!Number.isFinite(seconds)) return "";
  // Small clock differences between browser and server should not produce
  // "in 3 seconds".
  if (seconds < 45) return "just now";

  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return plural(minutes, "minute");

  const hours = Math.round(minutes / 60);
  if (hours < 24) return plural(hours, "hour");

  const days = Math.round(hours / 24);
  if (days === 1) return "yesterday";
  if (days < 30) return plural(days, "day");

  const months = Math.round(days / 30);
  if (months < 12) return plural(months, "month");

  return plural(Math.round(months / 12), "year");
}

function plural(count: number, unit: string): string {
  return `${count} ${unit}${count === 1 ? "" : "s"} ago`;
}

/// "3 sites", "1 site".
export function countOf(count: number, singular: string, plural?: string): string {
  const word = count === 1 ? singular : (plural ?? `${singular}s`);
  return `${count} ${word}`;
}

/// A calendar date, for things where the exact day matters.
export function shortDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    day: "numeric",
    month: "short",
    year: "numeric",
  });
}
