// Only a channel label is retained for this tab. No visitor identifier.
export type Source = "direct" | "youtube" | "dev" | "search" | "referral";
const sources: Source[] = ["direct", "youtube", "dev", "search", "referral"];
export function classifySource(search: string, referrer: string): Source {
  const tagged = new URLSearchParams(search).get("utm_source");
  if (tagged && sources.includes(tagged as Source)) return tagged as Source;
  try {
    const host = new URL(referrer).hostname.toLowerCase();
    if (host === "glarion.app" || host === "www.glarion.app") return "direct";
    if (host === "youtu.be" || host === "youtube.com" || host.endsWith(".youtube.com")) return "youtube";
    if (host === "dev.to") return "dev";
    if (["www.google.com", "www.google.it", "www.bing.com", "duckduckgo.com"].includes(host)) return "search";
    return "referral";
  } catch { return "direct"; }
}

export function acquisitionHeaders(): Record<string, string> {
  if (typeof window === "undefined" || window.location.hostname !== "glarion.app") return {};
  try {
    if (navigator.doNotTrack === "1" || (navigator as Navigator & {globalPrivacyControl?: boolean}).globalPrivacyControl) return {};
    const query = new URLSearchParams(window.location.search);
    if (query.get("growth") === "off") sessionStorage.setItem("glarion.growth.off", "1");
    if (sessionStorage.getItem("glarion.growth.off") === "1") return {};
    const saved = sessionStorage.getItem("glarion.growth.source");
    const channel = saved && sources.includes(saved as Source)
      ? saved : classifySource(window.location.search, document.referrer);
    sessionStorage.setItem("glarion.growth.source", channel);
    return {"x-glarion-source": channel};
  } catch { return {}; }
}

export function recordPage(event: "landing_view" | "sample_report_view" | "signup_view"): void {
  const headers = acquisitionHeaders();
  if (!headers["x-glarion-source"]) return;
  void fetch("/api/growth/page", {
    method: "POST", headers: {...headers, "content-type": "application/json"},
    credentials: "omit", body: JSON.stringify({event}), keepalive: true,
  }).catch(() => {});
}
