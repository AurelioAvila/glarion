// What we know about a site, assembled from the scan we already ran.
//
// Every scan collects a great deal that is not a problem: which server
// technologies answered, what the certificate says, whether mail is
// configured, whether a firewall is in front. Until now all of it was filed
// in an appendix under "checked, nothing to report" and never looked at.
//
// That was a waste. An agency about to talk to a client wants to know what
// the site *is* before it hears what is wrong with it, and we have the
// answer sitting in the database. Presenting it costs one more request and
// turns a sparse page into a briefing.

import type { TriagedFinding } from "./api.js";

export interface Fact {
  label: string;
  value: string;
}

/// Facts worth showing, in the order they should be read.
///
/// Curated rather than dumped: the appendix has thirty entries and most are
/// only interesting as evidence that they were checked. These are the ones
/// somebody would actually mention on a call.
interface Shown {
  template: string;
  label: string;
  /// Take the value from the matcher name rather than the evidence.
  ///
  /// For a detection template the matcher *is* the answer — "cloudflare"
  /// names the firewall, while the evidence is only the address we looked
  /// at, which produced the nonsense line "Firewall: acme-client.com".
  fromMatcher?: boolean;
  transform?: (raw: string) => string;
}

const SHOWN: Shown[] = [
  { template: "tech-detect", label: "Running" },
  { template: "waf-detect", label: "Firewall", fromMatcher: true, transform: titleCase },
  { template: "dns-waf-detect", label: "Firewall", fromMatcher: true, transform: titleCase },
  { template: "ssl-issuer", label: "Certificate", transform: firstOnly },
  { template: "tls-version", label: "TLS", transform: tlsVersions },
  { template: "mx-fingerprint", label: "Mail", transform: hostOnly },
  { template: "nameserver-fingerprint", label: "Name servers", transform: hostOnly },
  { template: "spf-record-detect", label: "SPF", transform: () => "Present" },
  { template: "dmarc-detect", label: "DMARC", transform: () => "Present" },
  { template: "dnssec-detection", label: "DNSSEC", transform: () => "Enabled" },
];

function titleCase(raw: string): string {
  return raw
    .split(/[,\s]+/)
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(", ");
}

/// "tls12, tls13" is how the scanner names versions. Nobody says that.
function tlsVersions(raw: string): string {
  const versions = raw
    .split(",")
    .map((part) => part.trim().replace(/^tls\s*/i, ""))
    .map((part) => (part.length === 2 ? `${part[0]}.${part[1]}` : part))
    .filter(Boolean);

  return versions.length > 0 ? `TLS ${versions.join(", ")}` : raw;
}

/// Evidence often arrives as a list of several matches. The first is the
/// useful one; the rest is noise on a summary line.
function firstOnly(raw: string): string {
  return raw.split(",")[0]?.trim() ?? raw;
}

/// Trims a trailing dot and any priority prefix from DNS values, which are
/// presentation-format records rather than things a reader wants to parse.
function hostOnly(raw: string): string {
  return raw
    .split(",")
    .map((part) => part.trim().replace(/^\d+\s+/, "").replace(/\.$/, ""))
    .filter(Boolean)
    .slice(0, 2)
    .join(", ");
}

/// Cap on a single value, so one very long technology list does not push
/// everything else off the line.
const MAX_VALUE = 90;

export function siteProfile(inventory: TriagedFinding[]): Fact[] {
  const facts: Fact[] = [];
  const seen = new Set<string>();

  for (const entry of SHOWN) {
    const finding = inventory.find((item) => item.template_id === entry.template);
    if (!finding) continue;

    // Two templates can describe the same thing — a firewall is detected
    // over DNS and over HTTP — and the label is what the reader sees, so
    // that is what must not repeat.
    if (seen.has(entry.label)) continue;

    const raw = (entry.fromMatcher ? finding.matcher : (finding.evidence ?? "")).trim();
    if (raw === "") continue;

    // A URL as "evidence" means the template matched but extracted
    // nothing; there is no fact to state.
    if (/^https?:\/\//i.test(raw)) continue;

    const value = (entry.transform ? entry.transform(raw) : raw).trim();
    if (value === "") continue;

    seen.add(entry.label);
    facts.push({
      label: entry.label,
      value: value.length > MAX_VALUE ? `${value.slice(0, MAX_VALUE - 1)}…` : value,
    });
  }

  return facts;
}
