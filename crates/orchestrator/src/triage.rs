//! Turning a scanner's output into something an agency can hand to a client.
//!
//! A real scan of a well-run static site produced 32 findings: none above
//! "low", three "low", twenty-nine "info". About five were worth acting on.
//! The rest were inventory — "you have an MX record", "your certificate is
//! issued by X". Handing that list to a paying client makes the sender look
//! careless, which is the actual problem this module solves.
//!
//! Two things follow from that, and they shape the whole design.
//!
//! **The scanner's severity is not our priority.** Nuclei rates a missing
//! Content-Security-Policy as `info`, because in the abstract it is a
//! configuration observation. On a client report it is one of the first
//! things to raise. Severity describes a finding class; priority describes
//! what this particular reader should do on Monday morning. We assign our
//! own and keep the original for reference.
//!
//! **Nothing is silently discarded.** Inventory is demoted, never dropped:
//! it belongs in an appendix, because "we checked and it was fine" is part
//! of what the client is paying for. An unrecognised finding is surfaced
//! rather than hidden, so a template we have not classified yet fails
//! toward visibility.

use crate::finding::{Finding, Severity};
use serde::{Deserialize, Serialize};

/// What the reader should do with a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Disposition {
    /// Something is wrong and there is a concrete fix.
    Act,
    /// Needs a human judgement call — whether it matters depends on what
    /// the site is for.
    Review,
    /// Not a problem. Evidence of what was checked, for the appendix.
    Inventory,
}

/// Our ordering, independent of what the scanner said.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    /// Appendix material.
    None,
    Low,
    Medium,
    High,
    Urgent,
}

/// Client-facing explanation. Written for the person paying for the report,
/// not for the person who ran the scan — so no jargon that a non-specialist
/// would have to look up.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Guidance {
    /// Why this matters, in terms of consequence rather than mechanism.
    pub why: String,
    /// What to actually change.
    pub fix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriagedFinding {
    pub title: String,
    pub disposition: Disposition,
    pub priority: Priority,
    /// What the scanner itself claimed, kept so a technical reader can
    /// reconcile our ranking with the raw tool output.
    pub scanner_severity: Severity,
    pub guidance: Option<Guidance>,
    pub evidence: Option<String>,
    /// The rule that produced this row. Where duplicates were folded
    /// together this is the first of them, so it identifies the row for
    /// debugging rather than enumerating everything behind it.
    pub template_id: String,
    /// Which matcher inside that rule fired.
    ///
    /// For a detection template this *is* the finding — "cloudflare" is the
    /// answer to "which firewall", while the evidence is only the address
    /// we happened to look at. Carried through so a reader-facing summary
    /// can say something more useful than the domain it already knows.
    pub matcher: String,
    /// How many raw findings were folded into this row. A scanner reports
    /// one result per matching rule, so a single misconfiguration can
    /// arrive three times over; printing it three times makes a report look
    /// padded, which is exactly the impression an agency is paying to avoid.
    pub occurrences: usize,
}

/// The result of triaging a whole scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriagedScan {
    /// Ordered by priority, highest first. What goes at the front of the
    /// report.
    pub actionable: Vec<TriagedFinding>,
    /// Judgement calls, for the agency to decide on before sending.
    pub review: Vec<TriagedFinding>,
    /// Everything verified and found unremarkable.
    pub inventory: Vec<TriagedFinding>,
}

impl TriagedScan {
    /// Rows the report will print. Lower than [`Self::observations`]
    /// whenever duplicates were folded together.
    pub fn rows(&self) -> usize {
        self.actionable.len() + self.review.len() + self.inventory.len()
    }

    /// Raw scanner results represented, duplicates included.
    ///
    /// Kept distinct from [`Self::rows`] because "we printed 28 lines" and
    /// "we examined 32 results" are different claims, and conflating them
    /// is how evidence goes missing unnoticed.
    pub fn observations(&self) -> usize {
        self.actionable
            .iter()
            .chain(self.review.iter())
            .chain(self.inventory.iter())
            .map(|f| f.occurrences)
            .sum()
    }

    /// The number a client actually reacts to.
    pub fn needs_attention(&self) -> usize {
        self.actionable.len()
    }
}

/// Triages a whole scan and sorts each bucket.
pub fn triage_scan(findings: &[Finding]) -> TriagedScan {
    let mut actionable = Vec::new();
    let mut review = Vec::new();
    let mut inventory = Vec::new();

    for finding in findings {
        let triaged = triage(finding);
        match triaged.disposition {
            Disposition::Act => actionable.push(triaged),
            Disposition::Review => review.push(triaged),
            Disposition::Inventory => inventory.push(triaged),
        }
    }

    // Collapse duplicates, then order highest priority first. Ties keep a
    // stable, alphabetical order so two runs of the same scan produce
    // byte-identical reports.
    for bucket in [&mut actionable, &mut review, &mut inventory] {
        *bucket = collapse_duplicates(std::mem::take(bucket));
        bucket.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then_with(|| a.title.cmp(&b.title))
        });
    }

    TriagedScan {
        actionable,
        review,
        inventory,
    }
}

/// Triages a single finding.
pub fn triage(finding: &Finding) -> TriagedFinding {
    let template_id = finding
        .raw
        .get("template-id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Some templates report several distinct issues and distinguish them
    // only by which matcher fired — a missing CSP and a missing
    // cross-origin policy arrive under the same template id but deserve
    // very different treatment.
    let matcher = finding
        .raw
        .get("matcher-name")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let (disposition, priority, guidance) = classify(&template_id, matcher, finding.severity);

    TriagedFinding {
        title: display_title(&template_id, matcher, &finding.title, disposition),
        disposition,
        priority,
        scanner_severity: finding.severity,
        guidance,
        evidence: extract_evidence(finding),
        template_id,
        matcher: matcher.to_string(),
        occurrences: 1,
    }
}

/// A client-readable title.
///
/// The scanner's names are written for operators ("HTTP Missing Security
/// Headers" repeated five times, "DNS DMARC - Detect"); a report needs to
/// name the actual issue, once per issue.
///
/// The disposition is an input because a title must never contradict the
/// section it is filed under. The `tls-version` template fires both when an
/// obsolete protocol is offered and when the configuration is perfectly
/// fine, so titling it "Obsolete TLS version accepted" unconditionally put
/// that sentence in the appendix under "found unremarkable" — which reads
/// as a contradiction and costs the reader confidence in the whole
/// document.
fn display_title(
    template_id: &str,
    matcher: &str,
    scanner_title: &str,
    disposition: Disposition,
) -> String {
    if disposition == Disposition::Inventory {
        return inventory_title(template_id, scanner_title);
    }

    match (template_id, matcher) {
        ("http-missing-security-headers", "content-security-policy") => {
            "No Content-Security-Policy header".to_string()
        }
        ("http-missing-security-headers", m) if !m.is_empty() => {
            format!("Missing security header: {m}")
        }
        ("weak-hsts-detect", _) => "HTTPS is not enforced for long enough".to_string(),
        ("fastly-debug-headers" | "x-debug-headers", _) => {
            "CDN debug headers exposed in responses".to_string()
        }
        ("email-extractor", _) => "Email addresses published in the page source".to_string(),
        ("robots-txt-endpoint", _) => "Paths disclosed in robots.txt".to_string(),
        ("tls-version", _) => "Obsolete TLS version accepted".to_string(),
        _ => scanner_title.to_string(),
    }
}

/// Appendix wording: a plain statement of what was checked. Phrased as a
/// completed check rather than as a defect, because everything here was
/// found to be in order.
fn inventory_title(template_id: &str, scanner_title: &str) -> String {
    match template_id {
        "tls-version" => "TLS protocol versions".to_string(),
        "tls-certificate-expiry" => "Certificate renewal date".to_string(),
        "ssl-issuer" => "Certificate issuer".to_string(),
        "ssl-dns-names" => "Names covered by the certificate".to_string(),
        "wildcard-tls" => "Wildcard certificate in use".to_string(),
        "dnssec-detection" => "DNSSEC".to_string(),
        "dmarc-detect" => "DMARC record".to_string(),
        "spf-record-detect" => "SPF record".to_string(),
        "caa-fingerprint" => "CAA record".to_string(),
        "mx-fingerprint" => "Mail servers".to_string(),
        "nameserver-fingerprint" => "Name servers".to_string(),
        "txt-fingerprint" => "DNS TXT records".to_string(),
        "aaaa-fingerprint" => "IPv6 addresses".to_string(),
        "waf-detect" | "dns-waf-detect" => "Web application firewall".to_string(),
        "tech-detect" => "Detected technologies".to_string(),
        "robots-txt" => "robots.txt".to_string(),
        "security-txt" => "security.txt".to_string(),
        "form-detection" => "Forms on the page".to_string(),
        "google-floc-disabled" => "Browser tracking opt-out".to_string(),
        _ => scanner_title.to_string(),
    }
}

fn guidance(why: &str, fix: &str) -> Option<Guidance> {
    Some(Guidance {
        why: why.to_string(),
        fix: fix.to_string(),
    })
}

/// The rules table.
///
/// Curated against the output of a real scan rather than assembled from the
/// template list in the abstract, so the common cases are the ones that are
/// actually covered.
fn classify(
    template_id: &str,
    matcher: &str,
    severity: Severity,
) -> (Disposition, Priority, Option<Guidance>) {
    match template_id {
        // --- Response headers -------------------------------------------
        "http-missing-security-headers" => match matcher {
            "content-security-policy" => (
                Disposition::Act,
                Priority::High,
                guidance(
                    "Without a Content-Security-Policy, any script that reaches the page \
                     can run — including one injected through a comment field, a \
                     third-party widget, or a compromised dependency. It is the single \
                     control that limits the damage of a cross-site scripting flaw.",
                    "Add a Content-Security-Policy header. Start in report-only mode to \
                     find what the site legitimately loads, then enforce it once the \
                     report is quiet.",
                ),
            ),
            "x-frame-options" => (
                Disposition::Act,
                Priority::Medium,
                guidance(
                    "The page can be embedded in a frame on another site, which allows \
                     clickjacking: the visitor believes they are clicking your interface \
                     while actually acting on a page the attacker controls.",
                    "Send X-Frame-Options: DENY, or a frame-ancestors directive in the \
                     Content-Security-Policy.",
                ),
            ),
            "x-content-type-options" => (
                Disposition::Act,
                Priority::Low,
                guidance(
                    "Browsers may guess at a file's type and treat an upload as script.",
                    "Send X-Content-Type-Options: nosniff.",
                ),
            ),
            "cross-origin-embedder-policy"
            | "cross-origin-opener-policy"
            | "cross-origin-resource-policy" => (
                Disposition::Review,
                Priority::Low,
                guidance(
                    "These headers isolate the page from other browser contexts. They \
                     matter for sites handling sensitive data in the browser, and are \
                     often unnecessary for a brochure or marketing site.",
                    "Worth adding if the site handles logged-in sessions or payment \
                     flows. Safe to note and move on otherwise — enabling them can break \
                     embedded third-party content.",
                ),
            ),
            // A header we have no specific opinion about. Still explained:
            // an unexplained row in the middle of explained ones reads as
            // an oversight, and the reader cannot act on it either way.
            _ => (
                Disposition::Review,
                Priority::Low,
                guidance(
                    "This hardening header is not being sent. It is a defence-in-depth                      measure rather than a flaw, and whether it is worth adding depends                      on what the site does.",
                    "Review against the site's needs. Adding it is usually harmless, but                      test first if the site embeds or is embedded by third-party content.",
                ),
            ),
        },

        "weak-hsts-detect" => (
            Disposition::Act,
            Priority::Medium,
            guidance(
                "HTTP Strict-Transport-Security is set, but with a short lifetime. \
                 Until it expires the browser remembers to use HTTPS; a visitor \
                 arriving after that window can still be pushed onto plain HTTP by an \
                 attacker on the same network.",
                "Raise max-age to at least 31536000 (one year), which is also the \
                 threshold for the browser preload list.",
            ),
        ),

        "fastly-debug-headers" | "x-debug-headers" => (
            Disposition::Act,
            Priority::Low,
            guidance(
                "The CDN is returning debug headers describing cache internals. It \
                 gives an attacker free reconnaissance about the infrastructure and \
                 signals that a debug setting was left on in production.",
                "Turn off debug header output in the CDN configuration for production \
                 traffic.",
            ),
        ),

        // --- Transport ---------------------------------------------------
        "tls-version" | "ssl-issuer" | "ssl-dns-names" | "wildcard-tls" => {
            // Old protocol versions are a real finding; the rest is
            // inventory. The scanner reports both under these ids, so lean
            // on the severity it assigned.
            if severity >= Severity::Medium {
                (
                    Disposition::Act,
                    Priority::High,
                    guidance(
                        "The server still negotiates an obsolete TLS version, which has \
                         known weaknesses and fails most compliance checks.",
                        "Disable TLS 1.0 and 1.1 at the server or CDN and serve TLS 1.2 \
                         and 1.3 only.",
                    ),
                )
            } else {
                (Disposition::Inventory, Priority::None, None)
            }
        }

        // Expiry is the one transport finding with a date attached, so it
        // is graded by how close that date is rather than by what the
        // scanner thought. An expired certificate outranks everything else
        // a scan can find: the site is not weakened, it is unreachable.
        "tls-certificate-expiry" => match matcher {
            "expired" => (
                Disposition::Act,
                Priority::Urgent,
                guidance(
                    "The certificate has already expired. Every mainstream browser now                      shows a full-page security warning instead of the site, so to a                      visitor it is indistinguishable from being offline — and to a                      customer mid-purchase it looks like fraud.",
                    "Renew the certificate immediately. If it was issued by Let's                      Encrypt or another automated authority, the renewal job has                      stopped: check that it still runs and that port 80 is reachable                      for the renewal challenge.",
                ),
            ),
            "critical" => (
                Disposition::Act,
                Priority::Urgent,
                guidance(
                    "The certificate expires within a week. When it does, the site stops                      loading for everyone: this is a scheduled outage unless something                      is done before the date.",
                    "Renew it now rather than waiting for the automation. An automated                      renewal that has not fired with a week to go has already failed                      several times.",
                ),
            ),
            "soon" => (
                Disposition::Act,
                Priority::High,
                guidance(
                    "The certificate expires within a fortnight. Automated renewal                      normally completes with about thirty days to spare, so passing this                      point usually means the renewal is broken rather than merely late.",
                    "Check that the renewal process runs and succeeds, and renew by hand                      if it does not.",
                ),
            ),
            "approaching" => (
                Disposition::Review,
                Priority::Medium,
                guidance(
                    "The certificate expires within a month. This is the window in which                      an automated renewal should already have happened, so it is worth                      confirming one is scheduled rather than assuming it.",
                    "Confirm the renewal is automated and working. If it is manual, put                      the date in a calendar now.",
                ),
            ),
            // Comfortably valid: the renewal date belongs in the appendix
            // as evidence the check ran.
            _ => (Disposition::Inventory, Priority::None, None),
        },

        "tls-certificate-name-mismatch" => (
            Disposition::Act,
            Priority::Urgent,
            guidance(
                "The certificate being served does not list this domain among the names                  it covers. Browsers treat that exactly like an expired certificate: a                  full-page warning instead of the site. It usually means a new subdomain                  was pointed at a server whose certificate was never reissued to include                  it.",
                "Reissue the certificate with this domain included, or point the domain                  at the host whose certificate already covers it.",
            ),
        ),

        "tls-certificate-self-signed" => (
            Disposition::Act,
            Priority::Urgent,
            guidance(
                "The certificate was issued by itself rather than by a recognised                  authority, so no browser trusts it. This is almost always a default                  certificate still in place because the real one was never installed —                  which means nobody has loaded the site in a browser since it was set up.",
                "Install a certificate from a trusted authority. Let's Encrypt issues                  them free and renews automatically.",
            ),
        ),

        // --- Exposure ----------------------------------------------------
        "email-extractor" => (
            Disposition::Review,
            Priority::Low,
            guidance(
                "Email addresses are published in the page source, where scrapers \
                 collect them for spam and for targeting phishing at named staff. \
                 Placeholder addresses left in a template also show up here, which is \
                 worth checking before a client notices.",
                "Confirm each address is meant to be public and is not leftover \
                 template text. Use a contact form where an address is not needed.",
            ),
        ),

        "robots-txt-endpoint" => (
            Disposition::Review,
            Priority::Low,
            guidance(
                "robots.txt lists paths the site asks crawlers to skip. It is public, \
                 so any administrative or staging path named there is effectively \
                 advertised to anyone looking.",
                "Check the listed paths. Anything sensitive needs authentication — \
                 excluding it from robots.txt is not protection either way.",
            ),
        ),

        // --- Inventory ---------------------------------------------------
        // Present because the client is paying to know these were checked.
        "waf-detect"
        | "dns-waf-detect"
        | "tech-detect"
        | "robots-txt"
        | "security-txt"
        | "google-floc-disabled"
        | "form-detection"
        | "dnssec-detection"
        | "caa-fingerprint"
        | "aaaa-fingerprint"
        | "txt-fingerprint"
        | "mx-fingerprint"
        | "nameserver-fingerprint"
        | "spf-record-detect"
        | "dmarc-detect" => (Disposition::Inventory, Priority::None, None),

        // --- Anything we have not classified -----------------------------
        // Fail toward visibility. A template we have never seen that the
        // scanner rated highly must not land in an appendix because our
        // table is incomplete.
        _ => match severity {
            Severity::Critical => (Disposition::Act, Priority::Urgent, None),
            Severity::High => (Disposition::Act, Priority::High, None),
            Severity::Medium => (Disposition::Act, Priority::Medium, None),
            Severity::Low => (Disposition::Review, Priority::Low, None),
            Severity::Info => (Disposition::Inventory, Priority::None, None),
        },
    }
}

/// Pulls the concrete detail out of a finding, so the report can say what
/// was actually observed rather than only naming the issue.
fn extract_evidence(finding: &Finding) -> Option<String> {
    if let Some(results) = finding
        .raw
        .get("extracted-results")
        .and_then(|v| v.as_array())
    {
        let joined: Vec<String> = results
            .iter()
            .filter_map(|v| v.as_str())
            .map(str::to_string)
            .collect();
        if !joined.is_empty() {
            return Some(joined.join(", "));
        }
    }

    finding
        .raw
        .get("matched-at")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// Folds rows describing the same issue into one, keeping every distinct
/// piece of evidence.
///
/// The same underlying problem often trips several rules — one CDN left in
/// debug mode produced three separate results in the scan this module was
/// built against. The reader needs to see it once, with all the places it
/// was observed.
fn collapse_duplicates(findings: Vec<TriagedFinding>) -> Vec<TriagedFinding> {
    let mut collapsed: Vec<TriagedFinding> = Vec::with_capacity(findings.len());

    for finding in findings {
        // Matched on the reader-facing title alone.
        //
        // Not on the template id: two different rules can describe the same
        // thing to a reader — a firewall detected over DNS and over HTTP
        // both produce "Web application firewall", and printing that twice
        // looks like a mistake. Nor title *and* template id, which is what
        // let that duplicate through.
        //
        // Distinct issues keep distinct titles by construction — each
        // missing header is named individually — so keying on the title
        // cannot merge things the reader needed to see apart.
        let existing = collapsed.iter_mut().find(|c| c.title == finding.title);

        match existing {
            Some(existing) => {
                existing.occurrences += 1;

                // Keep distinct evidence; the second sighting of the same
                // URL adds nothing.
                if let Some(new_evidence) = finding.evidence {
                    match &mut existing.evidence {
                        Some(current) => {
                            if !current.split(", ").any(|part| part == new_evidence) {
                                current.push_str(", ");
                                current.push_str(&new_evidence);
                            }
                        }
                        None => existing.evidence = Some(new_evidence),
                    }
                }

                // A duplicate that the rules ranked higher wins, so a
                // collapsed row is never quieter than its loudest member.
                if finding.priority > existing.priority {
                    existing.priority = finding.priority;
                }
            }
            None => collapsed.push(finding),
        }
    }

    collapsed
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn finding(severity: Severity, raw: serde_json::Value) -> Finding {
        Finding {
            severity,
            title: "Scanner title".to_string(),
            description: None,
            raw,
        }
    }

    fn header_finding(matcher: &str) -> Finding {
        finding(
            Severity::Info,
            json!({
                "template-id": "http-missing-security-headers",
                "matcher-name": matcher,
            }),
        )
    }

    #[test]
    fn missing_csp_is_promoted_above_the_scanner_severity() {
        // The whole premise of this module: the scanner calls this "info",
        // and a client report must not.
        let triaged = triage(&header_finding("content-security-policy"));

        assert_eq!(triaged.scanner_severity, Severity::Info);
        assert_eq!(triaged.disposition, Disposition::Act);
        assert_eq!(triaged.priority, Priority::High);
        assert!(triaged.guidance.is_some());
    }

    #[test]
    fn missing_csp_gets_a_title_a_client_can_read() {
        let triaged = triage(&header_finding("content-security-policy"));
        assert_eq!(triaged.title, "No Content-Security-Policy header");
    }

    #[test]
    fn repeated_header_template_is_split_by_which_header_is_missing() {
        // One template id, five findings, five different titles — otherwise
        // the report says "HTTP Missing Security Headers" five times.
        let csp = triage(&header_finding("content-security-policy"));
        let coep = triage(&header_finding("cross-origin-embedder-policy"));

        assert_ne!(csp.title, coep.title);
        assert_eq!(coep.disposition, Disposition::Review);
    }

    #[test]
    fn cross_origin_headers_are_a_judgement_call_not_a_defect() {
        for matcher in [
            "cross-origin-embedder-policy",
            "cross-origin-opener-policy",
            "cross-origin-resource-policy",
        ] {
            let triaged = triage(&header_finding(matcher));
            assert_eq!(
                triaged.disposition,
                Disposition::Review,
                "{matcher} should not be presented as a defect"
            );
        }
    }

    #[test]
    fn inventory_findings_are_demoted_but_never_dropped() {
        let scan = vec![
            finding(Severity::Info, json!({"template-id": "waf-detect"})),
            finding(Severity::Info, json!({"template-id": "mx-fingerprint"})),
        ];

        let triaged = triage_scan(&scan);

        assert_eq!(triaged.needs_attention(), 0);
        assert_eq!(triaged.inventory.len(), 2);
        assert_eq!(triaged.rows(), 2, "nothing may be silently discarded");
    }

    #[test]
    fn an_unknown_high_severity_template_is_surfaced_not_buried() {
        // Our rules table will always be incomplete. It must fail toward
        // showing the client too much rather than too little.
        let triaged = triage(&finding(
            Severity::Critical,
            json!({"template-id": "some-template-we-have-never-classified"}),
        ));

        assert_eq!(triaged.disposition, Disposition::Act);
        assert_eq!(triaged.priority, Priority::Urgent);
    }

    #[test]
    fn an_unknown_info_template_stays_in_the_appendix() {
        let triaged = triage(&finding(
            Severity::Info,
            json!({"template-id": "unknown-informational-thing"}),
        ));

        assert_eq!(triaged.disposition, Disposition::Inventory);
    }

    #[test]
    fn obsolete_tls_is_actionable_while_certificate_facts_are_not() {
        let old_protocol = triage(&finding(
            Severity::High,
            json!({"template-id": "tls-version"}),
        ));
        let issuer = triage(&finding(
            Severity::Info,
            json!({"template-id": "ssl-issuer"}),
        ));

        assert_eq!(old_protocol.disposition, Disposition::Act);
        assert_eq!(issuer.disposition, Disposition::Inventory);
    }

    #[test]
    fn evidence_prefers_the_extracted_value_over_the_url() {
        let triaged = triage(&finding(
            Severity::Info,
            json!({
                "template-id": "email-extractor",
                "extracted-results": ["someone@example.com"],
                "matched-at": "https://example.com",
            }),
        ));

        assert_eq!(triaged.evidence.as_deref(), Some("someone@example.com"));
    }

    #[test]
    fn evidence_falls_back_to_where_it_matched() {
        let triaged = triage(&finding(
            Severity::Info,
            json!({
                "template-id": "weak-hsts-detect",
                "matched-at": "https://example.com",
            }),
        ));

        assert_eq!(triaged.evidence.as_deref(), Some("https://example.com"));
    }

    #[test]
    fn actionable_findings_come_out_highest_priority_first() {
        let scan = vec![
            header_finding("x-content-type-options"),  // Act / Low
            header_finding("content-security-policy"), // Act / High
        ];

        let triaged = triage_scan(&scan);

        assert_eq!(triaged.actionable[0].priority, Priority::High);
        assert_eq!(triaged.actionable[1].priority, Priority::Low);
    }

    #[test]
    fn ordering_is_stable_so_two_runs_produce_the_same_report() {
        let scan = vec![
            header_finding("cross-origin-opener-policy"),
            header_finding("cross-origin-embedder-policy"),
            header_finding("cross-origin-resource-policy"),
        ];

        let first = triage_scan(&scan);
        let second = triage_scan(&scan);

        let titles =
            |s: &TriagedScan| -> Vec<String> { s.review.iter().map(|f| f.title.clone()).collect() };
        assert_eq!(titles(&first), titles(&second));
    }

    #[test]
    fn every_actionable_finding_we_classified_explains_itself() {
        // An "act on this" item with no explanation is useless to the
        // client the report is written for.
        for matcher in [
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
        ] {
            let triaged = triage(&header_finding(matcher));
            let guidance = triaged
                .guidance
                .unwrap_or_else(|| panic!("{matcher} must carry guidance"));

            assert!(!guidance.why.is_empty());
            assert!(!guidance.fix.is_empty());
        }
    }

    /// These come from the tls wrapper rather than from Nuclei, and the
    /// wrapper stamps the same `template-id`/`matcher-name` shape so they
    /// travel the same path. Asserted here because the two modules are
    /// coupled only by those strings: rename one and nothing fails to
    /// compile, it just quietly stops being classified.
    #[test]
    fn an_expired_certificate_outranks_everything_else() {
        let triaged = triage(&finding(
            Severity::Critical,
            json!({
                "template-id": "tls-certificate-expiry",
                "matcher-name": "expired",
            }),
        ));

        assert_eq!(triaged.disposition, Disposition::Act);
        assert_eq!(
            triaged.priority,
            Priority::Urgent,
            "a site nobody can load is the most urgent thing a scan can find"
        );
        assert!(triaged.guidance.is_some());
    }

    #[test]
    fn a_certificate_with_time_left_stays_in_the_appendix() {
        let triaged = triage(&finding(
            Severity::Info,
            json!({
                "template-id": "tls-certificate-expiry",
                "matcher-name": "valid",
            }),
        ));

        assert_eq!(triaged.disposition, Disposition::Inventory);
        assert_eq!(triaged.title, "Certificate renewal date");
    }

    #[test]
    fn every_certificate_band_is_classified_and_explains_itself() {
        // The wrapper emits exactly these matchers. A band with no rule
        // would fall through to the unclassified path and lose its
        // guidance, which is the whole product.
        for matcher in ["expired", "critical", "soon", "approaching"] {
            let triaged = triage(&finding(
                Severity::High,
                json!({
                    "template-id": "tls-certificate-expiry",
                    "matcher-name": matcher,
                }),
            ));

            assert_ne!(
                triaged.disposition,
                Disposition::Inventory,
                "{matcher} is a finding, not appendix material"
            );

            let guidance = triaged
                .guidance
                .unwrap_or_else(|| panic!("{matcher} must tell the reader what to do"));
            assert!(!guidance.why.is_empty());
            assert!(!guidance.fix.is_empty());
        }
    }

    #[test]
    fn a_name_mismatch_and_a_self_signed_certificate_are_both_actionable() {
        for template_id in [
            "tls-certificate-name-mismatch",
            "tls-certificate-self-signed",
        ] {
            let triaged = triage(&finding(
                Severity::Critical,
                json!({ "template-id": template_id, "matcher-name": "san" }),
            ));

            assert_eq!(triaged.disposition, Disposition::Act, "{template_id}");
            assert!(triaged.guidance.is_some(), "{template_id}");
        }
    }
}
