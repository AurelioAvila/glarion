//! Rendering a triaged scan as a self-contained HTML document.
//!
//! This is the artefact the customer actually hands to *their* client, so
//! it carries their name rather than ours. It is a single file with no
//! external requests: an agency emails it as an attachment, and a report
//! that phones home when opened would leak when and where it was read.
//!
//! **Everything interpolated here is untrusted.** Titles and evidence come
//! from a scanner that was pointed at somebody else's website, and that
//! site's operator chooses what appears in a page, a header, or a
//! certificate. Rendering any of it unescaped would put script from a
//! scanned site into a document an agency opens on their own machine — a
//! stored cross-site scripting hole in a security report. Every value goes
//! through [`escape`]; the only HTML in the output is written here.

use chrono::{DateTime, Utc};

use orchestrator::triage::{Disposition, Priority, TriagedFinding, TriagedScan};

/// Who the report is for and who it is from.
#[derive(Debug, Clone)]
pub struct ReportMeta {
    /// Shown as the author. This is the agency, not us — the point of the
    /// product is that they send it under their own name.
    pub agency_name: String,
    /// Optional logo. Restricted to https and data-image URLs by
    /// [`safe_image_src`]; anything else is dropped rather than rendered.
    pub agency_logo_url: Option<String>,
    pub client_name: String,
    pub target_domain: String,
    /// Passed in rather than read from the clock, so rendering the same
    /// scan twice produces the same bytes.
    pub scanned_at: DateTime<Utc>,
}

/// Escapes text for HTML text nodes and quoted attribute values.
///
/// Deliberately covers both contexts with one function: two escaping
/// routines invites using the weaker one in the stronger context.
fn escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Returns a logo URL only if it is one we are willing to put in `src`.
///
/// An agency-supplied string reaching `src` unchecked would accept
/// `javascript:` and other script-bearing schemes. Allowing only https and
/// inline images keeps the document self-contained as well.
fn safe_image_src(url: &str) -> Option<String> {
    let trimmed = url.trim();
    let lowered = trimmed.to_ascii_lowercase();

    let acceptable = lowered.starts_with("https://")
        || lowered.starts_with("data:image/png;base64,")
        || lowered.starts_with("data:image/jpeg;base64,")
        || lowered.starts_with("data:image/svg+xml;base64,")
        || lowered.starts_with("data:image/webp;base64,");

    acceptable.then(|| escape(trimmed))
}

fn priority_label(priority: Priority) -> &'static str {
    match priority {
        Priority::Urgent => "Urgent",
        Priority::High => "High",
        Priority::Medium => "Medium",
        Priority::Low => "Low",
        Priority::None => "Noted",
    }
}

fn priority_class(priority: Priority) -> &'static str {
    match priority {
        Priority::Urgent => "p-urgent",
        Priority::High => "p-high",
        Priority::Medium => "p-medium",
        Priority::Low => "p-low",
        Priority::None => "p-none",
    }
}

/// Plain-language summary line. Written so the first thing a non-technical
/// reader sees is a conclusion rather than a count.
fn headline(scan: &TriagedScan) -> String {
    match scan.needs_attention() {
        0 => "No issues requiring action were found.".to_string(),
        1 => "One issue needs attention.".to_string(),
        n => format!("{n} issues need attention."),
    }
}

pub fn render_html(meta: &ReportMeta, scan: &TriagedScan) -> String {
    let mut html = String::with_capacity(16 * 1024);

    html.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n");
    html.push_str("<meta charset=\"utf-8\">\n");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    // Every browser proposes `document.title` as the filename when the reader
    // saves the page as a PDF. Naming the client and the date here is the
    // difference between an attachment called "Security review.pdf" and one
    // the agency can drop straight into a client folder without renaming it.
    html.push_str(&format!(
        "<title>Security review — {} — {}</title>\n",
        escape(&meta.target_domain),
        escape(meta.scanned_at.format("%e %B %Y").to_string().trim())
    ));
    html.push_str(STYLES);
    html.push_str("</head>\n<body>\n");

    render_save_bar(&mut html);
    render_header(&mut html, meta, scan);
    render_section(
        &mut html,
        "Needs attention",
        "Findings with a concrete fix, most important first.",
        &scan.actionable,
        Disposition::Act,
    );
    render_section(
        &mut html,
        "Worth a decision",
        "Whether these matter depends on how the site is used.",
        &scan.review,
        Disposition::Review,
    );
    render_inventory(&mut html, scan);
    render_footer(&mut html, meta);
    render_running_footer(&mut html, meta);

    html.push_str("</body>\n</html>\n");
    html
}

/// The one line of interface in an otherwise inert document.
///
/// The report is already the client-ready artefact — self-contained, no
/// external requests, the agency's name on it — but agencies send PDFs, not
/// HTML files, and until this said so the reader had to work out for
/// themselves that printing was how they got one.
///
/// Deliberately not a server-rendered PDF. Producing one would mean either a
/// headless browser in the deploy image, which roughly triples it and adds a
/// browser's patch cadence to a security product's attack surface, or a Rust
/// PDF library whose CSS support would quietly render a different document
/// from the one that was reviewed. The browser already has an excellent
/// renderer for exactly this page, and the print stylesheet below is what
/// makes its output worth handing to a client.
///
/// `onclick` rather than a listener: this file is opened from disk as often
/// as it is served, and a report that carries a script block is a report an
/// email gateway is entitled to be suspicious of. One attribute, no script.
fn render_save_bar(html: &mut String) {
    html.push_str(
        "<div class=\"save\">\n\
         <button type=\"button\" onclick=\"window.print()\">Save as PDF</button>\n\
         <span>Choose &ldquo;Save as PDF&rdquo; as the destination. \
         Turn off headers and footers for a clean document.</span>\n\
         </div>\n",
    );
}

fn render_header(html: &mut String, meta: &ReportMeta, scan: &TriagedScan) {
    html.push_str("<header class=\"cover\">\n");

    if let Some(logo) = meta.agency_logo_url.as_deref().and_then(safe_image_src) {
        html.push_str(&format!(
            "<img class=\"logo\" src=\"{logo}\" alt=\"{}\">\n",
            escape(&meta.agency_name)
        ));
    }

    html.push_str(&format!(
        "<p class=\"by\">Prepared by {}</p>\n",
        escape(&meta.agency_name)
    ));
    html.push_str("<h1>Website security review</h1>\n");
    html.push_str(&format!(
        "<p class=\"subject\"><strong>{}</strong> — prepared for {}</p>\n",
        escape(&meta.target_domain),
        escape(&meta.client_name)
    ));
    html.push_str(&format!(
        "<p class=\"date\">Scanned {}</p>\n",
        escape(meta.scanned_at.format("%e %B %Y").to_string().trim())
    ));

    html.push_str(&format!(
        "<p class=\"headline\">{}</p>\n",
        escape(&headline(scan))
    ));

    html.push_str("<dl class=\"tally\">\n");
    html.push_str(&format!(
        "<div><dt>Need attention</dt><dd>{}</dd></div>\n",
        scan.actionable.len()
    ));
    html.push_str(&format!(
        "<div><dt>Worth a decision</dt><dd>{}</dd></div>\n",
        scan.review.len()
    ));
    html.push_str(&format!(
        "<div><dt>Checked, no issue</dt><dd>{}</dd></div>\n",
        scan.inventory.len()
    ));
    html.push_str("</dl>\n</header>\n");
}

fn render_section(
    html: &mut String,
    heading: &str,
    blurb: &str,
    findings: &[TriagedFinding],
    disposition: Disposition,
) {
    if findings.is_empty() {
        // An empty "needs attention" section is the best possible result,
        // so it is stated rather than left as a gap on the page.
        if disposition == Disposition::Act {
            html.push_str("<section>\n<h2>Needs attention</h2>\n");
            html.push_str(
                "<p class=\"empty\">Nothing in this scan requires a fix.</p>\n</section>\n",
            );
        }
        return;
    }

    html.push_str("<section>\n");
    html.push_str(&format!("<h2>{}</h2>\n", escape(heading)));
    html.push_str(&format!("<p class=\"blurb\">{}</p>\n", escape(blurb)));

    for finding in findings {
        render_finding(html, finding);
    }

    html.push_str("</section>\n");
}

fn render_finding(html: &mut String, finding: &TriagedFinding) {
    html.push_str("<article class=\"finding\">\n<div class=\"finding-head\">\n");
    html.push_str(&format!(
        "<span class=\"pill {}\">{}</span>\n",
        priority_class(finding.priority),
        escape(priority_label(finding.priority))
    ));
    html.push_str(&format!("<h3>{}</h3>\n", escape(&finding.title)));
    html.push_str("</div>\n");

    if finding.occurrences > 1 {
        html.push_str(&format!(
            "<p class=\"seen\">Observed {} times.</p>\n",
            finding.occurrences
        ));
    }

    if let Some(guidance) = &finding.guidance {
        html.push_str(&format!("<p class=\"why\">{}</p>\n", escape(&guidance.why)));
        html.push_str(&format!(
            "<p class=\"fix\"><span class=\"fix-label\">What to do</span> {}</p>\n",
            escape(&guidance.fix)
        ));
    }

    if let Some(evidence) = &finding.evidence {
        html.push_str(&format!(
            "<p class=\"evidence\"><span class=\"evidence-label\">Observed</span> <code>{}</code></p>\n",
            escape(evidence)
        ));
    }

    html.push_str("</article>\n");
}

/// The appendix. Compact on purpose: it exists to show the work, not to be
/// read line by line.
fn render_inventory(html: &mut String, scan: &TriagedScan) {
    if scan.inventory.is_empty() {
        return;
    }

    html.push_str("<section class=\"appendix\">\n<h2>Also checked</h2>\n");
    html.push_str(
        "<p class=\"blurb\">Verified during this scan and found unremarkable.</p>\n<ul>\n",
    );

    for finding in &scan.inventory {
        html.push_str(&format!("<li>{}</li>\n", escape(&finding.title)));
    }

    html.push_str("</ul>\n</section>\n");
}

/// The line that repeats at the foot of every printed page.
///
/// Printed reports get separated. Page four on its own is otherwise an
/// anonymous list of somebody's security weaknesses, with nothing on it
/// saying whose site it describes, who produced it, or how old it is — and
/// that is a document nobody should be circulating.
///
/// Rendered last so it sits outside the flowed content, and hidden on screen,
/// where a fixed bar would only float over the page it is describing.
fn render_running_footer(html: &mut String, meta: &ReportMeta) {
    html.push_str(&format!(
        "<div class=\"running\">{} &middot; prepared by {} &middot; {}</div>\n",
        escape(&meta.target_domain),
        escape(&meta.agency_name),
        escape(meta.scanned_at.format("%e %B %Y").to_string().trim())
    ));
}

fn render_footer(html: &mut String, meta: &ReportMeta) {
    html.push_str("<footer>\n");
    html.push_str(&format!(
        "<p>Prepared by {} for {}.</p>\n",
        escape(&meta.agency_name),
        escape(&meta.client_name)
    ));
    html.push_str(
        "<p class=\"caveat\">An automated scan reports what it can observe from outside. \
         It is not a substitute for a manual review of the application.</p>\n",
    );
    html.push_str("</footer>\n");
}

/// Inline stylesheet. Inline because the document has to survive being
/// emailed as a single attachment, and because a print stylesheet is what
/// turns it into a PDF without a rendering service.
const STYLES: &str = r#"<style>
  :root {
    --ink: #16191d;
    --muted: #5c6470;
    --line: #e2e5ea;
    --bg: #ffffff;
    --accent: #1f4ed8;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0 auto;
    padding: 3rem 1.5rem 4rem;
    max-width: 46rem;
    background: var(--bg);
    color: var(--ink);
    font: 16px/1.65 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }
  h1 { font-size: 1.9rem; line-height: 1.2; margin: .4rem 0 .6rem; }
  h2 { font-size: 1.15rem; margin: 2.6rem 0 .3rem; padding-bottom: .5rem; border-bottom: 1px solid var(--line); }
  h3 { font-size: 1rem; margin: 0; }
  .cover { border-bottom: 2px solid var(--ink); padding-bottom: 1.6rem; }
  .logo { max-height: 44px; max-width: 200px; margin-bottom: 1rem; }
  .by, .date { color: var(--muted); font-size: .85rem; margin: .2rem 0; }
  .by { text-transform: uppercase; letter-spacing: .07em; }
  .subject { font-size: 1.05rem; margin: .2rem 0; }
  .headline { font-size: 1.1rem; font-weight: 600; margin: 1.4rem 0 0; }
  .tally { display: flex; gap: 2.5rem; margin: 1.2rem 0 0; padding: 0; }
  .tally div { margin: 0; }
  .tally dt { color: var(--muted); font-size: .78rem; text-transform: uppercase; letter-spacing: .05em; }
  .tally dd { margin: .1rem 0 0; font-size: 1.5rem; font-weight: 600; }
  .blurb { color: var(--muted); font-size: .9rem; margin: .5rem 0 1.4rem; }
  .empty { color: var(--muted); margin: 1rem 0; }
  .finding { padding: 1.1rem 0 1.3rem; border-bottom: 1px solid var(--line); }
  .finding-head { display: flex; align-items: baseline; gap: .7rem; }
  .pill {
    flex: none; font-size: .68rem; font-weight: 700; letter-spacing: .06em;
    text-transform: uppercase; padding: .2rem .5rem; border-radius: 3px;
    border: 1px solid currentColor;
  }
  .p-urgent { color: #8c1d18; }
  .p-high   { color: #a03604; }
  .p-medium { color: #7a5c00; }
  .p-low    { color: #40566d; }
  .p-none   { color: var(--muted); }
  .why { margin: .6rem 0 .5rem; }
  .fix { margin: .5rem 0; }
  .fix-label, .evidence-label {
    font-size: .7rem; font-weight: 700; text-transform: uppercase;
    letter-spacing: .06em; color: var(--muted); margin-right: .35rem;
  }
  .seen { color: var(--muted); font-size: .85rem; margin: .35rem 0 0; }
  .evidence { margin: .5rem 0 0; font-size: .88rem; }
  code { background: #f4f5f7; padding: .1rem .3rem; border-radius: 3px; word-break: break-all; }
  .appendix ul { columns: 2; column-gap: 2rem; padding-left: 1.1rem; color: var(--muted); font-size: .88rem; }
  .appendix li { margin: .15rem 0; break-inside: avoid; }
  footer { margin-top: 3rem; padding-top: 1.2rem; border-top: 1px solid var(--line); color: var(--muted); font-size: .85rem; }
  .caveat { font-size: .8rem; }
  .save {
    display: flex; align-items: center; gap: .8rem; flex-wrap: wrap;
    margin: 0 0 2.2rem; padding: .8rem 1rem;
    border: 1px solid var(--line); border-radius: 6px; background: #f8f9fb;
  }
  .save button {
    font: inherit; font-size: .88rem; font-weight: 600;
    padding: .5rem .9rem; border: 1px solid var(--ink); border-radius: 4px;
    background: var(--ink); color: #fff; cursor: pointer;
  }
  .save span { color: var(--muted); font-size: .82rem; }

  /* What turns this page into a document an agency can send a client.
     Everything here exists because the default browser output gets one of
     these wrong. */
  @page {
    size: A4;
    /* Room at the foot for the running identifier below. */
    margin: 16mm 15mm 22mm;
  }
  @media print {
    body { padding: 0; max-width: none; font-size: 10.5pt; }

    /* The severity pills carry their meaning in colour, and browsers drop
       colour when printing unless told not to. A report whose "urgent" and
       "low" print as identical grey text is a report that has lost the one
       distinction it exists to draw. */
    * { -webkit-print-color-adjust: exact; print-color-adjust: exact; }

    /* The button is interface, not content. */
    .save { display: none; }

    /* A finding split across a page break separates a problem from its fix,
       which is exactly the pairing the reader is scanning for. */
    .finding, .appendix li, .tally { break-inside: avoid; }
    h2 { break-after: avoid; }
    h3 { break-after: avoid; }
    p { orphans: 3; widows: 3; }

    /* The inventory is reference material. Starting it on its own page keeps
       it from swallowing the tail of the findings, which is the part anyone
       actually reads. */
    .appendix { break-before: page; }

    /* Repeats on every printed page in every current browser: this is the
       one way to get a running footer without a paged-media engine. It is
       what stops page four of a printout, once it has been separated from
       page one, from being an anonymous list of somebody's vulnerabilities. */
    .running {
        display: block;
        position: fixed;
        bottom: -14mm; left: 0; right: 0;
        border-top: 1px solid var(--line);
        padding-top: 2mm;
        color: var(--muted); font-size: 8pt;
    }
  }
  /* Hidden on screen: on a scrolling page a fixed footer is a floating bar
     over the content, and the same information is already in the footer. */
  .running { display: none; }
</style>
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use orchestrator::finding::{Finding, Severity};
    use orchestrator::triage::{triage_scan, Guidance};
    use serde_json::json;

    fn meta() -> ReportMeta {
        ReportMeta {
            agency_name: "Northgate Studio".to_string(),
            agency_logo_url: None,
            client_name: "Acme Ltd".to_string(),
            target_domain: "example.com".to_string(),
            scanned_at: Utc.with_ymd_and_hms(2026, 8, 28, 9, 0, 0).unwrap(),
        }
    }

    fn finding_with(title: &str, raw: serde_json::Value) -> Finding {
        Finding {
            severity: Severity::Info,
            title: title.to_string(),
            description: None,
            raw,
        }
    }

    fn csp_scan() -> TriagedScan {
        triage_scan(&[finding_with(
            "HTTP Missing Security Headers",
            json!({
                "template-id": "http-missing-security-headers",
                "matcher-name": "content-security-policy",
                "matched-at": "https://example.com",
            }),
        )])
    }

    #[test]
    fn the_agency_is_named_and_we_are_not() {
        // The entire pitch is that the agency sends this under their own
        // name. Our name appearing anywhere would undercut it.
        let html = render_html(&meta(), &csp_scan());

        assert!(html.contains("Northgate Studio"));
        assert!(html.contains("Acme Ltd"));
        assert!(!html.to_lowercase().contains("glarion"));
    }

    #[test]
    fn script_in_a_finding_title_cannot_execute() {
        // Titles ultimately derive from a scanned site, whose operator is
        // not to be trusted. This document gets opened on the agency's
        // machine.
        let hostile = "<script>alert(1)</script>";
        let scan = triage_scan(&[finding_with(
            hostile,
            json!({"template-id": "unknown-thing-entirely", "info": {"severity": "high"}}),
        )]);

        let html = render_html(&meta(), &scan);

        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn script_in_evidence_cannot_execute() {
        let scan = triage_scan(&[finding_with(
            "Email addresses",
            json!({
                "template-id": "email-extractor",
                "extracted-results": ["<img src=x onerror=alert(1)>"],
            }),
        )]);

        let html = render_html(&meta(), &scan);

        // The attribute text survives as inert characters, which is fine —
        // what must not survive is a tag the browser will parse. Asserting
        // on the escaped angle bracket is the check that means something.
        assert!(!html.contains("<img src=x"));
        assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;"));
    }

    #[test]
    fn hostile_agency_details_are_escaped_too() {
        // The agency is a customer, not an author. Their name is input.
        let mut m = meta();
        m.agency_name = "</title><script>alert(1)</script>".to_string();
        m.client_name = "\"><script>alert(2)</script>".to_string();
        m.target_domain = "<b>evil</b>".to_string();

        let html = render_html(&m, &csp_scan());

        assert!(!html.contains("<script>"));
        assert!(!html.contains("<b>evil</b>"));
    }

    #[test]
    fn a_javascript_logo_url_is_dropped_rather_than_rendered() {
        let mut m = meta();
        m.agency_logo_url = Some("javascript:alert(1)".to_string());

        let html = render_html(&m, &csp_scan());

        assert!(!html.contains("javascript:"));
        assert!(!html.contains("<img class=\"logo\""));
    }

    #[test]
    fn plain_http_and_unknown_data_logos_are_dropped() {
        // http would break the self-contained promise and leak when the
        // report is opened; a non-image data URL can carry markup.
        for candidate in [
            "http://example.com/logo.png",
            "data:text/html;base64,PHNjcmlwdD4=",
            "DATA:TEXT/HTML,<script>alert(1)</script>",
        ] {
            let mut m = meta();
            m.agency_logo_url = Some(candidate.to_string());

            let html = render_html(&m, &csp_scan());

            assert!(
                !html.contains("<img class=\"logo\""),
                "{candidate} should not reach an img src"
            );
        }
    }

    #[test]
    fn an_https_logo_is_kept() {
        let mut m = meta();
        m.agency_logo_url = Some("https://cdn.example.com/logo.png".to_string());

        let html = render_html(&m, &csp_scan());

        assert!(html.contains("https://cdn.example.com/logo.png"));
    }

    #[test]
    fn the_reader_gets_a_conclusion_before_a_count() {
        let html = render_html(&meta(), &csp_scan());
        assert!(html.contains("One issue needs attention."));
    }

    #[test]
    fn a_clean_scan_says_so_instead_of_showing_an_empty_page() {
        let scan = triage_scan(&[finding_with(
            "WAF Detection",
            json!({"template-id": "waf-detect"}),
        )]);

        let html = render_html(&meta(), &scan);

        assert!(html.contains("No issues requiring action were found."));
        assert!(html.contains("Nothing in this scan requires a fix."));
    }

    #[test]
    fn guidance_reaches_the_page() {
        let html = render_html(&meta(), &csp_scan());

        // The explanation is the thing being sold; its absence would be a
        // silent failure, since the report would still look complete.
        assert!(html.contains("What to do"));
        assert!(html.contains("Content-Security-Policy"));
    }

    #[test]
    fn the_document_makes_no_external_requests() {
        // Emailed as an attachment; a report that calls out on open leaks
        // when and where it was read.
        let html = render_html(&meta(), &csp_scan());

        assert!(!html.contains("<script"));
        assert!(!html.contains("<link"));
        assert!(!html.contains("@import"));
        assert!(!html.contains("http://"));
    }

    #[test]
    fn rendering_twice_produces_identical_bytes() {
        // Reports get diffed between months to show what changed. Any
        // instability would make every diff noise.
        let scan = csp_scan();
        assert_eq!(render_html(&meta(), &scan), render_html(&meta(), &scan));
    }

    #[test]
    fn repeat_observations_are_stated_once_with_a_count() {
        let scan = triage_scan(&[
            finding_with(
                "Fastly CDN Debug Headers Exposure",
                json!({"template-id": "fastly-debug-headers", "matched-at": "https://example.com/a"}),
            ),
            finding_with(
                "Fastly CDN Debug Headers Exposure",
                json!({"template-id": "fastly-debug-headers", "matched-at": "https://example.com/b"}),
            ),
        ]);

        let html = render_html(&meta(), &scan);

        assert_eq!(html.matches("CDN debug headers exposed").count(), 1);
        assert!(html.contains("Observed 2 times."));
    }

    #[test]
    fn escaping_covers_every_dangerous_character() {
        assert_eq!(
            escape(r#"<a href="x" onclick='y'>&</a>"#),
            "&lt;a href=&quot;x&quot; onclick=&#x27;y&#x27;&gt;&amp;&lt;/a&gt;"
        );
    }

    #[test]
    fn ampersands_are_escaped_before_anything_else() {
        // Escaping in the wrong order yields &amp;lt; and shows the reader
        // literal entity text.
        assert_eq!(escape("&lt;"), "&amp;lt;");
    }

    #[test]
    fn guidance_text_is_escaped_even_though_we_wrote_it() {
        // Our own rules table is trusted today. Making the renderer depend
        // on that is how an injection arrives later, via a rule sourced
        // from somewhere else.
        let mut scan = csp_scan();
        scan.actionable[0].guidance = Some(Guidance {
            why: "<script>alert(1)</script>".to_string(),
            fix: "<script>alert(2)</script>".to_string(),
        });

        let html = render_html(&meta(), &scan);

        assert!(!html.contains("<script>alert"));
    }

    /// The report is the thing an agency hands a client, and they hand over
    /// PDFs. These pin the handful of print rules that decide whether the
    /// browser's own output is worth sending — each one is here because the
    /// default gets it wrong.
    #[test]
    fn the_document_is_set_up_to_print_as_a_deliverable() {
        let html = render_html(&meta(), &csp_scan());

        assert!(
            html.contains("@page"),
            "no page box means the browser's default margins"
        );
        assert!(
            html.contains("print-color-adjust: exact"),
            "browsers drop colour when printing, and the severity pills are colour"
        );
        assert!(
            html.contains(".save { display: none; }"),
            "the print button must not print"
        );
        assert!(
            html.contains("break-before: page"),
            "the inventory should not swallow the tail of the findings"
        );
        assert!(html.contains("orphans: 3"));
    }

    #[test]
    fn the_saved_file_names_itself() {
        // Browsers propose the title as the PDF filename. "Security review.pdf"
        // in a folder of client work is a file nobody can identify later.
        let html = render_html(&meta(), &csp_scan());
        let title = html
            .split("<title>")
            .nth(1)
            .and_then(|rest| rest.split("</title>").next())
            .expect("the document has a title");

        assert!(title.contains("example.com"), "title was {title:?}");
        assert!(title.contains("2026"), "title was {title:?}");
    }

    #[test]
    fn a_separated_page_still_says_whose_report_it_is() {
        // A printed report gets split up. Page four alone is otherwise an
        // anonymous list of somebody's security weaknesses.
        let html = render_html(&meta(), &csp_scan());
        let running = html
            .split("<div class=\"running\">")
            .nth(1)
            .and_then(|rest| rest.split("</div>").next())
            .expect("a running footer is rendered");

        assert!(running.contains("example.com"));
        assert!(running.contains("Northgate Studio"));
        assert!(
            html.contains("position: fixed"),
            "only a fixed element repeats on every printed page"
        );
    }

    #[test]
    fn the_print_button_does_not_make_it_a_scripted_document() {
        // An HTML attachment carrying a script block is one an email gateway
        // is entitled to strip or quarantine — and this report is sent as an
        // attachment. One inline attribute is the whole budget.
        let html = render_html(&meta(), &csp_scan());

        assert!(html.contains("window.print()"));
        assert!(!html.contains("<script"), "no script block may appear");
        assert_eq!(
            html.matches("onclick").count(),
            1,
            "one handler, on the one control"
        );
    }

    #[test]
    fn a_hostile_agency_name_cannot_escape_the_running_footer() {
        // The running footer is a third place the agency's own strings are
        // interpolated, and it was written after the two that already had
        // tests. Same rule: the agency is a customer, not an author.
        let mut m = meta();
        m.agency_name = "</div><script>alert(1)</script>".to_string();
        let html = render_html(&m, &csp_scan());

        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;"));
    }
}
