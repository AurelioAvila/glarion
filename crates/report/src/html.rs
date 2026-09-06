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
use std::fmt::Write;

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
    // Encode every scalar as a CSS escape: scanner/agency text must never
    // terminate a CSS string or the surrounding HTML style element.
    let identity = format!(
        "{} · prepared by {} · {}",
        meta.target_domain,
        meta.agency_name,
        meta.scanned_at.format("%e %B %Y")
    );
    let css_identity: String = identity
        .chars()
        .map(|ch| format!("\\{:x} ", ch as u32))
        .collect();
    html.push_str(&format!("<style>@page {{ @bottom-center {{ content: \"{css_identity}\"; font: 8pt/1.4 'Segoe UI', sans-serif; color: #695174; vertical-align: middle; overflow-wrap: anywhere; }} }}</style>\n"));
    html.push_str("</head>\n<body>\n");

    render_running_footer(&mut html, meta);
    render_save_bar(&mut html);
    html.push_str("<main class=\"report\" id=\"report\">\n");
    render_header(&mut html, meta, scan);
    render_action_plan(&mut html, scan);
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
    html.push_str("</main>\n");

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
         <span>Use Print or Ctrl/Cmd+P, then choose &ldquo;Save as PDF&rdquo;. \
         Turn off browser headers and footers.</span>\n\
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
        "<div class=\"overview\"><p class=\"headline\">{}</p>\n",
        escape(&headline(scan))
    ));
    html.push_str("<p class=\"summary-note\">A snapshot of the website's public surface. Use the findings below to plan fixes and review decisions.</p>\n");

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
        "<div><dt>For reference</dt><dd>{}</dd></div>\n",
        scan.inventory.len()
    ));
    html.push_str("</dl></div>\n</header>\n");
}

fn render_action_plan(html: &mut String, scan: &TriagedScan) {
    html.push_str("<nav class=\"report-nav\" aria-label=\"Report sections\"><a href=\"#actions\">Action required</a>");
    if !scan.review.is_empty() {
        html.push_str("<a href=\"#decisions\">Decisions</a>");
    }
    if !scan.inventory.is_empty() {
        html.push_str("<a href=\"#reference\">Reference</a>");
    }
    html.push_str("<a href=\"#scope\">Scope &amp; limits</a></nav>\n");
    if scan.actionable.is_empty() {
        return;
    }
    html.push_str("<section class=\"action-plan\"><h2>Start with these actions</h2><p class=\"blurb\">Review these priorities with the team responsible for the website. Each item links to its evidence and recommended fix.</p><ol class=\"plan-list\">\n");
    for (index, finding) in scan.actionable.iter().take(3).enumerate() {
        html.push_str(&format!("<li><span class=\"pill {}\">{}</span><a href=\"#action-{}\">{}<span class=\"plan-arrow\" aria-hidden=\"true\"> &rarr;</span></a></li>\n", priority_class(finding.priority), priority_label(finding.priority), index+1, escape(&finding.title)));
    }
    html.push_str("</ol>");
    if scan.actionable.len() > 3 {
        html.push_str(&format!(
            "<a class=\"all-actions\" href=\"#actions\">View all {} actions</a>",
            scan.actionable.len()
        ));
    }
    html.push_str("</section>\n");
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
            html.push_str("<section id=\"actions\">\n<h2>Needs attention</h2>\n");
            html.push_str(
                "<p class=\"empty\">Nothing in this scan requires a fix.</p>\n</section>\n",
            );
        }
        return;
    }

    let (section_id, prefix) = if disposition == Disposition::Act {
        ("actions", "action")
    } else {
        ("decisions", "decision")
    };
    html.push_str(&format!("<section id=\"{section_id}\">\n"));
    html.push_str(&format!("<h2>{}</h2>\n", escape(heading)));
    html.push_str(&format!("<p class=\"blurb\">{}</p>\n", escape(blurb)));

    for (index, finding) in findings.iter().enumerate() {
        render_finding(html, finding, prefix, index + 1);
    }

    html.push_str("</section>\n");
}

fn render_finding(html: &mut String, finding: &TriagedFinding, prefix: &str, number: usize) {
    html.push_str(&format!("<article class=\"finding\" id=\"{prefix}-{number}\">\n<div class=\"finding-head\"><span class=\"finding-ref\">{} {number:02}</span>\n", if prefix == "action" { "Action" } else { "Decision" }));
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
        html.push_str(&format!("<div class=\"finding-body\"><div class=\"impact\"><h4>Why it matters</h4><p class=\"why\">{}</p></div>\n", escape(&guidance.why)));
        html.push_str(&format!(
            "<div class=\"fix\"><h4 class=\"fix-label\">What to do</h4><p>{}</p></div></div>\n",
            escape(&guidance.fix)
        ));
    } else {
        html.push_str("<p class=\"why\">Confirm this observation with the website team and decide whether a change is needed. No specific remediation guidance is available for this finding.</p>\n");
    }

    if let Some(evidence) = &finding.evidence {
        html.push_str(&format!(
            "<div class=\"evidence\"><h4 class=\"evidence-label\">Observed evidence</h4><code>{}</code></div>\n",
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

    let appendix_class = if scan.inventory.len() > 8 {
        "appendix appendix-long"
    } else {
        "appendix"
    };
    write!(
        html,
        "<section class=\"{appendix_class}\" id=\"reference\">\n<h2>For reference</h2>\n"
    )
    .unwrap();
    html.push_str(
        "<p class=\"blurb\">Observations kept for context, not classified as actions or decisions. These are not a count of passed security tests.</p>\n<ul>\n",
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
    html.push_str("<footer id=\"scope\">\n<h2>Scope &amp; limits</h2>\n");
    html.push_str(&format!(
        "<p>Prepared by {} for {}.</p>\n",
        escape(&meta.agency_name),
        escape(&meta.client_name)
    ));
    html.push_str(
        "<p class=\"caveat\">An automated scan reports what it can observe from outside. \
         Findings describe the scan date; they do not prove a website is secure today. \
         This report is not a manual penetration test or a compliance certification.</p>\n",
    );
    html.push_str("</footer>\n");
}

/// Inline stylesheet. Inline because the document has to survive being
/// emailed as a single attachment, and because a print stylesheet is what
/// turns it into a PDF without a rendering service.
const STYLES: &str = concat!("<style>\n", include_str!("report.css"), "\n</style>\n");

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

        // The title also appears in the linked action summary, but the
        // repeated observations must still produce just one detail block.
        assert!(html.contains("CDN debug headers exposed"));
        assert_eq!(html.matches("<article class=\"finding\"").count(), 1);
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
    fn action_summary_links_to_details_without_inventing_passed_checks() {
        let html = render_html(&meta(), &csp_scan());
        assert!(html.contains("href=\"#action-1\""));
        assert!(html.contains("id=\"action-1\""));
        assert!(html.contains("For reference"));
        assert!(!html.contains("Checked, no issue"));
        assert!(html.contains("Why it matters"));
        assert!(html.contains("Observed evidence"));
    }

    #[test]
    fn missing_guidance_is_explicit_instead_of_looking_complete() {
        let mut scan = csp_scan();
        scan.actionable[0].guidance = None;
        let html = render_html(&meta(), &scan);
        assert!(html.contains("No specific remediation guidance is available"));
        assert!(html.contains("Observed evidence"));
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
            html.contains("@bottom-center"),
            "page margin boxes reserve a separate identity band on every printed page"
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
        m.agency_name = "</style></div><script>alert(1)</script>".to_string();
        let html = render_html(&m, &csp_scan());

        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;"));
        let print_style = html
            .split("<style>@page")
            .nth(1)
            .unwrap()
            .split("</style>")
            .next()
            .unwrap();
        assert!(!print_style.contains("<"));
        assert!(print_style.contains("\\3c \\2f \\73 \\74 \\79 \\6c \\65 \\3e "));
    }
}
