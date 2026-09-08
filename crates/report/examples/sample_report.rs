//! Regenerate the public sample with the production report renderer:
//! cargo run -p report --example sample_report > web/sample-report.html
use chrono::{TimeZone, Utc};
use orchestrator::triage::{Disposition, Guidance, Priority, TriagedFinding, TriagedScan};
use report::html::{render_html, ReportMeta};

fn finding(
    title: &str,
    disposition: Disposition,
    priority: Priority,
    why: &str,
    fix: &str,
    evidence: &str,
) -> TriagedFinding {
    TriagedFinding {
        title: title.into(),
        disposition,
        priority,
        scanner_severity: orchestrator::finding::Severity::Info,
        guidance: Some(Guidance {
            why: why.into(),
            fix: fix.into(),
        }),
        evidence: Some(evidence.into()),
        template_id: "fictional-example".into(),
        matcher: String::new(),
        occurrences: 1,
    }
}

fn main() {
    let meta = ReportMeta {
        agency_name: "Northstar Studio".into(),
        agency_logo_url: None,
        client_name: "Example Client".into(),
        target_domain: "example.com".into(),
        scanned_at: Utc.with_ymd_and_hms(2026, 9, 6, 10, 0, 0).unwrap(),
    };
    let scan = TriagedScan {
        actionable: vec![
            finding("Renew the TLS certificate", Disposition::Act, Priority::High,
                "If this certificate expires, browsers may warn visitors or block access to the website.",
                "Ask the hosting provider to confirm automatic renewal. Once renewed, check that the replacement certificate is being served.",
                "Fictional observation: the certificate for example.com:443 expires in 18 days."),
            finding("Add a Content Security Policy", Disposition::Act, Priority::Medium,
                "The browser has no declared policy limiting which scripts and resources this page may load. A policy can reduce the impact of injected content.",
                "Ask the development team to deploy a report-only policy first. Review required sources and violations before enforcing it.",
                "Fictional observation: the homepage response did not include a Content-Security-Policy header."),
        ],
        review: vec![finding("Publish a security contact", Disposition::Review, Priority::Low,
            "Researchers may have difficulty finding the right person to report a security issue to. The right contact depends on your support process.",
            "Choose a monitored contact address and decide whether to publish it in a security.txt file. Keep its expiry date current.",
            "Fictional observation: /.well-known/security.txt was not found.")],
        inventory: vec![
            finding("HTTPS endpoint observed", Disposition::Inventory, Priority::None, "", "", ""),
            finding("Public web server identified", Disposition::Inventory, Priority::None, "", "", ""),
        ],
    };
    let mut html = render_html(&meta, &scan);
    html = html.replacen(
        "<style>",
        "<link rel=\"stylesheet\" href=\"/prism.css\"><style>",
        1,
    );
    html = html.replace("</head>", "<meta name=\"description\" content=\"Explore a fictional Glarion client report with prioritized actions, clear explanations and evidence.\"><link rel=\"canonical\" href=\"https://glarion.app/sample-report.html\"><link rel=\"icon\" href=\"/glarion-mark-64.png\"><script src=\"/report-actions.js\" defer></script></head>");
    html = html.replace("</head>", r##"<meta name="theme-color" content="#faf7fb"><meta property="og:type" content="website"><meta property="og:title" content="Sample Website Security Report | Glarion"><meta property="og:description" content="A fictional, client-ready website security report showing prioritized findings, evidence and next steps."><meta property="og:url" content="https://glarion.app/sample-report.html"><meta property="og:image" content="https://glarion.app/og.png"><meta name="twitter:card" content="summary_large_image"></head>"##);
    html = html.replace("<body>", "<body><div class=\"sample-banner\"><strong>Glarion · sample report</strong><a href=\"/\">Back to Glarion</a></div>");
    html = html.replace("<header class=\"cover\">", "<p class=\"sample-note\">Fictional example · all findings and data are illustrative.</p><header class=\"cover\">");
    html = html.replace(" onclick=\"window.print()\"", "");
    print!("{html}");
}
