//! Renders the bundled real scan as a client-ready report.
//! cargo run -p report --example render_demo > report.html
use chrono::{TimeZone, Utc};
use orchestrator::finding::{Finding, Severity};
use orchestrator::triage::triage_scan;
use report::html::{render_html, ReportMeta};

fn main() {
    let raw = include_str!("../../orchestrator/tests/fixtures/nuclei_real_scan.jsonl");
    let findings: Vec<Finding> = raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            Finding {
                severity: v["info"]["severity"]
                    .as_str()
                    .map(Severity::from_tool_label)
                    .unwrap_or(Severity::Info),
                title: v["info"]["name"].as_str().unwrap_or("?").to_string(),
                description: None,
                raw: v,
            }
        })
        .collect();

    let meta = ReportMeta {
        agency_name: "Northgate Studio".to_string(),
        agency_logo_url: None,
        client_name: "Acme Ltd".to_string(),
        target_domain: "example.com".to_string(),
        scanned_at: Utc.with_ymd_and_hms(2026, 8, 28, 9, 0, 0).unwrap(),
    };

    print!("{}", render_html(&meta, &triage_scan(&findings)));
}
