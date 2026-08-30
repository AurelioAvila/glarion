//! Runs what the product runs against one domain, and prints the
//! triaged report, skipping the ownership gate.
//!
//! Development-only, for exactly one situation: the person running this
//! command is the domain's owner and wants to see the real output without
//! going through signup, DNS verification, and the scheduler. The gate
//! itself lives at the API layer (see routes::scans and routes::targets)
//! and is untouched by this — nothing this binary does is reachable from
//! the network, and it grants itself no authorization that a stranger
//! could also claim for somebody else's domain.
//!
//!   cargo run -p orchestrator --example full_scan -- example.com

use orchestrator::triage::triage_scan;
use orchestrator::{tools, triage};

/// Set to render the same HTML the product emails out, alongside the
/// terminal summary — one real scan, two views of it, rather than paying
/// for the scan twice.
const HTML_ARG: &str = "--html";

#[tokio::main]
async fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let want_html = args.iter().any(|a| a == HTML_ARG);
    args.retain(|a| a != HTML_ARG);

    let domain = args.into_iter().next().unwrap_or_else(|| {
        eprintln!("usage: full_scan <domain> [--html]");
        std::process::exit(2);
    });

    eprintln!("== {domain} ==");
    eprintln!("(nuclei can take a while on a full template run)");

    let (nuclei, tls) = tokio::join!(tools::nuclei::run(&domain), tools::tls::run(&domain));

    let mut findings = Vec::new();
    match nuclei {
        Ok(found) => findings.extend(found),
        Err(err) => eprintln!("nuclei: {err}"),
    }
    match tls {
        Ok(found) => findings.extend(found),
        Err(err) => eprintln!("tls: {err}"),
    }

    let scan = triage_scan(&findings);

    println!("\n{domain}");
    println!(
        "  {} observation(s) -> {} row(s): {} to act on, {} to review, {} on record\n",
        scan.observations(),
        scan.rows(),
        scan.actionable.len(),
        scan.review.len(),
        scan.inventory.len(),
    );

    for (label, bucket) in [
        ("ACT", &scan.actionable),
        ("REVIEW", &scan.review),
        ("INVENTORY", &scan.inventory),
    ] {
        if bucket.is_empty() {
            continue;
        }
        println!("-- {label} --");
        for item in bucket {
            print_finding(item);
        }
        println!();
    }

    if want_html {
        // Placeholder identity: this path is for the domain's owner
        // previewing their own report before it carries a real agency
        // name and logo, which is set from the account's profile in
        // production (see routes::profile).
        let meta = report::html::ReportMeta {
            agency_name: "Glarion".to_string(),
            agency_logo_url: None,
            client_name: domain.clone(),
            target_domain: domain.clone(),
            scanned_at: chrono::Utc::now(),
        };

        let html = report::html::render_html(&meta, &scan);
        let path = format!("{domain}-report.html");
        std::fs::write(&path, html).expect("could not write the report file");
        eprintln!("wrote {path}");
    }
}

fn print_finding(item: &triage::TriagedFinding) {
    let occurs = if item.occurrences > 1 {
        format!(" (x{})", item.occurrences)
    } else {
        String::new()
    };
    println!("  [{:?}] {}{}", item.priority, item.title, occurs);
    if let Some(guidance) = &item.guidance {
        println!("      why: {}", guidance.why);
        println!("      fix: {}", guidance.fix);
    }
}
