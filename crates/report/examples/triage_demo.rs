//! Prints the triage of the bundled real scan, to eyeball what a client
//! would actually see. Run with: cargo run -p report --example triage_demo
use orchestrator::finding::{Finding, Severity};
use report::triage::triage_scan;

fn main() {
    let raw = include_str!("../tests/fixtures/nuclei_real_scan.jsonl");
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

    let t = triage_scan(&findings);

    println!("RAW SCAN: {} findings\n", findings.len());
    println!("ACT ON THIS ({}):", t.actionable.len());
    for f in &t.actionable {
        println!(
            "  [{:?}] {}{}",
            f.priority,
            f.title,
            if f.occurrences > 1 {
                format!("  (seen {}x)", f.occurrences)
            } else {
                String::new()
            }
        );
        if let Some(g) = &f.guidance {
            println!("      why: {}", &g.why[..g.why.len().min(95)]);
        }
    }
    println!("\nREVIEW ({}):", t.review.len());
    for f in &t.review {
        println!("  {}", f.title);
    }
    println!("\nAPPENDIX / VERIFIED ({}):", t.inventory.len());
    println!("  {} items", t.inventory.len());
}
