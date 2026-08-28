//! Triage checked against the output of a real scan.
//!
//! The fixture is a genuine Nuclei run against a small production site,
//! with the host and any addresses replaced. It is kept because the *mix*
//! of findings is the thing worth testing against: 32 results, none above
//! "low", twenty-nine of them informational. Synthetic fixtures tend to be
//! written around the interesting cases and so never reproduce the ratio
//! that makes triage necessary in the first place.
//!
//! What these tests defend is the product claim: that we turn a long
//! undifferentiated list into a short one a client can act on, without
//! throwing away the evidence that the rest was checked.

use orchestrator::finding::{Finding, Severity};
use report::triage::{triage_scan, Disposition, Priority};

fn load_real_scan() -> Vec<Finding> {
    let raw = include_str!("fixtures/nuclei_real_scan.jsonl");

    raw.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let value: serde_json::Value =
                serde_json::from_str(line).expect("fixture line is not valid JSON");

            let severity = value
                .get("info")
                .and_then(|i| i.get("severity"))
                .and_then(|s| s.as_str())
                .map(Severity::from_tool_label)
                .unwrap_or(Severity::Info);

            let title = value
                .get("info")
                .and_then(|i| i.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("Unnamed finding")
                .to_string();

            Finding {
                severity,
                title,
                description: None,
                raw: value,
            }
        })
        .collect()
}

#[test]
fn the_fixture_is_the_scan_we_think_it_is() {
    // If this drifts, every ratio asserted below becomes meaningless.
    let findings = load_real_scan();

    assert_eq!(findings.len(), 32);
    assert!(
        findings.iter().all(|f| f.severity <= Severity::Low),
        "this fixture is valuable precisely because nothing in it is severe"
    );
}

#[test]
fn a_long_flat_list_becomes_a_short_actionable_one() {
    // The core claim. Raw output gives the reader 32 undifferentiated
    // lines; what reaches the front of the report should be a handful.
    let triaged = triage_scan(&load_real_scan());

    assert!(
        triaged.needs_attention() <= 8,
        "expected a short actionable list, got {}",
        triaged.needs_attention()
    );
    assert!(
        triaged.needs_attention() >= 1,
        "a real site with no CSP and weak HSTS must not produce an empty report"
    );
    assert!(
        triaged.inventory.len() > triaged.actionable.len(),
        "on a well-run site most findings should be inventory"
    );
}

#[test]
fn no_finding_is_lost_in_triage() {
    // Demoted or folded together, never dropped: the client is paying to
    // know what was checked, and a missing row is indistinguishable from a
    // missed check. Rows can legitimately be fewer than raw results once
    // duplicates collapse, so the accounting is done in observations.
    let findings = load_real_scan();
    let triaged = triage_scan(&findings);

    assert_eq!(triaged.observations(), findings.len());
    assert!(triaged.rows() <= findings.len());
}

#[test]
fn the_missing_csp_reaches_the_top_of_the_report() {
    // The scanner rated this "info" and buried it among four other
    // findings sharing one template id. It is the highest-value item in
    // the whole scan.
    let triaged = triage_scan(&load_real_scan());

    let csp = triaged
        .actionable
        .iter()
        .find(|f| f.title.contains("Content-Security-Policy"))
        .expect("the missing CSP must be surfaced as actionable");

    assert_eq!(csp.scanner_severity, Severity::Info);
    assert_eq!(csp.priority, Priority::High);
    assert_eq!(
        triaged.actionable[0].priority,
        Priority::High,
        "the highest-priority item should lead the report"
    );
}

#[test]
fn dns_and_certificate_facts_stay_in_the_appendix() {
    // "You have an MX record" is not a finding. Putting rows like this in
    // front of a client is what makes a report look padded.
    let triaged = triage_scan(&load_real_scan());

    for template in [
        "mx-fingerprint",
        "nameserver-fingerprint",
        "caa-fingerprint",
        "ssl-issuer",
        "dnssec-detection",
        "waf-detect",
    ] {
        assert!(
            triaged.inventory.iter().any(|f| f.template_id == template),
            "{template} belongs in the appendix"
        );
        assert!(
            !triaged.actionable.iter().any(|f| f.template_id == template),
            "{template} must not be presented as something to fix"
        );
    }
}

#[test]
fn repeated_template_ids_become_distinct_readable_rows() {
    // Five findings arrive as "HTTP Missing Security Headers". A report
    // that prints that name five times is unusable.
    let triaged = triage_scan(&load_real_scan());

    let mut header_titles: Vec<&str> = triaged
        .actionable
        .iter()
        .chain(triaged.review.iter())
        .filter(|f| f.template_id == "http-missing-security-headers")
        .map(|f| f.title.as_str())
        .collect();

    let count = header_titles.len();
    header_titles.sort_unstable();
    header_titles.dedup();

    assert!(
        count > 1,
        "the fixture should contain several header findings"
    );
    assert_eq!(
        header_titles.len(),
        count,
        "each missing header needs its own title"
    );
}

#[test]
fn everything_actionable_tells_the_reader_what_to_do() {
    // An agency forwards this to a client. A row saying only "something is
    // wrong" generates a support question instead of a fix.
    let triaged = triage_scan(&load_real_scan());

    for finding in &triaged.actionable {
        let guidance = finding.guidance.as_ref().unwrap_or_else(|| {
            panic!(
                "actionable finding '{}' ({}) has no guidance",
                finding.title, finding.template_id
            )
        });

        assert!(!guidance.why.trim().is_empty());
        assert!(!guidance.fix.trim().is_empty());
    }
}

#[test]
fn findings_carry_the_evidence_behind_them() {
    // A claim without the observation that produced it cannot be verified
    // by whoever receives the report.
    let triaged = triage_scan(&load_real_scan());

    for finding in &triaged.actionable {
        assert!(
            finding.evidence.is_some(),
            "'{}' should say what was observed",
            finding.title
        );
    }
}

#[test]
fn a_leftover_placeholder_address_is_put_in_front_of_a_human() {
    // The real scan this fixture came from caught an unreplaced
    // "your@email.com" in production. Nobody should have to read an
    // appendix to find that.
    let triaged = triage_scan(&load_real_scan());

    let email = triaged
        .review
        .iter()
        .find(|f| f.template_id == "email-extractor")
        .expect("exposed addresses need a human decision, not silent filing");

    assert_eq!(email.disposition, Disposition::Review);
    assert!(email.guidance.is_some());
}

#[test]
fn one_misconfiguration_produces_one_row() {
    // The CDN left in debug mode tripped three separate rules in the real
    // scan. A client report that lists the same sentence three times reads
    // as padding, which is the opposite of what an agency forwards it for.
    let triaged = triage_scan(&load_real_scan());

    let debug_rows: Vec<_> = triaged
        .actionable
        .iter()
        .filter(|f| f.template_id == "fastly-debug-headers")
        .collect();

    assert_eq!(
        debug_rows.len(),
        1,
        "three raw results for one misconfiguration should collapse into one row"
    );
    assert!(
        debug_rows[0].occurrences > 1,
        "the row should record that it was seen more than once"
    );
}

#[test]
fn collapsing_never_hides_a_distinct_issue() {
    // Rows sharing a template id but describing different problems — each
    // missing header — must survive as separate rows.
    let triaged = triage_scan(&load_real_scan());

    let header_rows: Vec<_> = triaged
        .actionable
        .iter()
        .chain(triaged.review.iter())
        .filter(|f| f.template_id == "http-missing-security-headers")
        .collect();

    assert!(
        header_rows.len() > 1,
        "different missing headers are different findings"
    );
}

#[test]
fn titles_are_written_for_the_client_not_the_operator() {
    // Scanner names like "Weak HTTP Strict-Transport-Security - Detect"
    // are operator shorthand. Anything reaching the front of the report
    // should read as a sentence about the site.
    let triaged = triage_scan(&load_real_scan());

    for finding in &triaged.actionable {
        assert!(
            !finding.title.contains(" - Detect"),
            "'{}' still uses the scanner's operator wording",
            finding.title
        );
    }
}
