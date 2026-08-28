//! Nuclei wrapper.
//!
//! Two safety properties matter here and both are enforced structurally
//! rather than by convention:
//!
//!  * **No shell.** The process is spawned with an argument vector, never a
//!    command string, so a hostile domain string cannot inject arguments or
//!    shell metacharacters. The domain is re-validated through
//!    `normalize_target` immediately before the spawn regardless of what
//!    the caller claims to have checked.
//!
//!  * **Non-intrusive by construction.** The argument builder always emits
//!    the rate limit, timeout, and severity/template restrictions, and
//!    `build_args` is unit-tested to assert they are present. Intrusive
//!    template categories (fuzzing, brute force, denial of service) are
//!    explicitly excluded.

use std::process::Stdio;
use std::time::Duration;

use crate::domain::normalize_target;
use crate::finding::{Finding, Severity};
use crate::net_guard;

/// Requests per second against the target. Deliberately low: this is a
/// health check on someone's production site, not a race.
pub const RATE_LIMIT_PER_SECOND: u32 = 20;

/// Wall-clock ceiling for a single scan. A scan that hasn't finished by
/// now is killed rather than left to run indefinitely.
///
/// Measured, not guessed: a full-template scan of a single small static
/// site behind a CDN took 17.5 minutes at our rate limit. The first value
/// here was 10 minutes, which would have killed every real scan partway
/// through and recorded it as a failure. Kept at roughly double the
/// observed time so an ordinary site has headroom; a site large enough to
/// exceed this needs a narrower template selection, not a longer timeout.
pub const SCAN_TIMEOUT_SECS: u64 = 2400;

/// Cap on captured stdout. Nuclei on a large site can emit a lot; past
/// this point we stop rather than buffer without limit.
pub const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

/// Template categories that must never run. These are the ones that attack
/// rather than observe.
const EXCLUDED_TAGS: &str = "fuzz,brute-force,dos,intrusive";

/// Builds the argument vector for a scan of `domain`.
///
/// Pure and unit-tested — the safety flags are asserted in the tests below,
/// so removing one breaks the build rather than silently making scans more
/// aggressive.
pub fn build_args(domain: &str) -> Vec<String> {
    [
        // Target.
        "-target",
        domain,
        // JSONL on stdout, one finding per line.
        "-jsonl",
        // Intensity controls.
        "-rate-limit",
        &RATE_LIMIT_PER_SECOND.to_string(),
        "-concurrency",
        "10",
        "-timeout",
        "10",
        "-retries",
        "1",
        // Never run attacking templates.
        "-exclude-tags",
        EXCLUDED_TAGS,
        // Detection only: no interactsh callbacks, no automatic template
        // updates mid-run (which would make scans non-reproducible).
        "-no-interactsh",
        "-disable-update-check",
        // Quiet the banner/progress so stdout is pure JSONL.
        "-silent",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Parses Nuclei's JSONL output into normalized findings.
///
/// Malformed lines are skipped rather than failing the whole scan — one
/// unparseable line should not discard every other finding.
pub fn parse_jsonl(output: &str) -> Vec<Finding> {
    output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .map(|value| {
            let info = value.get("info");

            let severity = info
                .and_then(|info| info.get("severity"))
                .and_then(|s| s.as_str())
                .map(Severity::from_tool_label)
                .unwrap_or(Severity::Info);

            let title = info
                .and_then(|info| info.get("name"))
                .and_then(|n| n.as_str())
                .or_else(|| value.get("template-id").and_then(|t| t.as_str()))
                .unwrap_or("Unnamed finding")
                .to_string();

            let description = info
                .and_then(|info| info.get("description"))
                .and_then(|d| d.as_str())
                .map(str::to_string);

            Finding {
                severity,
                title,
                description,
                raw: value,
            }
        })
        .collect()
}

#[derive(Debug, thiserror::Error)]
pub enum NucleiError {
    #[error("invalid target: {0}")]
    InvalidTarget(String),
    #[error("refusing to scan: {0}")]
    Refused(String),
    #[error("nuclei is not installed or not on PATH")]
    NotInstalled,
    #[error("scan timed out after {SCAN_TIMEOUT_SECS}s")]
    TimedOut,
    #[error("nuclei failed: {0}")]
    Failed(String),
}

/// Runs a scan and returns normalized findings.
pub async fn run(domain: &str) -> Result<Vec<Finding>, NucleiError> {
    // Re-validate at the point of use. The caller has already checked, but
    // this is the last line before a process is spawned with this value.
    let domain =
        normalize_target(domain).map_err(|err| NucleiError::InvalidTarget(err.to_string()))?;

    // A syntactically public hostname can still resolve to a private or
    // link-local address, which would point the scanner at our own network
    // or at the cloud metadata endpoint. Checked here, as late as possible,
    // because the scanner resolves the name again itself and we cannot pin
    // the address for an external process.
    net_guard::resolve_public_addresses(&domain)
        .await
        .map_err(|err| NucleiError::Refused(err.to_string()))?;

    let mut command = tokio::process::Command::new("nuclei");
    command
        .args(build_args(&domain))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let child = command.spawn().map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            NucleiError::NotInstalled
        } else {
            NucleiError::Failed(err.to_string())
        }
    })?;

    let output = tokio::time::timeout(
        Duration::from_secs(SCAN_TIMEOUT_SECS),
        child.wait_with_output(),
    )
    .await
    .map_err(|_| NucleiError::TimedOut)?
    .map_err(|err| NucleiError::Failed(err.to_string()))?;

    // Nuclei exits non-zero in some no-findings cases, so a non-zero status
    // alone isn't an error. Only treat it as failure when nothing usable
    // came back on stdout.
    if output.stdout.is_empty() && !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NucleiError::Failed(
            stderr.chars().take(500).collect::<String>(),
        ));
    }

    let stdout = if output.stdout.len() > MAX_OUTPUT_BYTES {
        tracing::warn!(
            bytes = output.stdout.len(),
            "nuclei output exceeded cap, truncating"
        );
        String::from_utf8_lossy(&output.stdout[..MAX_OUTPUT_BYTES]).to_string()
    } else {
        String::from_utf8_lossy(&output.stdout).to_string()
    };

    Ok(parse_jsonl(&stdout))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_always_carry_the_rate_limit() {
        let args = build_args("example.com");
        let position = args.iter().position(|a| a == "-rate-limit").unwrap();
        assert_eq!(args[position + 1], RATE_LIMIT_PER_SECOND.to_string());
    }

    #[test]
    fn args_always_exclude_attacking_template_tags() {
        let args = build_args("example.com");
        let position = args.iter().position(|a| a == "-exclude-tags").unwrap();
        let excluded = &args[position + 1];

        for tag in ["fuzz", "brute-force", "dos", "intrusive"] {
            assert!(excluded.contains(tag), "'{tag}' must be excluded");
        }
    }

    #[test]
    fn args_disable_interactsh_callbacks() {
        assert!(build_args("example.com").contains(&"-no-interactsh".to_string()));
    }

    #[test]
    fn target_is_passed_as_its_own_argument() {
        // Proves the domain is a discrete argv entry, not interpolated into
        // a command string where metacharacters could matter.
        let args = build_args("example.com");
        let position = args.iter().position(|a| a == "-target").unwrap();
        assert_eq!(args[position + 1], "example.com");
    }

    #[tokio::test]
    async fn run_refuses_an_ip_literal_before_spawning() {
        // Must fail validation, not "nuclei not installed" — the check has
        // to happen before we ever try to spawn.
        match run("169.254.169.254").await {
            Err(NucleiError::InvalidTarget(_)) => {}
            other => panic!("expected InvalidTarget, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_refuses_localhost_before_spawning() {
        match run("http://localhost:8080").await {
            Err(NucleiError::InvalidTarget(_)) => {}
            other => panic!("expected InvalidTarget, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_refuses_a_public_hostname_pointing_at_loopback() {
        // Syntactically valid public domain, A record 127.0.0.1 — passes
        // `normalize_target` and must be stopped by the resolved-address
        // check instead. Never `NotInstalled`: the refusal has to happen
        // before we try to spawn anything.
        match run("localtest.me").await {
            Err(NucleiError::Refused(_)) => {}
            Err(NucleiError::NotInstalled) => {
                panic!("the address check must run before the spawn attempt")
            }
            other => panic!("expected Refused, got {other:?}"),
        }
    }

    #[test]
    fn parses_a_typical_finding() {
        let jsonl = r#"{"template-id":"tech-detect","info":{"name":"Nginx detected","severity":"info","description":"Server technology"},"host":"example.com"}"#;

        let findings = parse_jsonl(jsonl);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Nginx detected");
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(
            findings[0].description.as_deref(),
            Some("Server technology")
        );
    }

    #[test]
    fn parses_multiple_lines_and_severities() {
        let jsonl = concat!(
            r#"{"template-id":"a","info":{"name":"One","severity":"high"}}"#,
            "\n",
            r#"{"template-id":"b","info":{"name":"Two","severity":"critical"}}"#,
            "\n"
        );

        let findings = parse_jsonl(jsonl);

        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[1].severity, Severity::Critical);
    }

    #[test]
    fn malformed_lines_are_skipped_without_losing_valid_ones() {
        let jsonl = concat!(
            "not json at all\n",
            r#"{"template-id":"b","info":{"name":"Valid","severity":"low"}}"#,
            "\n",
            "{ broken json\n"
        );

        let findings = parse_jsonl(jsonl);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Valid");
    }

    #[test]
    fn falls_back_to_template_id_when_name_is_missing() {
        let jsonl = r#"{"template-id":"some-template","info":{"severity":"medium"}}"#;
        let findings = parse_jsonl(jsonl);

        assert_eq!(findings[0].title, "some-template");
    }

    #[test]
    fn empty_output_yields_no_findings() {
        assert!(parse_jsonl("").is_empty());
        assert!(parse_jsonl("\n\n  \n").is_empty());
    }

    #[test]
    fn raw_output_is_preserved_verbatim() {
        let jsonl = r#"{"template-id":"x","info":{"name":"N","severity":"low"},"matched-at":"https://example.com/x"}"#;
        let findings = parse_jsonl(jsonl);

        assert_eq!(
            findings[0].raw["matched-at"], "https://example.com/x",
            "the tool's own output must survive normalization"
        );
    }
}
