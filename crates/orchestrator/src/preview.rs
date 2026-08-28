//! The check that needs no permission.
//!
//! A full scan probes: it requests paths the site never advertised and
//! tries known vulnerability fingerprints against them. Doing that to
//! somebody else's domain uninvited is what computer-misuse law exists to
//! describe, which is why nothing here reaches a scanner without proof of
//! ownership first.
//!
//! But a large part of what this product shows is not probing at all. DNS
//! records, the TLS handshake, the response headers on the front page, and
//! the two files a site publishes specifically for automated readers are
//! all things an ordinary browser or a search engine crawler collects on a
//! normal visit. There is nothing to authorise about reading what a site
//! broadcasts to the world.
//!
//! Separating the two is worth it twice over. Legally it keeps the gate
//! around the part that actually needs one, rather than around everything.
//! Commercially it removes the worst possible barrier: before this, nobody
//! could see a single result without first editing DNS for a client's
//! domain — which is to say, before we had shown them anything at all.
//!
//! The rules this observes, so it stays the harmless thing it claims to be:
//!
//!   * one request to the front page, and one to each of two well-known
//!     files, and nothing else. No path discovery, no guessing.
//!   * `GET` only, and redirects are not followed.
//!   * the same resolved-address guard as everything else, so it cannot be
//!     pointed at private space.

use std::time::Duration;

use crate::net_guard;

/// Ceiling for the whole preview. It runs while somebody waits on a page,
/// so it has to finish or fail quickly rather than be thorough.
const TOTAL_TIMEOUT_SECS: u64 = 12;

/// Per-request ceiling.
const REQUEST_TIMEOUT_SECS: u64 = 6;

/// Cap on how much of a response we read. The headers are the point; the
/// body is only needed for a short well-known file.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// The two files a site publishes for automated readers. Requesting these
/// is not discovery: they exist to be fetched by machines, and a site that
/// does not want them read simply does not publish them.
const PUBLIC_FILES: [&str; 2] = ["/robots.txt", "/.well-known/security.txt"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub label: String,
    pub value: String,
    /// True when this is something the owner would want to change.
    pub is_finding: bool,
}

#[derive(Debug, Default)]
pub struct Preview {
    pub observations: Vec<Observation>,
    /// What could not be checked, said out loud rather than left as a gap.
    pub notes: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum PreviewError {
    #[error("{0}")]
    InvalidTarget(String),
    #[error("could not reach {0}")]
    Unreachable(String),
}

/// Header names that carry a security decision, and what their absence
/// means to somebody who has to explain it.
///
/// Kept here rather than shared with the triage rules on purpose: this
/// runs before anyone has proved anything, so it deliberately reports less
/// and does not pretend to be a substitute for the real thing.
const HEADERS: [(&str, &str); 5] = [
    ("content-security-policy", "Content-Security-Policy"),
    ("strict-transport-security", "HTTPS enforcement (HSTS)"),
    ("x-frame-options", "Clickjacking protection"),
    ("x-content-type-options", "MIME sniffing protection"),
    ("referrer-policy", "Referrer policy"),
];

/// Looks at a domain using only what it publishes.
pub async fn preview(domain: &str) -> Result<Preview, PreviewError> {
    let domain = crate::domain::normalize_target(domain)
        .map_err(|err| PreviewError::InvalidTarget(err.to_string()))?;

    // The same guard the scanner uses. A preview is still an outbound
    // request from our servers, so it must not be aimable at private space
    // merely because it is the cheap tier.
    let addresses = net_guard::resolve_public_addresses(&domain)
        .await
        .map_err(|_| PreviewError::Unreachable(domain.clone()))?;

    let pinned = addresses
        .first()
        .copied()
        .ok_or_else(|| PreviewError::Unreachable(domain.clone()))?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::none())
        .resolve(&domain, pinned)
        .user_agent("Glarion/1.0 (+https://glarion.app/about-our-checks)")
        .build()
        .map_err(|_| PreviewError::Unreachable(domain.clone()))?;

    let work = collect(&client, &domain);

    tokio::time::timeout(Duration::from_secs(TOTAL_TIMEOUT_SECS), work)
        .await
        .map_err(|_| PreviewError::Unreachable(domain))?
}

async fn collect(client: &reqwest::Client, domain: &str) -> Result<Preview, PreviewError> {
    let mut preview = Preview::default();

    let response = client
        .get(format!("https://{domain}/"))
        .send()
        .await
        .map_err(|_| PreviewError::Unreachable(domain.to_string()))?;

    let headers = response.headers().clone();
    let status = response.status();

    // A redirect is not a failure — plenty of sites send the apex to www —
    // but the headers on a redirect say little, so it is worth naming.
    if status.is_redirection() {
        preview
            .notes
            .push("The front page redirects, so header checks may be incomplete.".to_string());
    }

    if let Some(server) = header_value(&headers, "server") {
        preview.observations.push(Observation {
            label: "Server".to_string(),
            value: server,
            is_finding: false,
        });
    }

    for (name, label) in HEADERS {
        match header_value(&headers, name) {
            Some(value) => preview.observations.push(Observation {
                label: label.to_string(),
                value: summarise(name, &value),
                is_finding: is_weak(name, &value),
            }),
            None => preview.observations.push(Observation {
                label: label.to_string(),
                value: "Not set".to_string(),
                is_finding: true,
            }),
        }
    }

    for path in PUBLIC_FILES {
        let url = format!("https://{domain}{path}");
        let present = match client.get(&url).send().await {
            Ok(file) => file.status().is_success(),
            Err(_) => false,
        };

        preview.observations.push(Observation {
            label: path.trim_start_matches('/').to_string(),
            value: if present {
                "Published".into()
            } else {
                "Not published".into()
            },
            is_finding: false,
        });
    }

    Ok(preview)
}

fn header_value(headers: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Whether a header that *is* present is nonetheless not doing its job.
///
/// Only the cases that are unambiguous. A preview that argues about a
/// debatable policy would be making claims it cannot support without the
/// full scan.
pub fn is_weak(name: &str, value: &str) -> bool {
    match name {
        // Under a year is below the browser preload threshold, and leaves a
        // window where a first visit can still be downgraded.
        "strict-transport-security" => max_age(value).is_some_and(|age| age < 31_536_000),
        _ => false,
    }
}

/// Shortens a header for display without losing what it decided.
pub fn summarise(name: &str, value: &str) -> String {
    match name {
        "strict-transport-security" => match max_age(value) {
            Some(age) => {
                let days = age / 86_400;
                format!("{days} days")
            }
            None => value.chars().take(60).collect(),
        },
        _ => {
            if value.chars().count() > 60 {
                format!("{}…", value.chars().take(59).collect::<String>())
            } else {
                value.to_string()
            }
        }
    }
}

fn max_age(value: &str) -> Option<u64> {
    value
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix("max-age="))
        .and_then(|age| age.trim().parse().ok())
}

/// How much of a body we are willing to read. Exposed so a caller can see
/// the bound rather than having to trust it.
pub const fn max_body_bytes() -> usize {
    MAX_BODY_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_hsts_lifetime_is_flagged() {
        // 180 days: set, but below the threshold that makes it dependable.
        assert!(is_weak("strict-transport-security", "max-age=15552000"));
    }

    #[test]
    fn a_year_of_hsts_is_not_flagged() {
        assert!(!is_weak("strict-transport-security", "max-age=31536000"));
        assert!(!is_weak(
            "strict-transport-security",
            "max-age=63072000; includeSubDomains; preload"
        ));
    }

    #[test]
    fn an_unparseable_hsts_is_not_claimed_to_be_weak() {
        // A preview should not make an accusation it cannot support.
        assert!(!is_weak("strict-transport-security", "nonsense"));
        assert!(!is_weak("strict-transport-security", ""));
    }

    #[test]
    fn no_other_header_is_judged_on_its_value() {
        // Whether a given CSP is any good needs the full scan; saying so
        // from a preview would be guessing.
        assert!(!is_weak("content-security-policy", "default-src 'none'"));
        assert!(!is_weak("x-frame-options", "ALLOWALL"));
    }

    #[test]
    fn hsts_is_summarised_in_days() {
        assert_eq!(
            summarise(
                "strict-transport-security",
                "max-age=15552000; includeSubDomains"
            ),
            "180 days"
        );
        assert_eq!(
            summarise("strict-transport-security", "max-age=31536000"),
            "365 days"
        );
    }

    #[test]
    fn long_header_values_are_shortened_rather_than_wrapped() {
        let long = "default-src 'self'; ".repeat(20);
        let shown = summarise("content-security-policy", &long);

        assert!(shown.chars().count() <= 60);
        assert!(shown.ends_with('…'));
    }

    #[test]
    fn a_short_value_is_left_alone() {
        assert_eq!(summarise("x-frame-options", "DENY"), "DENY");
    }

    #[tokio::test]
    async fn a_preview_refuses_an_ip_literal() {
        match preview("169.254.169.254").await {
            Err(PreviewError::InvalidTarget(_)) => {}
            other => panic!("expected InvalidTarget, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_preview_refuses_a_hostname_pointing_at_loopback() {
        // The cheap tier is still an outbound request from our servers, so
        // it gets the same guard as the scanner.
        match preview("localtest.me").await {
            Err(PreviewError::Unreachable(_)) => {}
            other => panic!("expected Unreachable, got {other:?}"),
        }
    }
}
