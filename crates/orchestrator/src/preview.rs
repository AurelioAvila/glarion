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
//!   * TXT lookups for SPF and DMARC, which are public DNS records that any
//!     mail server on the internet reads before accepting a message. Asking
//!     a resolver a question is not contacting the site at all.
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
const HEADERS: [(&str, &str); 6] = [
    ("content-security-policy", "Content-Security-Policy"),
    ("strict-transport-security", "HTTPS enforcement (HSTS)"),
    ("x-frame-options", "Clickjacking protection"),
    ("x-content-type-options", "MIME sniffing protection"),
    ("referrer-policy", "Referrer policy"),
    ("permissions-policy", "Camera, microphone and location"),
];

/// Headers whose only job is to announce what the site runs on.
const DISCLOSURE_HEADERS: [&str; 3] = ["x-powered-by", "x-aspnet-version", "x-generator"];

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

    // The certificate and the front page at the same time. The handshake is
    // its own connection and would otherwise add its latency to a wait
    // somebody is sitting through.
    let dmarc_name = format!("_dmarc.{domain}");
    let (response, certificate, spf, dmarc) = tokio::join!(
        client.get(format!("https://{domain}/")).send(),
        crate::tools::tls::inspect(domain),
        crate::verification::txt_records_at(domain),
        crate::verification::txt_records_at(&dmarc_name),
    );

    // First, because it is the only thing here with a deadline attached.
    //
    // Everything else this reports is a judgement someone could argue with
    // — whether a header is set tightly enough, whether a file should be
    // published. A renewal date is not an opinion, it is a date, and it is
    // the one fact in the free check that says something about *this* site
    // rather than about sites in general.
    match certificate {
        Ok(facts) => {
            let remaining = crate::tools::tls::days_remaining(facts.not_after, chrono::Utc::now());
            let expires = facts.not_after.format("%-d %B %Y");

            preview.observations.push(Observation {
                label: "Certificate".to_string(),
                value: if remaining < 0 {
                    format!("Expired on {expires}")
                } else {
                    format!("Valid until {expires} ({remaining} days)")
                },
                // Flagged on the same threshold the paid scan treats as
                // late, so the free check and the report never disagree
                // about the same certificate.
                is_finding: remaining <= crate::tools::tls::MEDIUM_AFTER_DAYS,
            });
        }
        Err(error) => {
            preview
                .notes
                .push(format!("The certificate could not be read: {error}"));
        }
    }

    // Whether anyone can send mail as this domain. Worth as much to an
    // agency as any header here: the client whose invoices get forged does
    // not care that it was not technically a website problem.
    match (spf, dmarc) {
        (Ok(spf), Ok(dmarc)) => {
            preview.observations.push(spf_summary(&spf));
            preview.observations.push(dmarc_summary(&dmarc));
        }
        _ => preview
            .notes
            .push("The mail records could not be read just now.".to_string()),
    }

    let response = response.map_err(|_| PreviewError::Unreachable(domain.to_string()))?;

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

    let cookies: Vec<String> = headers
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::to_string)
        .collect();
    if let Some(observation) = cookie_summary(&cookies) {
        preview.observations.push(observation);
    }

    let disclosed: Vec<String> = DISCLOSURE_HEADERS
        .iter()
        .filter_map(|name| header_value(&headers, name))
        .collect();
    if let Some(observation) = disclosure_summary(&disclosed) {
        preview.observations.push(observation);
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

/// What an SPF record says about mail claiming to come from this domain.
///
/// Pure, so the parsing is tested without a resolver. SPF is one TXT record
/// beginning `v=spf1`; the part that matters is how it ends. `-all` refuses
/// everything not listed, `~all` asks the receiver to accept it and mark it
/// as suspicious, and `?all` states no opinion at all — which for a domain
/// that sends invoices is close to publishing nothing.
pub fn spf_summary(records: &[String]) -> Observation {
    let record = records
        .iter()
        .map(|value| value.trim())
        .find(|value| value.to_ascii_lowercase().starts_with("v=spf1"));

    let Some(record) = record else {
        return Observation {
            label: "Email spoofing (SPF)".into(),
            value: "Not published".into(),
            is_finding: true,
        };
    };

    let lowered = record.to_ascii_lowercase();
    let (value, is_finding) = if lowered.contains("-all") {
        ("Strict — unlisted senders refused", false)
    } else if lowered.contains("~all") {
        ("Soft fail — unlisted senders only marked", true)
    } else if lowered.contains("?all") {
        ("Neutral — states no opinion", true)
    } else {
        (
            "Published, but does not say what to do with unlisted senders",
            true,
        )
    };

    Observation {
        label: "Email spoofing (SPF)".into(),
        value: value.into(),
        is_finding,
    }
}

/// What a DMARC record instructs receivers to do.
///
/// SPF alone tells a receiver how to judge a message; DMARC is what tells
/// it to act. `p=none` is the setting almost every domain is left on after
/// somebody "set up DMARC" — it monitors and nothing else, so a forged
/// invoice still lands in the customer's inbox.
pub fn dmarc_summary(records: &[String]) -> Observation {
    let record = records
        .iter()
        .map(|value| value.trim())
        .find(|value| value.to_ascii_lowercase().starts_with("v=dmarc1"));

    let Some(record) = record else {
        return Observation {
            label: "Email spoofing (DMARC)".into(),
            value: "Not published".into(),
            is_finding: true,
        };
    };

    let policy = record
        .to_ascii_lowercase()
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix("p=").map(|p| p.trim().to_string()));

    let (value, is_finding) = match policy.as_deref() {
        Some("reject") => ("Forgeries rejected".to_string(), false),
        Some("quarantine") => ("Forgeries sent to spam".to_string(), false),
        Some("none") => (
            "Monitoring only — forgeries still delivered".to_string(),
            true,
        ),
        _ => ("Published without a policy".to_string(), true),
    };

    Observation {
        label: "Email spoofing (DMARC)".into(),
        value,
        is_finding,
    }
}

/// Whether the cookies the front page sets are protected.
///
/// Read from `Set-Cookie` on a page anyone can request, so this needs no
/// permission — and a session cookie without `HttpOnly` is readable by any
/// script that gets onto the page, which turns a small injection into a
/// stolen session. `None` when the page sets no cookies at all: silence is
/// better than inventing a clean result for something not being done.
pub fn cookie_summary(cookies: &[String]) -> Option<Observation> {
    if cookies.is_empty() {
        return None;
    }

    let mut missing = Vec::new();
    let flag_missing = |flag: &str| {
        cookies
            .iter()
            .any(|cookie| !cookie.to_ascii_lowercase().contains(flag))
    };

    if flag_missing("httponly") {
        missing.push("HttpOnly");
    }
    if flag_missing("secure") {
        missing.push("Secure");
    }
    if flag_missing("samesite") {
        missing.push("SameSite");
    }

    let count = cookies.len();
    let noun = if count == 1 { "cookie" } else { "cookies" };

    Some(if missing.is_empty() {
        Observation {
            label: "Cookie protection".into(),
            value: format!("{count} {noun}, all flagged"),
            is_finding: false,
        }
    } else {
        Observation {
            label: "Cookie protection".into(),
            value: format!("{count} {noun} missing {}", missing.join(", ")),
            is_finding: true,
        }
    })
}

/// Software and version numbers the site volunteers in its headers.
///
/// Not a vulnerability by itself, and it is deliberately not scored as one:
/// it is the line an attacker reads first to decide which exploits are
/// worth trying, which is why the full scan starts from it.
pub fn disclosure_summary(values: &[String]) -> Option<Observation> {
    if values.is_empty() {
        return None;
    }

    let has_version = values
        .iter()
        .any(|value| value.chars().any(|c| c.is_ascii_digit()));

    Some(Observation {
        label: "Version disclosure".into(),
        value: values.join(", ").chars().take(80).collect(),
        is_finding: has_version,
    })
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

    #[test]
    fn spf_reads_the_ending_that_decides_what_receivers_do() {
        assert!(!spf_summary(&["v=spf1 include:_spf.google.com -all".into()]).is_finding);

        // The two settings that look like protection and are not.
        assert!(spf_summary(&["v=spf1 include:example.com ~all".into()]).is_finding);
        assert!(spf_summary(&["v=spf1 ?all".into()]).is_finding);

        // A domain with TXT records that are not SPF publishes no SPF.
        let unrelated = spf_summary(&["google-site-verification=abc".into()]);
        assert!(unrelated.is_finding);
        assert_eq!(unrelated.value, "Not published");
    }

    #[test]
    fn dmarc_distinguishes_monitoring_from_enforcement() {
        assert!(!dmarc_summary(&["v=DMARC1; p=reject; rua=mailto:a@b.c".into()]).is_finding);
        assert!(!dmarc_summary(&["v=DMARC1; p=quarantine".into()]).is_finding);

        // The setting nearly every domain is left on: it reports and does
        // nothing, so a forgery still reaches the customer.
        let monitoring = dmarc_summary(&["v=DMARC1; p=none; rua=mailto:a@b.c".into()]);
        assert!(monitoring.is_finding);
        assert!(monitoring.value.contains("still delivered"));

        assert!(dmarc_summary(&[]).is_finding);
    }

    #[test]
    fn cookie_flags_are_reported_only_when_cookies_are_set() {
        assert!(cookie_summary(&[]).is_none());

        let bare = cookie_summary(&["session=abc; Path=/".into()]).unwrap();
        assert!(bare.is_finding);
        assert!(bare.value.contains("HttpOnly"));
        assert!(bare.value.contains("Secure"));

        let flagged =
            cookie_summary(&["session=abc; Path=/; HttpOnly; Secure; SameSite=Lax".into()])
                .unwrap();
        assert!(!flagged.is_finding);

        // One unprotected cookie among several is still an unprotected
        // cookie: the summary must not be averaged into looking clean.
        let mixed =
            cookie_summary(&["a=1; HttpOnly; Secure; SameSite=Lax".into(), "b=2".into()]).unwrap();
        assert!(mixed.is_finding);
    }

    #[test]
    fn a_version_number_is_what_makes_disclosure_worth_flagging() {
        assert!(disclosure_summary(&[]).is_none());

        // A bare product name tells an attacker far less than a version.
        assert!(!disclosure_summary(&["PHP".into()]).unwrap().is_finding);
        assert!(
            disclosure_summary(&["PHP/8.1.2".into()])
                .unwrap()
                .is_finding
        );
    }
}
