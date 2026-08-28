//! Target ownership verification.
//!
//! No scan job may be created for a target whose verification is not
//! currently valid (see [`is_currently_verified`]). This module is
//! deliberately split into pure matching/expiry logic (unit-tested, no I/O)
//! and network fetchers (`fetch_dns_txt_records`, `fetch_well_known_file`)
//! so the safety-critical logic can be tested without a live DNS resolver
//! or HTTP server.

use chrono::{DateTime, Duration, Utc};
use rand::{distributions::Alphanumeric, Rng};

use crate::net_guard;

/// How long a successful verification remains valid before it must be
/// re-checked. A domain's ownership can change, so verification is not
/// "once and forever" — see scan_jobs join requirement in the migration.
pub const VERIFICATION_TTL_DAYS: i64 = 30;

/// Timeout budget for a single verification fetch (DNS or HTTP). Kept low:
/// verification is a gate, not a scan, and should never hang a request.
pub const FETCH_TIMEOUT_SECS: u64 = 5;

/// Cap on the well-known file body size we'll read. The file only needs to
/// hold a short token; anything larger is refused rather than buffered.
pub const WELL_KNOWN_MAX_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationMethod {
    DnsTxt,
    WellKnownFile,
}

impl VerificationMethod {
    pub fn as_db_str(&self) -> &'static str {
        match self {
            VerificationMethod::DnsTxt => "dns_txt",
            VerificationMethod::WellKnownFile => "well_known_file",
        }
    }
}

/// Generates a random per-target verification token. 32 alphanumeric chars
/// gives ample entropy against guessing while staying short enough to fit
/// comfortably in a DNS TXT record or a one-line file.
pub fn generate_token() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

pub fn dns_txt_record_name(domain: &str) -> String {
    format!("_glarion-verify.{domain}")
}

pub fn well_known_url(domain: &str) -> String {
    format!("https://{domain}/.well-known/glarion-verify.txt")
}

/// Pure check: does any of the fetched TXT records equal the expected
/// token? Exact match only — no substring matching, to avoid a record that
/// happens to contain the token as a false positive.
pub fn token_present(records: &[String], token: &str) -> bool {
    records.iter().any(|r| r.trim() == token)
}

/// Pure check: does the fetched file body equal the expected token once
/// surrounding whitespace/newlines are trimmed?
pub fn file_contains_token(body: &str, token: &str) -> bool {
    body.trim() == token
}

/// Minimal view of a `target_verifications` row needed to decide whether a
/// scan may proceed right now. Deliberately does not take `&TargetVerification`
/// from a hypothetical ORM struct — kept as plain fields so callers building
/// this from a `sqlx::query!` row don't need an extra mapping layer.
pub struct VerificationStatus {
    pub verified_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// The single source of truth for "is this target scannable right now".
/// Both `verified_at` being set AND `expires_at` being in the future are
/// required — a verification that was never completed, or that has lapsed,
/// must fail closed.
pub fn is_currently_verified(status: &VerificationStatus, now: DateTime<Utc>) -> bool {
    status.verified_at.is_some() && status.expires_at.is_some_and(|exp| exp > now)
}

pub fn expiry_from(now: DateTime<Utc>) -> DateTime<Utc> {
    now + Duration::days(VERIFICATION_TTL_DAYS)
}

/// Fetches TXT records for the verification subdomain. Returns an empty
/// Vec (not an error) when the record simply doesn't exist yet — that is
/// an expected, common state (user hasn't added it yet), not a failure.
pub async fn fetch_dns_txt_records(domain: &str) -> anyhow::Result<Vec<String>> {
    use hickory_resolver::TokioAsyncResolver;

    let resolver = TokioAsyncResolver::tokio_from_system_conf()?;
    let name = dns_txt_record_name(domain);

    let lookup = tokio::time::timeout(
        std::time::Duration::from_secs(FETCH_TIMEOUT_SECS),
        resolver.txt_lookup(name),
    )
    .await;

    match lookup {
        Ok(Ok(txt)) => Ok(txt
            .iter()
            .map(|record| record.to_string().trim_matches('"').to_string())
            .collect()),
        Ok(Err(_)) => Ok(Vec::new()),
        Err(_) => anyhow::bail!("DNS lookup timed out"),
    }
}

/// Fetches the well-known verification file over HTTPS only — plain HTTP
/// is refused since an attacker on-path could otherwise forge the body.
///
/// This is a server-side fetch of a user-supplied hostname, i.e. a textbook
/// SSRF sink, so three things are enforced:
///
///  * the resolved addresses must all be public ([`net_guard`]);
///  * the connection is pinned to an address we validated, closing the
///    DNS-rebinding window between check and connect;
///  * redirects are not followed, since a redirect could point anywhere.
pub async fn fetch_well_known_file(domain: &str) -> anyhow::Result<String> {
    let addresses = net_guard::resolve_public_addresses(domain).await?;
    let pinned = addresses
        .first()
        .copied()
        .ok_or_else(|| anyhow::anyhow!("no addresses for {domain}"))?;

    let url = well_known_url(domain);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(FETCH_TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::none())
        // Connect to the address we just vetted rather than re-resolving.
        .resolve(domain, pinned)
        .build()?;

    let response = client.get(&url).send().await?;
    if !response.status().is_success() {
        return Ok(String::new());
    }

    // Refuse an oversized body before downloading it, when the server is
    // honest enough to declare a length.
    if let Some(len) = response.content_length() {
        if len > WELL_KNOWN_MAX_BYTES as u64 {
            anyhow::bail!("well-known file exceeds size cap");
        }
    }

    // A missing or lying Content-Length still must not let us buffer an
    // unbounded body, so the stream is read with a hard ceiling.
    let mut body = Vec::new();
    let mut stream = response;
    while let Some(chunk) = stream.chunk().await? {
        if body.len() + chunk.len() > WELL_KNOWN_MAX_BYTES {
            anyhow::bail!("well-known file exceeds size cap");
        }
        body.extend_from_slice(&chunk);
    }

    Ok(String::from_utf8_lossy(&body).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_absent_when_no_records() {
        let records: Vec<String> = vec![];
        assert!(!token_present(&records, "expected-token"));
    }

    #[test]
    fn token_absent_when_wrong_value() {
        let records = vec!["some-other-value".to_string()];
        assert!(!token_present(&records, "expected-token"));
    }

    #[test]
    fn token_present_on_exact_match() {
        let records = vec!["unrelated".to_string(), "expected-token".to_string()];
        assert!(token_present(&records, "expected-token"));
    }

    #[test]
    fn token_present_trims_quoting_whitespace() {
        let records = vec!["  expected-token  ".to_string()];
        assert!(token_present(&records, "expected-token"));
    }

    #[test]
    fn well_known_file_valid_token() {
        assert!(file_contains_token("expected-token\n", "expected-token"));
    }

    #[test]
    fn well_known_file_wrong_token() {
        assert!(!file_contains_token("wrong-token\n", "expected-token"));
    }

    #[test]
    fn not_verified_when_never_completed() {
        let status = VerificationStatus {
            verified_at: None,
            expires_at: None,
        };
        assert!(!is_currently_verified(&status, Utc::now()));
    }

    #[test]
    fn not_verified_when_expired() {
        let now = Utc::now();
        let status = VerificationStatus {
            verified_at: Some(now - Duration::days(40)),
            expires_at: Some(now - Duration::days(10)),
        };
        assert!(!is_currently_verified(&status, now));
    }

    #[test]
    fn verified_when_within_ttl() {
        let now = Utc::now();
        let status = VerificationStatus {
            verified_at: Some(now - Duration::days(5)),
            expires_at: Some(now + Duration::days(25)),
        };
        assert!(is_currently_verified(&status, now));
    }

    #[test]
    fn generated_tokens_have_expected_length_and_are_unique() {
        let a = generate_token();
        let b = generate_token();
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
    }
}
