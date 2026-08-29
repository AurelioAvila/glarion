//! Certificate facts, read from the handshake.
//!
//! Nuclei reports who issued a certificate and which names it covers, but
//! never how long it has left. That omission matters more than it sounds:
//! an expired certificate is not a weakness someone might exploit one day,
//! it is an outage on a date that was knowable weeks in advance. Every
//! browser refuses the site outright, and the agency finds out because the
//! client phones them.
//!
//! It is also the reason a monitoring retainer is worth paying for. An
//! agency looking after forty client sites cannot hold forty renewal dates
//! in their head, and the failure is silent right up until it is total.
//!
//! Three things about how this is done:
//!
//!   * **No external tool.** testssl.sh would answer this, but it is a
//!     large shell script that duplicates what Nuclei's `ssl-*` templates
//!     already report, and it would have to be installed in the runtime
//!     image and kept current. The handshake gives us the certificate
//!     directly.
//!
//!   * **Certificate verification is deliberately turned off**, and this is
//!     the uncomfortable part, so it is worth being explicit. A verifying
//!     client aborts the handshake on exactly the certificates we most need
//!     to report — expired, self-signed, wrong hostname. Refusing to look
//!     at them would mean reporting nothing in precisely the cases the
//!     customer is paying us to catch. So the chain is accepted, read, and
//!     then judged here rather than by the TLS stack.
//!
//!     This is only safe because of what the connection is *for*: we
//!     complete a handshake, read the peer's certificate chain, and drop
//!     the socket. Nothing is sent, nothing is received, no credential or
//!     customer data ever crosses it. The disabled verifier below must
//!     never be reused for a connection that carries anything.
//!
//!   * **The same address guard as everything else** runs first, so this
//!     cannot be pointed at private space or at a metadata endpoint.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, TimeZone, Utc};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

use crate::domain::normalize_target;
use crate::finding::{Finding, Severity};
use crate::net_guard;

/// Ceiling for connect plus handshake. A host that cannot complete one in
/// this long is reported as unreachable rather than waited on: this runs
/// across every target on a schedule, so one dead host must not hold up
/// the queue.
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 15;

/// Thresholds, in days remaining, at which expiry stops being routine.
///
/// Calibrated against Let's Encrypt, which issues for 90 days and begins
/// renewing at 30 remaining. So 30 is the point where an automated renewal
/// should have happened and evidently has not; by 14 it has failed
/// repeatedly; by 7 the outage is close enough to be worth interrupting
/// someone over.
pub const MEDIUM_AFTER_DAYS: i64 = 30;
pub const HIGH_AFTER_DAYS: i64 = 14;
pub const CRITICAL_AFTER_DAYS: i64 = 7;

/// What the handshake told us. Separated from the judging so the rules
/// below can be tested against constructed certificates without opening a
/// socket.
#[derive(Debug, Clone)]
pub struct CertificateFacts {
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub issuer: String,
    pub subject: String,
    /// Names the certificate claims to cover, from the SAN extension.
    pub dns_names: Vec<String>,
    /// A chain of one that issued itself. Reported separately because the
    /// remedy is different: not "renew it" but "this is not the
    /// certificate you think is serving".
    pub self_signed: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("invalid target: {0}")]
    InvalidTarget(String),
    #[error("refusing to connect: {0}")]
    Refused(String),
    #[error("could not connect to {0}:443")]
    Unreachable(String),
    #[error("the TLS handshake did not complete: {0}")]
    HandshakeFailed(String),
    #[error("the server presented no certificate")]
    NoCertificate,
    #[error("the certificate could not be parsed: {0}")]
    Unreadable(String),
}

/// Days from `now` until `not_after`, rounded down.
///
/// Signed on purpose: an already-expired certificate gives a negative
/// number, which the caller reports rather than clamping to zero.
pub fn days_remaining(not_after: DateTime<Utc>, now: DateTime<Utc>) -> i64 {
    (not_after - now).num_days()
}

/// Whether `domain` is covered by any name on the certificate.
///
/// Wildcards match one label and only at the front, which is what the
/// specification says and what browsers enforce: `*.example.com` covers
/// `www.example.com` but not `example.com` itself, and not
/// `a.b.example.com`.
pub fn covers_domain(dns_names: &[String], domain: &str) -> bool {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();

    dns_names.iter().any(|name| {
        let name = name.trim_end_matches('.').to_ascii_lowercase();

        match name.strip_prefix("*.") {
            Some(suffix) => match domain.split_once('.') {
                // The wildcard stands in for exactly one label, so what
                // follows the first dot must match the rest exactly.
                Some((_, rest)) => rest == suffix,
                None => false,
            },
            None => name == domain,
        }
    })
}

/// Turns the certificate into findings.
///
/// Pure, and takes `now` rather than reading the clock, so the boundaries
/// can be tested exactly instead of approximately.
pub fn assess(facts: &CertificateFacts, domain: &str, now: DateTime<Utc>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let remaining = days_remaining(facts.not_after, now);

    // Expiry is always reported, including when it is far away. A renewal
    // date the reader can see is the difference between a report that says
    // nothing is wrong and one that says we looked.
    let (severity, title, description) = if remaining < 0 {
        (
            Severity::Critical,
            "TLS certificate has expired".to_string(),
            format!(
                "The certificate expired on {} — {} day{} ago. Browsers refuse the site \
                 with a full-page warning, so it is unreachable for visitors, not merely \
                 insecure. Renew it now.",
                facts.not_after.format("%-d %B %Y"),
                remaining.abs(),
                if remaining.abs() == 1 { "" } else { "s" },
            ),
        )
    } else if remaining <= CRITICAL_AFTER_DAYS {
        (
            Severity::Critical,
            format!("TLS certificate expires in {remaining} days"),
            format!(
                "The certificate expires on {}. If renewal is automated it has already \
                 failed several times; if it is manual it needs doing now. On the expiry \
                 date the site stops loading for every visitor.",
                facts.not_after.format("%-d %B %Y"),
            ),
        )
    } else if remaining <= HIGH_AFTER_DAYS {
        (
            Severity::High,
            format!("TLS certificate expires in {remaining} days"),
            format!(
                "The certificate expires on {}. Automated renewal normally completes with \
                 30 days to spare, so this is late enough to check that the renewal is \
                 running at all.",
                facts.not_after.format("%-d %B %Y"),
            ),
        )
    } else if remaining <= MEDIUM_AFTER_DAYS {
        (
            Severity::Medium,
            format!("TLS certificate expires in {remaining} days"),
            format!(
                "The certificate expires on {}. This is the point at which an automated \
                 renewal should have taken place. Worth confirming it is scheduled.",
                facts.not_after.format("%-d %B %Y"),
            ),
        )
    } else {
        (
            Severity::Info,
            "TLS certificate validity".to_string(),
            format!(
                "Valid until {} ({} days remaining), issued by {}.",
                facts.not_after.format("%-d %B %Y"),
                remaining,
                facts.issuer,
            ),
        )
    };

    findings.push(Finding {
        severity,
        title,
        description: Some(description),
        raw: serde_json::json!({
            "template-id": "tls-certificate-expiry",
            "matcher-name": expiry_matcher(remaining),
            "not-after": facts.not_after.to_rfc3339(),
            "not-before": facts.not_before.to_rfc3339(),
            "days-remaining": remaining,
            "issuer": facts.issuer,
            "subject": facts.subject,
        }),
    });

    // A certificate that does not cover the name it is serving produces the
    // same browser warning as an expired one, so it is graded the same.
    if !covers_domain(&facts.dns_names, domain) {
        findings.push(Finding {
            severity: Severity::Critical,
            title: "TLS certificate does not cover this domain".to_string(),
            description: Some(format!(
                "The certificate served for {domain} is valid for {} instead. Browsers \
                 reject a name mismatch outright, so visitors see a warning page rather \
                 than the site.",
                if facts.dns_names.is_empty() {
                    "no listed name".to_string()
                } else {
                    facts.dns_names.join(", ")
                },
            )),
            raw: serde_json::json!({
                "template-id": "tls-certificate-name-mismatch",
                "matcher-name": "san",
                "domain": domain,
                "dns-names": facts.dns_names,
            }),
        });
    }

    if facts.self_signed {
        findings.push(Finding {
            severity: Severity::High,
            title: "TLS certificate is self-signed".to_string(),
            description: Some(
                "The certificate was issued by itself rather than by a certificate \
                 authority, so no browser will trust it. This is usually a default \
                 certificate left in place because the real one never installed."
                    .to_string(),
            ),
            raw: serde_json::json!({
                "template-id": "tls-certificate-self-signed",
                "matcher-name": "issuer",
                "issuer": facts.issuer,
                "subject": facts.subject,
            }),
        });
    }

    findings
}

/// Which band the expiry fell into, recorded so a report can group by it
/// without re-deriving the thresholds.
fn expiry_matcher(remaining: i64) -> &'static str {
    if remaining < 0 {
        "expired"
    } else if remaining <= CRITICAL_AFTER_DAYS {
        "critical"
    } else if remaining <= HIGH_AFTER_DAYS {
        "soon"
    } else if remaining <= MEDIUM_AFTER_DAYS {
        "approaching"
    } else {
        "valid"
    }
}

/// Reads the certificate chain `domain` serves on 443.
pub async fn run(domain: &str) -> Result<Vec<Finding>, TlsError> {
    let facts = inspect(domain).await?;
    Ok(assess(&facts, domain, Utc::now()))
}

/// Completes a handshake and returns what the peer presented.
pub async fn inspect(domain: &str) -> Result<CertificateFacts, TlsError> {
    // Re-validated at the point of use, as in every other tool wrapper:
    // this is the last line before a socket is opened to this value.
    let domain =
        normalize_target(domain).map_err(|err| TlsError::InvalidTarget(err.to_string()))?;

    // Connect to an address we resolved and checked ourselves rather than
    // letting the connector resolve the name again — otherwise the name
    // could resolve to something public here and something private a
    // moment later, and the check would have guarded nothing.
    let addresses = net_guard::resolve_public_addresses(&domain)
        .await
        .map_err(|err| TlsError::Refused(err.to_string()))?;

    // Already carries port 443 — resolve_public_addresses looks the name up
    // as `host:443` so it can hand back SocketAddrs it has checked.
    let address = *addresses
        .first()
        .ok_or_else(|| TlsError::Unreachable(domain.clone()))?;

    let stream = tokio::time::timeout(
        Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        tokio::net::TcpStream::connect(address),
    )
    .await
    .map_err(|_| TlsError::Unreachable(domain.clone()))?
    .map_err(|_| TlsError::Unreachable(domain.clone()))?;

    // See the module comment: this verifier accepts everything, and this
    // connection carries nothing.
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|err| TlsError::HandshakeFailed(err.to_string()))?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(ReadOnlyVerifier))
    .with_no_client_auth();

    let server_name = ServerName::try_from(domain.clone())
        .map_err(|err| TlsError::InvalidTarget(err.to_string()))?;

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

    let tls = tokio::time::timeout(
        Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| TlsError::HandshakeFailed("timed out".to_string()))?
    .map_err(|err| TlsError::HandshakeFailed(err.to_string()))?;

    let chain = tls
        .get_ref()
        .1
        .peer_certificates()
        .ok_or(TlsError::NoCertificate)?
        .to_vec();

    // The socket has served its purpose. Dropped without writing a byte.
    drop(tls);

    let leaf = chain.first().ok_or(TlsError::NoCertificate)?;
    parse_leaf(leaf, chain.len())
}

/// Pulls the fields we report out of the leaf certificate.
fn parse_leaf(der: &CertificateDer<'_>, chain_length: usize) -> Result<CertificateFacts, TlsError> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(der.as_ref())
        .map_err(|err| TlsError::Unreadable(err.to_string()))?;

    let to_utc = |timestamp: i64| {
        Utc.timestamp_opt(timestamp, 0)
            .single()
            .ok_or_else(|| TlsError::Unreadable("certificate carries an impossible date".into()))
    };

    let not_before = to_utc(cert.validity().not_before.timestamp())?;
    let not_after = to_utc(cert.validity().not_after.timestamp())?;

    let issuer = cert.issuer().to_string();
    let subject = cert.subject().to_string();

    let mut dns_names: Vec<String> = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            if let GeneralName::DNSName(name) = name {
                dns_names.push((*name).to_string());
            }
        }
    }

    // A single certificate that names itself as its own issuer. Checked by
    // comparing the two distinguished names rather than by verifying the
    // signature: we are describing what was served, not deciding whether to
    // trust it, and a mismatch here is the thing worth reporting either way.
    let self_signed = chain_length == 1 && issuer == subject;

    Ok(CertificateFacts {
        not_before,
        not_after,
        issuer,
        subject,
        dns_names,
        self_signed,
    })
}

/// A certificate verifier that refuses nothing.
///
/// Exists so the handshake completes on certificates a browser would
/// reject, because those are the ones worth reporting. Confined to this
/// module and to a connection that transfers no data — see the module
/// comment before reusing it anywhere.
#[derive(Debug)]
struct ReadOnlyVerifier;

impl ServerCertVerifier for ReadOnlyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text)
            .unwrap()
            .with_timezone(&Utc)
    }

    fn facts_expiring(not_after: &str) -> CertificateFacts {
        CertificateFacts {
            not_before: at("2026-01-01T00:00:00Z"),
            not_after: at(not_after),
            issuer: "CN=Example CA".to_string(),
            subject: "CN=example.com".to_string(),
            dns_names: vec!["example.com".to_string(), "www.example.com".to_string()],
            self_signed: false,
        }
    }

    #[test]
    fn an_expired_certificate_is_critical_and_says_the_site_is_down() {
        let facts = facts_expiring("2026-08-01T00:00:00Z");
        let findings = assess(&facts, "example.com", at("2026-08-29T00:00:00Z"));

        let expiry = &findings[0];
        assert_eq!(expiry.severity, Severity::Critical);
        assert!(
            expiry.description.as_ref().unwrap().contains("unreachable"),
            "an expired certificate is an outage, and the report has to say so"
        );
    }

    #[test]
    fn severity_climbs_as_the_expiry_date_approaches() {
        let now = at("2026-08-29T00:00:00Z");

        let bands = [
            ("2026-12-29T00:00:00Z", Severity::Info),
            ("2026-09-25T00:00:00Z", Severity::Medium),
            ("2026-09-10T00:00:00Z", Severity::High),
            ("2026-09-02T00:00:00Z", Severity::Critical),
            ("2026-08-01T00:00:00Z", Severity::Critical),
        ];

        for (not_after, expected) in bands {
            let findings = assess(&facts_expiring(not_after), "example.com", now);
            assert_eq!(
                findings[0].severity, expected,
                "wrong severity for a certificate expiring {not_after}"
            );
        }
    }

    #[test]
    fn a_healthy_certificate_still_reports_its_renewal_date() {
        // Silence would be indistinguishable from not having looked.
        let findings = assess(
            &facts_expiring("2026-12-29T00:00:00Z"),
            "example.com",
            at("2026-08-29T00:00:00Z"),
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0]
            .description
            .as_ref()
            .unwrap()
            .contains("29 December 2026"));
    }

    #[test]
    fn the_boundaries_fall_on_the_documented_day() {
        let now = at("2026-08-29T00:00:00Z");

        // Exactly on a threshold belongs to the harsher band.
        let on_thirty = assess(&facts_expiring("2026-09-28T00:00:00Z"), "example.com", now);
        assert_eq!(on_thirty[0].severity, Severity::Medium);

        let just_past_thirty = assess(&facts_expiring("2026-09-29T00:00:00Z"), "example.com", now);
        assert_eq!(just_past_thirty[0].severity, Severity::Info);
    }

    #[test]
    fn a_name_the_certificate_does_not_cover_is_reported() {
        let findings = assess(
            &facts_expiring("2026-12-29T00:00:00Z"),
            "shop.example.com",
            at("2026-08-29T00:00:00Z"),
        );

        assert!(findings
            .iter()
            .any(|finding| finding.raw["template-id"] == "tls-certificate-name-mismatch"));
    }

    #[test]
    fn wildcards_cover_one_label_and_only_at_the_front() {
        let names = vec!["*.example.com".to_string()];

        assert!(covers_domain(&names, "www.example.com"));
        assert!(covers_domain(&names, "shop.example.com"));
        // A wildcard does not cover the bare domain, and does not span dots.
        assert!(!covers_domain(&names, "example.com"));
        assert!(!covers_domain(&names, "a.b.example.com"));
    }

    #[test]
    fn matching_is_case_insensitive_and_ignores_the_root_dot() {
        let names = vec!["Example.COM.".to_string()];
        assert!(covers_domain(&names, "example.com"));
    }

    #[test]
    fn a_self_signed_certificate_is_called_out_separately() {
        let mut facts = facts_expiring("2026-12-29T00:00:00Z");
        facts.self_signed = true;

        let findings = assess(&facts, "example.com", at("2026-08-29T00:00:00Z"));

        assert!(findings
            .iter()
            .any(|finding| finding.raw["template-id"] == "tls-certificate-self-signed"));
    }

    #[test]
    fn every_finding_carries_an_identifier_triage_can_key_on() {
        // Triage reads raw["template-id"]; a finding without one falls into
        // the unclassified path and loses its guidance.
        let mut facts = facts_expiring("2026-08-01T00:00:00Z");
        facts.self_signed = true;

        let findings = assess(&facts, "other.example.org", at("2026-08-29T00:00:00Z"));

        assert_eq!(findings.len(), 3);
        for finding in &findings {
            assert!(
                finding.raw["template-id"].is_string(),
                "every finding needs a template-id or triage cannot classify it"
            );
        }
    }

    #[test]
    fn days_remaining_goes_negative_rather_than_clamping() {
        let remaining = days_remaining(at("2026-08-01T00:00:00Z"), at("2026-08-29T00:00:00Z"));
        assert_eq!(remaining, -28);
    }
}
