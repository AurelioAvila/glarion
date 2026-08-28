//! Target domain parsing and validation.
//!
//! This is a safety boundary, not just input tidying. A target must be a
//! real, public, DNS-resolvable hostname, because:
//!
//!  1. Ownership verification relies on DNS TXT records — an IP literal or
//!     an internal name can never be verified, so accepting one would
//!     create a target that can never legitimately be scanned.
//!  2. Accepting loopback/private/link-local targets would turn the scanner
//!     into an SSRF primitive pointed at our own infrastructure or at the
//!     cloud metadata endpoint.
//!
//! Both concerns are handled here, up front, rather than being re-checked
//! at each call site.

use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, PartialEq, Eq)]
pub enum DomainError {
    Empty,
    TooLong,
    /// An IP literal was supplied where a hostname is required.
    IpLiteral,
    /// Loopback, private, link-local, or otherwise non-public name.
    NotPublic,
    /// Failed basic hostname syntax rules.
    Malformed,
}

impl std::fmt::Display for DomainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            DomainError::Empty => "domain must not be empty",
            DomainError::TooLong => "domain is too long",
            DomainError::IpLiteral => {
                "target must be a domain name, not an IP address — ownership is verified via DNS"
            }
            DomainError::NotPublic => "target must be a public internet domain",
            DomainError::Malformed => "domain is not a valid hostname",
        };
        write!(f, "{msg}")
    }
}

impl std::error::Error for DomainError {}

/// Hostnames that must never be accepted as scan targets regardless of what
/// DNS says about them.
const BLOCKED_SUFFIXES: &[&str] = &[
    "localhost",
    ".localhost",
    ".local",
    ".internal",
    ".localdomain",
    ".home.arpa",
    ".in-addr.arpa",
    ".ip6.arpa",
    ".onion",
];

/// Normalizes and validates a user-supplied target.
///
/// Accepts input with or without a scheme, path, port, or trailing dot and
/// returns the bare lowercase hostname. Rejects anything that is not a
/// plausible public domain name.
pub fn normalize_target(input: &str) -> Result<String, DomainError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(DomainError::Empty);
    }

    // Strip a scheme if present, then anything from the first path/query
    // separator onward — users paste full URLs constantly.
    let without_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed);

    let host_part = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(without_scheme);

    // Drop userinfo ("user@host") — never part of the hostname.
    let host_part = host_part
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(host_part);

    // IPv6 literals must be caught before the port is stripped: an
    // unbracketed "::1" would otherwise be truncated to ":" by the
    // rsplit below and never recognised as an IP. A hostname:port form
    // has exactly one colon, so two or more means IPv6.
    if host_part.starts_with('[') || host_part.matches(':').count() >= 2 {
        return Err(DomainError::IpLiteral);
    }

    // Strip a port. Done before the IPv4 check so "127.0.0.1:8080" is still
    // recognised as an IP literal rather than as a malformed name.
    let host_part = host_part
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(host_part);

    // Trailing dot is valid DNS ("example.com.") but we store the bare form.
    let host = host_part.trim_end_matches('.').to_ascii_lowercase();

    if host.is_empty() {
        return Err(DomainError::Empty);
    }
    // 253 is the maximum length of a DNS name in presentation format.
    if host.len() > 253 {
        return Err(DomainError::TooLong);
    }

    if host.parse::<Ipv4Addr>().is_ok() || host.parse::<Ipv6Addr>().is_ok() {
        return Err(DomainError::IpLiteral);
    }

    if is_blocked_name(&host) {
        return Err(DomainError::NotPublic);
    }

    validate_syntax(&host)?;

    // A public domain has at least one dot: a bare single label is either an
    // internal name or a TLD, neither of which we can verify ownership of.
    if !host.contains('.') {
        return Err(DomainError::NotPublic);
    }

    Ok(host)
}

fn is_blocked_name(host: &str) -> bool {
    BLOCKED_SUFFIXES.iter().any(|blocked| {
        if let Some(suffix) = blocked.strip_prefix('.') {
            host == suffix || host.ends_with(blocked)
        } else {
            host == *blocked
        }
    })
}

fn validate_syntax(host: &str) -> Result<(), DomainError> {
    if host.starts_with('.') || host.contains("..") {
        return Err(DomainError::Malformed);
    }

    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(DomainError::Malformed);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(DomainError::Malformed);
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(DomainError::Malformed);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_domain() {
        assert_eq!(normalize_target("example.com").unwrap(), "example.com");
    }

    #[test]
    fn strips_scheme_path_and_port() {
        assert_eq!(
            normalize_target("https://Example.com:8443/some/path?q=1").unwrap(),
            "example.com"
        );
    }

    #[test]
    fn strips_trailing_dot_and_userinfo() {
        assert_eq!(
            normalize_target("user@example.com.").unwrap(),
            "example.com"
        );
    }

    #[test]
    fn accepts_subdomains() {
        assert_eq!(
            normalize_target("api.staging.example.co.uk").unwrap(),
            "api.staging.example.co.uk"
        );
    }

    #[test]
    fn rejects_ipv4_literal() {
        assert_eq!(normalize_target("127.0.0.1"), Err(DomainError::IpLiteral));
        assert_eq!(normalize_target("8.8.8.8"), Err(DomainError::IpLiteral));
    }

    #[test]
    fn rejects_ipv4_literal_with_port() {
        assert_eq!(
            normalize_target("http://192.168.1.1:8080/admin"),
            Err(DomainError::IpLiteral)
        );
    }

    #[test]
    fn rejects_cloud_metadata_address() {
        // The classic SSRF target. Must never become a scannable target.
        assert_eq!(
            normalize_target("169.254.169.254"),
            Err(DomainError::IpLiteral)
        );
    }

    #[test]
    fn rejects_ipv6_literal() {
        assert_eq!(normalize_target("::1"), Err(DomainError::IpLiteral));
        assert_eq!(normalize_target("[::1]:8080"), Err(DomainError::IpLiteral));
    }

    #[test]
    fn rejects_localhost_and_internal_names() {
        assert_eq!(normalize_target("localhost"), Err(DomainError::NotPublic));
        assert_eq!(
            normalize_target("http://localhost:3000"),
            Err(DomainError::NotPublic)
        );
        assert_eq!(normalize_target("db.internal"), Err(DomainError::NotPublic));
        assert_eq!(
            normalize_target("printer.local"),
            Err(DomainError::NotPublic)
        );
        assert_eq!(
            normalize_target("something.onion"),
            Err(DomainError::NotPublic)
        );
    }

    #[test]
    fn rejects_bare_single_label() {
        assert_eq!(normalize_target("intranet"), Err(DomainError::NotPublic));
    }

    #[test]
    fn rejects_empty_and_whitespace() {
        assert_eq!(normalize_target(""), Err(DomainError::Empty));
        assert_eq!(normalize_target("   "), Err(DomainError::Empty));
        assert_eq!(normalize_target("https://"), Err(DomainError::Empty));
    }

    #[test]
    fn rejects_malformed_labels() {
        assert_eq!(
            normalize_target("-bad.example.com"),
            Err(DomainError::Malformed)
        );
        assert_eq!(
            normalize_target("bad-.example.com"),
            Err(DomainError::Malformed)
        );
        assert_eq!(
            normalize_target("double..dot.com"),
            Err(DomainError::Malformed)
        );
        assert_eq!(
            normalize_target("has space.com"),
            Err(DomainError::Malformed)
        );
    }

    #[test]
    fn rejects_overlong_names() {
        let long_label = "a".repeat(64);
        assert_eq!(
            normalize_target(&format!("{long_label}.com")),
            Err(DomainError::Malformed)
        );

        let long_host = format!("{}.com", "a.".repeat(200));
        assert_eq!(normalize_target(&long_host), Err(DomainError::TooLong));
    }
}
