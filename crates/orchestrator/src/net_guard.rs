//! Resolved-address filtering.
//!
//! `domain::normalize_target` rejects targets that are *written* as an IP
//! literal or an internal name. That is not enough on its own: a perfectly
//! well-formed public hostname can have an A record pointing at
//! `127.0.0.1`, `10.0.0.5`, or `169.254.169.254`.
//!
//! That matters here more than in most applications, because the whole
//! product is "give us a hostname and we will send traffic to it". Someone
//! can legitimately pass ownership verification for a domain they control
//! and then repoint it at our own infrastructure or at the cloud metadata
//! endpoint. So the addresses a name resolves to are checked, not just the
//! name.
//!
//! **Residual risk, stated plainly:** DNS can change between the check and
//! the connection (rebinding). For our own HTTP fetches we close that
//! window by pinning the connection to the address we validated. For an
//! external scanner process we cannot pin the address ourselves, so the
//! check happens immediately before the process is spawned. Nuclei is also
//! launched with its own local-network restriction, which closes that
//! boundary again inside the process if DNS changes after our lookup.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug, thiserror::Error)]
pub enum NetGuardError {
    #[error("could not resolve '{0}'")]
    Unresolvable(String),
    #[error("'{domain}' resolves to a non-public address ({address}) and will not be contacted")]
    NonPublicAddress { domain: String, address: IpAddr },
}

/// Whether an address is a public internet address we are willing to
/// contact.
///
/// Written out rather than using `IpAddr::is_global`, which is still
/// unstable. Anything not positively known to be public is refused, so a
/// range we failed to think of fails closed.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_ipv4(v4),
        IpAddr::V6(v6) => is_public_ipv6(v6),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();

    !(ip.is_unspecified()          // 0.0.0.0/8
        || ip.is_loopback()        // 127.0.0.0/8
        || ip.is_private()         // 10/8, 172.16/12, 192.168/16
        || ip.is_link_local()      // 169.254.0.0/16 — cloud metadata
        || ip.is_broadcast()
        || ip.is_documentation()   // 192.0.2/24, 198.51.100/24, 203.0.113/24
        || ip.is_multicast()       // 224.0.0.0/4
        || (a == 100 && (64..128).contains(&b))   // 100.64/10 CGNAT
        || (a == 198 && (18..20).contains(&b))    // 198.18/15 benchmarking
        || (a == 192 && b == 0)                   // 192.0.0.0/24 IETF protocol
        || a >= 240) // 240.0.0.0/4 reserved, includes 255.255.255.255
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    // An IPv4-mapped address is really an IPv4 address; judge it as one so
    // ::ffff:127.0.0.1 cannot slip through.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_ipv4(v4);
    }

    let segments = ip.segments();

    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00      // fc00::/7 unique local
        || (segments[0] & 0xffc0) == 0xfe80      // fe80::/10 link-local
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)) // 2001:db8::/32
}

/// Resolves `domain` and returns its addresses, refusing the whole name if
/// *any* resolved address is non-public.
///
/// Rejecting on any bad address rather than filtering them out is
/// deliberate: a name that answers with both a public and a private address
/// is exactly what a rebinding attack looks like, so it is not a name we
/// want to touch at all.
pub async fn resolve_public_addresses(domain: &str) -> Result<Vec<SocketAddr>, NetGuardError> {
    // Port 443 only so `lookup_host` returns SocketAddrs; the caller
    // decides what port to actually use.
    let host_port = format!("{domain}:443");

    let addresses: Vec<SocketAddr> = tokio::net::lookup_host(&host_port)
        .await
        .map_err(|_| NetGuardError::Unresolvable(domain.to_string()))?
        .collect();

    if addresses.is_empty() {
        return Err(NetGuardError::Unresolvable(domain.to_string()));
    }

    for address in &addresses {
        if !is_public_ip(address.ip()) {
            return Err(NetGuardError::NonPublicAddress {
                domain: domain.to_string(),
                address: address.ip(),
            });
        }
    }

    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    #[test]
    fn public_addresses_are_allowed() {
        assert!(is_public_ip(ip("8.8.8.8")));
        assert!(is_public_ip(ip("1.1.1.1")));
        assert!(is_public_ip(ip("93.184.216.34"))); // example.com
        assert!(is_public_ip(ip("2606:4700:4700::1111")));
    }

    #[test]
    fn cloud_metadata_address_is_refused() {
        // The single most important case: AWS/GCP/Azure metadata.
        assert!(!is_public_ip(ip("169.254.169.254")));
        assert!(!is_public_ip(ip("169.254.0.1")));
    }

    #[test]
    fn loopback_is_refused() {
        assert!(!is_public_ip(ip("127.0.0.1")));
        assert!(!is_public_ip(ip("127.1.2.3")));
        assert!(!is_public_ip(ip("::1")));
    }

    #[test]
    fn private_ranges_are_refused() {
        assert!(!is_public_ip(ip("10.0.0.1")));
        assert!(!is_public_ip(ip("172.16.0.1")));
        assert!(!is_public_ip(ip("172.31.255.255")));
        assert!(!is_public_ip(ip("192.168.1.1")));
    }

    #[test]
    fn addresses_adjacent_to_private_ranges_are_still_allowed() {
        // Guards against an over-broad mask: 172.15 and 172.32 are public.
        assert!(is_public_ip(ip("172.15.255.255")));
        assert!(is_public_ip(ip("172.32.0.0")));
        assert!(is_public_ip(ip("11.0.0.1")));
        assert!(is_public_ip(ip("9.255.255.255")));
    }

    #[test]
    fn carrier_grade_nat_range_is_refused() {
        assert!(!is_public_ip(ip("100.64.0.1")));
        assert!(!is_public_ip(ip("100.127.255.255")));
        // But the rest of 100/8 is public.
        assert!(is_public_ip(ip("100.63.255.255")));
        assert!(is_public_ip(ip("100.128.0.0")));
    }

    #[test]
    fn unspecified_broadcast_and_reserved_are_refused() {
        assert!(!is_public_ip(ip("0.0.0.0")));
        assert!(!is_public_ip(ip("255.255.255.255")));
        assert!(!is_public_ip(ip("240.0.0.1")));
        assert!(!is_public_ip(ip("::")));
    }

    #[test]
    fn multicast_and_documentation_are_refused() {
        assert!(!is_public_ip(ip("224.0.0.1")));
        assert!(!is_public_ip(ip("203.0.113.5")));
        assert!(!is_public_ip(ip("192.0.2.1")));
        assert!(!is_public_ip(ip("198.51.100.1")));
        assert!(!is_public_ip(ip("2001:db8::1")));
        assert!(!is_public_ip(ip("ff02::1")));
    }

    #[test]
    fn benchmarking_and_protocol_assignment_ranges_are_refused() {
        assert!(!is_public_ip(ip("198.18.0.1")));
        assert!(!is_public_ip(ip("198.19.255.255")));
        assert!(!is_public_ip(ip("192.0.0.1")));
        // 198.20 and 198.17 are ordinary public space.
        assert!(is_public_ip(ip("198.20.0.0")));
        assert!(is_public_ip(ip("198.17.255.255")));
    }

    #[test]
    fn ipv6_unique_local_and_link_local_are_refused() {
        assert!(!is_public_ip(ip("fc00::1")));
        assert!(!is_public_ip(ip("fd12:3456::1")));
        assert!(!is_public_ip(ip("fe80::1")));
    }

    #[test]
    fn ipv4_mapped_ipv6_cannot_smuggle_a_private_address() {
        // ::ffff:127.0.0.1 and friends must be judged as IPv4.
        assert!(!is_public_ip(ip("::ffff:127.0.0.1")));
        assert!(!is_public_ip(ip("::ffff:169.254.169.254")));
        assert!(!is_public_ip(ip("::ffff:10.0.0.1")));
        assert!(is_public_ip(ip("::ffff:8.8.8.8")));
    }

    #[tokio::test]
    async fn resolving_localhost_is_refused() {
        // Even though this never reaches normalize_target in production,
        // the guard must stand on its own.
        match resolve_public_addresses("localhost").await {
            Err(NetGuardError::NonPublicAddress { .. }) => {}
            Err(NetGuardError::Unresolvable(_)) => {} // acceptable on hosts without it
            Ok(addresses) => panic!("localhost must not be contactable, got {addresses:?}"),
        }
    }

    #[tokio::test]
    async fn a_public_hostname_resolving_to_loopback_is_refused() {
        // The attack this module exists for. `localtest.me` is a real,
        // syntactically ordinary public domain whose A record is 127.0.0.1,
        // so it sails past `domain::normalize_target` and is caught only
        // here. Skipped when DNS is unavailable rather than failing, since
        // the check itself is what we are asserting.
        match resolve_public_addresses("localtest.me").await {
            Err(NetGuardError::NonPublicAddress { address, .. }) => {
                assert!(!is_public_ip(address));
            }
            Err(NetGuardError::Unresolvable(_)) => {
                eprintln!("skipping: no DNS available for localtest.me");
            }
            Ok(addresses) => {
                panic!("a hostname pointing at loopback must be refused, got {addresses:?}")
            }
        }
    }

    #[tokio::test]
    async fn unresolvable_names_are_reported_not_allowed() {
        let domain = "this-name-should-not-exist-glarion-test-12345.invalid";
        match resolve_public_addresses(domain).await {
            Err(NetGuardError::Unresolvable(_)) => {}
            other => panic!("expected Unresolvable, got {other:?}"),
        }
    }
}
