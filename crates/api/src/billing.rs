//! Plans, and the parts of Stripe that must not be got wrong.
//!
//! Two things live here rather than in the handler, because both are pure
//! and both are the kind of code that fails silently when it is wrong: what
//! each plan is allowed to do, and whether a webhook actually came from
//! Stripe.
//!
//! The second is the one to be careful about. The webhook endpoint is how
//! an account gets upgraded, so an unverified one is a way for anybody on
//! the internet to grant themselves a subscription by posting the right
//! JSON at it.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// What somebody is entitled to.
///
/// The site allowance is the meter, and scheduling is the line between a
/// tool and a service — an unattended weekly check is the thing an agency
/// resells to its client, so it is what the paid tiers are actually for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    Free,
    Studio,
    Agency,
}

impl Plan {
    pub fn as_db_str(&self) -> &'static str {
        match self {
            Plan::Free => "free",
            Plan::Studio => "studio",
            Plan::Agency => "agency",
        }
    }

    /// Reads a stored plan.
    ///
    /// Anything unrecognised is Free. A row we cannot interpret must not
    /// grant more than the cheapest thing we sell — the failure mode of a
    /// bad read should be a customer who calls support, never an account
    /// with capabilities nobody paid for.
    pub fn from_db_str(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "studio" => Plan::Studio,
            "agency" => Plan::Agency,
            _ => Plan::Free,
        }
    }

    pub fn max_targets(&self) -> i32 {
        match self {
            Plan::Free => 1,
            Plan::Studio => 10,
            Plan::Agency => 40,
        }
    }

    /// Whether unattended re-checking is included.
    pub fn allows_scheduling(&self) -> bool {
        !matches!(self, Plan::Free)
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Plan::Free => "Free",
            Plan::Studio => "Studio",
            Plan::Agency => "Agency",
        }
    }
}

/// Monthly or yearly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interval {
    Monthly,
    Yearly,
}

impl Interval {
    pub fn from_str_or_monthly(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "yearly" | "annual" | "year" => Interval::Yearly,
            _ => Interval::Monthly,
        }
    }
}

/// Which Stripe price a plan and interval maps to.
///
/// Read from configuration rather than hard-coded: prices are created in
/// the Stripe dashboard, they differ between test and live mode, and an id
/// baked into a binary is one that cannot be changed without a deploy.
pub fn price_env_var(plan: Plan, interval: Interval) -> Option<&'static str> {
    match (plan, interval) {
        (Plan::Free, _) => None,
        (Plan::Studio, Interval::Monthly) => Some("STRIPE_PRICE_STUDIO_MONTHLY"),
        (Plan::Studio, Interval::Yearly) => Some("STRIPE_PRICE_STUDIO_YEARLY"),
        (Plan::Agency, Interval::Monthly) => Some("STRIPE_PRICE_AGENCY_MONTHLY"),
        (Plan::Agency, Interval::Yearly) => Some("STRIPE_PRICE_AGENCY_YEARLY"),
    }
}

/// Maps a Stripe price back to the plan it sells.
///
/// The webhook is told a price id and has to decide what the customer now
/// has. An id we do not recognise grants nothing, for the same reason an
/// unreadable plan string does.
pub fn plan_for_price(price_id: &str) -> Option<Plan> {
    for plan in [Plan::Studio, Plan::Agency] {
        for interval in [Interval::Monthly, Interval::Yearly] {
            let Some(var) = price_env_var(plan, interval) else {
                continue;
            };
            if let Ok(configured) = std::env::var(var) {
                if !configured.is_empty() && configured == price_id {
                    return Some(plan);
                }
            }
        }
    }
    None
}

/// Subscription states that should keep an account working.
///
/// `past_due` is included deliberately. A failed card is usually an expired
/// card, and locking somebody out of their monitoring the hour a payment
/// bounces loses a customer who would have paid on the retry. Stripe moves
/// the subscription to `canceled` or `unpaid` once it gives up, and those
/// are not on this list.
pub fn status_grants_access(status: &str) -> bool {
    matches!(status, "active" | "trialing" | "past_due")
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("the signature header is missing or malformed")]
    Malformed,
    #[error("the signature does not match")]
    Mismatch,
    #[error("the signature is outside the accepted time window")]
    Stale,
}

/// How far a webhook's timestamp may be from ours.
///
/// Bounded so a signature captured once cannot be replayed indefinitely.
/// Five minutes is Stripe's own recommendation and is generous enough to
/// survive ordinary clock drift.
pub const SIGNATURE_TOLERANCE_SECS: i64 = 300;

/// Checks that a webhook body really came from Stripe.
///
/// Written out rather than taken from a crate, because getting this subtly
/// wrong — comparing with `==`, forgetting the timestamp, signing the wrong
/// string — produces an endpoint that looks like it works and grants
/// subscriptions to anyone who asks. It is a dozen lines and it is worth
/// being able to read them.
///
/// `now` is a parameter so the time window can be tested without waiting.
pub fn verify_signature(
    payload: &[u8],
    header: &str,
    secret: &str,
    now: i64,
) -> Result<(), SignatureError> {
    let mut timestamp: Option<i64> = None;
    let mut signatures: Vec<&str> = Vec::new();

    for part in header.split(',') {
        let Some((key, value)) = part.trim().split_once('=') else {
            continue;
        };
        match key {
            "t" => timestamp = value.parse().ok(),
            // A header can carry several v1 signatures during a secret
            // rotation; any one of them matching is enough.
            "v1" => signatures.push(value),
            _ => {}
        }
    }

    let timestamp = timestamp.ok_or(SignatureError::Malformed)?;
    if signatures.is_empty() {
        return Err(SignatureError::Malformed);
    }

    if (now - timestamp).abs() > SIGNATURE_TOLERANCE_SECS {
        return Err(SignatureError::Stale);
    }

    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|_| SignatureError::Malformed)?;
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(payload);

    let expected = mac.finalize().into_bytes();

    for candidate in signatures {
        let Ok(decoded) = decode_hex(candidate) else {
            continue;
        };
        // Constant-time compare. A byte-by-byte early return leaks how much
        // of a guess was right, which is enough to forge one a byte at a
        // time given enough attempts.
        if decoded.len() == expected.len() && constant_time_eq(&decoded, &expected) {
            return Ok(());
        }
    }

    Err(SignatureError::Mismatch)
}

fn decode_hex(input: &str) -> Result<Vec<u8>, ()> {
    if !input.len().is_multiple_of(2) {
        return Err(());
    }
    (0..input.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&input[index..index + 2], 16).map_err(|_| ()))
        .collect()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign(payload: &[u8], secret: &str, timestamp: i64) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(timestamp.to_string().as_bytes());
        mac.update(b".");
        mac.update(payload);

        let hex: String = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();

        format!("t={timestamp},v1={hex}")
    }

    #[test]
    fn a_genuine_signature_is_accepted() {
        let payload = br#"{"id":"evt_1"}"#;
        let header = sign(payload, "whsec_test", 1_000);

        assert!(verify_signature(payload, &header, "whsec_test", 1_000).is_ok());
    }

    #[test]
    fn a_signature_from_the_wrong_secret_is_refused() {
        let payload = br#"{"id":"evt_1"}"#;
        let header = sign(payload, "whsec_attacker", 1_000);

        assert!(matches!(
            verify_signature(payload, &header, "whsec_test", 1_000),
            Err(SignatureError::Mismatch)
        ));
    }

    #[test]
    fn a_changed_body_invalidates_the_signature() {
        // The whole point: the signature covers the payload, so an upgrade
        // cannot be edited into a message that was signed for something
        // else.
        let header = sign(br#"{"plan":"free"}"#, "whsec_test", 1_000);

        assert!(matches!(
            verify_signature(br#"{"plan":"agency"}"#, &header, "whsec_test", 1_000),
            Err(SignatureError::Mismatch)
        ));
    }

    #[test]
    fn an_old_signature_is_refused_even_though_it_is_valid() {
        // Replay protection. Without the window, one captured request works
        // forever.
        let payload = br#"{"id":"evt_1"}"#;
        let header = sign(payload, "whsec_test", 1_000);

        assert!(matches!(
            verify_signature(
                payload,
                &header,
                "whsec_test",
                1_000 + SIGNATURE_TOLERANCE_SECS + 1
            ),
            Err(SignatureError::Stale)
        ));
    }

    #[test]
    fn a_signature_from_the_near_future_is_tolerated() {
        // Clocks drift; a webhook arriving a minute "early" is ordinary.
        let payload = br#"{"id":"evt_1"}"#;
        let header = sign(payload, "whsec_test", 1_060);

        assert!(verify_signature(payload, &header, "whsec_test", 1_000).is_ok());
    }

    #[test]
    fn a_header_without_a_timestamp_or_signature_is_refused() {
        let payload = br#"{}"#;

        assert!(matches!(
            verify_signature(payload, "v1=abcd", "whsec_test", 1_000),
            Err(SignatureError::Malformed)
        ));
        assert!(matches!(
            verify_signature(payload, "t=1000", "whsec_test", 1_000),
            Err(SignatureError::Malformed)
        ));
        assert!(matches!(
            verify_signature(payload, "", "whsec_test", 1_000),
            Err(SignatureError::Malformed)
        ));
    }

    #[test]
    fn several_signatures_are_accepted_if_any_matches() {
        // Stripe sends more than one during a secret rotation.
        let payload = br#"{"id":"evt_1"}"#;
        let genuine = sign(payload, "whsec_test", 1_000);
        let hex = genuine.split("v1=").nth(1).unwrap();
        let header = format!("t=1000,v1=00ff00ff,v1={hex}");

        assert!(verify_signature(payload, &header, "whsec_test", 1_000).is_ok());
    }

    #[test]
    fn a_malformed_hex_signature_does_not_pass() {
        assert!(verify_signature(b"{}", "t=1000,v1=zzzz", "whsec_test", 1_000).is_err());
        assert!(verify_signature(b"{}", "t=1000,v1=abc", "whsec_test", 1_000).is_err());
    }

    #[test]
    fn an_unreadable_plan_grants_the_least() {
        assert_eq!(Plan::from_db_str("enterprise"), Plan::Free);
        assert_eq!(Plan::from_db_str(""), Plan::Free);
        assert_eq!(Plan::from_db_str("STUDIO"), Plan::Studio);
    }

    #[test]
    fn only_paid_plans_include_unattended_checking() {
        assert!(!Plan::Free.allows_scheduling());
        assert!(Plan::Studio.allows_scheduling());
        assert!(Plan::Agency.allows_scheduling());
    }

    #[test]
    fn allowances_rise_with_the_plan() {
        assert!(Plan::Free.max_targets() < Plan::Studio.max_targets());
        assert!(Plan::Studio.max_targets() < Plan::Agency.max_targets());
    }

    #[test]
    fn a_failed_payment_does_not_immediately_lock_somebody_out() {
        // Usually an expired card. Stripe retries, and cutting access on
        // the first bounce loses a customer who would have paid.
        assert!(status_grants_access("past_due"));
        assert!(status_grants_access("active"));
        assert!(status_grants_access("trialing"));
    }

    #[test]
    fn an_abandoned_subscription_does_not_grant_access() {
        assert!(!status_grants_access("canceled"));
        assert!(!status_grants_access("unpaid"));
        assert!(!status_grants_access("incomplete_expired"));
        assert!(!status_grants_access(""));
    }

    #[test]
    fn an_unknown_price_grants_nothing() {
        // The webhook is told a price id. One we cannot map must not be
        // guessed at.
        assert_eq!(plan_for_price("price_does_not_exist"), None);
    }

    #[test]
    fn intervals_default_to_monthly() {
        assert_eq!(Interval::from_str_or_monthly("yearly"), Interval::Yearly);
        assert_eq!(Interval::from_str_or_monthly("ANNUAL"), Interval::Yearly);
        assert_eq!(Interval::from_str_or_monthly("nonsense"), Interval::Monthly);
    }
}
