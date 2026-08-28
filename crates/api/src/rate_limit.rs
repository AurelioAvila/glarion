//! Request rate limiting for the endpoints worth attacking.
//!
//! Without this, `POST /api/auth/login` is an unlimited password oracle:
//! Argon2 makes each guess expensive, but expensive is not the same as
//! bounded, and an attacker with a credential-stuffing list only needs
//! throughput, not cleverness.
//!
//! This is an in-process fixed-window counter, which means two things
//! worth being honest about:
//!
//!  * With more than one API instance the effective limit multiplies by the
//!    instance count. It is a speed bump sized for a single-node
//!    deployment; a shared store is the fix when we scale out.
//!  * A fixed window allows a burst of up to 2× the limit across a window
//!    boundary. Acceptable here — the goal is to make sustained guessing
//!    impractical, not to police individual bursts.
//!
//! The client key is the TCP peer address. Behind a reverse proxy that is
//! the proxy's address, which collapses every client into one bucket — so
//! deploying behind a proxy requires teaching this module to read a
//! forwarded header *from a trusted proxy only*. Reading such a header
//! unconditionally would be worse than the current behaviour: it is
//! attacker-controlled, so it would let one client mint a fresh bucket per
//! request and remove the limit entirely.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Attempts allowed per window for authentication endpoints.
pub const AUTH_ATTEMPTS_PER_WINDOW: u32 = 10;

/// Length of the authentication window.
pub const AUTH_WINDOW_SECS: u64 = 300;

/// Ownership checks allowed per window.
///
/// Each check makes us perform a DNS lookup or an outbound HTTPS request to
/// a host the caller nominated. Unmetered, that is a request-amplification
/// primitive: one cheap API call turns into traffic aimed at a third party
/// from our address space. The allowance is generous enough for someone
/// legitimately waiting on DNS propagation and retrying.
pub const VERIFICATION_CHECKS_PER_WINDOW: u32 = 20;

/// Length of the verification-check window.
pub const VERIFICATION_WINDOW_SECS: u64 = 300;

/// Entries older than this are dropped during cleanup so the map cannot
/// grow without bound from one-shot addresses.
const ENTRY_TTL_SECS: u64 = 900;

#[derive(Clone, Copy)]
struct Window {
    started: Instant,
    count: u32,
}

/// Decides whether a request may proceed, given the current window state.
///
/// Pure, so the policy can be tested without waiting on real time.
fn decide(
    window: Option<Window>,
    now: Instant,
    limit: u32,
    window_len: Duration,
) -> (bool, Window) {
    match window {
        // Window still open: allow only while under the limit.
        Some(existing) if now.duration_since(existing.started) < window_len => {
            let allowed = existing.count < limit;
            (
                allowed,
                Window {
                    started: existing.started,
                    // Count refused attempts too, so hammering the endpoint
                    // cannot keep the counter artificially low.
                    count: existing.count.saturating_add(1),
                },
            )
        }
        // No window, or the previous one has elapsed: start a fresh one.
        _ => (
            true,
            Window {
                started: now,
                count: 1,
            },
        ),
    }
}

#[derive(Clone)]
pub struct RateLimiter {
    buckets: Arc<Mutex<HashMap<IpAddr, Window>>>,
    limit: u32,
    window: Duration,
}

impl RateLimiter {
    pub fn new(limit: u32, window: Duration) -> Self {
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
            limit,
            window,
        }
    }

    /// The limiter used for signup and login.
    pub fn for_auth() -> Self {
        Self::new(
            AUTH_ATTEMPTS_PER_WINDOW,
            Duration::from_secs(AUTH_WINDOW_SECS),
        )
    }

    /// The limiter used for ownership verification checks.
    pub fn for_verification() -> Self {
        Self::new(
            VERIFICATION_CHECKS_PER_WINDOW,
            Duration::from_secs(VERIFICATION_WINDOW_SECS),
        )
    }

    /// Records an attempt from `client` and reports whether it may proceed.
    pub fn check(&self, client: IpAddr) -> bool {
        let now = Instant::now();

        // A poisoned mutex means another thread panicked mid-update. Fail
        // closed: refuse the request rather than skipping the limit.
        let mut buckets = match self.buckets.lock() {
            Ok(guard) => guard,
            Err(_) => return false,
        };

        // Opportunistic cleanup, cheap because it only runs when the map
        // has grown enough to be worth it.
        if buckets.len() > 10_000 {
            let ttl = Duration::from_secs(ENTRY_TTL_SECS);
            buckets.retain(|_, window| now.duration_since(window.started) < ttl);
        }

        let (allowed, updated) =
            decide(buckets.get(&client).copied(), now, self.limit, self.window);
        buckets.insert(client, updated);

        allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn client(last_octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, last_octet))
    }

    #[test]
    fn allows_requests_up_to_the_limit() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60));

        assert!(limiter.check(client(1)));
        assert!(limiter.check(client(1)));
        assert!(limiter.check(client(1)));
    }

    #[test]
    fn refuses_once_the_limit_is_reached() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60));

        for _ in 0..3 {
            assert!(limiter.check(client(1)));
        }

        assert!(!limiter.check(client(1)));
        assert!(!limiter.check(client(1)));
    }

    #[test]
    fn clients_are_limited_independently() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));

        assert!(limiter.check(client(1)));
        assert!(limiter.check(client(1)));
        assert!(!limiter.check(client(1)));

        // A different address is unaffected by the first one's exhaustion.
        assert!(limiter.check(client(2)));
        assert!(limiter.check(client(2)));
    }

    #[test]
    fn window_resets_after_it_elapses() {
        let now = Instant::now();
        let window = Duration::from_secs(60);

        let exhausted = Window {
            started: now - Duration::from_secs(61),
            count: 99,
        };

        let (allowed, updated) = decide(Some(exhausted), now, 3, window);

        assert!(allowed, "a lapsed window must not keep blocking");
        assert_eq!(updated.count, 1, "the counter must restart");
    }

    #[test]
    fn refused_attempts_still_count() {
        // Otherwise an attacker could hold the counter at the limit forever
        // while continuing to guess.
        let now = Instant::now();
        let at_limit = Window {
            started: now,
            count: 5,
        };

        let (allowed, updated) = decide(Some(at_limit), now, 5, Duration::from_secs(60));

        assert!(!allowed);
        assert_eq!(updated.count, 6);
    }

    #[test]
    fn counter_saturates_rather_than_overflowing() {
        let now = Instant::now();
        let maxed = Window {
            started: now,
            count: u32::MAX,
        };

        let (allowed, updated) = decide(Some(maxed), now, 5, Duration::from_secs(60));

        assert!(!allowed);
        assert_eq!(updated.count, u32::MAX);
    }

    #[test]
    fn auth_limiter_uses_the_documented_policy() {
        let limiter = RateLimiter::for_auth();

        for _ in 0..AUTH_ATTEMPTS_PER_WINDOW {
            assert!(limiter.check(client(7)));
        }

        assert!(
            !limiter.check(client(7)),
            "login must stop accepting guesses after the configured limit"
        );
    }
}
