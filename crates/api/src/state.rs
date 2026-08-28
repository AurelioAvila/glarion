use sqlx::PgPool;
use std::sync::Arc;

use crate::mailer::Mailer;

use crate::rate_limit::RateLimiter;

/// Shared handler state. Cheap to clone — `PgPool` and `RateLimiter` are
/// Arc-backed and the secret is a small String.
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub jwt_secret: String,
    /// Shared across all auth requests, so the limit is per client rather
    /// than per connection.
    pub auth_limiter: RateLimiter,
    /// Separate budget for ownership checks, which cause outbound traffic.
    pub verification_limiter: RateLimiter,
    /// Shared so the HTTP client and configuration are built once.
    pub mailer: Arc<Mailer>,
}

impl AppState {
    pub fn new(pool: PgPool, jwt_secret: String) -> Self {
        Self {
            pool,
            jwt_secret,
            auth_limiter: RateLimiter::for_auth(),
            verification_limiter: RateLimiter::for_verification(),
            mailer: Arc::new(Mailer::from_env()),
        }
    }
}
