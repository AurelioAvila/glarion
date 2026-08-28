//! Authentication: password hashing, JWT issuing, and the `AuthUser`
//! extractor.
//!
//! Tokens carry a `token_version` claim that is compared against the value
//! stored on the user row on every authenticated request. Bumping that
//! column invalidates every token previously issued to that user — this is
//! how password changes and "log out everywhere" revoke access without
//! needing a token blocklist. (Same scheme as the PC Tweaker backend.)

use argon2::Argon2;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Access token lifetime. Short enough that a leaked token has limited
/// value, long enough to avoid re-auth churn in a dashboard session.
const TOKEN_TTL_HOURS: i64 = 12;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject: the user id.
    pub sub: Uuid,
    /// Must match `users.token_version` at verification time.
    pub token_version: i32,
    pub exp: i64,
    pub iat: i64,
}

pub fn hash_password(password: &str) -> ApiResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|err| ApiError::Internal(anyhow::anyhow!("password hashing failed: {err}")))
}

/// Verifies a password against a stored hash. A malformed stored hash is
/// treated as a failed verification, never as a success.
pub fn verify_password(password: &str, stored_hash: &str) -> bool {
    match PasswordHash::new(stored_hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

pub fn issue_token(secret: &str, user_id: Uuid, token_version: i32) -> ApiResult<String> {
    let now = Utc::now();
    let claims = Claims {
        sub: user_id,
        token_version,
        iat: now.timestamp(),
        exp: (now + Duration::hours(TOKEN_TTL_HOURS)).timestamp(),
    };

    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|err| ApiError::Internal(anyhow::anyhow!("token encoding failed: {err}")))
}

/// Decodes and validates a token's signature and expiry. Does *not* check
/// `token_version` — that requires a DB read and happens in the extractor.
pub fn decode_token(secret: &str, token: &str) -> Result<Claims, ApiError> {
    // Pin the algorithm. Without this, a token could assert `alg: none` or a
    // different algorithm and bypass signature verification.
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_required_spec_claims(&["exp", "sub"]);

    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|_| ApiError::Unauthorized)
}

/// An authenticated user. Extracting this in a handler signature is what
/// makes a route require auth — there is no separate middleware to forget
/// to apply.
pub struct AuthUser {
    pub id: Uuid,
}

#[axum::async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or(ApiError::Unauthorized)?;

        let token = header
            .strip_prefix("Bearer ")
            .ok_or(ApiError::Unauthorized)?
            .trim();

        let claims = decode_token(&state.jwt_secret, token)?;

        // Revocation check: the token's version must still match the user's
        // current version. A stale token fails here even though its
        // signature and expiry are valid.
        let current_version: Option<i32> =
            sqlx::query_scalar("select token_version from users where id = $1")
                .bind(claims.sub)
                .fetch_optional(&state.pool)
                .await?;

        match current_version {
            Some(version) if version == claims.token_version => Ok(AuthUser { id: claims.sub }),
            // User deleted, or token revoked by a version bump.
            _ => Err(ApiError::Unauthorized),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-secret-that-is-long-enough-for-hs256";

    #[test]
    fn password_round_trip() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &hash));
        assert!(!verify_password("wrong password", &hash));
    }

    #[test]
    fn malformed_stored_hash_never_verifies() {
        assert!(!verify_password("anything", "not-a-valid-phc-string"));
        assert!(!verify_password("anything", ""));
    }

    #[test]
    fn token_round_trip_preserves_subject_and_version() {
        let user_id = Uuid::new_v4();
        let token = issue_token(SECRET, user_id, 7).unwrap();
        let claims = decode_token(SECRET, &token).unwrap();

        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.token_version, 7);
    }

    #[test]
    fn token_signed_with_other_secret_is_rejected() {
        let token = issue_token(SECRET, Uuid::new_v4(), 0).unwrap();
        assert!(decode_token("a-completely-different-secret-value-here", &token).is_err());
    }

    #[test]
    fn garbage_token_is_rejected() {
        assert!(decode_token(SECRET, "not.a.token").is_err());
        assert!(decode_token(SECRET, "").is_err());
    }
}
