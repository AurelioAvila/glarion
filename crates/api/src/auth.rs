//! Authentication: password hashing, JWT issuing, and the `AuthUser`
//! extractor.
//!
//! Tokens carry a `token_version` claim that is compared against the value
//! stored on the user row on every authenticated request. Bumping that
//! column invalidates every token previously issued to that user — this is
//! how password changes and "log out everywhere" revoke access without
//! needing a token blocklist. (Same scheme as the PC Tweaker backend.)
//!
//! The JWT itself is written by hand rather than taken from a library, for
//! a reason that only became concrete once, not a preference stated in
//! advance: the crate previously used here (`jsonwebtoken`) has to support
//! RSA and EdDSA as well as HMAC, and pulling in the RSA implementation to
//! get HS256 dragged an unrelated, unfixed timing-side-channel advisory
//! (RUSTSEC-2023-0071) into a binary that never signs or verifies an RSA
//! token. HS256 is four lines of HMAC-SHA256 over base64url — see
//! `routes::billing::verify_signature` for the same call already made
//! about Stripe's webhook signature, and the same reasoning applies here.

use argon2::Argon2;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Access token lifetime. Short enough that a leaked token has limited
/// value, long enough to avoid re-auth churn in a dashboard session.
const TOKEN_TTL_HOURS: i64 = 12;

/// The header is fixed rather than parsed: `alg` is pinned to HS256 by
/// construction, so there is no `alg: none` or algorithm-confusion case
/// to defend against, because there is no code path that reads one.
const HEADER_JSON: &str = r#"{"alg":"HS256","typ":"JWT"}"#;

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

    let claims_json = serde_json::to_string(&claims)
        .map_err(|err| ApiError::Internal(anyhow::anyhow!("token encoding failed: {err}")))?;

    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(HEADER_JSON),
        URL_SAFE_NO_PAD.encode(&claims_json),
    );

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|err| ApiError::Internal(anyhow::anyhow!("bad JWT secret: {err}")))?;
    mac.update(signing_input.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

    Ok(format!("{signing_input}.{signature}"))
}

/// Decodes and validates a token's signature and expiry. Does *not* check
/// `token_version` — that requires a DB read and happens in the extractor.
pub fn decode_token(secret: &str, token: &str) -> Result<Claims, ApiError> {
    let mut parts = token.split('.');
    let (Some(header_b64), Some(claims_b64), Some(signature_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(ApiError::Unauthorized);
    };

    // The header is not parsed, only checked byte-for-byte against the one
    // this module ever issues. A token whose header claims a different
    // algorithm is rejected here rather than by inspecting `alg` — nothing
    // downstream ever asks what algorithm a token claims to use.
    if URL_SAFE_NO_PAD
        .decode(header_b64)
        .is_ok_and(|decoded| decoded != HEADER_JSON.as_bytes())
    {
        return Err(ApiError::Unauthorized);
    }

    let signature = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| ApiError::Unauthorized)?;

    let signing_input = format!("{header_b64}.{claims_b64}");

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|err| ApiError::Internal(anyhow::anyhow!("bad JWT secret: {err}")))?;
    mac.update(signing_input.as_bytes());
    // Constant-time by construction — the whole reason to route the
    // comparison through the Mac type rather than `==` on two Vecs.
    mac.verify_slice(&signature)
        .map_err(|_| ApiError::Unauthorized)?;

    let claims_bytes = URL_SAFE_NO_PAD
        .decode(claims_b64)
        .map_err(|_| ApiError::Unauthorized)?;
    let claims: Claims =
        serde_json::from_slice(&claims_bytes).map_err(|_| ApiError::Unauthorized)?;

    if claims.exp < Utc::now().timestamp() {
        return Err(ApiError::Unauthorized);
    }

    Ok(claims)
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

    #[test]
    fn a_tampered_payload_is_rejected() {
        // The signature must cover the payload, not just the header — a
        // token whose middle segment is swapped out has to fail even
        // though the signature segment "looks" well-formed.
        let token = issue_token(SECRET, Uuid::new_v4(), 0).unwrap();
        let mut segments: Vec<&str> = token.split('.').collect();
        let other = issue_token(SECRET, Uuid::new_v4(), 0).unwrap();
        let other_claims = other.split('.').nth(1).unwrap();
        segments[1] = other_claims;
        let tampered = segments.join(".");

        assert!(decode_token(SECRET, &tampered).is_err());
    }

    #[test]
    fn an_expired_token_is_rejected() {
        let now = Utc::now();
        let claims = Claims {
            sub: Uuid::new_v4(),
            token_version: 0,
            iat: (now - Duration::hours(TOKEN_TTL_HOURS + 1)).timestamp(),
            exp: (now - Duration::hours(1)).timestamp(),
        };
        let claims_json = serde_json::to_string(&claims).unwrap();
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(HEADER_JSON),
            URL_SAFE_NO_PAD.encode(&claims_json),
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
        mac.update(signing_input.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        let expired_token = format!("{signing_input}.{signature}");

        assert!(decode_token(SECRET, &expired_token).is_err());
    }

    #[test]
    fn a_token_claiming_a_different_algorithm_is_rejected() {
        // The header is never trusted for what algorithm to use — HS256 is
        // the only one this module ever verifies with — but a token that
        // lies about its header should still be refused outright rather
        // than silently accepted with the header ignored.
        let claims = Claims {
            sub: Uuid::new_v4(),
            token_version: 0,
            iat: Utc::now().timestamp(),
            exp: (Utc::now() + Duration::hours(1)).timestamp(),
        };
        let claims_json = serde_json::to_string(&claims).unwrap();
        let fake_header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
        let signing_input = format!("{fake_header}.{}", URL_SAFE_NO_PAD.encode(&claims_json));
        let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
        mac.update(signing_input.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        let token = format!("{signing_input}.{signature}");

        assert!(decode_token(SECRET, &token).is_err());
    }
}
