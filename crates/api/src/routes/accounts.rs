//! Signup and login.

use axum::extract::{ConnectInfo, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::OnceLock;
use uuid::Uuid;

use crate::auth::{hash_password, issue_token, verify_password};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Minimum password length. Deliberately a length floor rather than a
/// composition rule (no "must contain a symbol") — length is what actually
/// resists offline cracking.
const MIN_PASSWORD_LEN: usize = 12;

/// Maximum accepted password length.
///
/// Not a security policy — it is a cost ceiling. Argon2 hashes whatever it
/// is given, so without a cap an attacker can post a multi-megabyte body
/// and make each request cost far more to reject than to send. 256 is far
/// above any real passphrase.
const MAX_PASSWORD_LEN: usize = 256;

#[derive(Deserialize)]
pub struct CredentialsRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub token: String,
    pub user_id: Uuid,
}

pub async fn signup(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<CredentialsRequest>,
) -> ApiResult<Json<TokenResponse>> {
    // Rate limited alongside login: unlimited signup is an account-flooding
    // and email-bombing primitive even though no password is being guessed.
    if !state.auth_limiter.check(peer.ip()) {
        return Err(ApiError::TooManyRequests);
    }

    let email = normalize_email(&body.email)?;

    let password_len = body.password.chars().count();
    if password_len < MIN_PASSWORD_LEN {
        return Err(ApiError::BadRequest(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        )));
    }
    if password_len > MAX_PASSWORD_LEN {
        return Err(ApiError::BadRequest(format!(
            "password must be at most {MAX_PASSWORD_LEN} characters"
        )));
    }

    let password_hash = hash_password(&body.password)?;

    // `on conflict do nothing` + a null check tells us the email was taken
    // without a separate lookup, and without a race between the two.
    let user_id: Option<Uuid> = sqlx::query_scalar(
        "insert into users (email, password_hash) values ($1, $2)
         on conflict (email) do nothing
         returning id",
    )
    .bind(&email)
    .bind(&password_hash)
    .fetch_optional(&state.pool)
    .await?;

    let user_id = user_id.ok_or_else(|| ApiError::Conflict("email already registered".into()))?;

    // Every new account starts on the free plan with a single target.
    sqlx::query(
        "insert into entitlements (user_id, product, plan, max_targets)
         values ($1, 'glarion', 'free', 1)
         on conflict (user_id, product) do nothing",
    )
    .bind(user_id)
    .execute(&state.pool)
    .await?;

    let token = issue_token(&state.jwt_secret, user_id, 0)?;
    Ok(Json(TokenResponse { token, user_id }))
}

pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<CredentialsRequest>,
) -> ApiResult<Json<TokenResponse>> {
    // Checked before anything else: an attacker must not be able to spend
    // our Argon2 cycles, or learn anything from the response, once they are
    // over the limit.
    if !state.auth_limiter.check(peer.ip()) {
        return Err(ApiError::TooManyRequests);
    }

    // Reject an oversized password before hashing rather than after: the
    // whole point of the cap is to not spend Argon2 time on it.
    if body.password.len() > MAX_PASSWORD_LEN * 4 {
        return Err(ApiError::InvalidCredentials);
    }

    let email = normalize_email(&body.email)?;

    let row: Option<(Uuid, String, i32)> =
        sqlx::query_as("select id, password_hash, token_version from users where email = $1")
            .bind(&email)
            .fetch_optional(&state.pool)
            .await?;

    // Same error for "no such user" and "wrong password" so the response
    // body cannot be used to enumerate registered addresses.
    //
    // The response *timing* would still leak it if we returned early here:
    // an unknown address would skip Argon2 entirely and answer in
    // microseconds, while a known one would take the full hashing time. So
    // a verification is always performed — against a decoy hash when the
    // account does not exist — and the outcome is only branched on
    // afterwards.
    let (user_id, password_hash, token_version) = match row {
        Some(row) => row,
        None => {
            verify_password(&body.password, decoy_hash());
            return Err(ApiError::InvalidCredentials);
        }
    };

    if !verify_password(&body.password, &password_hash) {
        return Err(ApiError::InvalidCredentials);
    }

    let token = issue_token(&state.jwt_secret, user_id, token_version)?;
    Ok(Json(TokenResponse { token, user_id }))
}

/// A genuine Argon2 hash of a value nobody knows, used to spend the same
/// CPU time as a real verification when the account does not exist.
///
/// Produced with `hash_password` rather than a hard-coded constant so it
/// always carries the same parameters as the hashes we actually store — a
/// pasted-in hash with different parameters would take a different amount
/// of time and reintroduce the very leak this closes.
fn decoy_hash() -> &'static str {
    static DECOY: OnceLock<String> = OnceLock::new();
    DECOY.get_or_init(|| {
        hash_password(&Uuid::new_v4().to_string()).expect("could not build the decoy hash")
    })
}

fn normalize_email(input: &str) -> ApiResult<String> {
    let email = input.trim().to_ascii_lowercase();

    // Intentionally shallow validation: the authoritative check is whether a
    // confirmation mail arrives, not a regex.
    if email.is_empty() || !email.contains('@') || email.len() > 320 {
        return Err(ApiError::BadRequest("a valid email is required".into()));
    }

    Ok(email)
}
