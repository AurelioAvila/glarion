//! Registration, email confirmation, and sign-in.

use axum::extract::{ConnectInfo, State};
use axum::Json;
use chrono::{DateTime, Datelike, Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::OnceLock;
use uuid::Uuid;

use crate::auth::{hash_password, issue_token, verify_password};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use orchestrator::mailer::verification_email;

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

const MAX_NAME_LEN: usize = 80;

/// Accounts are commercial contracts, which is the reason a date of birth
/// is collected at all: to confirm the holder can enter one.
const MIN_AGE_YEARS: i32 = 18;

/// How long a confirmation link stays usable.
const VERIFICATION_VALID_HOURS: i64 = 24;

/// How long before another confirmation email may be requested. Stops the
/// resend endpoint from being used to send someone repeated mail.
const RESEND_COOLDOWN_MINUTES: i64 = 2;

#[derive(Deserialize)]
pub struct SignupRequest {
    pub first_name: String,
    pub last_name: String,
    /// ISO date, `YYYY-MM-DD`.
    pub date_of_birth: String,
    pub email: String,
    pub password: String,
    pub password_confirmation: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub token: String,
    pub user_id: Uuid,
}

#[derive(Serialize)]
pub struct SignupResponse {
    /// No token: the account cannot be used until the address is confirmed,
    /// so returning a session here would contradict that.
    pub email: String,
    pub message: String,
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub token: String,
}

#[derive(Deserialize)]
pub struct ResendRequest {
    pub email: String,
}

#[derive(Serialize)]
pub struct MessageResponse {
    pub message: String,
}

/// What the resend endpoint needs to decide whether to send anything.
#[derive(sqlx::FromRow)]
struct PendingConfirmation {
    id: Uuid,
    first_name: String,
    email_verified_at: Option<DateTime<Utc>>,
    verification_sent_at: Option<DateTime<Utc>>,
}

pub async fn signup(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<SignupRequest>,
) -> ApiResult<Json<SignupResponse>> {
    // Rate limited alongside login: unlimited signup is an account-flooding
    // and mail-bombing primitive even though no password is being guessed.
    if !state.auth_limiter.check(peer.ip()) {
        return Err(ApiError::TooManyRequests);
    }

    let first_name = required_name(&body.first_name, "first name")?;
    let last_name = required_name(&body.last_name, "last name")?;
    let email = normalize_email(&body.email)?;
    let date_of_birth = parse_date_of_birth(&body.date_of_birth, Utc::now().date_naive())?;

    // Compared before hashing: no reason to spend Argon2 time on a request
    // that cannot succeed.
    if body.password != body.password_confirmation {
        return Err(ApiError::BadRequest("the passwords do not match".into()));
    }

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
    let (token, token_hash) = new_verification_token();

    // `on conflict do nothing` plus a null check tells us the address was
    // taken without a separate lookup, and without a race between the two.
    let user_id: Option<Uuid> = sqlx::query_scalar(
        "insert into users
             (email, password_hash, first_name, last_name, date_of_birth,
              verification_token_hash, verification_sent_at)
         values ($1, $2, $3, $4, $5, $6, now())
         on conflict (email) do nothing
         returning id",
    )
    .bind(&email)
    .bind(&password_hash)
    .bind(&first_name)
    .bind(&last_name)
    .bind(date_of_birth)
    .bind(&token_hash)
    .fetch_optional(&state.pool)
    .await?;

    // An address already registered gets the same answer as a new one.
    //
    // Saying "that email is taken" here turns signup into a way to test
    // whether somebody has an account, which is exactly what the sign-in
    // endpoint is careful not to leak. The real owner is told nothing new;
    // someone probing learns nothing either.
    let Some(user_id) = user_id else {
        return Ok(Json(SignupResponse {
            email,
            message: "Check your email to confirm your address.".into(),
        }));
    };

    sqlx::query(
        "insert into entitlements (user_id, product, plan, max_targets)
         values ($1, 'glarion', 'free', 1)
         on conflict (user_id, product) do nothing",
    )
    .bind(user_id)
    .execute(&state.pool)
    .await?;

    send_verification(&state, &email, &first_name, &token).await;

    Ok(Json(SignupResponse {
        email,
        message: "Check your email to confirm your address.".into(),
    }))
}

/// Sends the confirmation message, logging rather than failing on error.
///
/// The account already exists at this point. Returning an error would tell
/// the user signup failed when it did not, and leave them unable to retry
/// because the address is now taken. A failure here is recoverable through
/// the resend endpoint; a misleading error is not.
async fn send_verification(state: &AppState, email: &str, first_name: &str, token: &str) {
    let link = state.mailer.verification_link(token);
    let body = verification_email(first_name, &link);

    if let Err(error) = state
        .mailer
        .send(email, "Confirm your email address", &body)
        .await
    {
        tracing::error!(error = ?error, "could not send the confirmation email");
    }
}

pub async fn verify_email(
    State(state): State<AppState>,
    Json(body): Json<VerifyRequest>,
) -> ApiResult<Json<TokenResponse>> {
    let token_hash = hash_token(body.token.trim());
    let cutoff = Utc::now() - Duration::hours(VERIFICATION_VALID_HOURS);

    // Clearing the hash in the same statement makes the link single-use:
    // a second request finds no row rather than succeeding again.
    let row: Option<(Uuid, i32)> = sqlx::query_as(
        "update users
         set email_verified_at = coalesce(email_verified_at, now()),
             verification_token_hash = null
         where verification_token_hash = $1 and verification_sent_at > $2
         returning id, token_version",
    )
    .bind(&token_hash)
    .bind(cutoff)
    .fetch_optional(&state.pool)
    .await?;

    let (user_id, token_version) = row.ok_or_else(|| {
        ApiError::BadRequest("This confirmation link is no longer valid. Request a new one.".into())
    })?;

    // Signing in here saves the user a round trip through the sign-in form
    // immediately after proving they control the address.
    let token = issue_token(&state.jwt_secret, user_id, token_version)?;
    Ok(Json(TokenResponse { token, user_id }))
}

pub async fn resend_verification(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<ResendRequest>,
) -> ApiResult<Json<MessageResponse>> {
    if !state.auth_limiter.check(peer.ip()) {
        return Err(ApiError::TooManyRequests);
    }

    let email = normalize_email(&body.email)?;

    // Always the same answer, whether or not the address exists and whether
    // or not anything was actually sent. This endpoint would otherwise be a
    // cheap way to enumerate registered addresses.
    let answer = Ok(Json(MessageResponse {
        message: "If that address needs confirming, a new link is on its way.".into(),
    }));

    let row: Option<PendingConfirmation> = sqlx::query_as(
        "select id, coalesce(first_name, '') as first_name,
                email_verified_at, verification_sent_at
         from users where email = $1",
    )
    .bind(&email)
    .fetch_optional(&state.pool)
    .await?;

    let Some(user) = row else {
        return answer;
    };

    if user.email_verified_at.is_some() {
        return answer;
    }

    // Per-address cooldown, on top of the per-IP limit above: without it,
    // one address could be mailed repeatedly from many addresses.
    if let Some(sent_at) = user.verification_sent_at {
        if Utc::now() - sent_at < Duration::minutes(RESEND_COOLDOWN_MINUTES) {
            return answer;
        }
    }

    let (token, token_hash) = new_verification_token();
    sqlx::query(
        "update users set verification_token_hash = $2, verification_sent_at = now()
         where id = $1",
    )
    .bind(user.id)
    .bind(&token_hash)
    .execute(&state.pool)
    .await?;

    send_verification(&state, &email, &user.first_name, &token).await;

    answer
}

pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<LoginRequest>,
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

    let row: Option<(Uuid, String, i32, Option<DateTime<Utc>>)> = sqlx::query_as(
        "select id, password_hash, token_version, email_verified_at from users where email = $1",
    )
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
    let (user_id, password_hash, token_version, verified_at) = match row {
        Some(row) => row,
        None => {
            verify_password(&body.password, decoy_hash());
            return Err(ApiError::InvalidCredentials);
        }
    };

    if !verify_password(&body.password, &password_hash) {
        return Err(ApiError::InvalidCredentials);
    }

    // Only after the password is confirmed. Reporting "confirm your email"
    // to someone who did not supply the right password would tell them the
    // address is registered.
    if verified_at.is_none() {
        return Err(ApiError::EmailNotVerified);
    }

    let token = issue_token(&state.jwt_secret, user_id, token_version)?;
    Ok(Json(TokenResponse { token, user_id }))
}

/// Generates a confirmation token and the hash to store for it.
///
/// The plain token goes in the email; only the hash is written down, so a
/// database dump cannot be used to confirm other people's addresses.
fn new_verification_token() -> (String, String) {
    use rand::distributions::Alphanumeric;
    use rand::Rng;

    let token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(48)
        .map(char::from)
        .collect();

    let hash = hash_token(&token);
    (token, hash)
}

fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    format!("{digest:x}")
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

fn required_name(input: &str, label: &str) -> ApiResult<String> {
    let trimmed = input.trim();

    if trimmed.is_empty() {
        return Err(ApiError::BadRequest(format!("{label} is required")));
    }
    if trimmed.chars().count() > MAX_NAME_LEN {
        return Err(ApiError::BadRequest(format!(
            "{label} must be at most {MAX_NAME_LEN} characters"
        )));
    }

    Ok(trimmed.to_string())
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

/// Parses the date of birth and checks the person is old enough.
///
/// `today` is a parameter so the age boundaries can be tested without
/// waiting for a birthday.
fn parse_date_of_birth(input: &str, today: NaiveDate) -> ApiResult<NaiveDate> {
    let date = NaiveDate::parse_from_str(input.trim(), "%Y-%m-%d")
        .map_err(|_| ApiError::BadRequest("date of birth must be a valid date".into()))?;

    if date > today {
        return Err(ApiError::BadRequest(
            "date of birth cannot be in the future".into(),
        ));
    }

    if age_on(date, today) < MIN_AGE_YEARS {
        return Err(ApiError::BadRequest(format!(
            "you must be at least {MIN_AGE_YEARS} to open an account"
        )));
    }

    Ok(date)
}

/// Completed years between two dates.
fn age_on(birth: NaiveDate, today: NaiveDate) -> i32 {
    let mut years = today.year() - birth.year();

    // Not yet had this year's birthday.
    if (today.month(), today.day()) < (birth.month(), birth.day()) {
        years -= 1;
    }

    years
}

#[cfg(test)]
mod tests {
    use super::*;

    fn today() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 8, 28).unwrap()
    }

    #[test]
    fn names_are_trimmed_and_required() {
        assert_eq!(
            required_name("  Aurelio  ", "first name").unwrap(),
            "Aurelio"
        );
        assert!(required_name("   ", "first name").is_err());
        assert!(required_name(&"a".repeat(81), "first name").is_err());
    }

    #[test]
    fn emails_are_lowercased_and_trimmed() {
        assert_eq!(
            normalize_email("  Person@Example.COM ").unwrap(),
            "person@example.com"
        );
        assert!(normalize_email("not-an-email").is_err());
        assert!(normalize_email("").is_err());
    }

    #[test]
    fn an_adult_date_of_birth_is_accepted() {
        assert!(parse_date_of_birth("1991-05-02", today()).is_ok());
    }

    #[test]
    fn someone_under_the_minimum_age_is_refused() {
        // Turns 18 tomorrow.
        assert!(parse_date_of_birth("2008-08-29", today()).is_err());
    }

    #[test]
    fn the_eighteenth_birthday_itself_counts() {
        // A boundary that an off-by-one would get wrong in the direction of
        // wrongly refusing a legitimate customer.
        assert!(parse_date_of_birth("2008-08-28", today()).is_ok());
    }

    #[test]
    fn a_future_date_of_birth_is_refused() {
        assert!(parse_date_of_birth("2030-01-01", today()).is_err());
    }

    #[test]
    fn a_malformed_date_is_refused() {
        assert!(parse_date_of_birth("not-a-date", today()).is_err());
        assert!(parse_date_of_birth("28/08/1991", today()).is_err());
        assert!(parse_date_of_birth("1991-13-45", today()).is_err());
    }

    #[test]
    fn age_handles_the_day_before_and_after_a_birthday() {
        let birth = NaiveDate::from_ymd_opt(2000, 6, 15).unwrap();

        assert_eq!(
            age_on(birth, NaiveDate::from_ymd_opt(2026, 6, 14).unwrap()),
            25
        );
        assert_eq!(
            age_on(birth, NaiveDate::from_ymd_opt(2026, 6, 15).unwrap()),
            26
        );
        assert_eq!(
            age_on(birth, NaiveDate::from_ymd_opt(2026, 6, 16).unwrap()),
            26
        );
    }

    #[test]
    fn age_handles_a_leap_day_birth() {
        let birth = NaiveDate::from_ymd_opt(2004, 2, 29).unwrap();

        // In a non-leap year the birthday effectively falls on 1 March.
        assert_eq!(
            age_on(birth, NaiveDate::from_ymd_opt(2026, 2, 28).unwrap()),
            21
        );
        assert_eq!(
            age_on(birth, NaiveDate::from_ymd_opt(2026, 3, 1).unwrap()),
            22
        );
    }

    #[test]
    fn a_verification_token_is_long_random_and_stored_only_as_a_hash() {
        let (first, first_hash) = new_verification_token();
        let (second, _) = new_verification_token();

        assert_eq!(first.len(), 48);
        assert_ne!(first, second);
        assert_ne!(first_hash, first, "the stored value must not be the token");
        assert_eq!(first_hash.len(), 64, "sha-256 hex");
    }

    #[test]
    fn hashing_a_token_is_deterministic() {
        // The confirmation link has to match what was stored at signup.
        assert_eq!(hash_token("abc"), hash_token("abc"));
        assert_ne!(hash_token("abc"), hash_token("abd"));
    }
}
