//! Registration, email confirmation, and sign-in.

use axum::extract::{ConnectInfo, State};
use axum::http::{header::SET_COOKIE, HeaderMap, HeaderValue, StatusCode};
use axum::Json;
use chrono::{DateTime, Datelike, Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::OnceLock;
use uuid::Uuid;

use crate::auth::{hash_password, issue_token, verify_password, AuthUser};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use orchestrator::mailer::{
    email_change_alert, email_change_confirmation, password_changed_email, password_reset_email,
    verification_email, welcome_email,
};

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

/// How long a password-reset link stays usable.
///
/// Much shorter than the 24 hours a confirmation link gets, and on purpose: a
/// confirmation link can only prove an address, while a reset link *is* the
/// account for as long as it lives. An hour is enough to read an email and
/// act on it, and short enough that a link left sitting in a mailbox that is
/// later compromised is usually already dead.
const RESET_VALID_MINUTES: i64 = 60;

/// How long before another reset email may be requested for the same account.
const RESET_COOLDOWN_MINUTES: i64 = 2;

/// How long a change-of-address link stays usable.
///
/// Same hour a reset link gets, and for the same reason: while it lives, it
/// is the account. A confirmation link only proves an address; this one moves
/// where every future reset link will be sent.
const EMAIL_CHANGE_VALID_MINUTES: i64 = 60;

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
pub struct SessionResponse {
    pub user_id: Uuid,
}

#[derive(Serialize)]
pub struct SignupResponse {
    /// No token: the account cannot be used until the address is confirmed,
    /// so returning a session here would contradict that.
    pub email: String,
    pub message: String,
    /// Whether the confirmation message actually left. Signup still succeeds
    /// when it did not — the account exists — but telling someone to check an
    /// inbox nothing was sent to is how a broken mail path stays invisible
    /// while every new account silently fails to confirm.
    pub delivered: bool,
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub token: String,
}

#[derive(Deserialize)]
pub struct ResendRequest {
    pub email: String,
}

#[derive(Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
}

#[derive(Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub password: String,
    pub password_confirmation: String,
}

#[derive(Serialize)]
pub struct MessageResponse {
    pub message: String,
}

fn session_header(state: &AppState, token: &str) -> ApiResult<HeaderMap> {
    let value = session_cookie_value(&state.mailer.public_url, token);
    let mut headers = HeaderMap::new();
    headers.insert(
        SET_COOKIE,
        HeaderValue::from_str(&value).map_err(|_| ApiError::Unauthorized)?,
    );
    Ok(headers)
}

fn session_cookie_value(public_url: &str, token: &str) -> String {
    let secure = if public_url.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    format!("glarion_session={token}; Path=/; Max-Age=43200; HttpOnly; SameSite=Strict{secure}")
}

fn clear_session_cookie_value(public_url: &str) -> String {
    let secure = if public_url.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    format!("glarion_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict{secure}")
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
    if !state
        .auth_limiter
        .check_shared(&state.pool, "auth", peer.ip())
        .await
    {
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
        return Ok(Json(signup_answer(&state, email)));
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

    Ok(Json(signup_answer(&state, email)))
}

/// The one answer signup gives, whichever branch produced it.
///
/// Built in a single place on purpose: a new address and an address already
/// registered must be indistinguishable, or signup becomes a way to test who
/// has an account. `delivered` therefore reports the mailer's state, which is
/// the same for both, and never this recipient's own result.
fn signup_answer(state: &AppState, email: String) -> SignupResponse {
    let delivered = state.mailer.last_send_ok();

    SignupResponse {
        email,
        message: if delivered {
            "Check your email to confirm your address.".into()
        } else {
            "Your account exists, but the confirmation email could not be sent.              Try the resend link in a few minutes, or use the contact address on glarion.app."
                .into()
        },
        delivered,
    }
}

/// Sends the confirmation message, logging rather than failing on error.
///
/// Never fails signup: the account already exists at this point, so returning
/// an error would tell the user signup failed when it did not, and leave them
/// unable to retry because the address is now taken. Whether it arrived is
/// reported through `signup_answer`, from the mailer's own state.
async fn send_verification(state: &AppState, email: &str, first_name: &str, token: &str) -> bool {
    let link = state.mailer.verification_link(token);
    let message = verification_email(first_name, &link);

    match state.mailer.send(email, &message).await {
        Ok(()) => true,
        Err(error) => {
            tracing::error!(error = ?error, "could not send the confirmation email");
            false
        }
    }
}

/// Sent once the address is confirmed, never before.
///
/// Best-effort, for the same reason the confirmation itself is: the account
/// is already usable by the time this runs, so a mail provider having a bad
/// minute must not turn a successful confirmation into an error the person
/// would read as "it did not work".
async fn send_welcome(state: &AppState, email: &str, first_name: &str) {
    let message = welcome_email(first_name, &state.mailer.app_link("/targets"));

    if let Err(error) = state.mailer.send(email, &message).await {
        tracing::warn!(error = ?error, "could not send the welcome email");
    }
}

pub async fn verify_email(
    State(state): State<AppState>,
    Json(body): Json<VerifyRequest>,
) -> ApiResult<(HeaderMap, Json<SessionResponse>)> {
    let token_hash = hash_token(body.token.trim());
    let cutoff = Utc::now() - Duration::hours(VERIFICATION_VALID_HOURS);

    // Clearing the hash in the same statement makes the link single-use:
    // a second request finds no row rather than succeeding again.
    let row: Option<(Uuid, i32, String, String)> = sqlx::query_as(
        "update users
         set email_verified_at = coalesce(email_verified_at, now()),
             verification_token_hash = null
         where verification_token_hash = $1 and verification_sent_at > $2
         returning id, token_version, email, coalesce(first_name, '')",
    )
    .bind(&token_hash)
    .bind(cutoff)
    .fetch_optional(&state.pool)
    .await?;

    let (user_id, token_version, email, first_name) = row.ok_or_else(|| {
        ApiError::BadRequest("This confirmation link is no longer valid. Request a new one.".into())
    })?;

    // Exactly once per account, without needing a column to remember it: the
    // statement above only matches a row that still holds this token hash and
    // clears it in the same breath, and resend_verification refuses to issue
    // a new token to an address that is already confirmed. So there is no
    // second path back through here for an account that has been welcomed.
    send_welcome(&state, &email, &first_name).await;

    // Signing in here saves the user a round trip through the sign-in form
    // immediately after proving they control the address.
    let token = issue_token(&state.jwt_secret, user_id, token_version)?;
    Ok((
        session_header(&state, &token)?,
        Json(SessionResponse { user_id }),
    ))
}

pub async fn resend_verification(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<ResendRequest>,
) -> ApiResult<Json<MessageResponse>> {
    if !state
        .auth_limiter
        .check_shared(&state.pool, "auth", peer.ip())
        .await
    {
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
) -> ApiResult<(HeaderMap, Json<SessionResponse>)> {
    // Checked before anything else: an attacker must not be able to spend
    // our Argon2 cycles, or learn anything from the response, once they are
    // over the limit.
    if !state
        .auth_limiter
        .check_shared(&state.pool, "auth", peer.ip())
        .await
    {
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
    Ok((
        session_header(&state, &token)?,
        Json(SessionResponse { user_id }),
    ))
}

pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<(HeaderMap, StatusCode)> {
    if headers
        .get("x-glarion-csrf")
        .and_then(|value| value.to_str().ok())
        != Some("1")
    {
        return Err(ApiError::Unauthorized);
    }

    let mut headers = HeaderMap::new();
    headers.insert(
        SET_COOKIE,
        HeaderValue::from_str(&clear_session_cookie_value(&state.mailer.public_url))
            .map_err(|_| ApiError::Unauthorized)?,
    );
    Ok((headers, StatusCode::NO_CONTENT))
}

/// Starts a password reset.
///
/// Answers identically whether or not the address has an account, whether or
/// not it is confirmed, and whether or not anything was actually sent. The
/// sign-in endpoint goes to real trouble not to leak which addresses are
/// registered — including hashing against a decoy so the *timing* does not
/// leak it either — and an honest "no account with that email" here would
/// give away for free exactly what that protects.
pub async fn forgot_password(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<ForgotPasswordRequest>,
) -> ApiResult<Json<MessageResponse>> {
    if !state.auth_limiter.check(peer.ip()) {
        return Err(ApiError::TooManyRequests);
    }

    let email = normalize_email(&body.email)?;

    let answer = Ok(Json(MessageResponse {
        message: "If that address has an account, a reset link is on its way.".into(),
    }));

    let row: Option<(Uuid, Option<String>, Option<DateTime<Utc>>)> =
        sqlx::query_as("select id, first_name, password_reset_sent_at from users where email = $1")
            .bind(&email)
            .fetch_optional(&state.pool)
            .await?;

    let Some((user_id, first_name, sent_at)) = row else {
        return answer;
    };

    // Per-account cooldown on top of the per-IP limiter. Without it, one
    // address can be mail-bombed from a rotating set of IPs, each of which
    // stays comfortably inside its own budget.
    if let Some(sent_at) = sent_at {
        if Utc::now() - sent_at < Duration::minutes(RESET_COOLDOWN_MINUTES) {
            return answer;
        }
    }

    let (token, token_hash) = new_verification_token();
    sqlx::query(
        "update users
         set password_reset_token_hash = $2, password_reset_sent_at = now()
         where id = $1",
    )
    .bind(user_id)
    .bind(&token_hash)
    .execute(&state.pool)
    .await?;

    let link = state.mailer.reset_link(&token);
    let message = password_reset_email(
        first_name.as_deref().unwrap_or(""),
        &link,
        RESET_VALID_MINUTES,
    );
    if let Err(error) = state.mailer.send(&email, &message).await {
        // Logged rather than surfaced. The caller cannot act on our mail
        // provider having a bad minute, and an error here that the "if that
        // address has an account" path does not also produce would tell an
        // attacker the address exists.
        tracing::error!(error = ?error, "could not send the password reset email");
    }

    answer
}

/// Finishes a password reset.
///
/// Three things happen together and none of them is optional:
///   * the token is consumed in the same statement that reads it, so a
///     replay finds no row rather than succeeding twice;
///   * `token_version` is bumped, which invalidates every session that
///     already exists — the point of a reset is to take an account back from
///     somebody, and leaving their session alive would defeat it entirely;
///   * the address is marked confirmed if it was not, because receiving this
///     link proves control of the inbox exactly as the confirmation link
///     does, and refusing afterwards would leave an account that can neither
///     sign in nor be recovered.
pub async fn reset_password(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<ResetPasswordRequest>,
) -> ApiResult<(HeaderMap, Json<SessionResponse>)> {
    if !state.auth_limiter.check(peer.ip()) {
        return Err(ApiError::TooManyRequests);
    }

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

    let token_hash = hash_token(body.token.trim());
    let cutoff = Utc::now() - Duration::minutes(RESET_VALID_MINUTES);
    let password_hash = hash_password(&body.password)?;

    let row: Option<(Uuid, i32, String, Option<String>)> = sqlx::query_as(
        "update users
         set password_hash = $3,
             password_reset_token_hash = null,
             password_reset_sent_at = null,
             email_verified_at = coalesce(email_verified_at, now()),
             token_version = token_version + 1
         where password_reset_token_hash = $1 and password_reset_sent_at > $2
         returning id, token_version, email, first_name",
    )
    .bind(&token_hash)
    .bind(cutoff)
    .bind(&password_hash)
    .fetch_optional(&state.pool)
    .await?;

    let (user_id, token_version, email, first_name) = row.ok_or_else(|| {
        ApiError::BadRequest("This reset link is no longer valid. Request a new one.".into())
    })?;

    // Best-effort, after the fact: the password has already changed, and
    // failing the request now would tell someone their reset did not work
    // when it did — leaving them with a password they do not know they have.
    let notice = password_changed_email(first_name.as_deref().unwrap_or(""));
    if let Err(error) = state.mailer.send(&email, &notice).await {
        tracing::warn!(error = ?error, "could not send the password-changed notice");
    }

    // Signed in immediately, like confirmation is: they have just proved
    // control of the address and set the password, so asking for it back on
    // a sign-in form adds a step and proves nothing further. The session goes
    // into the same httpOnly cookie every other entry point sets — a reset
    // that handed the token back in the body would be the one path where a
    // session lands somewhere script can read it.
    let token = issue_token(&state.jwt_secret, user_id, token_version)?;
    Ok((
        session_header(&state, &token)?,
        Json(SessionResponse { user_id }),
    ))
}

#[derive(Deserialize)]
pub struct ChangeEmailRequest {
    pub new_email: String,
    /// Re-proves the account holder, exactly as deleting does. The bearer
    /// token is the one thing a stolen session already has; an action that
    /// hands the account to a different mailbox needs the one thing it would
    /// not also have.
    pub password: String,
}

#[derive(Deserialize)]
pub struct ConfirmEmailChangeRequest {
    pub token: String,
}

/// Starts a change of address.
///
/// Two messages go out, and the second is what makes this safe to offer at
/// all. A stolen session plus a change of address is a complete takeover —
/// the thief redirects every future reset link to themselves — so the
/// address currently on the account is told while the move can still be
/// stopped. The confirmation link goes only to the new address, because the
/// single question it settles is whether mail can be received there.
///
/// The answer is the same whether or not the requested address is already
/// registered. Saying "that email is taken" would turn a signed-in account
/// into an oracle for enumerating every other one — which, for a product
/// sold to agencies, is a list of who their competitors' customers are.
pub async fn change_email(
    State(state): State<AppState>,
    user: AuthUser,
    Json(body): Json<ChangeEmailRequest>,
) -> ApiResult<Json<MessageResponse>> {
    let new_email = normalize_email(&body.new_email)?;

    let row: Option<(String, String, Option<String>)> =
        sqlx::query_as("select email, password_hash, first_name from users where id = $1")
            .bind(user.id)
            .fetch_optional(&state.pool)
            .await?;
    let Some((current_email, password_hash, first_name)) = row else {
        return Err(ApiError::Unauthorized);
    };

    if !verify_password(&body.password, &password_hash) {
        return Err(ApiError::InvalidCredentials);
    }

    if new_email == current_email {
        return Err(ApiError::BadRequest(
            "that is already the address on this account".into(),
        ));
    }

    let answer = Ok(Json(MessageResponse {
        message: "If that address can be used, a link to confirm it is on its way.".into(),
    }));

    // Taken addresses stop here, after the same work and with the same
    // answer. Nothing is written and no link is issued, so a request aimed at
    // somebody else's address cannot even generate mail to them.
    let taken: Option<Uuid> = sqlx::query_scalar("select id from users where email = $1")
        .bind(&new_email)
        .fetch_optional(&state.pool)
        .await?;
    if taken.is_some() {
        return answer;
    }

    let (token, token_hash) = new_verification_token();
    sqlx::query(
        "update users
         set pending_email = $2, email_change_token_hash = $3, email_change_sent_at = now()
         where id = $1",
    )
    .bind(user.id)
    .bind(&new_email)
    .bind(&token_hash)
    .execute(&state.pool)
    .await?;

    let link = state.mailer.app_link(&format!("/confirm-email/{token}"));
    let confirmation = email_change_confirmation(
        first_name.as_deref().unwrap_or(""),
        &link,
        EMAIL_CHANGE_VALID_MINUTES,
    );
    if let Err(error) = state.mailer.send(&new_email, &confirmation).await {
        tracing::error!(error = ?error, "could not send the change-of-address confirmation");
    }

    // To the address being left behind, always, and even if the one above
    // failed: being told is the whole protection.
    let alert = email_change_alert(first_name.as_deref().unwrap_or(""), &new_email);
    if let Err(error) = state.mailer.send(&current_email, &alert).await {
        tracing::warn!(error = ?error, "could not warn the old address of a change");
    }

    answer
}

/// Finishes a change of address.
///
/// Unauthenticated by necessity — the link is followed from whatever mailbox
/// received it, which by design is not where the session is. The token is the
/// authorization, and it is consumed in the statement that reads it so a
/// second request finds no row.
///
/// `token_version` is bumped, which signs out everything. That is not tidiness:
/// if this move was made by somebody who should not have been signed in, the
/// bump is what removes them, and the person who confirmed from the new
/// mailbox is the one who signs back in.
pub async fn confirm_email_change(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<ConfirmEmailChangeRequest>,
) -> ApiResult<Json<MessageResponse>> {
    if !state.auth_limiter.check(peer.ip()) {
        return Err(ApiError::TooManyRequests);
    }

    let token_hash = hash_token(body.token.trim());
    let cutoff = Utc::now() - Duration::minutes(EMAIL_CHANGE_VALID_MINUTES);

    // `where not exists` rather than a check beforehand: between a check and
    // an update, the address could be registered by somebody else, and the
    // unique constraint would surface as a 500 instead of a refusal.
    let changed: Option<(Uuid,)> = sqlx::query_as(
        "update users
         set email = pending_email,
             pending_email = null,
             email_change_token_hash = null,
             email_change_sent_at = null,
             email_verified_at = coalesce(email_verified_at, now()),
             token_version = token_version + 1
         where email_change_token_hash = $1
           and email_change_sent_at > $2
           and pending_email is not null
           and not exists (select 1 from users other where other.email = users.pending_email)
         returning id",
    )
    .bind(&token_hash)
    .bind(cutoff)
    .fetch_optional(&state.pool)
    .await?;

    if changed.is_none() {
        return Err(ApiError::BadRequest(
            "This link is no longer valid. Request the change again from your account.".into(),
        ));
    }

    Ok(Json(MessageResponse {
        message: "Your address has been changed. Sign in again with the new one.".into(),
    }))
}

#[derive(Deserialize)]
pub struct DeleteAccountRequest {
    pub password: String,
}

/// Erases the account's personal data. Does not delete the row.
///
/// The row cannot be deleted outright: `scan_authorizations` references
/// `users` without `on delete cascade`, deliberately — it is the
/// immutable record of who authorized a scan against a domain, which is
/// the legal basis the whole product's ownership gate rests on (see the
/// module comment on `crate::routes::scans`). Destroying it on request
/// would remove the one thing that could show a scan was authorised if
/// its target ever disputed one, which is precisely the record GDPR
/// Article 17(3)(e) allows a controller to keep — establishment or
/// defence of legal claims.
///
/// So this satisfies the right to erasure the way that exception expects:
/// every field that identifies *this person* is overwritten, and the row
/// stays only as the anchor those authorization records point to. `id`
/// is never reused, so there is nothing to link the anonymised row back
/// to the person who held it.
pub async fn delete_account(
    State(state): State<AppState>,
    user: AuthUser,
    Json(body): Json<DeleteAccountRequest>,
) -> ApiResult<Json<MessageResponse>> {
    let password_hash: Option<String> =
        sqlx::query_scalar("select password_hash from users where id = $1")
            .bind(user.id)
            .fetch_optional(&state.pool)
            .await?;

    let Some(password_hash) = password_hash else {
        return Err(ApiError::Unauthorized);
    };

    // Re-proves the password rather than trusting the bearer token alone.
    // The token is exactly what a stolen session already has; an
    // irreversible action needs the one thing it would not also have.
    if !verify_password(&body.password, &password_hash) {
        return Err(ApiError::InvalidCredentials);
    }

    // A live subscription has to end at Stripe first. Cancelling it here
    // as a side effect of deletion would be a second, undocumented way to
    // cancel — see `routes::billing::open_portal` for why that path is
    // deliberately just the one, through Stripe's own portal.
    let status: Option<String> = sqlx::query_scalar(
        "select subscription_status from entitlements where user_id = $1 and product = 'glarion'",
    )
    .bind(user.id)
    .fetch_optional(&state.pool)
    .await?
    .flatten();

    if status
        .as_deref()
        .is_some_and(crate::billing::status_grants_access)
    {
        return Err(ApiError::BadRequest(
            "Cancel your subscription from Manage billing before deleting your account.".into(),
        ));
    }

    // A hash of nobody's password, the same way `decoy_hash` is: not left
    // null, because null would need `login` to special-case it, and not a
    // constant, because a constant is one shared secret away from being a
    // password.
    let unusable_hash = hash_password(&Uuid::new_v4().to_string())?;
    let placeholder_email = format!("deleted-{}@deleted.invalid", user.id);

    sqlx::query(
        "update users
         set email = $2,
             password_hash = $3,
             first_name = null,
             last_name = null,
             date_of_birth = null,
             agency_name = null,
             agency_logo_url = null,
             email_verified_at = null,
             verification_token_hash = null,
             verification_sent_at = null,
             token_version = token_version + 1
         where id = $1",
    )
    .bind(user.id)
    .bind(&placeholder_email)
    .bind(&unusable_hash)
    .execute(&state.pool)
    .await?;

    // No legal-retention reason to keep this once the account cannot sign
    // in: it is billing state for a subscription that, by this point, does
    // not exist.
    sqlx::query("delete from entitlements where user_id = $1 and product = 'glarion'")
        .bind(user.id)
        .execute(&state.pool)
        .await?;

    Ok(Json(MessageResponse {
        message: "Your account has been deleted.".into(),
    }))
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
    fn production_session_cookie_is_http_only_secure_and_strict() {
        let value = session_cookie_value("https://glarion.example", "token");
        assert!(value.contains("HttpOnly"));
        assert!(value.contains("Secure"));
        assert!(value.contains("SameSite=Strict"));
        assert!(value.contains("Max-Age=43200"));
    }

    #[test]
    fn local_logout_clears_the_same_cookie_without_forcing_secure() {
        assert_eq!(
            clear_session_cookie_value("http://localhost:8080"),
            "glarion_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"
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
