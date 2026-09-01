//! Integration tests for password recovery.
//!
//! Recovery is the one flow whose whole purpose is to take an account back
//! from whoever currently has it. That makes three things load-bearing, and
//! each is easy to leave out without anything looking broken:
//!
//!   * the link works once — a replayed token must not set a second password;
//!   * sessions that already exist die — otherwise the thief keeps the
//!     account and the rightful owner has only changed a string;
//!   * the endpoint says the same thing about an address that exists and one
//!     that does not — the sign-in path goes to real trouble not to leak that,
//!     including hashing against a decoy so the timing does not leak it either,
//!     and an honest answer here would give it away for free.
//!
//! Same infrastructure as `scan_gate.rs` and `account_deletion.rs`: requires
//! `TEST_DATABASE_URL`, skips rather than fails without it.

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::net::SocketAddr;
use tower::ServiceExt;
use uuid::Uuid;

use api::auth::issue_token;
use api::state::AppState;

const JWT_SECRET: &str = "integration-test-secret-long-enough-for-hs256";
const OLD_PASSWORD: &str = "a-sufficiently-long-password";
const NEW_PASSWORD: &str = "an-entirely-different-passphrase";

async fn test_pool() -> Option<PgPool> {
    let url = match std::env::var("TEST_DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            eprintln!("skipping: TEST_DATABASE_URL not set");
            return None;
        }
    };

    let pool = PgPool::connect(&url)
        .await
        .expect("could not connect to TEST_DATABASE_URL");

    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("migrations failed");

    sqlx::query("truncate users, targets, target_verifications, scan_authorizations, scan_jobs, entitlements, rate_limit_buckets cascade")
        .execute(&pool)
        .await
        .expect("truncate failed");

    Some(pool)
}

fn app(pool: PgPool) -> axum::Router {
    api::router(AppState::new(pool, JWT_SECRET.to_string()))
}

/// Each caller gets its own address so the per-IP limiter, which is shared
/// across the whole router, does not make one test's traffic fail the next.
async fn send_full(
    app: &axum::Router,
    ip: [u8; 4],
    mut req: Request<Body>,
) -> (StatusCode, HeaderMap, Value) {
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ip, 51234))));
    let response = app.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, headers, body)
}

async fn send_from(app: &axum::Router, ip: [u8; 4], req: Request<Body>) -> (StatusCode, Value) {
    let (status, _, body) = send_full(app, ip, req).await;
    (status, body)
}

async fn send(app: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    send_from(app, [203, 0, 113, 10], req).await
}

fn post(path: &str, token: Option<&str>, body: Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

fn get(path: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

/// Registers, confirms, and signs in. Returns a live session token.
async fn signed_in(app: &axum::Router, pool: &PgPool, email: &str) -> String {
    let (status, body) = send(
        app,
        post(
            "/api/auth/signup",
            None,
            json!({
                "first_name": "Test",
                "last_name": "Person",
                "date_of_birth": "1990-01-01",
                "email": email,
                "password": OLD_PASSWORD,
                "password_confirmation": OLD_PASSWORD,
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "signup failed: {body}");

    sqlx::query("update users set email_verified_at = now() where email = $1")
        .bind(email)
        .execute(pool)
        .await
        .unwrap();

    let (status, body) = send(
        app,
        post(
            "/api/auth/login",
            None,
            json!({ "email": email, "password": OLD_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login failed: {body}");
    assert!(
        body.get("token").is_none(),
        "session credentials must never be exposed to browser JavaScript"
    );

    // The session lives in an HttpOnly cookie, so there is no token in the
    // reply to reuse. Minting an equivalent bearer here keeps these tests
    // about recovery rather than about cookie plumbing — and it is still a
    // real session, so the token_version bump under test genuinely kills it.
    let user_id = Uuid::parse_str(body["user_id"].as_str().unwrap()).unwrap();
    let token_version: i32 = sqlx::query_scalar("select token_version from users where id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap();
    issue_token(JWT_SECRET, user_id, token_version).unwrap()
}

/// Starts a reset and returns a token the caller can present as the link's.
///
/// The plaintext token exists only in the email, by design — the database
/// holds nothing but its SHA-256 — so a test cannot read back the one that
/// was actually issued, and it should not be able to. Instead it substitutes
/// a token of its own, stored the same way the endpoint stores its own. The
/// code under test never learns the difference, because it only ever compares
/// hashes; and the assertion below still proves the endpoint issued a link at
/// all, which is the part worth checking.
async fn reset_token_for(app: &axum::Router, pool: &PgPool, email: &str) -> String {
    let (status, _) = send(
        app,
        post("/api/auth/forgot-password", None, json!({ "email": email })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let token = "integration-test-reset-token-000000000000000000";
    let hash = format!("{:x}", <sha2::Sha256 as sha2::Digest>::digest(token));
    let updated = sqlx::query(
        "update users set password_reset_token_hash = $2
         where email = $1 and password_reset_token_hash is not null",
    )
    .bind(email)
    .bind(&hash)
    .execute(pool)
    .await
    .unwrap();
    assert_eq!(
        updated.rows_affected(),
        1,
        "forgot-password did not store a reset token for {email}"
    );

    token.to_string()
}

#[tokio::test]
async fn a_reset_replaces_the_password_and_kills_every_existing_session() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());
    let email = "reset@example.com";

    let old_session = signed_in(&app, &pool, email).await;
    let (status, _) = send(&app, get("/api/targets", &old_session)).await;
    assert_eq!(status, StatusCode::OK, "the session should start out valid");

    let token = reset_token_for(&app, &pool, email).await;
    let (status, headers, body) = send_full(
        &app,
        [203, 0, 113, 10],
        post(
            "/api/auth/reset-password",
            None,
            json!({
                "token": token,
                "password": NEW_PASSWORD,
                "password_confirmation": NEW_PASSWORD,
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "reset failed: {body}");

    // Signed in, but through the same HttpOnly cookie every other entry point
    // sets. A reset that handed the token back in the body would be the one
    // path where a session lands where script can read it.
    assert!(
        body.get("token").is_none(),
        "a reset must not hand a session to browser JavaScript"
    );
    let cookie = headers
        .get(axum::http::header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("a reset signs the user in");
    assert!(cookie.contains("HttpOnly"), "cookie was {cookie:?}");

    // The whole point of a reset: whoever held the old session no longer has
    // the account. Without the token_version bump this passes silently.
    let (status, _) = send(&app, get("/api/targets", &old_session)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a session from before the reset must not survive it"
    );

    // The new password works and the old one does not.
    let (status, _) = send_from(
        &app,
        [203, 0, 113, 11],
        post(
            "/api/auth/login",
            None,
            json!({ "email": email, "password": NEW_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the new password must sign in");

    let (status, _) = send_from(
        &app,
        [203, 0, 113, 12],
        post(
            "/api/auth/login",
            None,
            json!({ "email": email, "password": OLD_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the password that was reset away must stop working"
    );
}

#[tokio::test]
async fn a_reset_link_cannot_be_used_twice() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());
    let email = "replay@example.com";

    signed_in(&app, &pool, email).await;
    let token = reset_token_for(&app, &pool, email).await;

    let body = json!({
        "token": token,
        "password": NEW_PASSWORD,
        "password_confirmation": NEW_PASSWORD,
    });

    let (status, _) = send(&app, post("/api/auth/reset-password", None, body.clone())).await;
    assert_eq!(status, StatusCode::OK);

    // A link that keeps working is a permanent skeleton key sitting in an
    // inbox: anyone who later reads that mailbox owns the account.
    let (status, _) = send(&app, post("/api/auth/reset-password", None, body)).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the same link must not set a second password"
    );
}

#[tokio::test]
async fn an_expired_link_is_refused() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());
    let email = "stale@example.com";

    signed_in(&app, &pool, email).await;
    let token = reset_token_for(&app, &pool, email).await;

    sqlx::query(
        "update users set password_reset_sent_at = now() - interval '2 hours' where email = $1",
    )
    .bind(email)
    .execute(&pool)
    .await
    .unwrap();

    let (status, _) = send(
        &app,
        post(
            "/api/auth/reset-password",
            None,
            json!({
                "token": token,
                "password": NEW_PASSWORD,
                "password_confirmation": NEW_PASSWORD,
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // And the old password still works, rather than the account being left in
    // some half-reset state.
    let (status, _) = send_from(
        &app,
        [203, 0, 113, 13],
        post(
            "/api/auth/login",
            None,
            json!({ "email": email, "password": OLD_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn forgot_password_does_not_reveal_whether_an_address_is_registered() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());
    let email = "known@example.com";

    signed_in(&app, &pool, email).await;

    let (known_status, known_body) = send_from(
        &app,
        [203, 0, 113, 20],
        post("/api/auth/forgot-password", None, json!({ "email": email })),
    )
    .await;
    let (unknown_status, unknown_body) = send_from(
        &app,
        [203, 0, 113, 21],
        post(
            "/api/auth/forgot-password",
            None,
            json!({ "email": "nobody@example.com" }),
        ),
    )
    .await;

    assert_eq!(known_status, unknown_status);
    assert_eq!(
        known_body, unknown_body,
        "the answer must not differ between a registered address and an unknown one"
    );

    // And nothing was written for the address that does not exist.
    let rows: i64 = sqlx::query_scalar("select count(*) from users where email = $1")
        .bind("nobody@example.com")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 0);
}

#[tokio::test]
async fn a_second_request_within_the_cooldown_does_not_reissue() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());
    let email = "cooldown@example.com";

    signed_in(&app, &pool, email).await;
    let token = reset_token_for(&app, &pool, email).await;
    let hash_of_first: String =
        sqlx::query_scalar("select password_reset_token_hash from users where email = $1")
            .bind(email)
            .fetch_one(&pool)
            .await
            .unwrap();

    // A per-IP limiter alone does not stop this: one address can be mail-
    // bombed from a rotating set of IPs, each comfortably inside its budget.
    let (status, _) = send_from(
        &app,
        [203, 0, 113, 30],
        post("/api/auth/forgot-password", None, json!({ "email": email })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the answer stays the same");

    let hash_now: String =
        sqlx::query_scalar("select password_reset_token_hash from users where email = $1")
            .bind(email)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        hash_now, hash_of_first,
        "a request inside the cooldown must not issue a second link"
    );

    // The first link is still the live one, and still works.
    let (status, _) = send(
        &app,
        post(
            "/api/auth/reset-password",
            None,
            json!({
                "token": token,
                "password": NEW_PASSWORD,
                "password_confirmation": NEW_PASSWORD,
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn a_reset_confirms_an_address_that_was_never_confirmed() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());
    let email = "unconfirmed@example.com";

    let (status, _) = send(
        &app,
        post(
            "/api/auth/signup",
            None,
            json!({
                "first_name": "Test",
                "last_name": "Person",
                "date_of_birth": "1990-01-01",
                "email": email,
                "password": OLD_PASSWORD,
                "password_confirmation": OLD_PASSWORD,
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let token = reset_token_for(&app, &pool, email).await;
    let (status, body) = send(
        &app,
        post(
            "/api/auth/reset-password",
            None,
            json!({
                "token": token,
                "password": NEW_PASSWORD,
                "password_confirmation": NEW_PASSWORD,
            }),
        ),
    )
    .await;

    // Following this link proves control of the inbox exactly as the
    // confirmation link does. Refusing afterwards would leave an account that
    // can neither sign in nor be recovered — locked out by the very flow that
    // exists to unlock it.
    assert_eq!(status, StatusCode::OK, "reset failed: {body}");
    let confirmed: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("select email_verified_at from users where email = $1")
            .bind(email)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(confirmed.is_some(), "the reset should confirm the address");
}

#[tokio::test]
async fn a_short_password_is_refused_and_changes_nothing() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());
    let email = "short@example.com";

    signed_in(&app, &pool, email).await;
    let token = reset_token_for(&app, &pool, email).await;

    let (status, _) = send(
        &app,
        post(
            "/api/auth/reset-password",
            None,
            json!({ "token": token, "password": "short", "password_confirmation": "short" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // The token must survive a rejected attempt, or a typo would burn the
    // link and send the person back to the start.
    let live: Option<String> =
        sqlx::query_scalar("select password_reset_token_hash from users where email = $1")
            .bind(email)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        live.is_some(),
        "a rejected password must not consume the link"
    );
}

#[tokio::test]
async fn mismatched_confirmation_is_refused() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());
    let email = "mismatch@example.com";

    signed_in(&app, &pool, email).await;
    let token = reset_token_for(&app, &pool, email).await;

    let (status, _) = send(
        &app,
        post(
            "/api/auth/reset-password",
            None,
            json!({
                "token": token,
                "password": NEW_PASSWORD,
                "password_confirmation": "something-else-entirely",
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn an_invented_token_is_refused() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());

    let (status, _) = send(
        &app,
        post(
            "/api/auth/reset-password",
            None,
            json!({
                "token": "not-a-token-anyone-ever-issued",
                "password": NEW_PASSWORD,
                "password_confirmation": NEW_PASSWORD,
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
