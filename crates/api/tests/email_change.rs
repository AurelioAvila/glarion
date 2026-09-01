//! Integration tests for changing the address on an account.
//!
//! Changing an email is an account takeover with the serial numbers filed
//! off: whoever controls the address on the account controls every future
//! password reset. Four things carry that weight here, and each is easy to
//! leave out without anything looking broken:
//!
//!   * the password is required, because a stolen session already has the
//!     token and needs no help;
//!   * the address being left behind is warned while the move can still be
//!     stopped — that warning is the whole protection;
//!   * nothing moves until the new address proves it can receive;
//!   * sessions die when it does, which is what removes the intruder if the
//!     move was theirs.
//!
//! Same infrastructure as the other suites: requires `TEST_DATABASE_URL`,
//! skips rather than fails without it.

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::net::SocketAddr;
use tower::ServiceExt;
use uuid::Uuid;

use api::auth::issue_token;
use api::state::AppState;

const JWT_SECRET: &str = "integration-test-secret-long-enough-for-hs256";
const PASSWORD: &str = "a-sufficiently-long-password";

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

async fn send_from(app: &axum::Router, ip: [u8; 4], mut req: Request<Body>) -> (StatusCode, Value) {
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ip, 51234))));
    let response = app.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
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

/// Registers, confirms, signs in. Returns a live bearer session.
async fn signed_in(app: &axum::Router, pool: &PgPool, email: &str) -> String {
    let (status, body) = send(
        app,
        post(
            "/api/auth/signup",
            None,
            json!({
                "first_name": "Test", "last_name": "Person",
                "date_of_birth": "1990-01-01", "email": email,
                "password": PASSWORD, "password_confirmation": PASSWORD,
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
            json!({ "email": email, "password": PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login failed: {body}");

    let user_id = Uuid::parse_str(body["user_id"].as_str().unwrap()).unwrap();
    let version: i32 = sqlx::query_scalar("select token_version from users where id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap();
    issue_token(JWT_SECRET, user_id, version).unwrap()
}

/// Substitutes a token of the test's choosing for the one that was mailed.
///
/// The plaintext only ever exists in the email, by design, so a test cannot
/// read back the issued one and should not be able to. The endpoint under
/// test never learns the difference: it only compares hashes. The assertion
/// still proves a link was issued at all, which is the part worth checking.
async fn change_token_for(pool: &PgPool, email: &str) -> String {
    let token = "integration-test-email-change-token-0000000000";
    let hash = format!("{:x}", <sha2::Sha256 as sha2::Digest>::digest(token));
    let updated = sqlx::query(
        "update users set email_change_token_hash = $2
         where email = $1 and email_change_token_hash is not null",
    )
    .bind(email)
    .bind(&hash)
    .execute(pool)
    .await
    .unwrap();
    assert_eq!(
        updated.rows_affected(),
        1,
        "no change-of-address link was issued for {email}"
    );
    token.to_string()
}

#[tokio::test]
async fn a_confirmed_change_moves_the_account_and_ends_every_session() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());
    let old = "moving@example.com";
    let new = "moved@example.com";

    let session = signed_in(&app, &pool, old).await;
    let (status, _) = send(&app, get("/api/targets", &session)).await;
    assert_eq!(status, StatusCode::OK, "the session should start out valid");

    let (status, body) = send(
        &app,
        post(
            "/api/account/email",
            Some(&session),
            json!({ "new_email": new, "password": PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "request failed: {body}");

    // Nothing has moved yet: the account still answers to the old address.
    let pending: Option<String> =
        sqlx::query_scalar("select pending_email from users where email = $1")
            .bind(old)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(pending.as_deref(), Some(new), "the move should be pending");

    let token = change_token_for(&pool, old).await;
    let (status, body) = send(
        &app,
        post(
            "/api/auth/confirm-email-change",
            None,
            json!({ "token": token }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "confirm failed: {body}");

    // The account is now the new address, and the pending state is cleared.
    let row: Option<(String, Option<String>)> =
        sqlx::query_as("select email, pending_email from users where email = $1")
            .bind(new)
            .fetch_optional(&pool)
            .await
            .unwrap();
    let (email, pending) = row.expect("the account should now be the new address");
    assert_eq!(email, new);
    assert_eq!(pending, None);

    // And the session that made the request is gone. If the move was made by
    // somebody who should not have been signed in, this is what removes them.
    let (status, _) = send(&app, get("/api/targets", &session)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a session from before the move must not survive it"
    );

    // The new address signs in; the old one no longer exists.
    let (status, _) = send_from(
        &app,
        [203, 0, 113, 11],
        post(
            "/api/auth/login",
            None,
            json!({ "email": new, "password": PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send_from(
        &app,
        [203, 0, 113, 12],
        post(
            "/api/auth/login",
            None,
            json!({ "email": old, "password": PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_stolen_session_cannot_move_the_account_without_the_password() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());
    let owner = "owner@example.com";

    let session = signed_in(&app, &pool, owner).await;

    let (status, _) = send(
        &app,
        post(
            "/api/account/email",
            Some(&session),
            json!({ "new_email": "thief@example.com", "password": "not-the-password" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // And nothing was written, so no mail could have gone anywhere either.
    let pending: Option<String> =
        sqlx::query_scalar("select pending_email from users where email = $1")
            .bind(owner)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        pending, None,
        "a rejected request must leave no pending move"
    );
}

#[tokio::test]
async fn the_link_works_once() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());
    let old = "once@example.com";

    let session = signed_in(&app, &pool, old).await;
    send(
        &app,
        post(
            "/api/account/email",
            Some(&session),
            json!({ "new_email": "once-moved@example.com", "password": PASSWORD }),
        ),
    )
    .await;
    let token = change_token_for(&pool, old).await;
    let body = json!({ "token": token });

    let (status, _) = send(
        &app,
        post("/api/auth/confirm-email-change", None, body.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // A link that keeps working is a key to the account sitting in a mailbox.
    let (status, _) = send(&app, post("/api/auth/confirm-email-change", None, body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn an_expired_link_leaves_the_account_where_it_was() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());
    let old = "stale@example.com";

    let session = signed_in(&app, &pool, old).await;
    send(
        &app,
        post(
            "/api/account/email",
            Some(&session),
            json!({ "new_email": "stale-moved@example.com", "password": PASSWORD }),
        ),
    )
    .await;
    let token = change_token_for(&pool, old).await;

    sqlx::query(
        "update users set email_change_sent_at = now() - interval '2 hours' where email = $1",
    )
    .bind(old)
    .execute(&pool)
    .await
    .unwrap();

    let (status, _) = send(
        &app,
        post(
            "/api/auth/confirm-email-change",
            None,
            json!({ "token": token }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let still: Option<Uuid> = sqlx::query_scalar("select id from users where email = $1")
        .bind(old)
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert!(
        still.is_some(),
        "the account must still answer to its address"
    );
}

#[tokio::test]
async fn a_taken_address_is_refused_without_saying_so() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());

    signed_in(&app, &pool, "occupied@example.com").await;
    let session = signed_in(&app, &pool, "mover@example.com").await;

    let (taken_status, taken_body) = send(
        &app,
        post(
            "/api/account/email",
            Some(&session),
            json!({ "new_email": "occupied@example.com", "password": PASSWORD }),
        ),
    )
    .await;
    let (free_status, free_body) = send(
        &app,
        post(
            "/api/account/email",
            Some(&session),
            json!({ "new_email": "nobody@example.com", "password": PASSWORD }),
        ),
    )
    .await;

    // Identical answers. Otherwise one account becomes an oracle for
    // enumerating every other — which, on a product sold to agencies, is a
    // list of who a competitor's customers are.
    assert_eq!(taken_status, free_status);
    assert_eq!(taken_body, free_body);
}

#[tokio::test]
async fn a_taken_address_is_never_written_as_pending() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());

    signed_in(&app, &pool, "held@example.com").await;
    let session = signed_in(&app, &pool, "hopeful@example.com").await;

    send(
        &app,
        post(
            "/api/account/email",
            Some(&session),
            json!({ "new_email": "held@example.com", "password": PASSWORD }),
        ),
    )
    .await;

    // No pending move, so no confirmation link could have been mailed to the
    // address either — a request aimed at somebody else cannot generate mail
    // to them.
    let pending: Option<String> =
        sqlx::query_scalar("select pending_email from users where email = $1")
            .bind("hopeful@example.com")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(pending, None);
}

#[tokio::test]
async fn moving_to_the_address_you_already_have_is_refused() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());
    let email = "same@example.com";
    let session = signed_in(&app, &pool, email).await;

    let (status, _) = send(
        &app,
        post(
            "/api/account/email",
            Some(&session),
            json!({ "new_email": email, "password": PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn an_address_claimed_while_the_link_was_in_flight_does_not_collide() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());
    let old = "racer@example.com";
    let contested = "contested@example.com";

    let session = signed_in(&app, &pool, old).await;
    send(
        &app,
        post(
            "/api/account/email",
            Some(&session),
            json!({ "new_email": contested, "password": PASSWORD }),
        ),
    )
    .await;
    let token = change_token_for(&pool, old).await;

    // Somebody registers it in the meantime. Without the guard in the update
    // this surfaces as a unique-constraint violation and a 500.
    signed_in(&app, &pool, contested).await;

    let (status, _) = send(
        &app,
        post(
            "/api/auth/confirm-email-change",
            None,
            json!({ "token": token }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a lost race is a refusal, not a crash"
    );

    let still: Option<Uuid> = sqlx::query_scalar("select id from users where email = $1")
        .bind(old)
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert!(still.is_some(), "the mover keeps the address it had");
}

#[tokio::test]
async fn an_invented_token_changes_nothing() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());

    let (status, _) = send(
        &app,
        post(
            "/api/auth/confirm-email-change",
            None,
            json!({ "token": "not-a-token-anyone-ever-issued" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn signing_out_is_not_enough_to_move_an_account() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());

    let (status, _) = send(
        &app,
        post(
            "/api/account/email",
            None,
            json!({ "new_email": "anywhere@example.com", "password": PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
