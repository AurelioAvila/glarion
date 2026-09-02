//! Integration tests for changing the password from inside the account.
//!
//! Three things carry the weight here, and each one is easy to leave out
//! without anything looking broken:
//!
//!   * the current password is required, because a stolen session already
//!     holds the only other credential involved;
//!   * every session dies when the password changes — that is usually the
//!     entire reason somebody is changing it;
//!   * the new password works afterwards, and the old one does not.
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
const NEW_PASSWORD: &str = "an-even-longer-replacement-password";

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

async fn send(app: &axum::Router, mut req: Request<Body>) -> (StatusCode, Value) {
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 10], 51234))));
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

    let user_id: Uuid = sqlx::query_scalar("select id from users where email = $1")
        .bind(email)
        .fetch_one(pool)
        .await
        .unwrap();
    let version: i32 = sqlx::query_scalar("select token_version from users where id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap();
    issue_token(JWT_SECRET, user_id, version).unwrap()
}

fn change(token: &str, current: &str, next: &str) -> Request<Body> {
    post(
        "/api/account/password",
        Some(token),
        json!({
            "current_password": current,
            "new_password": next,
            "new_password_confirmation": next,
        }),
    )
}

fn get(path: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn a_change_replaces_the_password_and_ends_every_session() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());
    let token = signed_in(&app, &pool, "change@example.com").await;

    let (status, body) = send(&app, change(&token, PASSWORD, NEW_PASSWORD)).await;
    assert_eq!(status, StatusCode::OK, "change failed: {body}");

    // The session that made the change is invalidated with the rest. The
    // response carries a replacement cookie, which is what keeps that device
    // signed in — this bearer token is not it.
    let (status, _) = send(&app, get("/api/targets", &token)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "old sessions survived");

    let (status, body) = send(
        &app,
        post(
            "/api/auth/login",
            None,
            json!({ "email": "change@example.com", "password": NEW_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "new password does not work: {body}");

    let (status, _) = send(
        &app,
        post(
            "/api/auth/login",
            None,
            json!({ "email": "change@example.com", "password": PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "old password still works");
}

#[tokio::test]
async fn the_current_password_is_required() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());
    let token = signed_in(&app, &pool, "wrong@example.com").await;

    let (status, _) = send(&app, change(&token, "not-the-right-password", NEW_PASSWORD)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Nothing moved: the original password still signs in.
    let (status, body) = send(
        &app,
        post(
            "/api/auth/login",
            None,
            json!({ "email": "wrong@example.com", "password": PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the account was disturbed: {body}");
}

#[tokio::test]
async fn a_short_or_mismatched_new_password_is_refused() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());
    let token = signed_in(&app, &pool, "short@example.com").await;

    let (status, _) = send(&app, change(&token, PASSWORD, "too-short")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = send(
        &app,
        post(
            "/api/account/password",
            Some(&token),
            json!({
                "current_password": PASSWORD,
                "new_password": NEW_PASSWORD,
                "new_password_confirmation": "something-else-entirely",
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_signed_out_caller_cannot_change_anything() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());

    let (status, _) = send(
        &app,
        post(
            "/api/account/password",
            None,
            json!({
                "current_password": PASSWORD,
                "new_password": NEW_PASSWORD,
                "new_password_confirmation": NEW_PASSWORD,
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
