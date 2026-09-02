//! Integration tests for the scan authorization gate.
//!
//! These are the tests that matter most in this codebase: they prove that a
//! scan cannot be queued against a domain whose ownership is not currently
//! verified. The unit tests in `orchestrator::verification` prove the
//! predicate is correct; these prove the HTTP layer actually consults it.
//!
//! They require a real Postgres, addressed by `TEST_DATABASE_URL`, whose
//! tables they TRUNCATE. The usual way to run them:
//!
//!   bash scripts/dev-db.sh test
//!
//! Without that variable the tests skip rather than fail, so `cargo test`
//! stays green on a machine with no database — but CI must set it, because
//! an unexercised gate is not a verified gate.

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::net::SocketAddr;
use tower::ServiceExt;
use uuid::Uuid;

use api::auth::issue_token;
use api::state::AppState;

const JWT_SECRET: &str = "integration-test-secret-long-enough-for-hs256";

/// Returns None (and prints why) when no test database is configured.
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

    // Fresh state per test run. Cascade because everything hangs off users.
    sqlx::query("truncate users, targets, target_verifications, scan_authorizations, scan_jobs, entitlements, rate_limit_buckets cascade")
        .execute(&pool)
        .await
        .expect("truncate failed");

    Some(pool)
}

fn app(pool: PgPool) -> axum::Router {
    api::router(AppState::new(pool, JWT_SECRET.to_string()))
}

/// Sends a request with ConnectInfo populated, which the scan handler needs
/// in order to record the caller's IP in the audit trail.
async fn send(app: &axum::Router, mut req: Request<Body>) -> (StatusCode, Value) {
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 10], 51234))));

    let response = app.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

fn post(path: &str, token: Option<&str>, body: Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");

    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }

    builder.body(Body::from(body.to_string())).unwrap()
}

const TEST_PASSWORD: &str = "a-sufficiently-long-password";

/// Registers a user, confirms the address, and signs in.
///
/// Signup deliberately returns no session — the account cannot be used
/// until the emailed link is followed. Rather than intercept mail, the
/// confirmation is applied straight to the database, which keeps these
/// tests about the scan gate instead of about email delivery. The sign-in
/// afterwards is what proves confirmation actually took effect.
async fn signup(app: &axum::Router, pool: &PgPool, email: &str) -> (String, Uuid) {
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
                "password": TEST_PASSWORD,
                "password_confirmation": TEST_PASSWORD,
            }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "signup failed: {body}");

    sqlx::query("update users set email_verified_at = now() where email = $1")
        .bind(email)
        .execute(pool)
        .await
        .expect("could not confirm the test account");

    let (status, body) = send(
        app,
        post(
            "/api/auth/login",
            None,
            json!({ "email": email, "password": TEST_PASSWORD }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "login failed: {body}");
    assert!(
        body.get("token").is_none(),
        "session credentials must never be exposed to browser JavaScript"
    );
    let user_id = Uuid::parse_str(body["user_id"].as_str().unwrap()).unwrap();
    let token_version: i32 = sqlx::query_scalar("select token_version from users where id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap();
    (
        issue_token(JWT_SECRET, user_id, token_version).unwrap(),
        user_id,
    )
}

#[tokio::test]
async fn an_unconfirmed_account_cannot_sign_in() {
    // The account exists and the password is right; only the address is
    // unconfirmed. Letting this through would make the emailed link
    // decorative.
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool);

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
                "password": TEST_PASSWORD,
                "password_confirmation": TEST_PASSWORD,
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = send(
        &app,
        post(
            "/api/auth/login",
            None,
            json!({ "email": email, "password": TEST_PASSWORD }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "email_not_verified");
}

#[tokio::test]
async fn cookie_sessions_require_csrf_on_state_changing_requests() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());
    let (token, _) = signup(&app, &pool, "cookie-csrf@example.com").await;

    let request = |csrf: bool, domain: &str| {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/api/targets")
            .header("content-type", "application/json")
            .header("cookie", format!("glarion_session={token}"));
        if csrf {
            builder = builder.header("x-glarion-csrf", "1");
        }
        builder
            .body(Body::from(json!({ "domain": domain }).to_string()))
            .unwrap()
    };

    let (status, _) = send(&app, request(false, "blocked.example.com")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, body) = send(&app, request(true, "allowed.example.com")).await;
    assert_eq!(status, StatusCode::OK, "cookie request failed: {body}");
}

#[tokio::test]
async fn signup_does_not_reveal_that_an_address_is_already_registered() {
    // Otherwise signup becomes the account-enumeration oracle that the
    // sign-in endpoint is careful not to be.
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());

    let email = "taken@example.com";
    let register = || {
        post(
            "/api/auth/signup",
            None,
            json!({
                "first_name": "Test",
                "last_name": "Person",
                "date_of_birth": "1990-01-01",
                "email": email,
                "password": TEST_PASSWORD,
                "password_confirmation": TEST_PASSWORD,
            }),
        )
    };

    let (first_status, first_body) = send(&app, register()).await;
    let (second_status, second_body) = send(&app, register()).await;

    assert_eq!(first_status, second_status);
    assert_eq!(first_body, second_body);

    let accounts: i64 = sqlx::query_scalar("select count(*) from users where email = $1")
        .bind(email)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(accounts, 1, "the second attempt must not create an account");
}

async fn create_target(app: &axum::Router, token: &str, domain: &str) -> Uuid {
    let (status, body) = send(
        app,
        post("/api/targets", Some(token), json!({ "domain": domain })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "create target failed: {body}");
    Uuid::parse_str(body["id"].as_str().unwrap()).unwrap()
}

/// Writes a completed verification straight to the database, bypassing the
/// DNS lookup. The lookup itself is unit-tested; what we need here is a
/// target in the "verified" state so the gate has something to allow.
async fn insert_verification(
    pool: &PgPool,
    target_id: Uuid,
    verified_ago: Duration,
    expires_in: Duration,
) {
    let now = Utc::now();
    sqlx::query(
        "insert into target_verifications (target_id, method, token, verified_at, expires_at)
         values ($1, 'dns_txt', $2, $3, $4)",
    )
    .bind(target_id)
    .bind("test-token")
    .bind(now - verified_ago)
    .bind(now + expires_in)
    .execute(pool)
    .await
    .expect("could not insert verification");
}

#[tokio::test]
async fn scan_is_refused_when_target_was_never_verified() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());

    let (token, _) = signup(&app, &pool, "never-verified@example.com").await;
    let target_id = create_target(&app, &token, "example.com").await;

    let (status, body) = send(
        &app,
        post(
            "/api/scans",
            Some(&token),
            json!({ "target_id": target_id, "tool": "nuclei", "accept_terms": true }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "target_not_verified");
}

#[tokio::test]
async fn scan_is_refused_when_verification_has_expired() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());

    let (token, _) = signup(&app, &pool, "expired@example.com").await;
    let target_id = create_target(&app, &token, "example.com").await;

    // Verified 40 days ago, expired 10 days ago.
    insert_verification(&pool, target_id, Duration::days(40), Duration::days(-10)).await;

    let (status, body) = send(
        &app,
        post(
            "/api/scans",
            Some(&token),
            json!({ "target_id": target_id, "tool": "nuclei", "accept_terms": true }),
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an expired verification must not permit a scan"
    );
    assert_eq!(body["error"], "target_not_verified");
}

/// Puts an account on a paid plan.
///
/// The full scan is what a subscription buys, so every test that expects a
/// scan to be *allowed* has to say which plan is paying for it. Tests that
/// expect a refusal deliberately do not call this: a free account is the
/// state a new signup is already in.
async fn subscribe(pool: &PgPool, email: &str) {
    sqlx::query(
        "insert into entitlements (user_id, product, plan, max_targets, subscription_status)
         select id, 'glarion', 'studio', 10, 'active' from users where email = $1
         on conflict (user_id, product) do update
         set plan = 'studio', max_targets = 10, subscription_status = 'active'",
    )
    .bind(email)
    .execute(pool)
    .await
    .expect("could not create the entitlement");
}

#[tokio::test]
async fn scan_is_queued_when_verification_is_current() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());

    let (token, _) = signup(&app, &pool, "verified@example.com").await;
    subscribe(&pool, "verified@example.com").await;
    let target_id = create_target(&app, &token, "example.com").await;
    insert_verification(&pool, target_id, Duration::days(1), Duration::days(29)).await;

    let (status, body) = send(
        &app,
        post(
            "/api/scans",
            Some(&token),
            json!({ "target_id": target_id, "tool": "nuclei", "accept_terms": true }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "scan should be allowed: {body}");
    assert_eq!(body["status"], "queued");

    // The audit trail must exist for the queued job — a job without one
    // would mean we cannot show who authorized the scan.
    let authorized: i64 = sqlx::query_scalar(
        "select count(*) from scan_jobs j
         join scan_authorizations a on a.id = j.scan_authorization_id
         where j.target_id = $1",
    )
    .bind(target_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(authorized, 1);
}

#[tokio::test]
async fn scan_is_refused_without_explicit_consent() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());

    let (token, _) = signup(&app, &pool, "no-consent@example.com").await;
    let target_id = create_target(&app, &token, "example.com").await;
    insert_verification(&pool, target_id, Duration::days(1), Duration::days(29)).await;

    let (status, _) = send(
        &app,
        post(
            "/api/scans",
            Some(&token),
            json!({ "target_id": target_id, "tool": "nuclei", "accept_terms": false }),
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a verified target still requires per-scan consent"
    );

    let jobs: i64 = sqlx::query_scalar("select count(*) from scan_jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(jobs, 0, "no job may be written without consent");
}

#[tokio::test]
async fn scan_is_refused_for_a_tool_outside_the_allowlist() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());

    let (token, _) = signup(&app, &pool, "bad-tool@example.com").await;
    let target_id = create_target(&app, &token, "example.com").await;
    insert_verification(&pool, target_id, Duration::days(1), Duration::days(29)).await;

    let (status, _) = send(
        &app,
        post(
            "/api/scans",
            Some(&token),
            json!({ "target_id": target_id, "tool": "sqlmap", "accept_terms": true }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_user_cannot_scan_someone_elses_target() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());

    let (owner_token, _) = signup(&app, &pool, "owner@example.com").await;
    let target_id = create_target(&app, &owner_token, "example.com").await;
    insert_verification(&pool, target_id, Duration::days(1), Duration::days(29)).await;

    let (attacker_token, _) = signup(&app, &pool, "attacker@example.com").await;

    let (status, _) = send(
        &app,
        post(
            "/api/scans",
            Some(&attacker_token),
            json!({ "target_id": target_id, "tool": "nuclei", "accept_terms": true }),
        ),
    )
    .await;

    // 404 rather than 403: another user's target id should not be
    // confirmable as existing.
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn scan_requires_authentication() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool);

    let (status, _) = send(
        &app,
        post(
            "/api/scans",
            None,
            json!({ "target_id": Uuid::new_v4(), "tool": "nuclei", "accept_terms": true }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn repeated_failed_logins_are_rate_limited() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());

    signup(&app, &pool, "brute-force-target@example.com").await;

    // Guess past the limit. The point is that the endpoint stops answering
    // at all, rather than continuing to accept guesses indefinitely.
    let mut saw_rate_limit = false;
    for _ in 0..(api::rate_limit::AUTH_ATTEMPTS_PER_WINDOW + 10) {
        let (status, _) = send(
            &app,
            post(
                "/api/auth/login",
                None,
                json!({
                    "email": "brute-force-target@example.com",
                    "password": "definitely-the-wrong-password"
                }),
            ),
        )
        .await;

        if status == StatusCode::TOO_MANY_REQUESTS {
            saw_rate_limit = true;
            break;
        }
    }

    assert!(
        saw_rate_limit,
        "login must start refusing once the attempt limit is reached"
    );
}

#[tokio::test]
async fn ip_literal_targets_are_refused_at_creation() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());

    let (token, _) = signup(&app, &pool, "ip-target@example.com").await;

    for candidate in ["127.0.0.1", "169.254.169.254", "http://localhost:3000"] {
        let (status, _) = send(
            &app,
            post("/api/targets", Some(&token), json!({ "domain": candidate })),
        )
        .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{candidate} must not be registrable as a target"
        );
    }
}

/// The gate that turns the product into a business.
///
/// A free account can prove it owns a domain and still not be allowed to
/// scan it: proving ownership answers "may we", and the plan answers "is
/// this paid for". Both have to be true, and this is the one that used to
/// be missing — the free plan was handing out the only thing anybody would
/// pay for.
#[tokio::test]
async fn the_full_scan_is_refused_on_the_free_plan() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());

    let (token, _) = signup(&app, &pool, "freeplan@example.com").await;
    let target_id = create_target(&app, &token, "example.com").await;
    insert_verification(&pool, target_id, Duration::days(1), Duration::days(29)).await;

    let (status, body) = send(
        &app,
        post(
            "/api/scans",
            Some(&token),
            json!({ "target_id": target_id, "tool": "nuclei", "accept_terms": true }),
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a verified domain is not a substitute for a subscription"
    );
    assert_eq!(body["error"], "plan_limit");

    // Nothing was written: a refused scan must not leave a job behind.
    let jobs: i64 = sqlx::query_scalar("select count(*) from scan_jobs where target_id = $1")
        .bind(target_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(jobs, 0);
}

/// The same account, once it is paying.
#[tokio::test]
async fn the_full_scan_is_allowed_once_the_account_subscribes() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());

    let (token, _) = signup(&app, &pool, "upgraded@example.com").await;
    let target_id = create_target(&app, &token, "example.com").await;
    insert_verification(&pool, target_id, Duration::days(1), Duration::days(29)).await;
    subscribe(&pool, "upgraded@example.com").await;

    let (status, body) = send(
        &app,
        post(
            "/api/scans",
            Some(&token),
            json!({ "target_id": target_id, "tool": "nuclei", "accept_terms": true }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "a paid plan should scan: {body}");
    assert_eq!(body["status"], "queued");
}
