//! Integration tests for deleting an account.
//!
//! `delete_account` anonymizes rather than removing the row — see the
//! doc comment on `routes::accounts::delete_account` for why. These tests
//! exist to prove that guarantee from the outside: after deletion, the
//! audit trail a scan's authorization depends on must still resolve, and
//! the token that just performed the deletion must not still work.
//!
//! Same infrastructure as `scan_gate.rs`: requires `TEST_DATABASE_URL`,
//! skips rather than fails without it.

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use chrono::Duration;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::net::SocketAddr;
use tower::ServiceExt;
use uuid::Uuid;

use api::auth::issue_token;
use api::state::AppState;

const JWT_SECRET: &str = "integration-test-secret-long-enough-for-hs256";
const TEST_PASSWORD: &str = "a-sufficiently-long-password";

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
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

fn req(method: Method, path: &str, token: Option<&str>, body: Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");

    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }

    builder.body(Body::from(body.to_string())).unwrap()
}

fn post(path: &str, token: Option<&str>, body: Value) -> Request<Body> {
    req(Method::POST, path, token, body)
}

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
        .unwrap();

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

async fn create_target(app: &axum::Router, token: &str, domain: &str) -> Uuid {
    let (status, body) = send(
        app,
        post("/api/targets", Some(token), json!({ "domain": domain })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create target failed: {body}");
    Uuid::parse_str(body["id"].as_str().unwrap()).unwrap()
}

async fn insert_verification(pool: &PgPool, target_id: Uuid) {
    let now = chrono::Utc::now();
    sqlx::query(
        "insert into target_verifications (target_id, method, token, verified_at, expires_at)
         values ($1, 'dns_txt', $2, $3, $4)",
    )
    .bind(target_id)
    .bind("test-token")
    .bind(now - Duration::days(1))
    .bind(now + Duration::days(29))
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn deleting_an_account_wrong_password_is_refused() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());

    let (token, _) = signup(&app, &pool, "wrong-password@example.com").await;

    let (status, _) = send(
        &app,
        req(
            Method::DELETE,
            "/api/account",
            Some(&token),
            json!({ "password": "not the right one" }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let still_there: i64 =
        sqlx::query_scalar("select count(*) from users where email = 'wrong-password@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(still_there, 1, "a wrong password must not delete anything");
}

#[tokio::test]
async fn deletion_anonymizes_personal_fields_and_the_row_survives() {
    // The row has to survive: it is what scan_authorizations.user_id points
    // at, and that table has no cascade to users on purpose (see the
    // handler's doc comment). This is the guarantee that actually matters
    // — not that the fields are gone, but that removing them does not also
    // remove the audit trail that depends on the row still existing.
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());

    let (token, user_id) = signup(&app, &pool, "leaving@example.com").await;
    let target_id = create_target(&app, &token, "example.com").await;
    insert_verification(&pool, target_id).await;

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

    let (status, body) = send(
        &app,
        req(
            Method::DELETE,
            "/api/account",
            Some(&token),
            json!({ "password": TEST_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "deletion failed: {body}");

    #[derive(sqlx::FromRow, Debug)]
    struct Row {
        email: String,
        first_name: Option<String>,
        date_of_birth: Option<chrono::NaiveDate>,
        email_verified_at: Option<chrono::DateTime<chrono::Utc>>,
    }

    let row: Row = sqlx::query_as(
        "select email, first_name, date_of_birth, email_verified_at from users where id = $1",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .expect("the row must still exist");

    assert!(row.email.starts_with("deleted-"), "got {}", row.email);
    assert!(row.email.ends_with("@deleted.invalid"));
    assert_eq!(row.first_name, None);
    assert_eq!(row.date_of_birth, None);
    assert_eq!(row.email_verified_at, None);

    // The point of the whole exercise: the scan this account authorized is
    // still traceable to an authorization row, which still resolves.
    let authorized: i64 = sqlx::query_scalar(
        "select count(*) from scan_jobs j
         join scan_authorizations a on a.id = j.scan_authorization_id
         where j.target_id = $1 and a.user_id = $2",
    )
    .bind(target_id)
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        authorized, 1,
        "the authorization record must survive account deletion"
    );
}

#[tokio::test]
async fn the_token_used_to_delete_the_account_stops_working() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());

    let (token, _) = signup(&app, &pool, "revoked@example.com").await;

    let (status, body) = send(
        &app,
        req(
            Method::DELETE,
            "/api/account",
            Some(&token),
            json!({ "password": TEST_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "deletion failed: {body}");

    let (status, _) = send(&app, post("/api/targets", Some(&token), json!({}))).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the deleted account's own token must be revoked, not just its password"
    );
}

#[tokio::test]
async fn an_active_subscription_blocks_deletion() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let app = app(pool.clone());

    let (token, user_id) = signup(&app, &pool, "subscribed@example.com").await;

    // Signup already writes the free-plan row; upgrade it in place rather
    // than inserting a second one for the same (user_id, product).
    sqlx::query(
        "update entitlements
         set plan = 'studio', subscription_status = 'active', stripe_customer_id = 'cus_test'
         where user_id = $1 and product = 'glarion'",
    )
    .bind(user_id)
    .execute(&pool)
    .await
    .unwrap();

    let (status, body) = send(
        &app,
        req(
            Method::DELETE,
            "/api/account",
            Some(&token),
            json!({ "password": TEST_PASSWORD }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let still_verified: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("select email_verified_at from users where id = $1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        still_verified.is_some(),
        "a blocked deletion must not have touched the account"
    );
}
