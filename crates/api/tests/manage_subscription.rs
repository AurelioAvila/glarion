//! Manage subscription: reading, cancelling at period end and resuming the
//! caller's own subscription, through the HTTP layer.
//!
//! Stripe is a local stand-in (debug builds only read STRIPE_API_BASE), and
//! email goes to a folder (EMAIL_SINK). Needs `TEST_DATABASE_URL`, truncates
//! its tables and sets process environment variables: run with
//! `--test-threads=1`.

use axum::body::Body;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::{Form, Json, Router};
use chrono::{Duration, Utc};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
use uuid::Uuid;

use api::auth::issue_token;
use api::state::AppState;

const JWT_SECRET: &str = "integration-test-secret-long-enough-for-hs256";
const PASSWORD: &str = "A-sufficiently-long-password";
const STUDIO_MONTHLY: &str = "price_test_studio_monthly";

// --- the Stripe stand-in ----------------------------------------------------

#[derive(Default)]
struct Stripe {
    subscriptions: HashMap<String, Value>,
    /// Every update, as the form Stripe received.
    updates: Vec<(String, HashMap<String, String>)>,
}

type Shared = Arc<Mutex<Stripe>>;

async fn stub_get(
    State(stripe): State<Shared>,
    Path(id): Path<String>,
) -> (StatusCode, Json<Value>) {
    match stripe.lock().unwrap().subscriptions.get(&id) {
        Some(found) => (StatusCode::OK, Json(found.clone())),
        None => (StatusCode::NOT_FOUND, Json(json!({ "error": {} }))),
    }
}

/// Applies an update the way Stripe does for the fields the API sends.
async fn stub_update(
    State(stripe): State<Shared>,
    Path(id): Path<String>,
    Form(form): Form<Vec<(String, String)>>,
) -> (StatusCode, Json<Value>) {
    let form: HashMap<String, String> = form.into_iter().collect();
    let mut stripe = stripe.lock().unwrap();
    stripe.updates.push((id.clone(), form.clone()));
    let Some(subscription) = stripe.subscriptions.get_mut(&id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": {} })));
    };
    let period_end = subscription["items"]["data"][0]["current_period_end"].clone();
    if let Some(flag) = form.get("cancel_at_period_end") {
        let on = flag == "true";
        subscription["cancel_at_period_end"] = json!(on);
        subscription["cancel_at"] = if on { period_end } else { Value::Null };
    }
    if form.get("cancel_at").is_some_and(|value| value.is_empty()) {
        subscription["cancel_at"] = Value::Null;
    }
    if let Some(feedback) = form.get("cancellation_details[feedback]") {
        subscription["cancellation_details"]["feedback"] = json!(feedback);
    }
    if let Some(comment) = form.get("cancellation_details[comment]") {
        subscription["cancellation_details"]["comment"] = json!(comment);
    }
    (StatusCode::OK, Json(subscription.clone()))
}

async fn stub_customer() -> Json<Value> {
    Json(json!({ "address": { "country": "IT" } }))
}

async fn start_stripe() -> Shared {
    let shared: Shared = Arc::default();
    let router = Router::new()
        .route("/v1/subscriptions/:id", get(stub_get).post(stub_update))
        .route("/v1/customers/:id", get(stub_customer))
        .with_state(shared.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    std::env::set_var("STRIPE_API_BASE", format!("http://{address}"));
    std::env::set_var("STRIPE_SECRET_KEY", "sk_test_stand_in");
    std::env::set_var("STRIPE_PRICE_STUDIO_MONTHLY", STUDIO_MONTHLY);
    for unset in [
        "TRIAL_ENABLED",
        "RESEND_API_KEY",
        "SMTP2GO_API_KEY",
        "MAILJET_API_KEY",
    ] {
        std::env::remove_var(unset);
    }
    shared
}

/// A renewing Studio subscription paid by a Visa ending 4242.
fn subscription(id: &str, customer: &str, status: &str) -> Value {
    let end = (Utc::now() + Duration::days(20)).timestamp();
    let trial_end = if status == "trialing" {
        json!(end)
    } else {
        Value::Null
    };
    json!({
        "id": id,
        "object": "subscription",
        "customer": customer,
        "status": status,
        "trial_end": trial_end,
        "cancel_at_period_end": false,
        "cancel_at": null,
        "cancellation_details": { "comment": null, "feedback": null, "reason": null },
        "default_payment_method": { "id": "pm_test", "card": { "brand": "visa", "last4": "4242" } },
        "items": { "data": [{
            "quantity": 1,
            "price": { "id": STUDIO_MONTHLY, "unit_amount": 3900, "currency": "eur", "recurring": { "interval": "month" } },
            "current_period_end": end
        }] }
    })
}

/// Where this test's email lands.
fn sink() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("glarion-manage-sink-{}", Uuid::new_v4()));
    std::env::set_var("EMAIL_SINK", "1");
    std::env::set_var("EMAIL_SINK_DIR", &dir);
    std::env::set_var("MAIL_FROM", "Glarion <noreply@glarion.app>");
    dir
}

/// The owner notices in the sink (signup mail lands there too).
fn mails(dir: &PathBuf) -> Vec<String> {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .filter(|f| f.path().extension().is_some_and(|e| e == "txt"))
                .map(|f| std::fs::read_to_string(f.path()).unwrap())
                .filter(|text| text.starts_with("A customer scheduled a cancellation"))
                .collect()
        })
        .unwrap_or_default()
}

// --- the API under test -----------------------------------------------------

async fn test_pool() -> Option<PgPool> {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return None;
    };
    let pool = PgPool::connect(&url).await.expect("TEST_DATABASE_URL");
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("migrations failed");
    sqlx::query("truncate users, targets, target_verifications, scan_authorizations, scan_jobs, entitlements, rate_limit_buckets, stripe_events, trial_claims cascade")
        .execute(&pool)
        .await
        .expect("truncate failed");
    Some(pool)
}

fn app(pool: PgPool) -> Router {
    api::router(AppState::new(pool, JWT_SECRET.to_string()))
}

async fn send(app: &Router, mut request: Request<Body>) -> (StatusCode, Value) {
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 30], 50000))));
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn request(method: &str, path: &str, token: &str, body: Option<Value>) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .header("x-glarion-csrf", "1")
        .body(
            body.map(|b| Body::from(b.to_string()))
                .unwrap_or_else(Body::empty),
        )
        .unwrap()
}

async fn signup(app: &Router, pool: &PgPool, email: &str) -> (String, Uuid) {
    let mut signup = Request::builder()
        .method("POST")
        .uri("/api/auth/signup")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "first_name": "Manage", "last_name": "Check", "date_of_birth": "1990-01-01",
                "email": email, "password": PASSWORD, "password_confirmation": PASSWORD,
            })
            .to_string(),
        ))
        .unwrap();
    signup
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 31], 50000))));
    let response = app.clone().oneshot(signup).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK, "signup failed");
    let (id, version): (Uuid, i32) =
        sqlx::query_as("select id, token_version from users where email = $1")
            .bind(email)
            .fetch_one(pool)
            .await
            .unwrap();
    (issue_token(JWT_SECRET, id, version).unwrap(), id)
}

/// Binds the account to a Stripe customer and subscription, as the webhook
/// would have.
async fn subscribe(pool: &PgPool, user: Uuid, customer: &str, subscription: &str) {
    sqlx::query(
        "update entitlements set stripe_customer_id = $2, stripe_subscription_id = $3,
                plan = 'studio', max_targets = 10, subscription_status = 'active'
          where user_id = $1 and product = 'glarion'",
    )
    .bind(user)
    .bind(customer)
    .bind(subscription)
    .execute(pool)
    .await
    .unwrap();
}

fn put(stripe: &Shared, value: Value) {
    let id = value["id"].as_str().unwrap().to_string();
    stripe.lock().unwrap().subscriptions.insert(id, value);
}

fn update_count(stripe: &Shared) -> usize {
    stripe.lock().unwrap().updates.len()
}

// --- the tests --------------------------------------------------------------

#[tokio::test]
async fn an_account_without_a_subscription_has_nothing_to_cancel() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let stripe = start_stripe().await;
    let app = app(pool.clone());
    let (token, _) = signup(&app, &pool, "free@example.com").await;

    let (status, body) = send(
        &app,
        request("GET", "/api/billing/subscription", &token, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "none");
    assert_eq!(body["plan"], "free");
    assert_eq!(body["can_cancel"], false);
    assert_eq!(body["can_resume"], false);
    assert_eq!(body["lifetime"], false);
    assert_eq!(body["portal"], false);

    for path in [
        "/api/billing/subscription/cancel",
        "/api/billing/subscription/resume",
    ] {
        let (status, _) = send(&app, request("POST", path, &token, Some(json!({})))).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }
    assert_eq!(update_count(&stripe), 0);
}

#[tokio::test]
async fn cancelling_keeps_the_plan_to_the_period_end_and_tells_the_owner_once() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let stripe = start_stripe().await;
    let dir = sink();
    let app = app(pool.clone());
    let (token, user) = signup(&app, &pool, "agency@example.com").await;
    subscribe(&pool, user, "cus_agency", "sub_agency").await;
    put(&stripe, subscription("sub_agency", "cus_agency", "active"));

    let (status, body) = send(
        &app,
        request("GET", "/api/billing/subscription", &token, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["product"], "glarion");
    assert_eq!(body["plan"], "studio");
    assert_eq!(body["plan_name"], "Studio");
    assert_eq!(body["interval"], "month");
    assert_eq!(body["amount"], 3900);
    assert_eq!(body["currency"], "eur");
    assert_eq!(body["status"], "active");
    assert_eq!(body["payment_method"]["brand"], "visa");
    assert_eq!(body["payment_method"]["last4"], "4242");
    assert_eq!(body["max_sites"], 10);
    assert_eq!(body["can_cancel"], true);
    assert_eq!(body["can_resume"], false);
    assert_eq!(body["portal"], true);
    let renews = body["current_period_end"].clone();
    assert!(renews.is_string());

    let (status, body) = send(
        &app,
        request(
            "POST",
            "/api/billing/subscription/cancel",
            &token,
            Some(json!({ "reason": "other", "comment": "  Moving the\nclient sites   in-house <b>soon</b>\u{7}  " })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["cancel_at_period_end"], true);
    assert_eq!(body["cancel_at"], renews, "ends when the paid period ends");
    assert_eq!(body["status"], "active", "access continues until then");
    assert_eq!(body["can_cancel"], false);
    assert_eq!(body["can_resume"], true);

    {
        let stripe = stripe.lock().unwrap();
        let (id, form) = &stripe.updates[0];
        assert_eq!(id, "sub_agency");
        assert_eq!(form["cancel_at_period_end"], "true");
        assert_eq!(form["cancellation_details[feedback]"], "other");
        assert_eq!(
            form["cancellation_details[comment]"],
            "Moving the client sites in-house <b>soon</b>"
        );
        assert!(
            !form.contains_key("cancel_at"),
            "never an immediate cancellation"
        );
    }
    let flag: bool =
        sqlx::query_scalar("select cancel_at_period_end from entitlements where user_id = $1")
            .bind(user)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(flag, "the Pricing page agrees before the webhook");
    let plan: String = sqlx::query_scalar("select plan from entitlements where user_id = $1")
        .bind(user)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(plan, "studio", "the plan stays until the period ends");

    // Asking again changes nothing at Stripe and sends nothing more.
    let (status, again) = send(
        &app,
        request(
            "POST",
            "/api/billing/subscription/cancel",
            &token,
            Some(json!({})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again["can_resume"], true);
    assert_eq!(update_count(&stripe), 1);

    let sent = mails(&dir);
    assert_eq!(sent.len(), 1, "one owner notice per cancellation");
    let notice = &sent[0];
    assert!(notice.contains("Plan: Studio — Monthly"), "{notice}");
    assert!(notice.contains("Customer: agency@example.com"), "{notice}");
    assert!(notice.contains("Country: IT"), "{notice}");
    assert!(notice.contains("Reason: Other"), "{notice}");
    assert!(
        notice.contains("Comment: Moving the client sites in-house <b>soon</b>"),
        "{notice}"
    );
    let html = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .filter(|f| f.path().extension().is_some_and(|e| e == "html"))
        .map(|f| std::fs::read_to_string(f.path()).unwrap())
        .find(|html| html.contains("A customer scheduled a cancellation"))
        .unwrap();
    assert!(
        html.contains("&lt;b&gt;soon&lt;/b&gt;"),
        "the comment is escaped"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn resuming_undoes_a_scheduled_cancellation_once() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let stripe = start_stripe().await;
    let dir = sink();
    let app = app(pool.clone());
    let (token, user) = signup(&app, &pool, "resume@example.com").await;
    subscribe(&pool, user, "cus_resume", "sub_resume").await;
    put(&stripe, subscription("sub_resume", "cus_resume", "active"));

    // Nothing to resume yet: a no-op, not a write.
    let (status, body) = send(
        &app,
        request(
            "POST",
            "/api/billing/subscription/resume",
            &token,
            Some(json!({})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["can_cancel"], true);
    assert_eq!(update_count(&stripe), 0);

    // No reason at all is fine.
    let (status, body) = send(
        &app,
        request(
            "POST",
            "/api/billing/subscription/cancel",
            &token,
            Some(json!({})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    {
        let stripe = stripe.lock().unwrap();
        let form = &stripe.updates[0].1;
        assert!(!form.contains_key("cancellation_details[feedback]"));
        assert!(!form.contains_key("cancellation_details[comment]"));
    }

    let (status, body) = send(
        &app,
        request(
            "POST",
            "/api/billing/subscription/resume",
            &token,
            Some(json!({})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["cancel_at_period_end"], false);
    assert!(body["cancel_at"].is_null());
    assert_eq!(body["can_cancel"], true);
    assert_eq!(body["can_resume"], false);
    assert_eq!(
        stripe.lock().unwrap().updates[1].1["cancel_at_period_end"],
        "false"
    );
    let flag: bool =
        sqlx::query_scalar("select cancel_at_period_end from entitlements where user_id = $1")
            .bind(user)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!flag);

    let (status, _) = send(
        &app,
        request(
            "POST",
            "/api/billing/subscription/resume",
            &token,
            Some(json!({})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(update_count(&stripe), 2, "resuming twice writes once");

    // Cancelling again in the same period does not tell the owner twice.
    let (status, _) = send(
        &app,
        request(
            "POST",
            "/api/billing/subscription/cancel",
            &token,
            Some(json!({ "reason": "unused" })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(mails(&dir).len(), 1);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn only_the_callers_own_subscription_can_be_touched() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let stripe = start_stripe().await;
    let app = app(pool.clone());
    let (_, owner) = signup(&app, &pool, "owner@example.com").await;
    subscribe(&pool, owner, "cus_owner", "sub_owner").await;
    put(&stripe, subscription("sub_owner", "cus_owner", "active"));

    // Another account, even one whose record somehow names the owner's
    // subscription, finds nothing under its own customer.
    let (token, other) = signup(&app, &pool, "other@example.com").await;
    subscribe(&pool, other, "cus_other", "sub_owner").await;

    let (status, body) = send(
        &app,
        request("GET", "/api/billing/subscription", &token, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "none");
    let (status, _) = send(
        &app,
        request(
            "POST",
            "/api/billing/subscription/cancel",
            &token,
            Some(json!({})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(update_count(&stripe), 0);

    // Signed out: nothing at all.
    let anonymous = Request::builder()
        .method("GET")
        .uri("/api/billing/subscription")
        .body(Body::empty())
        .unwrap();
    let (status, _) = send(&app, anonymous).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn bad_feedback_is_refused_before_anything_changes() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let stripe = start_stripe().await;
    let app = app(pool.clone());
    let (token, user) = signup(&app, &pool, "feedback@example.com").await;
    subscribe(&pool, user, "cus_feedback", "sub_feedback").await;
    put(
        &stripe,
        subscription("sub_feedback", "cus_feedback", "trialing"),
    );

    for body in [
        json!({ "reason": "because" }),
        json!({ "reason": "other", "comment": "x".repeat(501) }),
    ] {
        let (status, answer) = send(
            &app,
            request(
                "POST",
                "/api/billing/subscription/cancel",
                &token,
                Some(body),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    }
    assert_eq!(update_count(&stripe), 0);

    // A trial ends at the trial's end, with nothing charged.
    let (status, body) = send(
        &app,
        request(
            "POST",
            "/api/billing/subscription/cancel",
            &token,
            Some(json!({ "reason": "too_expensive", "comment": "x".repeat(500) })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "trialing");
    assert_eq!(body["trial_end"], body["cancel_at"]);
}

#[tokio::test]
async fn billing_trouble_and_hammering_are_answered_honestly() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let stripe = start_stripe().await;
    let app = app(pool.clone());
    let (token, user) = signup(&app, &pool, "trouble@example.com").await;
    // Stripe does not know this subscription: billing is unavailable, not
    // "you have no plan".
    subscribe(&pool, user, "cus_trouble", "sub_missing").await;
    let (status, body) = send(
        &app,
        request("GET", "/api/billing/subscription", &token, None),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body["error"], "billing_unavailable");

    put(
        &stripe,
        subscription("sub_missing", "cus_trouble", "active"),
    );
    for _ in 0..20 {
        let (status, _) = send(
            &app,
            request(
                "POST",
                "/api/billing/subscription/resume",
                &token,
                Some(json!({})),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
    let (status, _) = send(
        &app,
        request(
            "POST",
            "/api/billing/subscription/resume",
            &token,
            Some(json!({})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}
