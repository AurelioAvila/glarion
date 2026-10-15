//! The three-day free trial, end to end through the HTTP layer.
//!
//! Stripe is replaced by a local stand-in (debug builds only read
//! STRIPE_API_BASE), so these tests see exactly what the API asks Stripe for
//! and can play back any subscription state. Like the scan gate tests they
//! need `TEST_DATABASE_URL` and truncate its tables; run them with
//! `--test-threads=1`, since they also set process environment variables.

use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use sqlx::PgPool;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
use uuid::Uuid;

use api::auth::issue_token;
use api::state::AppState;

const JWT_SECRET: &str = "integration-test-secret-long-enough-for-hs256";
const WEBHOOK_SECRET: &str = "whsec_trial_integration";
const PASSWORD: &str = "A-sufficiently-long-password";
const SOLO_MONTHLY: &str = "price_test_solo_monthly";
const STUDIO_MONTHLY: &str = "price_test_studio_monthly";
const STUDIO_YEARLY: &str = "price_test_studio_yearly";

// --- the Stripe stand-in ----------------------------------------------------

#[derive(Default)]
struct Stripe {
    subscriptions: HashMap<String, Value>,
    prices: HashMap<String, Value>,
    checkouts: Vec<HashMap<String, String>>,
    cancelled: Vec<(String, String)>,
}

type Shared = Arc<Mutex<Stripe>>;

async fn stub_checkout(
    State(stripe): State<Shared>,
    Form(form): Form<Vec<(String, String)>>,
) -> Json<Value> {
    stripe
        .lock()
        .unwrap()
        .checkouts
        .push(form.into_iter().collect());
    Json(json!({ "url": "https://checkout.stripe.test/session" }))
}

async fn stub_subscription(
    State(stripe): State<Shared>,
    Path(id): Path<String>,
) -> (StatusCode, Json<Value>) {
    match stripe.lock().unwrap().subscriptions.get(&id) {
        Some(found) => (StatusCode::OK, Json(found.clone())),
        None => (StatusCode::NOT_FOUND, Json(json!({ "error": {} }))),
    }
}

async fn stub_cancel(
    State(stripe): State<Shared>,
    Path(id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    let comment = query
        .get("cancellation_details[comment]")
        .cloned()
        .unwrap_or_default();
    let mut stripe = stripe.lock().unwrap();
    stripe.cancelled.push((id.clone(), comment.clone()));
    let subscription = stripe.subscriptions.entry(id).or_insert_with(|| json!({}));
    subscription["status"] = json!("canceled");
    subscription["cancellation_details"] =
        json!({ "comment": comment, "reason": "cancellation_requested" });
    Json(subscription.clone())
}

async fn stub_preview() -> Json<Value> {
    Json(json!({ "amount_due": 4758, "currency": "eur" }))
}

async fn stub_price(
    State(stripe): State<Shared>,
    Path(id): Path<String>,
) -> (StatusCode, Json<Value>) {
    match stripe.lock().unwrap().prices.get(&id) {
        Some(found) => (StatusCode::OK, Json(found.clone())),
        None => (StatusCode::NOT_FOUND, Json(json!({ "error": {} }))),
    }
}

async fn start_stripe() -> Shared {
    let shared: Shared = Arc::default();
    let router = Router::new()
        .route("/v1/checkout/sessions", post(stub_checkout))
        .route(
            "/v1/subscriptions/:id",
            get(stub_subscription).delete(stub_cancel),
        )
        .route("/v1/invoices/create_preview", post(stub_preview))
        .route("/v1/prices/:id", get(stub_price))
        .with_state(shared.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    std::env::set_var("STRIPE_API_BASE", format!("http://{address}"));
    std::env::set_var("STRIPE_SECRET_KEY", "sk_test_stand_in");
    std::env::set_var("STRIPE_WEBHOOK_SECRET", WEBHOOK_SECRET);
    std::env::set_var("STRIPE_PRICE_SOLO_MONTHLY", SOLO_MONTHLY);
    std::env::set_var("STRIPE_PRICE_STUDIO_MONTHLY", STUDIO_MONTHLY);
    std::env::set_var("STRIPE_PRICE_STUDIO_YEARLY", STUDIO_YEARLY);
    for unset in [
        "STRIPE_PRICE_SOLO_YEARLY",
        "STRIPE_PRICE_AGENCY_MONTHLY",
        "STRIPE_PRICE_AGENCY_YEARLY",
        "PROMO_ID",
        "RESEND_API_KEY",
        "SMTP2GO_API_KEY",
        "MAILJET_API_KEY",
        "EMAIL_SINK",
    ] {
        std::env::remove_var(unset);
    }
    shared
}

fn switch(on: bool) {
    if on {
        std::env::set_var("TRIAL_ENABLED", "true");
    } else {
        std::env::remove_var("TRIAL_ENABLED");
    }
}

/// A subscription as Stripe returns it with the payment method expanded.
fn subscription(
    id: &str,
    customer: &str,
    user_id: Uuid,
    status: &str,
    price: &str,
    three_day: bool,
    card: &str,
) -> Value {
    let end = (Utc::now() + Duration::days(3)).timestamp();
    let mut metadata = json!({ "user_id": user_id.to_string() });
    if three_day {
        metadata["glarion_trial"] = json!("3d");
    }
    json!({
        "id": id,
        "object": "subscription",
        "customer": customer,
        "status": status,
        "metadata": metadata,
        "trial_end": end,
        "cancel_at_period_end": false,
        "cancellation_details": { "comment": null, "reason": null },
        "default_payment_method": { "id": "pm_test", "card": { "fingerprint": card } },
        "items": { "data": [{
            "price": { "id": price, "recurring": { "interval": "month" } },
            "current_period_end": end
        }] }
    })
}

fn set_subscription(stripe: &Shared, value: Value) {
    let id = value["id"].as_str().unwrap().to_string();
    stripe.lock().unwrap().subscriptions.insert(id, value);
}

fn set_status(stripe: &Shared, id: &str, status: &str) {
    stripe.lock().unwrap().subscriptions.get_mut(id).unwrap()["status"] = json!(status);
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

async fn send(app: &Router, mut request: Request<Body>) -> (StatusCode, Value) {
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 20], 50000))));
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

fn request(method: &str, path: &str, token: Option<&str>, body: Option<Value>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    builder
        .body(
            body.map(|b| Body::from(b.to_string()))
                .unwrap_or_else(Body::empty),
        )
        .unwrap()
}

async fn signup(app: &Router, pool: &PgPool, email: &str) -> (String, Uuid) {
    let (status, body) = send(
        app,
        request(
            "POST",
            "/api/auth/signup",
            None,
            Some(json!({
                "first_name": "Trial", "last_name": "Check", "date_of_birth": "1990-01-01",
                "email": email, "password": PASSWORD, "password_confirmation": PASSWORD,
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "signup failed: {body}");
    sqlx::query("update users set email_verified_at = now() where email = $1")
        .bind(email.to_lowercase())
        .execute(pool)
        .await
        .unwrap();
    let (status, body) = send(
        app,
        request(
            "POST",
            "/api/auth/login",
            None,
            Some(json!({ "email": email, "password": PASSWORD })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login failed: {body}");
    let id = Uuid::parse_str(body["user_id"].as_str().unwrap()).unwrap();
    let version: i32 = sqlx::query_scalar("select token_version from users where id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap();
    (issue_token(JWT_SECRET, id, version).unwrap(), id)
}

async fn billing(app: &Router, token: &str) -> Value {
    let (status, body) = send(app, request("GET", "/api/billing", Some(token), None)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

async fn checkout(app: &Router, token: &str, body: Value) -> (StatusCode, Value) {
    send(
        app,
        request("POST", "/api/billing/checkout", Some(token), Some(body)),
    )
    .await
}

/// Delivers a signed event, as Stripe would.
async fn deliver(app: &Router, event_type: &str, object: Value) -> StatusCode {
    let body = json!({
        "id": format!("evt_{}", Uuid::new_v4().simple()),
        "type": event_type,
        "data": { "object": object },
    })
    .to_string();
    let timestamp = Utc::now().timestamp();
    let mut mac = Hmac::<Sha256>::new_from_slice(WEBHOOK_SECRET.as_bytes()).unwrap();
    mac.update(format!("{timestamp}.{body}").as_bytes());
    let signature: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/billing/webhook")
        .header("stripe-signature", format!("t={timestamp},v1={signature}"))
        .body(Body::from(body))
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 20], 50000))));
    app.clone().oneshot(request).await.unwrap().status()
}

async fn add_site(app: &Router, token: &str, domain: &str) -> (StatusCode, Value) {
    send(
        app,
        request(
            "POST",
            "/api/targets",
            Some(token),
            Some(json!({ "domain": domain })),
        ),
    )
    .await
}

async fn verify(pool: &PgPool, target: &str) {
    sqlx::query(
        "insert into target_verifications (target_id, method, token, verified_at, expires_at)
         values ($1, 'dns_txt', 'test-token', now() - interval '1 hour', now() + interval '29 days')",
    )
    .bind(Uuid::parse_str(target).unwrap())
    .execute(pool)
    .await
    .unwrap();
}

async fn scan(app: &Router, token: &str, target: &str) -> (StatusCode, Value) {
    send(
        app,
        request(
            "POST",
            "/api/scans",
            Some(token),
            Some(json!({ "target_id": target, "tool": "nuclei", "accept_terms": true })),
        ),
    )
    .await
}

fn app(pool: PgPool) -> Router {
    api::router(AppState::new(pool, JWT_SECRET.to_string()))
}

/// Starts a three-day trial for this account through the webhook.
async fn start_trial(
    app: &Router,
    stripe: &Shared,
    id: &str,
    user: Uuid,
    price: &str,
    card: &str,
) -> StatusCode {
    let customer = format!("cus_{id}");
    set_subscription(
        stripe,
        subscription(id, &customer, user, "trialing", price, true, card),
    );
    deliver(app, "customer.subscription.created", json!({ "id": id })).await
}

// --- the tests --------------------------------------------------------------

#[tokio::test]
async fn with_the_switch_off_nothing_changes() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let stripe = start_stripe().await;
    switch(false);
    let app = app(pool.clone());
    let (token, user) = signup(&app, &pool, "legacy@agency.example").await;

    let account = billing(&app, &token).await;
    assert_eq!(account["trial_enabled"], false);
    assert_eq!(account["can_start_trial"], false);
    assert_eq!(account["state"], "none");

    // Today's dashboard sends no choice: Solo keeps its 14-day trial.
    let (status, body) = checkout(
        &app,
        &token,
        json!({ "plan": "solo", "interval": "monthly" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["trial"], true);
    let form = stripe.lock().unwrap().checkouts.last().cloned().unwrap();
    assert_eq!(form["subscription_data[trial_period_days]"], "14");
    assert!(!form.contains_key("subscription_data[metadata][glarion_trial]"));

    // A three-day trial is not on offer, and "no trial" means none.
    let (status, body) = checkout(
        &app,
        &token,
        json!({ "plan": "studio", "start_trial": true }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "trial_unavailable");
    let (status, _) = checkout(
        &app,
        &token,
        json!({ "plan": "solo", "start_trial": false }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let form = stripe.lock().unwrap().checkouts.last().cloned().unwrap();
    assert!(!form.contains_key("subscription_data[trial_period_days]"));

    // An existing subscriber keeps today's grace on a failed payment.
    set_subscription(
        &stripe,
        subscription(
            "sub_legacy",
            "cus_legacy",
            user,
            "past_due",
            STUDIO_MONTHLY,
            false,
            "fp_legacy",
        ),
    );
    assert_eq!(
        deliver(
            &app,
            "customer.subscription.updated",
            json!({ "id": "sub_legacy" })
        )
        .await,
        StatusCode::OK
    );
    let account = billing(&app, &token).await;
    assert_eq!(account["plan"], "studio");
    assert_eq!(account["state"], "active");
}

#[tokio::test]
async fn the_customer_chooses_between_the_trial_and_subscribing_now() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let stripe = start_stripe().await;
    switch(true);
    let app = app(pool.clone());
    let (token, _) = signup(&app, &pool, "chooser@agency.example").await;

    let account = billing(&app, &token).await;
    assert_eq!(account["trial_enabled"], true);
    assert_eq!(account["trial_days"], 3);
    assert_eq!(account["can_start_trial"], true);

    let (status, body) = checkout(
        &app,
        &token,
        json!({ "plan": "studio", "interval": "monthly", "start_trial": true }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["trial"], true);
    assert_eq!(body["trial_days"], 3);
    let form = stripe.lock().unwrap().checkouts.last().cloned().unwrap();
    assert_eq!(form["subscription_data[trial_period_days]"], "3");
    assert_eq!(form["payment_method_collection"], "always");
    assert_eq!(
        form["subscription_data[trial_settings][end_behavior][missing_payment_method]"],
        "cancel"
    );
    assert_eq!(form["subscription_data[metadata][glarion_trial]"], "3d");

    // "Subscribe now", and a dashboard that sends no choice: no trial at all,
    // not even the old Solo one.
    for body in [
        json!({ "plan": "studio", "start_trial": false }),
        json!({ "plan": "solo" }),
    ] {
        let (status, response) = checkout(&app, &token, body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(response["trial"], false);
        let form = stripe.lock().unwrap().checkouts.last().cloned().unwrap();
        assert!(!form.contains_key("subscription_data[trial_period_days]"));
        assert!(!form.contains_key("subscription_data[metadata][glarion_trial]"));
    }
}

#[tokio::test]
async fn a_trial_runs_on_tighter_limits_and_never_past_the_ownership_gate() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let stripe = start_stripe().await;
    switch(true);
    let app = app(pool.clone());
    let (token, user) = signup(&app, &pool, "limits@agency.example").await;
    assert_eq!(
        start_trial(
            &app,
            &stripe,
            "sub_limits",
            user,
            STUDIO_MONTHLY,
            "fp_limits"
        )
        .await,
        StatusCode::OK
    );

    let account = billing(&app, &token).await;
    assert_eq!(account["plan"], "studio");
    assert_eq!(account["state"], "trialing");
    assert_eq!(account["max_targets"], 3, "Studio has 10; the trial 3");
    assert_eq!(account["trial_limits"]["scans_per_site_per_day"], 2);
    assert_eq!(account["trial_limits"]["branded_reports"], false);
    assert_eq!(account["first_charge"]["amount"], 4758);
    assert_eq!(account["can_start_trial"], false);
    assert!(account["trial_ends_at"].is_string());

    let mut sites = Vec::new();
    for domain in ["one.example", "two.example", "three.example"] {
        let (status, body) = add_site(&app, &token, domain).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        sites.push(body["id"].as_str().unwrap().to_string());
    }
    let (status, body) = add_site(&app, &token, "four.example").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "plan_limit");

    // The trial changes limits, never the gate.
    let (status, body) = scan(&app, &token, &sites[0]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "target_not_verified");

    verify(&pool, &sites[0]).await;
    for _ in 0..2 {
        let (status, body) = scan(&app, &token, &sites[0]).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let (status, body) = scan(&app, &token, &sites[0]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        body["message"].as_str().unwrap().contains("free trial"),
        "{body}"
    );
}

#[tokio::test]
async fn a_failed_first_payment_blocks_at_once_and_a_retry_restores_the_plan() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let stripe = start_stripe().await;
    switch(true);
    let app = app(pool.clone());
    let (token, user) = signup(&app, &pool, "card@agency.example").await;
    start_trial(&app, &stripe, "sub_card", user, STUDIO_MONTHLY, "fp_card").await;

    let (_, site) = add_site(&app, &token, "monitored.example").await;
    let site = site["id"].as_str().unwrap().to_string();
    verify(&pool, &site).await;
    let (status, body) = send(
        &app,
        request(
            "PUT",
            &format!("/api/targets/{site}/cadence"),
            Some(&token),
            Some(json!({ "cadence": "weekly" })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The trial ends and the charge fails: blocked at once, not after dunning.
    set_status(&stripe, "sub_card", "past_due");
    assert_eq!(
        deliver(
            &app,
            "invoice.payment_failed",
            json!({ "subscription": "sub_card" })
        )
        .await,
        StatusCode::OK
    );
    let account = billing(&app, &token).await;
    assert_eq!(account["plan"], "free");
    assert_eq!(account["state"], "blocked");
    assert_eq!(account["blocked_reason"], "payment_failed");
    let (status, _) = scan(&app, &token, &site).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // Paused, not dismantled: the schedule is kept for when payment succeeds.
    let cadence: String = sqlx::query_scalar("select scan_cadence from targets where id = $1")
        .bind(Uuid::parse_str(&site).unwrap())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(cadence, "weekly");

    // Stripe's retry succeeds (new event shape): the plan returns by itself,
    // without the trial's limits.
    set_status(&stripe, "sub_card", "active");
    assert_eq!(
        deliver(
            &app,
            "invoice.paid",
            json!({ "subscription": null, "parent": { "subscription_details": { "subscription": "sub_card" } } })
        )
        .await,
        StatusCode::OK
    );
    let account = billing(&app, &token).await;
    assert_eq!(account["plan"], "studio");
    assert_eq!(account["state"], "active");
    assert_eq!(account["max_targets"], 10);
    assert!(account["trial_limits"].is_null());
    let (status, body) = scan(&app, &token, &site).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn one_trial_per_account_mailbox_and_card() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let stripe = start_stripe().await;
    switch(true);
    let app = app(pool.clone());
    let (alpha_token, alpha) = signup(&app, &pool, "alpha.trial@gmail.com").await;
    start_trial(&app, &stripe, "sub_alpha", alpha, SOLO_MONTHLY, "fp_alpha").await;
    assert_eq!(billing(&app, &alpha_token).await["state"], "trialing");

    // The same Gmail mailbox written differently: no trial offered or given.
    let (beta_token, _) = signup(&app, &pool, "AlphaTrial+second@googlemail.com").await;
    assert_eq!(billing(&app, &beta_token).await["can_start_trial"], false);
    let (status, body) = checkout(
        &app,
        &beta_token,
        json!({ "plan": "solo", "start_trial": true }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "trial_unavailable");
    // Subscribing now still works.
    let (status, _) = checkout(
        &app,
        &beta_token,
        json!({ "plan": "solo", "start_trial": false }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Another person, another mailbox, the same card: cancelled before any
    // charge, labelled for Stripe's dashboard, and the plan never granted.
    let (gamma_token, gamma) = signup(&app, &pool, "gamma@other.example").await;
    assert_eq!(billing(&app, &gamma_token).await["can_start_trial"], true);
    start_trial(&app, &stripe, "sub_gamma", gamma, SOLO_MONTHLY, "fp_alpha").await;
    assert!(stripe
        .lock()
        .unwrap()
        .cancelled
        .contains(&("sub_gamma".to_string(), "trial_already_used".to_string())));
    assert_eq!(billing(&app, &gamma_token).await["plan"], "free");
    // Stripe then reports the cancellation.
    deliver(
        &app,
        "customer.subscription.deleted",
        json!({ "id": "sub_gamma" }),
    )
    .await;
    let account = billing(&app, &gamma_token).await;
    assert_eq!(account["state"], "blocked");
    assert_eq!(account["blocked_reason"], "trial_already_used");

    // A second checkout by somebody already on a trial is closed quietly;
    // the trial goes on.
    start_trial(
        &app,
        &stripe,
        "sub_alpha_again",
        alpha,
        SOLO_MONTHLY,
        "fp_other",
    )
    .await;
    assert!(stripe
        .lock()
        .unwrap()
        .cancelled
        .iter()
        .any(|(id, _)| id == "sub_alpha_again"));
    deliver(
        &app,
        "customer.subscription.deleted",
        json!({ "id": "sub_alpha_again" }),
    )
    .await;
    let account = billing(&app, &alpha_token).await;
    assert_eq!(account["state"], "trialing");
    assert_eq!(account["plan"], "solo");
}

#[tokio::test]
async fn a_site_gets_one_free_trial() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let stripe = start_stripe().await;
    switch(true);
    let app = app(pool.clone());

    let (first_token, first) = signup(&app, &pool, "first@agency.example").await;
    start_trial(&app, &stripe, "sub_first", first, SOLO_MONTHLY, "fp_first").await;
    let (_, site) = add_site(&app, &first_token, "client-site.example").await;
    let site = site["id"].as_str().unwrap().to_string();
    verify(&pool, &site).await;
    let (status, _) = scan(&app, &first_token, &site).await;
    assert_eq!(status, StatusCode::OK);

    // A new mailbox and a new card, the same client site.
    let (second_token, second) = signup(&app, &pool, "second@elsewhere.example").await;
    start_trial(
        &app,
        &stripe,
        "sub_second",
        second,
        SOLO_MONTHLY,
        "fp_second",
    )
    .await;
    let (_, same) = add_site(&app, &second_token, "client-site.example").await;
    let same = same["id"].as_str().unwrap().to_string();
    verify(&pool, &same).await;
    let (status, body) = scan(&app, &second_token, &same).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body["message"]
        .as_str()
        .unwrap()
        .contains("another account's free trial"));

    // Its own site is fine.
    let (_, own) = add_site(&app, &second_token, "second-own.example").await;
    let own = own["id"].as_str().unwrap().to_string();
    verify(&pool, &own).await;
    let (status, body) = scan(&app, &second_token, &own).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn neither_www_nor_a_schedule_gets_a_site_a_second_free_trial() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let stripe = start_stripe().await;
    switch(true);
    let app = app(pool.clone());

    let (first_token, first) = signup(&app, &pool, "first@agency.example").await;
    start_trial(&app, &stripe, "sub_first", first, SOLO_MONTHLY, "fp_first").await;
    let (_, site) = add_site(&app, &first_token, "client-site.example").await;
    let site = site["id"].as_str().unwrap().to_string();
    verify(&pool, &site).await;
    assert_eq!(scan(&app, &first_token, &site).await.0, StatusCode::OK);

    let (second_token, second) = signup(&app, &pool, "second@elsewhere.example").await;
    start_trial(
        &app,
        &stripe,
        "sub_second",
        second,
        SOLO_MONTHLY,
        "fp_second",
    )
    .await;
    let mut ids = Vec::new();
    for domain in ["www.client-site.example", "second-own.example"] {
        let (_, body) = add_site(&app, &second_token, domain).await;
        let id = body["id"].as_str().unwrap().to_string();
        verify(&pool, &id).await;
        let (status, body) = send(
            &app,
            request(
                "PUT",
                &format!("/api/targets/{id}/cadence"),
                Some(&second_token),
                Some(json!({ "cadence": "weekly" })),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        ids.push(id);
    }

    // The www name is the same site.
    let (status, body) = scan(&app, &second_token, &ids[0]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body["message"]
        .as_str()
        .unwrap()
        .contains("another account's free trial"));

    // The scheduler applies the same rule: the trial's own site is queued,
    // the other trial's site is not.
    orchestrator::scheduler::tick(&pool).await.unwrap();
    let jobs = |id: &str| {
        sqlx::query_scalar::<_, i64>("select count(*) from scan_jobs where target_id = $1")
            .bind(Uuid::parse_str(id).unwrap())
            .fetch_one(&pool)
    };
    assert_eq!(
        jobs(&ids[0]).await.unwrap(),
        0,
        "a schedule must not scan it either"
    );
    assert!(
        jobs(&ids[1]).await.unwrap() > 0,
        "its own site is scheduled"
    );

    // And the trial's daily budget holds for schedules: the run above used it.
    sqlx::query("update targets set last_scheduled_at = null where id = $1")
        .bind(Uuid::parse_str(&ids[1]).unwrap())
        .execute(&pool)
        .await
        .unwrap();
    let before = jobs(&ids[1]).await.unwrap();
    orchestrator::scheduler::tick(&pool).await.unwrap();
    assert_eq!(jobs(&ids[1]).await.unwrap(), before);
}

#[tokio::test]
async fn public_prices_come_from_stripe_and_a_mismatch_is_left_out() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let stripe = start_stripe().await;
    switch(true);
    {
        let mut stripe = stripe.lock().unwrap();
        stripe.prices.insert(
            SOLO_MONTHLY.into(),
            json!({ "active": true, "unit_amount": 1900, "currency": "eur", "tax_behavior": "exclusive", "recurring": { "interval": "month" } }),
        );
        stripe.prices.insert(
            STUDIO_MONTHLY.into(),
            json!({ "active": true, "unit_amount": 3900, "currency": "eur", "tax_behavior": "exclusive", "recurring": { "interval": "month" } }),
        );
        // A yearly slot holding a monthly price is not published.
        stripe.prices.insert(
            STUDIO_YEARLY.into(),
            json!({ "active": true, "unit_amount": 35000, "currency": "eur", "tax_behavior": "exclusive", "recurring": { "interval": "month" } }),
        );
    }
    let app = app(pool);
    let (status, body) = send(&app, request("GET", "/api/billing/prices", None, None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["trial_enabled"], true);
    assert_eq!(body["trial_days"], 3);
    let prices = body["prices"].as_array().unwrap();
    assert!(prices
        .iter()
        .any(|p| p["plan"] == "solo" && p["interval"] == "monthly" && p["amount"] == 1900));
    assert!(prices
        .iter()
        .any(|p| p["plan"] == "studio" && p["interval"] == "monthly" && p["amount"] == 3900));
    assert!(!prices
        .iter()
        .any(|p| p["plan"] == "studio" && p["interval"] == "yearly"));
    assert!(
        !body.to_string().contains("price_test"),
        "no Stripe ids in public"
    );
}

#[tokio::test]
async fn the_reminder_goes_once_a_day_before_the_end_and_not_after_cancelling() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let stripe = start_stripe().await;
    switch(true);
    let app = app(pool.clone());
    let (_, ends_soon) = signup(&app, &pool, "soon@agency.example").await;
    let (_, cancelled) = signup(&app, &pool, "cancelled@agency.example").await;
    start_trial(
        &app,
        &stripe,
        "sub_soon",
        ends_soon,
        SOLO_MONTHLY,
        "fp_soon",
    )
    .await;
    start_trial(
        &app,
        &stripe,
        "sub_cancelled",
        cancelled,
        SOLO_MONTHLY,
        "fp_cancelled",
    )
    .await;
    sqlx::query("update entitlements set trial_ends_at = now() + interval '20 hours'")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("update entitlements set cancel_at_period_end = true where user_id = $1")
        .bind(cancelled)
        .execute(&pool)
        .await
        .unwrap();

    let sink = std::env::temp_dir().join(format!("glarion-trial-sink-{}", Uuid::new_v4()));
    std::env::set_var("EMAIL_SINK", "1");
    std::env::set_var("EMAIL_SINK_DIR", &sink);
    std::env::set_var("MAIL_FROM", "Glarion <noreply@glarion.app>");
    let mailer = orchestrator::mailer::Mailer::from_env();

    orchestrator::trial_reminder::send_due(&pool, &mailer, Utc::now())
        .await
        .unwrap();
    orchestrator::trial_reminder::send_due(&pool, &mailer, Utc::now())
        .await
        .unwrap();
    let sent: Vec<_> = std::fs::read_dir(&sink)
        .map(|dir| {
            dir.flatten()
                .filter(|f| f.path().extension().is_some_and(|e| e == "txt"))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(sent.len(), 1, "one reminder, for the trial still running");
    let text = std::fs::read_to_string(sent[0].path()).unwrap();
    assert!(text.contains("€47.58 is taken"), "{text}");

    std::fs::remove_dir_all(&sink).ok();
    for unset in ["EMAIL_SINK", "EMAIL_SINK_DIR", "MAIL_FROM"] {
        std::env::remove_var(unset);
    }
}
