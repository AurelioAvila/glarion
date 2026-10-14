//! Subscribing, managing, and hearing back from Stripe.
//!
//! Money never moves through this application. Checkout and the customer
//! portal are hosted by Stripe, so no card detail ever reaches our servers
//! and the whole of PCI compliance stays somebody else's problem. What we
//! keep is a customer id and what they are entitled to.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::billing::{
    blocked_reason, current_access, email_hash, plan_for_price, price_env_var,
    status_grants_access, status_keeps_plan, trial_days, trial_enabled, verify_signature, Interval,
    Plan, PAID_PLANS, TRIAL_DAYS, TRIAL_MARKER_KEY, TRIAL_MARKER_VALUE,
    TRIAL_MAX_SCANS_PER_TARGET_PER_DAY, TRIAL_REJECTED_COMMENT,
};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

#[derive(Serialize)]
pub struct Subscription {
    pub plan: String,
    pub plan_name: String,
    /// The allowance in force: the plan's, or the trial's smaller one.
    pub max_targets: i32,
    pub targets_used: i64,
    pub allows_scheduling: bool,
    /// Whether the scanner may be run at all, from the same method the scan
    /// gate reads. The dashboard needs it to know whether to make the case
    /// for a plan or to offer the button, and deriving that from
    /// `allows_scheduling` — true for the same plans today — would be one
    /// pricing change away from offering a button that always fails.
    pub allows_full_scan: bool,
    pub status: Option<String>,
    pub current_period_end: Option<DateTime<Utc>>,
    /// True when there is a Stripe customer to manage, which decides
    /// whether the dashboard offers a "manage billing" route at all.
    pub manageable: bool,
    // The three-day trial. Additive: the dashboards already deployed read
    // none of these.
    pub trial_enabled: bool,
    pub trial_days: u32,
    /// `none`, `trialing`, `active` or `blocked`. Unknown values read as
    /// `none` in the dashboard.
    pub state: &'static str,
    /// `none`, `payment_failed`, `canceled` or `trial_already_used`.
    pub blocked_reason: &'static str,
    pub trial_ends_at: Option<DateTime<Utc>>,
    pub cancel_at_period_end: bool,
    /// A hint for the dashboard; checkout decides again.
    pub can_start_trial: bool,
    /// `month` or `year`, once there is a subscription.
    pub billing_interval: Option<String>,
    /// Set while a three-day trial runs.
    pub trial_limits: Option<TrialLimits>,
    /// What Stripe will take when the trial ends: its own preview of the
    /// first invoice, coupon and tax included. Absent when unknown.
    pub first_charge: Option<Charge>,
}

#[derive(Serialize)]
pub struct TrialLimits {
    pub max_targets: i32,
    pub scans_per_site_per_day: i64,
    pub branded_reports: bool,
}

#[derive(Serialize)]
pub struct Charge {
    /// Minor units (cents).
    pub amount: i64,
    pub currency: String,
}

/// What this account currently has.
pub async fn get_subscription(
    State(state): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<Subscription>> {
    #[derive(sqlx::FromRow)]
    struct Row {
        subscription_status: Option<String>,
        current_period_end: Option<DateTime<Utc>>,
        stripe_customer_id: Option<String>,
        trial_ends_at: Option<DateTime<Utc>>,
        cancel_at_period_end: bool,
        blocked_reason: Option<String>,
        billing_interval: Option<String>,
        first_charge_amount: Option<i64>,
        first_charge_currency: Option<String>,
    }

    let row: Option<Row> = sqlx::query_as(
        "select subscription_status, current_period_end, stripe_customer_id, trial_ends_at,
                cancel_at_period_end, blocked_reason, billing_interval, first_charge_amount,
                first_charge_currency
         from entitlements where user_id = $1 and product = 'glarion'",
    )
    .bind(user.id)
    .fetch_optional(&state.pool)
    .await?;

    let used: i64 = sqlx::query_scalar("select count(*) from targets where user_id = $1")
        .bind(user.id)
        .fetch_one(&state.pool)
        .await?;

    // No row means no plan, which means the free one — the same fail-closed
    // reading the rest of the system uses.
    let row = row.unwrap_or(Row {
        subscription_status: None,
        current_period_end: None,
        stripe_customer_id: None,
        trial_ends_at: None,
        cancel_at_period_end: false,
        blocked_reason: None,
        billing_interval: None,
        first_charge_amount: None,
        first_charge_currency: None,
    });

    let access = current_access(&state.pool, user.id).await?;
    let plan = access.plan;
    let status = row.subscription_status.as_deref();

    // Rows written before the trial existed carry no reason, so it is
    // derived from the status the same way the webhook derives it.
    let reason: &'static str = match (plan, status) {
        (Plan::Free, Some(status)) => match row.blocked_reason.as_deref() {
            Some("trial_already_used") => "trial_already_used",
            Some("payment_failed") => "payment_failed",
            Some("canceled") => "canceled",
            _ => blocked_reason(status, None),
        },
        _ => "none",
    };
    let account_state = match (plan, status) {
        (Plan::Free, _) if reason != "none" => "blocked",
        (Plan::Free, _) => "none",
        (_, Some("trialing")) => "trialing",
        _ => "active",
    };

    let can_start_trial =
        row.stripe_customer_id.is_none() && trial_available(&state, user.id, None).await?;

    Ok(Json(Subscription {
        plan: plan.as_db_str().to_string(),
        plan_name: plan.display_name().to_string(),
        max_targets: access.max_targets(),
        targets_used: used,
        allows_scheduling: plan.allows_scheduling(),
        allows_full_scan: plan.allows_full_scan(),
        status: row.subscription_status.clone(),
        current_period_end: row.current_period_end,
        manageable: row.stripe_customer_id.is_some(),
        trial_enabled: trial_enabled(),
        trial_days: TRIAL_DAYS,
        state: account_state,
        blocked_reason: reason,
        trial_ends_at: (account_state == "trialing")
            .then_some(row.trial_ends_at)
            .flatten(),
        cancel_at_period_end: row.cancel_at_period_end,
        can_start_trial,
        billing_interval: row.billing_interval,
        trial_limits: access.trial.then(|| TrialLimits {
            max_targets: access.max_targets(),
            scans_per_site_per_day: TRIAL_MAX_SCANS_PER_TARGET_PER_DAY,
            branded_reports: false,
        }),
        first_charge: match (
            account_state == "trialing",
            row.first_charge_amount,
            row.first_charge_currency,
        ) {
            (true, Some(amount), Some(currency)) => Some(Charge { amount, currency }),
            _ => None,
        },
    }))
}

/// Whether this account may still start the three-day trial: the switch is
/// on, and neither the account nor its mailbox has had one. The card is only
/// known once Stripe has it, so the webhook checks that one.
///
/// Callers also require that the account has never been a Stripe customer:
/// anyone who has subscribed before, trial or not, subscribes directly.
async fn trial_available(state: &AppState, user_id: Uuid, email: Option<&str>) -> ApiResult<bool> {
    if !trial_enabled() {
        return Ok(false);
    }
    let email = match email {
        Some(email) => email.to_string(),
        None => account_email(state, user_id).await?,
    };
    let claimed: bool = sqlx::query_scalar(
        "select exists (select 1 from trial_claims where user_id = $1 or email_hash = $2)",
    )
    .bind(user_id)
    .bind(email_hash(&email))
    .fetch_one(&state.pool)
    .await?;
    Ok(!claimed)
}

#[derive(Deserialize)]
pub struct CheckoutRequest {
    pub plan: String,
    #[serde(default)]
    pub interval: String,
    /// `true` from "Start 3-day free trial", `false` from "Subscribe now".
    /// Absent from dashboards that predate the trial.
    #[serde(default)]
    pub start_trial: Option<bool>,
}

#[derive(Serialize)]
pub struct RedirectResponse {
    pub url: String,
}

#[derive(Serialize)]
pub struct CheckoutResponse {
    pub url: String,
    /// Whether this checkout starts a free trial (of either kind).
    pub trial: bool,
    pub trial_days: Option<u32>,
}

/// Starts a Stripe Checkout session and hands back where to send the
/// browser.
pub async fn start_checkout(
    State(state): State<AppState>,
    user: AuthUser,
    Json(body): Json<CheckoutRequest>,
) -> ApiResult<Json<CheckoutResponse>> {
    let plan = Plan::from_db_str(&body.plan);
    if plan == Plan::Free {
        return Err(ApiError::BadRequest(
            "choose a paid plan to subscribe".into(),
        ));
    }

    let interval = Interval::from_str_or_monthly(&body.interval);
    let price_id = price_env_var(plan, interval)
        .and_then(|var| std::env::var(var).ok())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            // Configuration, not the caller's fault — and it must not read
            // as though the plan does not exist.
            tracing::error!(plan = plan.as_db_str(), "no Stripe price configured");
            ApiError::Internal(anyhow::anyhow!("billing is not configured"))
        })?;

    // A second checkout would start a second subscription, and cancelling
    // the old one later would then drop the account to free while the new
    // one is still being paid. Plan changes go through the billing portal.
    let current: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "select stripe_subscription_id, subscription_status from entitlements
         where user_id = $1 and product = 'glarion'",
    )
    .bind(user.id)
    .fetch_optional(&state.pool)
    .await?;
    if let Some((Some(_), Some(status))) = current {
        if status_grants_access(&status) {
            return Err(ApiError::Conflict(
                "you already have a subscription; change plan from Manage billing".into(),
            ));
        }
    }

    let secret = stripe_secret()?;
    let email = account_email(&state, user.id).await?;
    let customer_id = existing_customer(&state, user.id).await?;

    // Which trial, if any. With the switch on the customer chooses, and a
    // trial they ask for is granted only when the account may have one;
    // "Subscribe now" never carries one. With it off nothing changes for the
    // dashboards in use today, which send no choice and keep the 14-day Solo
    // trial; an explicit `false` still means no trial.
    let three_day = match body.start_trial {
        Some(true) => {
            if customer_id.is_some() || !trial_available(&state, user.id, Some(&email)).await? {
                return Err(ApiError::TrialUnavailable);
            }
            true
        }
        _ => false,
    };
    let trial = if three_day {
        Some(TRIAL_DAYS)
    } else if body.start_trial.is_none() && !trial_enabled() {
        trial_days(plan, customer_id.is_some())
    } else {
        None
    };

    // Back to the plan page either way: it is the page that shows what
    // they now have, and after paying that is the only thing they want to
    // see. (The old destination carried a `subscribed=1` flag nothing ever
    // read.)
    let plan_page = state.mailer.app_link("/plan");
    let mut form: Vec<(String, String)> = vec![
        ("mode".into(), "subscription".into()),
        ("line_items[0][price]".into(), price_id),
        ("line_items[0][quantity]".into(), "1".into()),
        ("success_url".into(), plan_page.clone()),
        ("cancel_url".into(), plan_page),
        // Carried through Checkout and returned on the webhook. Matching a
        // Stripe customer back to an account by email would break the
        // moment somebody changes either one.
        ("client_reference_id".into(), user.id.to_string()),
        (
            "subscription_data[metadata][user_id]".into(),
            user.id.to_string(),
        ),
        // Charging European customers means charging VAT, and getting the
        // rate right per country is not something to hand-roll.
        ("automatic_tax[enabled]".into(), "true".into()),
    ];

    if let Some(days) = trial {
        form.push((
            "subscription_data[trial_period_days]".into(),
            days.to_string(),
        ));
        form.push(("payment_method_collection".into(), "always".into()));
        // Belt and braces: with the card collected above this cannot
        // trigger, but a trial must never roll into an unpaid subscription.
        form.push((
            "subscription_data[trial_settings][end_behavior][missing_payment_method]".into(),
            "cancel".into(),
        ));
    }
    if three_day {
        // How the webhook knows this subscription runs on the trial's rules:
        // one trial per account, mailbox and card, tighter limits, and a
        // failed first payment blocks at once. Several open checkouts cannot
        // add up to several trials: the claim is taken when Stripe creates
        // the subscription, and a second one is cancelled before any charge.
        form.push((
            format!("subscription_data[metadata][{TRIAL_MARKER_KEY}]"),
            TRIAL_MARKER_VALUE.into(),
        ));
        form.push((
            format!("metadata[{TRIAL_MARKER_KEY}]"),
            TRIAL_MARKER_VALUE.into(),
        ));
    }

    // The Halloween offer follows the plan resolved above and the server's
    // clock, never the client. Empty outside the window.
    form.extend(crate::promo::checkout_fields(
        crate::promo::enabled_from_env(),
        Utc::now(),
        plan,
        interval,
    ));

    // Reuse the customer when there is one, so a second subscription does
    // not create a duplicate record with the same person in it.
    match customer_id {
        Some(id) => {
            form.push(("customer".into(), id));
            form.push(("customer_update[address]".into(), "auto".into()));
        }
        None => {
            form.push(("customer_email".into(), email));
            form.push(("tax_id_collection[enabled]".into(), "true".into()));
        }
    }

    let url = stripe_post(&secret, &stripe_url("/v1/checkout/sessions"), &form)
        .await?
        .get("url")
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("Stripe returned no checkout url")))?;

    Ok(Json(CheckoutResponse {
        url,
        trial: trial.is_some(),
        trial_days: trial,
    }))
}

#[derive(Serialize, Clone)]
pub struct PlanPrice {
    pub plan: &'static str,
    pub interval: &'static str,
    /// Minor units (cents), as the Stripe Price has it.
    pub amount: i64,
    pub currency: String,
    /// `exclusive`: VAT is added at checkout.
    pub tax_behavior: String,
}

#[derive(Serialize)]
pub struct PublicPrices {
    pub server_time: String,
    pub trial_enabled: bool,
    pub trial_days: u32,
    pub prices: Vec<PlanPrice>,
}

/// How long the prices read from Stripe are reused. A price change shows up
/// within this; a page view never waits on Stripe. An empty read is kept for
/// a minute only, and still kept, so an outage cannot turn every page view
/// into six calls to Stripe.
const PRICE_CACHE_SECS: u64 = 600;
const PRICE_RETRY_SECS: u64 = 60;

type PriceCache = Option<(std::time::Instant, Vec<PlanPrice>)>;
static PRICE_CACHE: std::sync::Mutex<PriceCache> = std::sync::Mutex::new(None);

/// GET /api/billing/prices: public. Every paid plan's price as the Stripe
/// Price says it, so the line "then €39/month" is never a number written in
/// the page. A price that cannot be read, or whose interval does not match
/// its slot, is left out rather than guessed.
pub async fn public_prices() -> Json<PublicPrices> {
    let cached = PRICE_CACHE
        .lock()
        .ok()
        .and_then(|cache| cache.clone())
        .filter(|(at, prices)| {
            let ttl = if prices.is_empty() {
                PRICE_RETRY_SECS
            } else {
                PRICE_CACHE_SECS
            };
            at.elapsed().as_secs() < ttl
        })
        .map(|(_, prices)| prices);

    let prices = match cached {
        Some(prices) => prices,
        None => {
            let fresh = read_prices().await;
            if let Ok(mut cache) = PRICE_CACHE.lock() {
                *cache = Some((std::time::Instant::now(), fresh.clone()));
            }
            fresh
        }
    };

    Json(PublicPrices {
        server_time: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        trial_enabled: trial_enabled(),
        trial_days: TRIAL_DAYS,
        prices,
    })
}

async fn read_prices() -> Vec<PlanPrice> {
    let Some(secret) = std::env::var("STRIPE_SECRET_KEY")
        .ok()
        .filter(|value| !value.is_empty())
    else {
        return Vec::new();
    };
    // All at once, so the wait is the slowest answer rather than the sum.
    let mut reads = tokio::task::JoinSet::new();
    for (rank, plan) in PAID_PLANS.into_iter().enumerate() {
        for (interval, label, stripe_interval) in [
            (Interval::Monthly, "monthly", "month"),
            (Interval::Yearly, "yearly", "year"),
        ] {
            let Some(id) = price_env_var(plan, interval)
                .and_then(|var| std::env::var(var).ok())
                .filter(|id| !id.is_empty())
            else {
                continue;
            };
            let secret = secret.clone();
            reads.spawn(async move {
                let url = stripe_url(&format!("/v1/prices/{id}"));
                let price = stripe_get(&secret, &url, &[]).await.ok();
                (rank, plan, label, stripe_interval, price)
            });
        }
    }

    let mut prices = Vec::new();
    while let Some(Ok((rank, plan, label, stripe_interval, price))) = reads.join_next().await {
        let Some(price) = price else {
            continue;
        };
        let amount = price.get("unit_amount").and_then(|v| v.as_i64());
        let recurring = price
            .get("recurring")
            .and_then(|r| r.get("interval"))
            .and_then(|v| v.as_str());
        let active = price.get("active").and_then(|v| v.as_bool()) == Some(true);
        match (amount, recurring) {
            (Some(amount), Some(found)) if active && amount > 0 && found == stripe_interval => {
                let text = |key: &str, default: &str| {
                    price
                        .get(key)
                        .and_then(|v| v.as_str())
                        .unwrap_or(default)
                        .to_string()
                };
                prices.push((
                    (rank, label),
                    PlanPrice {
                        plan: plan.as_db_str(),
                        interval: label,
                        amount,
                        currency: text("currency", "eur"),
                        tax_behavior: text("tax_behavior", "unspecified"),
                    },
                ));
            }
            _ => tracing::warn!(
                plan = plan.as_db_str(),
                label,
                "a Stripe price was not published"
            ),
        }
    }
    prices.sort_by_key(|(order, _)| *order);
    prices.into_iter().map(|(_, price)| price).collect()
}

/// Sends an existing subscriber to Stripe's own portal to change card,
/// switch plan, or cancel.
///
/// Cancelling is deliberately not something we implement: a subscription
/// somebody can only end by emailing support is a dark pattern, and the
/// portal already does it properly.
pub async fn open_portal(
    State(state): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<RedirectResponse>> {
    let secret = stripe_secret()?;
    let customer_id = existing_customer(&state, user.id)
        .await?
        .ok_or_else(|| ApiError::BadRequest("there is no subscription to manage".into()))?;

    let mut form = vec![
        ("customer".to_string(), customer_id),
        ("return_url".to_string(), state.mailer.app_link("/plan")),
    ];
    if let Some(configuration) = portal_configuration().await {
        form.push(("configuration".to_string(), configuration));
    }

    let url = stripe_post(&secret, &stripe_url("/v1/billing_portal/sessions"), &form)
        .await?
        .get("url")
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("Stripe returned no portal url")))?;

    Ok(Json(RedirectResponse { url }))
}

/// Where Stripe tells us what happened.
///
/// Unauthenticated by necessity, so the signature is the only thing
/// standing between this and anybody granting themselves a subscription by
/// posting the right JSON. It is checked before the body is even parsed.
pub async fn webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> ApiResult<&'static str> {
    let secret = std::env::var("STRIPE_WEBHOOK_SECRET")
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            // Refusing outright rather than accepting unverified events: an
            // endpoint that trusts anything while misconfigured is worse
            // than one that is simply down.
            tracing::error!("STRIPE_WEBHOOK_SECRET is unset; refusing webhooks");
            ApiError::Internal(anyhow::anyhow!("billing is not configured"))
        })?;

    let signature = headers
        .get("stripe-signature")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();

    verify_signature(&body, signature, &secret, Utc::now().timestamp()).map_err(|error| {
        tracing::warn!(?error, "rejected a webhook with a bad signature");
        // Deliberately vague. A caller probing this endpoint should not be
        // told whether the secret, the body or the clock was the problem.
        ApiError::Unauthorized
    })?;

    let event: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|_| ApiError::BadRequest("malformed event".into()))?;

    let event_id = event
        .get("id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| ApiError::BadRequest("event has no id".into()))?;
    let event_type = event
        .get("type")
        .and_then(|value| value.as_str())
        .unwrap_or("");

    // Claim before working. Stripe retries on any non-2xx and redelivers
    // after a timeout even when the work did happen, so a second copy has
    // to find the door already shut rather than rely on each handler
    // happening to be idempotent. A claim that never completed — the work
    // failed and Stripe is retrying — is taken over once it is two minutes
    // old, long enough that it cannot still be in progress; otherwise a
    // single failed attempt would drop the event for good.
    let claimed: Option<(String,)> = sqlx::query_as(
        "insert into stripe_events (id, event_type) values ($1, $2)
         on conflict (id) do update set received_at = now()
           where stripe_events.completed_at is null
             and stripe_events.received_at < now() - interval '2 minutes'
         returning id",
    )
    .bind(event_id)
    .bind(event_type)
    .fetch_optional(&state.pool)
    .await?;

    if claimed.is_none() {
        let done: Option<(bool,)> =
            sqlx::query_as("select completed_at is not null from stripe_events where id = $1")
                .bind(event_id)
                .fetch_optional(&state.pool)
                .await?;
        if matches!(done, Some((true,))) {
            // Already applied. Answering 200 stops Stripe retrying it.
            return Ok("duplicate");
        }
        // Claimed moments ago and not finished: in progress, or just failed.
        // A non-2xx keeps Stripe retrying until a later delivery can take
        // the claim over.
        return Err(ApiError::Conflict("event is still being processed".into()));
    }

    if let Err(error) = apply(&state, event_type, &event).await {
        // The claim row stays without a completion stamp, which is how an
        // incomplete event is found later.
        tracing::error!(event_id, event_type, error = ?error, "could not apply a Stripe event");
        return Err(error);
    }

    sqlx::query("update stripe_events set completed_at = now() where id = $1")
        .bind(event_id)
        .execute(&state.pool)
        .await?;

    Ok("ok")
}

/// Applies one event.
///
/// Only subscription lifecycle is handled. Anything else is acknowledged
/// and ignored, because an event we do not act on is not an error and
/// returning one would have Stripe retry it forever.
async fn apply(state: &AppState, event_type: &str, event: &serde_json::Value) -> ApiResult<()> {
    let object = event
        .get("data")
        .and_then(|data| data.get("object"))
        .ok_or_else(|| ApiError::BadRequest("event has no object".into()))?;

    match event_type {
        "checkout.session.completed" => {
            // The only place the account id is reliably present, so the
            // customer is bound to the account here and every later event
            // is matched by customer id.
            let user_id = object
                .get("client_reference_id")
                .and_then(|value| value.as_str())
                .and_then(|value| Uuid::parse_str(value).ok());
            let customer = object.get("customer").and_then(|value| value.as_str());

            if let (Some(user_id), Some(customer)) = (user_id, customer) {
                sqlx::query(
                    "update entitlements set stripe_customer_id = $2
                     where user_id = $1 and product = 'glarion'",
                )
                .bind(user_id)
                .bind(customer)
                .execute(&state.pool)
                .await?;
            }
            Ok(())
        }

        "customer.subscription.created"
        | "customer.subscription.updated"
        | "customer.subscription.deleted" => {
            // Re-read rather than trust the payload: events arrive in any
            // order, and applying an old "trialing" after a newer "past_due"
            // would hand the plan back. The fresh copy also carries the card
            // fingerprint the one-trial rule needs.
            let Some(id) = object.get("id").and_then(|value| value.as_str()) else {
                return Ok(());
            };
            with_customer_lock(state, object, async {
                match fetch_subscription(id).await? {
                    Some(fresh) => apply_subscription(state, &fresh).await,
                    None => apply_subscription(state, object).await,
                }
            })
            .await
        }

        // A charge succeeded or failed. The subscription changes state with
        // it; reading it now rather than waiting for its own event is what
        // makes a failed first payment block at once.
        "invoice.paid" | "invoice.payment_failed" | "invoice.payment_action_required" => {
            let Some(id) = invoice_subscription(object) else {
                return Ok(());
            };
            with_customer_lock(state, object, async {
                match fetch_subscription(&id).await? {
                    Some(fresh) => apply_subscription(state, &fresh).await,
                    None => {
                        tracing::warn!(
                            event_type,
                            "no STRIPE_SECRET_KEY to re-read the subscription"
                        );
                        Ok(())
                    }
                }
            })
            .await
        }

        // Stripe sends it three days before a trial ends, which for a
        // three-day trial is the moment it starts. Our own reminder goes out
        // a day before the end instead (orchestrator::trial_reminder).
        "customer.subscription.trial_will_end" => {
            tracing::info!(
                subscription = object.get("id").and_then(|value| value.as_str()),
                "trial will end"
            );
            Ok(())
        }

        _ => Ok(()),
    }
}

/// Applies events about one customer one at a time.
///
/// Stripe sends `customer.subscription.created` and the trial's zero
/// `invoice.paid` within the same second. Applied side by side, both read the
/// account as unpaid and both sent the welcome; both found a refused trial
/// and both cancelled it, the second time into an error. A Postgres advisory
/// lock per customer, taken before the subscription is re-read, makes the
/// second wait and then see what the first wrote. Waiters retry rather than
/// block, so they never hold a pool connection the holder needs.
async fn with_customer_lock<T>(
    state: &AppState,
    object: &serde_json::Value,
    work: impl std::future::Future<Output = ApiResult<T>>,
) -> ApiResult<T> {
    let Some(customer) = object.get("customer").and_then(|value| value.as_str()) else {
        return work.await;
    };
    let key = format!("glarion-stripe:{customer}");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut connection = loop {
        let mut connection = state.pool.acquire().await?;
        let locked: bool = sqlx::query_scalar("select pg_try_advisory_lock(hashtext($1))")
            .bind(&key)
            .fetch_one(&mut *connection)
            .await?;
        if locked {
            break connection;
        }
        drop(connection);
        if std::time::Instant::now() > deadline {
            // Not an error worth logging: Stripe redelivers it.
            return Err(ApiError::Conflict(
                "another event for this customer is being applied".into(),
            ));
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    };

    let result = work.await;

    let unlocked = sqlx::query("select pg_advisory_unlock(hashtext($1))")
        .bind(&key)
        .execute(&mut *connection)
        .await;
    if unlocked.is_err() {
        // A connection still holding the lock must not go back to the pool.
        use sqlx::Connection;
        let _ = connection.detach().close().await;
    }
    result
}

/// The subscription an invoice belongs to, under either API version's shape.
fn invoice_subscription(invoice: &serde_json::Value) -> Option<String> {
    invoice
        .get("subscription")
        .and_then(|value| value.as_str())
        .or_else(|| {
            invoice
                .get("parent")
                .and_then(|parent| parent.get("subscription_details"))
                .and_then(|details| details.get("subscription"))
                .and_then(|value| value.as_str())
        })
        .map(str::to_string)
}

/// The subscription as Stripe has it now, with its payment method expanded.
/// None when no secret key is configured, so local setups without one keep
/// working from the event payload.
async fn fetch_subscription(id: &str) -> ApiResult<Option<serde_json::Value>> {
    let Some(secret) = std::env::var("STRIPE_SECRET_KEY")
        .ok()
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let subscription = stripe_get(
        &secret,
        &stripe_url(&format!("/v1/subscriptions/{id}")),
        &[
            ("expand[]", "default_payment_method"),
            ("expand[]", "latest_invoice"),
        ],
    )
    .await?;
    Ok(Some(subscription))
}

async fn apply_subscription(state: &AppState, subscription: &serde_json::Value) -> ApiResult<()> {
    let Some(customer) = subscription
        .get("customer")
        .and_then(|value| value.as_str())
    else {
        return Ok(());
    };

    // Stripe does not guarantee delivery order between this event and
    // checkout.session.completed, which is what normally binds
    // stripe_customer_id to the account. If this one arrives first, the
    // customer id match below finds nothing and the grant is silently
    // lost. start_checkout stamps the subscription with this metadata for
    // exactly this case, so the row can still be found by user_id.
    let user_id = subscription
        .get("metadata")
        .and_then(|value| value.get("user_id"))
        .and_then(|value| value.as_str())
        .and_then(|value| Uuid::parse_str(value).ok());

    let status = subscription
        .get("status")
        .and_then(|value| value.as_str())
        .unwrap_or("");

    let price_id = subscription
        .get("items")
        .and_then(|items| items.get("data"))
        .and_then(|data| data.get(0))
        .and_then(|item| item.get("price"))
        .and_then(|price| price.get("id"))
        .and_then(|value| value.as_str())
        .unwrap_or("");

    // A three-day trial carries its rules for the life of the subscription.
    let three_day = subscription
        .get("metadata")
        .and_then(|value| value.get(TRIAL_MARKER_KEY))
        .and_then(|value| value.as_str())
        == Some(TRIAL_MARKER_VALUE);
    let trial_end = subscription
        .get("trial_end")
        .and_then(|value| value.as_i64())
        .and_then(|seconds| Utc.timestamp_opt(seconds, 0).single());
    let cancel_at_period_end = subscription
        .get("cancel_at_period_end")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let cancellation_comment = subscription
        .get("cancellation_details")
        .and_then(|details| details.get("comment"))
        .and_then(|value| value.as_str());
    let billing_interval = subscription
        .get("items")
        .and_then(|items| items.get("data"))
        .and_then(|data| data.get(0))
        .and_then(|item| item.get("price"))
        .and_then(|price| price.get("recurring"))
        .and_then(|recurring| recurring.get("interval"))
        .and_then(|value| value.as_str());

    // A plan is granted only when the price is one we recognise *and* the
    // subscription is in a state that should work. Either failing drops the
    // account to free rather than leaving whatever it had.
    let strict = trial_enabled() || three_day;
    let plan = match (status_keeps_plan(status, strict), plan_for_price(price_id)) {
        (true, Some(plan)) => plan,
        _ => Plan::Free,
    };
    let reason = if plan == Plan::Free && !status.is_empty() {
        blocked_reason(status, cancellation_comment)
    } else {
        "none"
    };

    // Read from the item first, then the subscription.
    //
    // Stripe moved the billing period onto subscription items in a recent
    // API version, so the field is simply absent at the top level on a
    // current account — which showed up as a renewal date that was always
    // blank. Checking both keeps this working either way rather than
    // pinning us to one version.
    let period_end = subscription
        .get("items")
        .and_then(|items| items.get("data"))
        .and_then(|data| data.get(0))
        .and_then(|item| item.get("current_period_end"))
        .and_then(|value| value.as_i64())
        .or_else(|| {
            subscription
                .get("current_period_end")
                .and_then(|value| value.as_i64())
        })
        .and_then(|seconds| Utc.timestamp_opt(seconds, 0).single());

    let subscription_id = subscription.get("id").and_then(|value| value.as_str());

    // An event about an older subscription must not overwrite a newer one
    // that is still paid for: cancelling a replaced subscription would
    // otherwise drop the account to free.
    let current: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "select stripe_subscription_id, subscription_status from entitlements
         where product = 'glarion' and (stripe_customer_id = $1 or user_id = $2)",
    )
    .bind(customer)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;
    if let Some((Some(current_id), Some(current_status))) = &current {
        if Some(current_id.as_str()) != subscription_id
            && status_grants_access(current_status)
            && !status_grants_access(status)
        {
            tracing::info!(
                current_id,
                ?subscription_id,
                "ignored an event for a replaced subscription"
            );
            return Ok(());
        }
    }

    // Read the plan this account is on before the update overwrites it, so a
    // first paid subscription can be told apart from a renewal. Stripe sends
    // customer.subscription.updated on every renewal and every card change,
    // and welcoming someone once a month is not a welcome.
    #[derive(sqlx::FromRow)]
    struct Previous {
        plan: String,
        user_id: Uuid,
        email: Option<String>,
        first_name: Option<String>,
        subscription_status: Option<String>,
        stripe_subscription_id: Option<String>,
        first_charge_amount: Option<i64>,
        first_charge_currency: Option<String>,
    }
    let previous: Option<Previous> = sqlx::query_as(
        "select e.plan, e.user_id, u.email, u.first_name, e.subscription_status,
                e.stripe_subscription_id, e.first_charge_amount, e.first_charge_currency
           from entitlements e
           left join users u on u.id = e.user_id
          where e.product = 'glarion'
            and (e.stripe_customer_id = $1 or e.user_id = $2)",
    )
    .bind(customer)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;
    let same_subscription = previous
        .as_ref()
        .is_some_and(|row| row.stripe_subscription_id.as_deref() == subscription_id);

    // The three-day trial is claimed when Stripe creates it, against the
    // account, the mailbox and the card. A trial that collides is cancelled
    // before anything is charged and never grants the plan.
    if three_day {
        if let (Some(trial_end), Some(subscription_id), Some(previous)) =
            (trial_end, subscription_id, previous.as_ref())
        {
            let card = card_fingerprint(subscription);
            let email = previous.email.clone().unwrap_or_default();
            let claimed = claim_trial(
                state,
                previous.user_id,
                &email,
                card.as_deref(),
                subscription_id,
                trial_end,
            )
            .await?;
            if !claimed && status == "trialing" {
                // A second checkout by somebody already on a trial is closed
                // quietly: their trial goes on. Anyone else is told why.
                let running_elsewhere = !same_subscription
                    && previous
                        .subscription_status
                        .as_deref()
                        .is_some_and(status_grants_access);
                cancel_subscription(subscription_id).await?;
                tracing::info!(
                    subscription_id,
                    running_elsewhere,
                    "refused a trial that was already used"
                );
                if !running_elsewhere && !email.is_empty() {
                    let message = orchestrator::mailer::trial_rejected_email(
                        previous.first_name.as_deref().unwrap_or(""),
                        plan_for_price(price_id)
                            .unwrap_or(Plan::Solo)
                            .display_name(),
                        &state.mailer.app_link("/plan"),
                    );
                    if let Err(error) = state.mailer.send(&email, &message).await {
                        tracing::warn!(%error, "could not send the trial-refused notice");
                    }
                }
                return Ok(());
            }
        }
    }

    // What Stripe will take when the trial ends, asked once per trial.
    let first_charge = if three_day && status == "trialing" {
        match previous.as_ref() {
            Some(Previous {
                first_charge_amount: Some(amount),
                first_charge_currency: Some(currency),
                ..
            }) if same_subscription => Some((*amount, currency.clone())),
            _ => match subscription_id {
                Some(id) => preview_first_charge(id).await,
                None => None,
            },
        }
    } else {
        None
    };

    sqlx::query(
        "update entitlements
         set stripe_customer_id = $1,
             plan = $2,
             max_targets = $3,
             subscription_status = $4,
             stripe_subscription_id = $5,
             current_period_end = $6,
             trial_ends_at = $8,
             cancel_at_period_end = $9,
             blocked_reason = $10,
             billing_interval = $11,
             first_charge_amount = $12,
             first_charge_currency = $13
         where product = 'glarion'
           and (stripe_customer_id = $1 or user_id = $7)",
    )
    .bind(customer)
    .bind(plan.as_db_str())
    .bind(plan.max_targets())
    .bind(status)
    .bind(subscription_id)
    .bind(period_end)
    .bind(user_id)
    .bind((status == "trialing").then_some(trial_end).flatten())
    .bind(cancel_at_period_end)
    .bind((reason != "none").then_some(reason))
    .bind(billing_interval)
    .bind(first_charge.as_ref().map(|(amount, _)| *amount))
    .bind(first_charge.as_ref().map(|(_, currency)| currency.as_str()))
    .execute(&state.pool)
    .await?;

    // Welcome only on the crossing from unpaid to paid. A row that was
    // already on a paid plan is renewing, and one that has just dropped to
    // free is not a moment to congratulate anyone.
    // Whether this account was on a paid plan a moment ago. Both directions
    // of the crossing need it: one to welcome, one to explain the loss.
    let previous_plan = previous
        .as_ref()
        .map(|row| Plan::from_db_str(&row.plan))
        .unwrap_or(Plan::Free);
    let was_paid = previous_plan.allows_scheduling();
    let email = previous.as_ref().and_then(|row| row.email.clone());
    let first_name = previous
        .as_ref()
        .and_then(|row| row.first_name.clone())
        .unwrap_or_default();

    if plan.allows_scheduling() && !was_paid {
        if let Some(email) = email.as_deref() {
            if three_day && status == "trialing" {
                // Nothing charged yet: the date, the amount and the limits.
                let message = orchestrator::mailer::trial_started_email(
                    &first_name,
                    plan.display_name(),
                    trial_end.unwrap_or_else(Utc::now),
                    first_charge
                        .as_ref()
                        .map(|(amount, currency)| orchestrator::mailer::money(*amount, currency))
                        .as_deref(),
                    billing_interval.unwrap_or("month"),
                    orchestrator::mailer::TrialTerms {
                        sites: crate::billing::Access { plan, trial: true }.max_targets(),
                        scans_per_site_per_day: TRIAL_MAX_SCANS_PER_TARGET_PER_DAY,
                    },
                    &state.mailer.app_link("/targets"),
                );
                if let Err(error) = state.mailer.send(email, &message).await {
                    tracing::warn!(%error, "could not send the trial welcome");
                }
            } else if !three_day {
                // A trial has charged nothing yet, so it gets the version of
                // the welcome that names the first payment date instead of a
                // receipt.
                let trial_ends = (status == "trialing").then_some(trial_end).flatten();
                send_subscription_welcome(state, email, plan, trial_ends).await;
            }
        }
    }

    // A three-day trial's subscription is confirmed once, when a payment has
    // really been taken: after the trial (Stripe moves it to `active` an
    // hour before it charges, so the status alone would announce a payment
    // that may still fail), or after a failed one is paid. Marked on the row
    // so a later event cannot send it again.
    let invoice = subscription.get("latest_invoice");
    let charged = invoice
        .and_then(|invoice| invoice.get("status"))
        .and_then(|value| value.as_str())
        == Some("paid")
        && invoice
            .and_then(|invoice| invoice.get("amount_paid"))
            .and_then(|value| value.as_i64())
            .unwrap_or(0)
            > 0;
    if three_day && status == "active" && plan.allows_scheduling() && charged {
        let first: Option<(Uuid,)> = sqlx::query_as(
            "update entitlements set activation_mailed_for = $2
              where product = 'glarion' and stripe_customer_id = $1
                and activation_mailed_for is distinct from $2
             returning user_id",
        )
        .bind(customer)
        .bind(subscription_id)
        .fetch_optional(&state.pool)
        .await?;
        if let (Some(_), Some(email)) = (first, email.as_deref()) {
            send_subscription_welcome(state, email, plan, None).await;
        }
    }

    // The other direction, which said nothing at all before. The account
    // dropped to free, scheduled scanning was paused or switched off below,
    // and the first the agency knew was noticing a client site had not been
    // checked in a fortnight — on a security product, the worst thing to
    // find late.
    if !plan.allows_scheduling() && was_paid {
        if let Some(email) = email.as_deref() {
            // Stripe says why itself when it knows. A subscription cancelled
            // after dunning gives cancellation_details.reason, which is the
            // difference between "your card needs updating" and "you chose to
            // leave" — and getting that backwards reads as a company not
            // paying attention.
            let stripe_reason = subscription
                .get("cancellation_details")
                .and_then(|details| details.get("reason"))
                .and_then(|value| value.as_str())
                .unwrap_or("");
            let payment_problem = stripe_reason == "payment_failure" || reason == "payment_failed";
            send_subscription_ended(state, email, previous_plan, payment_problem).await;
        }
    }

    // Losing the paid plan has to switch off what the paid plan bought,
    // otherwise a cancelled account keeps being scanned every week for
    // free — and keeps costing us the scans. A plan paused by a failed
    // payment keeps its schedules: the scheduler skips accounts without a
    // paid plan, so they resume by themselves once a retry succeeds, which is
    // what the payment-failed email promises.
    if !plan.allows_scheduling() && reason != "payment_failed" {
        sqlx::query(
            "update targets set scan_cadence = 'manual'
             where scan_cadence <> 'manual'
               and user_id = (select user_id from entitlements
                              where stripe_customer_id = $1 and product = 'glarion')",
        )
        .bind(customer)
        .execute(&state.pool)
        .await?;
    }

    tracing::info!(
        customer,
        status,
        plan = plan.as_db_str(),
        "subscription updated"
    );
    Ok(())
}

fn stripe_secret() -> ApiResult<String> {
    std::env::var("STRIPE_SECRET_KEY")
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            tracing::error!("STRIPE_SECRET_KEY is unset");
            ApiError::Internal(anyhow::anyhow!("billing is not configured"))
        })
}

/// Best-effort notice that a paid plan has stopped.
///
/// Never returns an error, for the same reason the welcome does not: the
/// entitlement has already been written by the time this runs, and failing
/// the webhook over an email would have Stripe retry the whole delivery and
/// re-apply work that already succeeded.
async fn send_subscription_ended(state: &AppState, email: &str, plan: Plan, payment_problem: bool) {
    let first_name: Option<String> =
        sqlx::query_scalar("select first_name from users where email = $1")
            .bind(email)
            .fetch_optional(&state.pool)
            .await
            .ok()
            .flatten();
    let message = orchestrator::mailer::subscription_ended_email(
        first_name.as_deref().unwrap_or(""),
        plan.display_name(),
        payment_problem,
        &state.mailer.app_link("/plan"),
    );
    if let Err(error) = state.mailer.send(email, &message).await {
        tracing::warn!(%error, "could not send the subscription-ended notice");
    }
}

/// Best-effort welcome after a first payment.
///
/// Never returns an error: the plan is already granted by the time this runs,
/// and failing the webhook over an email would have Stripe retry the whole
/// delivery and re-apply work that already succeeded.
async fn send_subscription_welcome(
    state: &AppState,
    email: &str,
    plan: Plan,
    trial_ends: Option<chrono::DateTime<Utc>>,
) {
    let first_name: Option<String> =
        sqlx::query_scalar("select first_name from users where email = $1")
            .bind(email)
            .fetch_optional(&state.pool)
            .await
            .ok()
            .flatten();
    let message = orchestrator::mailer::subscription_email(
        first_name.as_deref().unwrap_or(""),
        plan.display_name(),
        plan.max_targets(),
        plan.allows_scheduling(),
        &state.mailer.app_link(""),
        trial_ends,
    );
    if let Err(error) = state.mailer.send(email, &message).await {
        tracing::warn!(%error, "could not send the subscription welcome");
    }
}

async fn account_email(state: &AppState, user_id: Uuid) -> ApiResult<String> {
    sqlx::query_scalar("select email from users where id = $1")
        .bind(user_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(ApiError::NotFound)
}

async fn existing_customer(state: &AppState, user_id: Uuid) -> ApiResult<Option<String>> {
    Ok(sqlx::query_scalar(
        "select stripe_customer_id from entitlements
         where user_id = $1 and product = 'glarion'",
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?
    .flatten())
}

/// Takes the trial for this subscription, or reports that the account, its
/// mailbox or its card already had one. Idempotent: the same subscription
/// claims once and is found again on every later event. A card Stripe only
/// reports after the first event is added then, and can still turn the
/// claim into a duplicate.
async fn claim_trial(
    state: &AppState,
    user_id: Uuid,
    email: &str,
    card: Option<&str>,
    subscription_id: &str,
    trial_end: DateTime<Utc>,
) -> ApiResult<bool> {
    let inserted: Option<(Uuid,)> = sqlx::query_as(
        "insert into trial_claims (user_id, email_hash, card_fingerprint, subscription_id, trial_ends_at)
         values ($1, $2, $3, $4, $5)
         on conflict do nothing
         returning id",
    )
    .bind(user_id)
    .bind(email_hash(email))
    .bind(card)
    .bind(subscription_id)
    .bind(trial_end)
    .fetch_optional(&state.pool)
    .await?;
    if inserted.is_some() {
        return Ok(true);
    }

    let ours: Option<Option<String>> =
        sqlx::query_scalar("select card_fingerprint from trial_claims where subscription_id = $1")
            .bind(subscription_id)
            .fetch_optional(&state.pool)
            .await?;
    match (ours, card) {
        // Somebody else's claim stands in the way.
        (None, _) => Ok(false),
        (Some(None), Some(card)) => {
            match sqlx::query(
                "update trial_claims set card_fingerprint = $2
                 where subscription_id = $1 and card_fingerprint is null",
            )
            .bind(subscription_id)
            .bind(card)
            .execute(&state.pool)
            .await
            {
                Ok(_) => Ok(true),
                Err(sqlx::Error::Database(error)) if error.is_unique_violation() => Ok(false),
                Err(error) => Err(error.into()),
            }
        }
        (Some(_), _) => Ok(true),
    }
}

/// Stripe's fingerprint of the card behind a subscription: the same number
/// on every account the card is used with. Only present on the copy read
/// with the payment method expanded.
fn card_fingerprint(subscription: &serde_json::Value) -> Option<String> {
    subscription
        .get("default_payment_method")
        .and_then(|method| method.get("card"))
        .and_then(|card| card.get("fingerprint"))
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// Ends a refused trial at once, before its first invoice, with the reason
/// recorded where Stripe's dashboard shows it.
async fn cancel_subscription(id: &str) -> ApiResult<()> {
    let secret = stripe_secret()?;
    let response = reqwest::Client::new()
        .delete(stripe_url(&format!("/v1/subscriptions/{id}")))
        .basic_auth(&secret, Option::<&str>::None)
        .query(&[("cancellation_details[comment]", TRIAL_REJECTED_COMMENT)])
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|error| ApiError::Internal(anyhow::anyhow!("could not reach Stripe: {error}")))?;
    if !response.status().is_success() {
        // Already cancelled is what we wanted.
        if let Ok(Some(current)) = fetch_subscription(id).await {
            if current.get("status").and_then(|value| value.as_str()) == Some("canceled") {
                return Ok(());
            }
        }
        let payload: serde_json::Value = response.json().await.unwrap_or_default();
        tracing::error!(?payload, "Stripe refused to cancel a refused trial");
        return Err(ApiError::Internal(anyhow::anyhow!("Stripe refused")));
    }
    Ok(())
}

/// Stripe's preview of the invoice the trial ends with: coupon and tax
/// included, so the email and the dashboard quote what will really be
/// taken. None when Stripe cannot say; the copy then names the plan price.
async fn preview_first_charge(subscription_id: &str) -> Option<(i64, String)> {
    let secret = stripe_secret().ok()?;
    let form = vec![("subscription".to_string(), subscription_id.to_string())];
    match stripe_post(&secret, &stripe_url("/v1/invoices/create_preview"), &form).await {
        Ok(invoice) => Some((
            invoice.get("amount_due")?.as_i64()?,
            invoice.get("currency")?.as_str()?.to_string(),
        )),
        Err(_) => None,
    }
}

/// Marks Glarion's own customer-portal configuration in its metadata.
const PORTAL_MARK: &str = "glarion-portal-v1";
static PORTAL_CONFIGURATION: tokio::sync::OnceCell<String> = tokio::sync::OnceCell::const_new();

/// Glarion's own customer-portal configuration: cancel at period end, card,
/// invoices, and plan changes between Glarion's prices only. The account's
/// default configuration is shared with the other products sold through the
/// same Stripe account and offers their prices as "plan changes", which would
/// move a Glarion subscriber onto another product's price. Found by its
/// metadata, created the first time, remembered for the process;
/// STRIPE_PORTAL_CONFIGURATION overrides. None (the account default, as
/// before) when Stripe refuses, so the portal still opens.
// ponytail: two machines starting together can each create one; either works.
pub async fn portal_configuration() -> Option<String> {
    if let Some(id) = std::env::var("STRIPE_PORTAL_CONFIGURATION")
        .ok()
        .filter(|value| value.starts_with("bpc_"))
    {
        return Some(id);
    }
    let secret = stripe_secret().ok()?;
    match PORTAL_CONFIGURATION
        .get_or_try_init(|| ensure_portal_configuration(&secret))
        .await
    {
        Ok(id) => Some(id.clone()),
        Err(error) => {
            tracing::error!(
                ?error,
                "no Glarion portal configuration; using the account default"
            );
            None
        }
    }
}

async fn ensure_portal_configuration(secret: &str) -> ApiResult<String> {
    let existing = stripe_get(
        secret,
        &stripe_url("/v1/billing_portal/configurations"),
        &[("active", "true"), ("limit", "100")],
    )
    .await?;
    if let Some(id) = existing["data"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|config| config["metadata"]["glarion"] == PORTAL_MARK)
        .and_then(|config| config["id"].as_str())
    {
        return Ok(id.to_string());
    }

    // Grouped by product, as the portal wants them: Glarion's plans are
    // separate products per interval on the live account, one on test.
    let mut products: Vec<(String, Vec<String>)> = Vec::new();
    for plan in PAID_PLANS {
        for interval in [Interval::Monthly, Interval::Yearly] {
            let Some(price) = price_env_var(plan, interval)
                .and_then(|var| std::env::var(var).ok())
                .filter(|value| !value.is_empty())
            else {
                continue;
            };
            let read = stripe_get(secret, &stripe_url(&format!("/v1/prices/{price}")), &[]).await?;
            let Some(product) = read["product"].as_str() else {
                continue;
            };
            match products.iter_mut().find(|(id, _)| id == product) {
                Some((_, prices)) => prices.push(price),
                None => products.push((product.to_string(), vec![price])),
            }
        }
    }
    if products.is_empty() {
        return Err(ApiError::Internal(anyhow::anyhow!(
            "no plan prices configured"
        )));
    }

    let mut form: Vec<(String, String)> = [
        (
            "business_profile[headline]",
            "Manage your Glarion subscription",
        ),
        ("features[customer_update][enabled]", "true"),
        ("features[customer_update][allowed_updates][]", "name"),
        ("features[customer_update][allowed_updates][]", "email"),
        ("features[customer_update][allowed_updates][]", "address"),
        ("features[customer_update][allowed_updates][]", "phone"),
        ("features[invoice_history][enabled]", "true"),
        ("features[payment_method_update][enabled]", "true"),
        ("features[subscription_cancel][enabled]", "true"),
        ("features[subscription_cancel][mode]", "at_period_end"),
        ("features[subscription_cancel][proration_behavior]", "none"),
        ("features[subscription_update][enabled]", "true"),
        (
            "features[subscription_update][default_allowed_updates][]",
            "price",
        ),
        (
            "features[subscription_update][proration_behavior]",
            "always_invoice",
        ),
        // Nothing is charged during a trial (Terms): a plan change keeps it.
        (
            "features[subscription_update][trial_update_behavior]",
            "continue_trial",
        ),
        ("metadata[glarion]", PORTAL_MARK),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_string(), value.to_string()))
    .collect();
    for (index, (product, prices)) in products.iter().enumerate() {
        form.push((
            format!("features[subscription_update][products][{index}][product]"),
            product.clone(),
        ));
        for price in prices {
            form.push((
                format!("features[subscription_update][products][{index}][prices][]"),
                price.clone(),
            ));
        }
    }

    let created = stripe_post(
        secret,
        &stripe_url("/v1/billing_portal/configurations"),
        &form,
    )
    .await?;
    created["id"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("Stripe returned no configuration id")))
}

/// Stripe's API. Tests point debug builds at a local stand-in through
/// STRIPE_API_BASE; a release build always talks to Stripe, so a stray
/// variable can never send the secret key anywhere else.
fn stripe_url(path: &str) -> String {
    #[cfg(debug_assertions)]
    if let Some(base) = std::env::var("STRIPE_API_BASE")
        .ok()
        .filter(|value| !value.is_empty())
    {
        return format!("{}{path}", base.trim_end_matches('/'));
    }
    format!("https://api.stripe.com{path}")
}

async fn stripe_get(
    secret: &str,
    url: &str,
    query: &[(&str, &str)],
) -> ApiResult<serde_json::Value> {
    let response = reqwest::Client::new()
        .get(url)
        .basic_auth(secret, Option::<&str>::None)
        .query(query)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|error| ApiError::Internal(anyhow::anyhow!("could not reach Stripe: {error}")))?;
    let status = response.status();
    let payload: serde_json::Value = response.json().await.unwrap_or(serde_json::Value::Null);
    if !status.is_success() {
        tracing::error!(%status, ?payload, "Stripe refused a request");
        return Err(ApiError::Internal(anyhow::anyhow!("Stripe refused")));
    }
    Ok(payload)
}

async fn stripe_post(
    secret: &str,
    url: &str,
    form: &[(String, String)],
) -> ApiResult<serde_json::Value> {
    let response = reqwest::Client::new()
        .post(url)
        .basic_auth(secret, Option::<&str>::None)
        .form(form)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|error| ApiError::Internal(anyhow::anyhow!("could not reach Stripe: {error}")))?;

    let status = response.status();
    let payload: serde_json::Value = response.json().await.unwrap_or(serde_json::Value::Null);

    if !status.is_success() {
        // Stripe's own message goes to the log, not to the caller: it can
        // name internal configuration, and there is nothing a customer can
        // do about it either way.
        tracing::error!(%status, ?payload, "Stripe refused a request");
        return Err(ApiError::Internal(anyhow::anyhow!("Stripe refused")));
    }

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_invoice_names_its_subscription_in_either_shape() {
        let old = serde_json::json!({ "subscription": "sub_old" });
        let basil = serde_json::json!({ "subscription": null, "parent": { "subscription_details": { "subscription": "sub_new" } } });
        assert_eq!(invoice_subscription(&old).as_deref(), Some("sub_old"));
        assert_eq!(invoice_subscription(&basil).as_deref(), Some("sub_new"));
        assert_eq!(invoice_subscription(&serde_json::json!({})), None);
    }

    #[test]
    fn the_card_fingerprint_is_read_only_from_the_expanded_method() {
        let expanded =
            serde_json::json!({ "default_payment_method": { "card": { "fingerprint": "fp_1" } } });
        let bare = serde_json::json!({ "default_payment_method": "pm_1" });
        assert_eq!(card_fingerprint(&expanded).as_deref(), Some("fp_1"));
        assert_eq!(card_fingerprint(&bare), None);
    }
}
