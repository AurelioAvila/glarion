//! Subscribing, managing, and hearing back from Stripe.
//!
//! Money never moves through this application. Checkout and the customer
//! portal are hosted by Stripe, so no card detail ever reaches our servers
//! and the whole of PCI compliance stays somebody else's problem. What we
//! keep is a customer id and what they are entitled to.

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::Json;
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::billing::{
    blocked_reason, consent_required, current_access, email_hash, plan_for_price, price_env_var,
    status_grants_access, status_keeps_plan, trial_days, trial_enabled, user_agent_family,
    verify_signature, Interval, Plan, CONSENT_KEY, DISPUTE_MARK, PAID_PLANS, TERMS_VERSION,
    TRIAL_DAYS, TRIAL_MARKER_KEY, TRIAL_MARKER_VALUE, TRIAL_MAX_SCANS_PER_TARGET_PER_DAY,
    TRIAL_REJECTED_COMMENT,
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
    /// `none`, `payment_failed`, `canceled`, `trial_already_used` or
    /// `disputed` (held while a bank looks at a disputed payment).
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
    /// The Terms the tick box before checkout accepts; checkout is sent it
    /// back, so a page opened before the Terms changed is caught.
    pub terms_version: &'static str,
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
            Some("disputed") => "disputed",
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
        terms_version: TERMS_VERSION,
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
    /// The tick box before Stripe. Absent from dashboards that predate it.
    #[serde(default)]
    pub consent: Option<CheckoutConsent>,
}

#[derive(Deserialize)]
pub struct CheckoutConsent {
    #[serde(default)]
    pub accepted: bool,
    /// The `terms_version` the page was given with the plan.
    #[serde(default)]
    pub terms_version: String,
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
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Json(body): Json<CheckoutRequest>,
) -> ApiResult<Json<CheckoutResponse>> {
    let plan = Plan::from_db_str(&body.plan);
    if plan == Plan::Free {
        return Err(ApiError::BadRequest(
            "choose a paid plan to subscribe".into(),
        ));
    }

    // The tick box before Stripe (owner decision, 3 November 2026): the
    // Terms, immediate access and the end of the right of withdrawal. With
    // CHECKOUT_CONSENT_REQUIRED off a ticked box is recorded and a missing one
    // still goes through, so no purchase breaks while pages roll out; with it
    // on, no consent or consent to older Terms is refused before Stripe.
    let consent = body
        .consent
        .as_ref()
        .filter(|consent| consent.accepted)
        .map(|consent| {
            consent
                .terms_version
                .trim()
                .chars()
                .take(32)
                .collect::<String>()
        });
    if consent_required() {
        match consent.as_deref() {
            None => {
                return Err(ApiError::BadRequest(
                    "Tick the box to accept the Terms before checkout.".into(),
                ))
            }
            Some(version) if version != TERMS_VERSION => {
                return Err(ApiError::Conflict(
                    "The Terms have changed since this page was opened. Reload it and tick the box again.".into(),
                ))
            }
            Some(_) => {}
        }
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
    // The account's customer: the one stored, or, in the seconds between
    // paying and Stripe's webhook reaching us, the one its completed checkout
    // created. Reused either way, so a person stays one customer.
    let customer_id = match existing_customer(&state, user.id).await? {
        Some(id) => Some(id),
        None => completed_checkout_customer(&secret, user.id, &email).await?,
    };
    // The row above says nothing yet about a payment Stripe has but the
    // webhook has not applied: a second click then would start a second
    // subscription and charge twice. Stripe is asked instead.
    if let Some(customer) = customer_id.as_deref() {
        if has_live_subscription(&secret, customer).await? {
            return Err(ApiError::Conflict(
                "Your payment is still being confirmed by Stripe. Your plan appears on this page as soon as it is, so there is no need to pay again.".into(),
            ));
        }
    }

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
    // see. After paying it carries the session (Stripe fills the template),
    // so the page waits for Stripe's confirmation instead of offering the
    // plans again while the webhook is on its way.
    let plan_page = state.mailer.app_link("/plan");
    let mut form: Vec<(String, String)> = vec![
        ("mode".into(), "subscription".into()),
        ("line_items[0][price]".into(), price_id),
        ("line_items[0][quantity]".into(), "1".into()),
        (
            "success_url".into(),
            format!("{plan_page}?checkout={{CHECKOUT_SESSION_ID}}"),
        ),
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
        // The full billing address, not only the country Managed Payments
        // asks for outside the US: more for Stripe's fraud screening to match
        // against the card, so fewer genuine buyers are blocked.
        ("billing_address_collection".into(), "required".into()),
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

    // The consent is written before Stripe is asked, so no session exists
    // without its record, and is named on the session and the subscription
    // it creates: the welcome mail reads it there, and a dispute can be
    // answered with the row.
    let mut consent_id = None;
    if let Some(version) = consent.as_deref() {
        let user_agent = headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        let interval_name = match interval {
            Interval::Monthly => "monthly",
            Interval::Yearly => "yearly",
        };
        let id: Uuid = sqlx::query_scalar(
            "insert into checkout_consents (user_id, plan, terms_version, ip, user_agent_family)
             values ($1, $2, $3, $4, $5)
             returning id",
        )
        .bind(user.id)
        .bind(format!("{}_{interval_name}", plan.as_db_str()))
        .bind(version)
        .bind(peer.ip().to_string())
        .bind(user_agent_family(user_agent))
        .fetch_one(&state.pool)
        .await?;
        for prefix in ["metadata", "subscription_data[metadata]"] {
            form.push((format!("{prefix}[{CONSENT_KEY}]"), id.to_string()));
            form.push((format!("{prefix}[terms_version]"), version.to_string()));
        }
        consent_id = Some(id);
    }

    let session = stripe_post(&secret, &stripe_url("/v1/checkout/sessions"), &form).await?;
    let url = session
        .get("url")
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("Stripe returned no checkout url")))?;
    // The session exists by now, so a failure here must not cost the buyer
    // their checkout: the row still holds the consent and the session names it.
    if let Some(id) = consent_id {
        if let Err(error) =
            sqlx::query("update checkout_consents set checkout_session_id = $2 where id = $1")
                .bind(id)
                .bind(session.get("id").and_then(|value| value.as_str()))
                .execute(&state.pool)
                .await
        {
            tracing::warn!(%error, %id, "could not store the checkout session on its consent");
        }
    }

    Ok(Json(CheckoutResponse {
        url,
        trial: trial.is_some(),
        trial_days: trial,
    }))
}

/// A first payment at Checkout that was declined or blocked (Stripe's
/// network-level fraud screening cannot be switched off) gets one email
/// offering the same plan again with another card, Apple Pay, Google Pay or
/// Link.
///
/// Our webhook does not receive `payment_intent.payment_failed`, so the
/// Events API is read instead. A failed subscription start is a PaymentIntent
/// described "Subscription creation" with no metadata; its customer is the
/// Checkout Session's, which carries the account (`client_reference_id`) and
/// the price. Only failures between 30 minutes and a day old, so someone
/// still retrying on Stripe's page is not interrupted and the same failure is
/// never seen after its claim has lapsed. Skipped once the account has a
/// plan in force (they paid after all), and at most one per account and plan
/// a day, claimed before sending. A failed send is not retried: missing one
/// beats sending two.
pub async fn recover_failed_checkouts(state: &AppState, now: DateTime<Utc>) -> ApiResult<usize> {
    let Some(secret) = std::env::var("STRIPE_SECRET_KEY")
        .ok()
        .filter(|value| !value.is_empty())
    else {
        return Ok(0);
    };
    let from = (now - chrono::Duration::hours(24)).timestamp().to_string();
    let to = (now - chrono::Duration::minutes(30))
        .timestamp()
        .to_string();
    // ponytail: one page of 100 failures a day; paginate if that ever fills.
    let events = stripe_get(
        &secret,
        &stripe_url("/v1/events"),
        &[
            ("type", "payment_intent.payment_failed"),
            ("created[gte]", &from),
            ("created[lte]", &to),
            ("limit", "100"),
        ],
    )
    .await?;
    let mut sent = 0;
    for event in events["data"].as_array().into_iter().flatten() {
        let intent = &event["data"]["object"];
        // Renewals are "Subscription cycle"/"update" and have their own notice.
        if intent["description"].as_str() != Some("Subscription creation") {
            continue;
        }
        let (Some(customer), Some(failed_at)) =
            (intent["customer"].as_str(), intent["created"].as_i64())
        else {
            continue;
        };
        // One unreadable record must not stall every other recovery.
        let Ok(sessions) = stripe_get(
            &secret,
            &stripe_url("/v1/checkout/sessions"),
            &[("customer", customer), ("limit", "10")],
        )
        .await
        else {
            continue;
        };
        // Newest first: the session the failed attempt was made in.
        let Some(session) = sessions["data"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|session| {
                session["created"]
                    .as_i64()
                    .is_some_and(|at| at <= failed_at)
            })
        else {
            continue;
        };
        if session["status"].as_str() == Some("complete") {
            continue;
        }
        let (Some(session_id), Some(user_id)) = (
            session["id"].as_str(),
            session["client_reference_id"]
                .as_str()
                .and_then(|value| Uuid::parse_str(value).ok()),
        ) else {
            continue;
        };
        let Ok(items) = stripe_get(
            &secret,
            &stripe_url(&format!("/v1/checkout/sessions/{session_id}/line_items")),
            &[],
        )
        .await
        else {
            continue;
        };
        // Another product on the same Stripe account matches no Glarion price.
        let Some((plan, interval)) = items["data"][0]["price"]["id"]
            .as_str()
            .and_then(plan_and_interval_for_price)
        else {
            continue;
        };
        let account: Option<(String, Option<String>, Option<String>)> = sqlx::query_as(
            "select u.email, u.first_name, e.subscription_status from users u
             left join entitlements e on e.user_id = u.id and e.product = 'glarion'
             where u.id = $1",
        )
        .bind(user_id)
        .fetch_optional(&state.pool)
        .await?;
        let Some((email, first_name, status)) = account else {
            continue;
        };
        if status.as_deref().is_some_and(status_grants_access) {
            continue;
        }
        let claimed: Option<(i64,)> = sqlx::query_as(
            "insert into rate_limit_buckets (scope, client_key, window_started_at, attempt_count)
             values ('checkout_recovery', $1, now(), 1)
             on conflict (scope, client_key) do update set window_started_at = now()
               where rate_limit_buckets.window_started_at <= now() - interval '24 hours'
             returning attempt_count",
        )
        .bind(format!("{user_id}:{}", plan.as_db_str()))
        .fetch_optional(&state.pool)
        .await?;
        if claimed.is_none() {
            continue;
        }
        let interval = match interval {
            Interval::Monthly => "monthly",
            Interval::Yearly => "yearly",
        };
        let message = orchestrator::mailer::checkout_failed_email(
            first_name.as_deref().unwrap_or(""),
            plan.display_name(),
            &state.mailer.app_link(&format!(
                "/plan?plan={}&interval={interval}",
                plan.as_db_str()
            )),
        );
        match state.mailer.send(&email, &message).await {
            Ok(()) => sent += 1,
            Err(error) => {
                tracing::warn!(%error, %user_id, "could not send the checkout recovery email; not retried")
            }
        }
    }
    Ok(sent)
}

/// Every quarter of an hour, for as long as the API runs. The same pass
/// deletes checkout consents once they are 13 months old, as the privacy
/// notice says.
pub async fn recover_failed_checkouts_forever(state: AppState) {
    loop {
        if let Err(error) = recover_failed_checkouts(&state, Utc::now()).await {
            tracing::warn!(
                ?error,
                "checkout recovery pass failed; the next pass retries"
            );
        }
        if let Err(error) = sqlx::query(
            "delete from checkout_consents where accepted_at < now() - interval '13 months'",
        )
        .execute(&state.pool)
        .await
        {
            tracing::warn!(%error, "could not delete old checkout consents; the next pass retries");
        }
        tokio::time::sleep(std::time::Duration::from_secs(15 * 60)).await;
    }
}

fn plan_and_interval_for_price(price_id: &str) -> Option<(Plan, Interval)> {
    PAID_PLANS.into_iter().find_map(|plan| {
        [Interval::Monthly, Interval::Yearly]
            .into_iter()
            .find(|&interval| {
                price_env_var(plan, interval)
                    .and_then(|var| std::env::var(var).ok())
                    .is_some_and(|configured| !configured.is_empty() && configured == price_id)
            })
            .map(|interval| (plan, interval))
    })
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

// --- Manage subscription ----------------------------------------------------
//
// The account menu's panel: what this account pays for, and cancelling or
// resuming it without leaving the dashboard. Cancelling is always at the end
// of the period already paid for, never immediate and never a refund. Every
// call acts on the caller's own subscription only: the request never names
// one, it is read from the caller's entitlement and checked against the
// caller's Stripe customer.

/// The reasons a customer can give, as Stripe records them
/// (`cancellation_details.feedback`), with the label they saw.
pub const CANCEL_REASONS: [(&str, &str); 8] = [
    ("too_expensive", "Too expensive"),
    ("unused", "I don't use it enough"),
    ("missing_features", "Missing a feature I need"),
    ("switched_service", "Switching to another tool"),
    ("low_quality", "Technical problems / bugs"),
    ("too_complex", "Too complicated to use"),
    ("customer_service", "Problems with support"),
    ("other", "Other"),
];

/// The longest comment kept, in characters.
pub const CANCEL_COMMENT_MAX: usize = 500;

/// Where the cancellation notice goes: the inbox the owner reads for every
/// product's sales.
const OWNER_NOTICE_TO: &str = "support@pctweaker.app";

/// Per account, per quarter of an hour.
const MANAGE_WINDOW: std::time::Duration = std::time::Duration::from_secs(15 * 60);
const MANAGE_READS_PER_WINDOW: u32 = 120;
const MANAGE_WRITES_PER_WINDOW: u32 = 20;

#[derive(Serialize)]
pub struct Card {
    pub brand: String,
    pub last4: String,
}

/// What the Manage subscription panel shows.
#[derive(Serialize)]
pub struct ManagedSubscription {
    pub product: &'static str,
    /// `free`, `solo`, `studio` or `agency`.
    pub plan: String,
    pub plan_name: String,
    /// `month` or `year`; null without a subscription.
    pub interval: Option<String>,
    /// The plan's list price per interval in minor units, before tax and
    /// discounts.
    pub amount: Option<i64>,
    pub currency: Option<String>,
    /// Stripe's status (`active`, `trialing`, `past_due`, `unpaid`,
    /// `paused`), or `none`.
    pub status: String,
    pub trial_end: Option<DateTime<Utc>>,
    /// The renewal date, or the last day of access once it is set to end.
    pub current_period_end: Option<DateTime<Utc>>,
    pub cancel_at_period_end: bool,
    pub cancel_at: Option<DateTime<Utc>>,
    /// Card only; null for Link, wallets or when unknown.
    pub payment_method: Option<Card>,
    /// Glarion sells no lifetime plan. Kept for the shared contract.
    pub lifetime: bool,
    pub can_cancel: bool,
    pub can_resume: bool,
    pub sites_used: i64,
    pub max_sites: i32,
    /// Whether Stripe's portal (card, invoices) has anything to show.
    pub portal: bool,
}

#[derive(Deserialize, Default)]
pub struct CancelRequest {
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub comment: Option<String>,
}

/// The reason, checked against Stripe's own list, and the comment with
/// control characters and runs of whitespace folded to single spaces.
pub fn clean_cancel_feedback(
    reason: Option<&str>,
    comment: Option<&str>,
) -> ApiResult<(Option<&'static str>, Option<String>)> {
    let reason = match reason.map(str::trim).filter(|value| !value.is_empty()) {
        None => None,
        Some(value) => Some(
            CANCEL_REASONS
                .iter()
                .map(|(code, _)| *code)
                .find(|code| *code == value)
                .ok_or_else(|| ApiError::BadRequest("unknown cancellation reason".into()))?,
        ),
    };
    let comment = comment
        .unwrap_or("")
        .split(|c: char| c.is_whitespace() || c.is_control())
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if comment.chars().count() > CANCEL_COMMENT_MAX {
        return Err(ApiError::BadRequest(format!(
            "the comment is longer than {CANCEL_COMMENT_MAX} characters"
        )));
    }
    Ok((reason, (!comment.is_empty()).then_some(comment)))
}

/// The caller's billing records.
struct Owned {
    email: String,
    customer: Option<String>,
    subscription: Option<String>,
    sites_used: i64,
}

async fn owned(state: &AppState, user_id: Uuid) -> ApiResult<Owned> {
    let row: (String, Option<String>, Option<String>, i64) = sqlx::query_as(
        "select u.email, e.stripe_customer_id, e.stripe_subscription_id,
                (select count(*) from targets t where t.user_id = u.id)
           from users u
           left join entitlements e on e.user_id = u.id and e.product = 'glarion'
          where u.id = $1",
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(Owned {
        email: row.0,
        customer: row.1,
        subscription: row.2,
        sites_used: row.3,
    })
}

async fn manage_rate_limit(
    state: &AppState,
    user_id: Uuid,
    scope: &str,
    limit: u32,
) -> ApiResult<()> {
    let allowed = crate::rate_limit::RateLimiter::new(limit, MANAGE_WINDOW)
        .check_shared_key(&state.pool, scope, &user_id.to_string())
        .await;
    if allowed {
        Ok(())
    } else {
        Err(ApiError::TooManyRequests)
    }
}

/// The caller's subscription as Stripe has it now, when one has not ended
/// and it belongs to the caller's own customer.
async fn live_subscription(owned: &Owned) -> ApiResult<Option<serde_json::Value>> {
    let (Some(customer), Some(id)) = (owned.customer.as_deref(), owned.subscription.as_deref())
    else {
        return Ok(None);
    };
    let secret = stripe_secret().map_err(|_| ApiError::BillingUnavailable)?;
    let subscription = stripe_get(
        &secret,
        &stripe_url(&format!("/v1/subscriptions/{id}")),
        &[("expand[]", "default_payment_method")],
    )
    .await
    .map_err(|_| ApiError::BillingUnavailable)?;
    let ours = subscription["customer"].as_str() == Some(customer);
    let live = matches!(
        subscription["status"].as_str(),
        Some("active" | "trialing" | "past_due" | "unpaid" | "paused")
    );
    Ok((ours && live).then_some(subscription))
}

fn timestamp(value: &serde_json::Value) -> Option<DateTime<Utc>> {
    value
        .as_i64()
        .and_then(|seconds| Utc.timestamp_opt(seconds, 0).single())
}

/// The panel's view of the caller's subscription, or of the free plan.
fn managed_view(
    subscription: Option<&serde_json::Value>,
    access: crate::billing::Access,
    owned: &Owned,
) -> ManagedSubscription {
    let mut view = ManagedSubscription {
        product: "glarion",
        plan: access.plan.as_db_str().to_string(),
        plan_name: access.plan.display_name().to_string(),
        interval: None,
        amount: None,
        currency: None,
        status: "none".into(),
        trial_end: None,
        current_period_end: None,
        cancel_at_period_end: false,
        cancel_at: None,
        payment_method: None,
        lifetime: false,
        can_cancel: false,
        can_resume: false,
        sites_used: owned.sites_used,
        max_sites: access.max_targets(),
        portal: owned.customer.is_some(),
    };
    let Some(subscription) = subscription else {
        return view;
    };

    let item = &subscription["items"]["data"][0];
    let price = &item["price"];
    if let Some(plan) = price["id"].as_str().and_then(plan_for_price) {
        view.plan = plan.as_db_str().to_string();
        view.plan_name = plan.display_name().to_string();
    }
    view.interval = price["recurring"]["interval"].as_str().map(str::to_string);
    view.amount = price["unit_amount"]
        .as_i64()
        .map(|amount| amount * item["quantity"].as_i64().unwrap_or(1));
    view.currency = price["currency"].as_str().map(str::to_string);
    view.status = subscription["status"]
        .as_str()
        .unwrap_or("none")
        .to_string();
    view.trial_end = (view.status == "trialing")
        .then(|| timestamp(&subscription["trial_end"]))
        .flatten();
    view.current_period_end = timestamp(&item["current_period_end"])
        .or_else(|| timestamp(&subscription["current_period_end"]));
    view.cancel_at_period_end = subscription["cancel_at_period_end"].as_bool() == Some(true);
    view.cancel_at = timestamp(&subscription["cancel_at"]);
    let card = &subscription["default_payment_method"]["card"];
    view.payment_method = match (card["brand"].as_str(), card["last4"].as_str()) {
        (Some(brand), Some(last4)) => Some(Card {
            brand: brand.to_string(),
            last4: last4.to_string(),
        }),
        _ => None,
    };
    let running = matches!(view.status.as_str(), "active" | "trialing" | "past_due");
    let ending = view.cancel_at_period_end || view.cancel_at.is_some();
    view.can_cancel = running && !ending;
    view.can_resume = running && ending;
    view
}

/// GET /api/billing/subscription: the caller's subscription, read live from
/// Stripe.
pub async fn manage_subscription(
    State(state): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<ManagedSubscription>> {
    manage_rate_limit(&state, user.id, "billing_read", MANAGE_READS_PER_WINDOW).await?;
    let owned = owned(&state, user.id).await?;
    let subscription = live_subscription(&owned).await?;
    let access = current_access(&state.pool, user.id).await?;
    Ok(Json(managed_view(subscription.as_ref(), access, &owned)))
}

/// POST /api/billing/subscription/cancel: ends the caller's subscription at
/// the end of the period already paid for, with the optional reason and
/// comment stored on Stripe's own cancellation details. Asking again changes
/// nothing and sends nothing.
pub async fn schedule_cancellation(
    State(state): State<AppState>,
    user: AuthUser,
    Json(body): Json<CancelRequest>,
) -> ApiResult<Json<ManagedSubscription>> {
    let (reason, comment) = clean_cancel_feedback(body.reason.as_deref(), body.comment.as_deref())?;
    manage_rate_limit(&state, user.id, "billing_write", MANAGE_WRITES_PER_WINDOW).await?;
    let owned = owned(&state, user.id).await?;
    let current = live_subscription(&owned).await?.ok_or(ApiError::NotFound)?;
    let access = current_access(&state.pool, user.id).await?;
    let view = managed_view(Some(&current), access, &owned);
    if view.can_resume {
        return Ok(Json(view));
    }
    if !view.can_cancel {
        return Err(ApiError::Conflict(
            "this subscription can only be changed in the billing portal".into(),
        ));
    }

    let id = current["id"].as_str().unwrap_or_default().to_string();
    let mut form: Vec<(String, String)> = vec![
        ("cancel_at_period_end".into(), "true".into()),
        ("expand[]".into(), "default_payment_method".into()),
    ];
    if let Some(reason) = reason {
        form.push(("cancellation_details[feedback]".into(), reason.into()));
    }
    if let Some(comment) = &comment {
        form.push(("cancellation_details[comment]".into(), comment.clone()));
    }
    let secret = stripe_secret().map_err(|_| ApiError::BillingUnavailable)?;
    let updated = stripe_post(
        &secret,
        &stripe_url(&format!("/v1/subscriptions/{id}")),
        &form,
    )
    .await
    .map_err(|_| ApiError::BillingUnavailable)?;
    let view = managed_view(Some(&updated), access, &owned);
    record_cancel_flag(&state, user.id, view.can_resume).await?;
    tracing::info!(
        audit = "subscription_cancel_scheduled",
        user_id = %user.id,
        subscription = %id,
        reason = reason.unwrap_or("none"),
        ends = ?view.cancel_at.or(view.current_period_end),
        "subscription set to cancel at period end"
    );
    notify_owner_of_cancellation(&state, &owned, &view, &id, reason, comment.as_deref()).await;
    Ok(Json(view))
}

/// POST /api/billing/subscription/resume: undoes a scheduled cancellation.
/// Asking again changes nothing.
pub async fn resume_subscription(
    State(state): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<ManagedSubscription>> {
    manage_rate_limit(&state, user.id, "billing_write", MANAGE_WRITES_PER_WINDOW).await?;
    let owned = owned(&state, user.id).await?;
    let current = live_subscription(&owned).await?.ok_or(ApiError::NotFound)?;
    let access = current_access(&state.pool, user.id).await?;
    let view = managed_view(Some(&current), access, &owned);
    if !view.can_resume {
        return Ok(Json(view));
    }

    let id = current["id"].as_str().unwrap_or_default().to_string();
    // Stripe takes one or the other: the flag, or a date set elsewhere.
    let clear = if view.cancel_at_period_end {
        ("cancel_at_period_end", "false")
    } else {
        ("cancel_at", "")
    };
    let form: Vec<(String, String)> = vec![
        (clear.0.into(), clear.1.into()),
        ("expand[]".into(), "default_payment_method".into()),
    ];
    let secret = stripe_secret().map_err(|_| ApiError::BillingUnavailable)?;
    let updated = stripe_post(
        &secret,
        &stripe_url(&format!("/v1/subscriptions/{id}")),
        &form,
    )
    .await
    .map_err(|_| ApiError::BillingUnavailable)?;
    let view = managed_view(Some(&updated), access, &owned);
    record_cancel_flag(&state, user.id, view.can_resume).await?;
    tracing::info!(
        audit = "subscription_resumed",
        user_id = %user.id,
        subscription = %id,
        "subscription resumed"
    );
    Ok(Json(view))
}

/// Mirrors the change at once, so the Pricing page agrees before Stripe's
/// webhook arrives (which writes the same value).
async fn record_cancel_flag(state: &AppState, user_id: Uuid, ending: bool) -> ApiResult<()> {
    sqlx::query(
        "update entitlements set cancel_at_period_end = $2
          where user_id = $1 and product = 'glarion'",
    )
    .bind(user_id)
    .bind(ending)
    .execute(&state.pool)
    .await?;
    Ok(())
}

/// One email to the owner per cancellation: claimed per subscription and
/// end date before sending, so a retry or a resume-and-cancel within the
/// same period cannot send a second. Best effort: the cancellation stands
/// whatever happens to the email.
async fn notify_owner_of_cancellation(
    state: &AppState,
    owned: &Owned,
    view: &ManagedSubscription,
    subscription_id: &str,
    reason: Option<&str>,
    comment: Option<&str>,
) {
    let Some(ends) = view.cancel_at.or(view.current_period_end) else {
        return;
    };
    let claimed: Result<Option<(i64,)>, _> = sqlx::query_as(
        "insert into rate_limit_buckets (scope, client_key, window_started_at, attempt_count)
         values ('cancel_notice', $1, now(), 1)
         on conflict (scope, client_key) do nothing
         returning attempt_count",
    )
    .bind(format!("{subscription_id}:{}", ends.timestamp()))
    .fetch_optional(&state.pool)
    .await;
    if !matches!(claimed, Ok(Some(_))) {
        return;
    }
    let interval = match view.interval.as_deref() {
        Some("year") => "Yearly",
        Some("month") => "Monthly",
        _ => "Subscription",
    };
    let plan = format!("{} — {interval}", view.plan_name);
    let country = customer_country(owned.customer.as_deref()).await;
    let message = orchestrator::mailer::cancellation_notice_email(
        &orchestrator::mailer::CancellationNotice {
            plan: &plan,
            email: &owned.email,
            country: country.as_deref(),
            ends,
            reason: reason.and_then(|code| {
                CANCEL_REASONS
                    .iter()
                    .find(|(known, _)| *known == code)
                    .map(|(_, label)| *label)
            }),
            comment,
            reference: subscription_id,
        },
    );
    if let Err(error) = state.mailer.send(OWNER_NOTICE_TO, &message).await {
        tracing::warn!(%error, "could not send the cancellation notice; not retried");
    }
}

/// The billing country Stripe holds for the customer, when it can say.
async fn customer_country(customer: Option<&str>) -> Option<String> {
    let secret = stripe_secret().ok()?;
    let found = stripe_get(
        &secret,
        &stripe_url(&format!("/v1/customers/{}", customer?)),
        &[],
    )
    .await
    .ok()?;
    found["address"]["country"].as_str().map(str::to_string)
}

/// Sends an existing subscriber to Stripe's own portal to change card,
/// see invoices, switch plan, or cancel there too.
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

            // Never over a customer whose subscription is still live: a
            // second checkout paid before the first reached us would move the
            // account to the new customer and leave the first subscription
            // out of Manage billing. The duplicate is dealt with when its
            // subscription arrives (apply_subscription).
            if let (Some(user_id), Some(customer)) = (user_id, customer) {
                sqlx::query(
                    "update entitlements set stripe_customer_id = $2
                     where user_id = $1 and product = 'glarion'
                       and (stripe_customer_id is null or stripe_customer_id = $2
                            or subscription_status is null
                            or subscription_status not in ('active', 'trialing', 'past_due'))",
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
            if other_product(state, object, id).await? {
                return Ok(());
            }
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
            if other_product(state, object, &id).await? {
                return Ok(());
            }
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

        "charge.dispute.created" | "charge.dispute.closed" => settle_dispute(state, object).await,

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

/// The prices a subscription (`items`) or invoice (`lines`) names, in either
/// API version's shape: `price` as an object or an id, or the newer
/// `pricing.price_details.price` on invoice lines.
fn payload_prices(object: &serde_json::Value) -> Vec<&str> {
    ["items", "lines"]
        .into_iter()
        .filter_map(|key| object.get(key)?.get("data")?.as_array())
        .flatten()
        .filter_map(|line| {
            line.get("price")
                .and_then(|price| price.get("id").unwrap_or(price).as_str())
                .or_else(|| {
                    line.get("pricing")?
                        .get("price_details")?
                        .get("price")?
                        .as_str()
                })
        })
        .collect()
}

/// Another product's subscription on the shared Stripe account (PC Tweaker
/// sells through it too): the event names prices, none of them Glarion's,
/// and no account here holds the subscription. Skipped before the Stripe
/// read-back, which would otherwise run for every one of their events. An
/// event that names no price is not judged here, and a Glarion subscription
/// moved onto a price no longer configured still has its account's row, so
/// both are applied as before.
async fn other_product(
    state: &AppState,
    object: &serde_json::Value,
    subscription_id: &str,
) -> ApiResult<bool> {
    let prices = payload_prices(object);
    if prices.is_empty() || prices.iter().any(|price| plan_for_price(price).is_some()) {
        return Ok(false);
    }
    let ours: bool = sqlx::query_scalar(
        "select exists (select 1 from entitlements
                         where product = 'glarion' and stripe_subscription_id = $1)",
    )
    .bind(subscription_id)
    .fetch_one(&state.pool)
    .await?;
    Ok(!ours)
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

/// Written to `cancellation_details.comment` when a lost dispute ends a
/// subscription.
const DISPUTE_LOST_COMMENT: &str = "dispute_lost";

/// Where a dispute stands, as Stripe has it now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DisputeOutcome {
    Open,
    Lost,
    /// Won, an inquiry closed without a dispute, or prevented.
    Cleared,
}

fn dispute_outcome(status: &str) -> DisputeOutcome {
    match status {
        "lost" => DisputeOutcome::Lost,
        "won" | "warning_closed" | "prevented" => DisputeOutcome::Cleared,
        _ => DisputeOutcome::Open,
    }
}

/// A payment of one of our subscriptions is disputed (owner decision,
/// 3 November 2026). While the bank looks at it the plan is held and
/// collection paused, so nothing more is charged to a card that is
/// contesting; if the payment stands everything comes back, and if it is
/// lost the subscription ends at once. Sites and schedules are kept until
/// then.
///
/// The outcome is read from Stripe's list of the charge's disputes rather
/// than taken from the event, so `created` and `closed` arriving twice or in
/// either order settle the same way. One that is not listed yet is an error,
/// which Stripe answers by delivering the event again.
///
/// ponytail: one mark per subscription. Two payments of the same
/// subscription disputed at once release the hold when the first is won.
async fn settle_dispute(state: &AppState, dispute: &serde_json::Value) -> ApiResult<()> {
    let Some(charge) = dispute.get("charge").and_then(|value| value.as_str()) else {
        return Ok(());
    };
    let Some(secret) = std::env::var("STRIPE_SECRET_KEY")
        .ok()
        .filter(|value| !value.is_empty())
    else {
        tracing::warn!(charge, "no STRIPE_SECRET_KEY to settle a dispute");
        return Ok(());
    };
    // Not a subscription payment, or another product's.
    let Some(invoice) = disputed_invoice(&secret, dispute).await? else {
        return Ok(());
    };
    let Some(subscription_id) = invoice_subscription(&invoice) else {
        return Ok(());
    };
    if other_product(state, &invoice, &subscription_id).await? {
        return Ok(());
    }

    with_customer_lock(state, &invoice, async {
        let Some(subscription) = fetch_subscription(&subscription_id).await? else {
            return Ok(());
        };
        let status = subscription["status"].as_str().unwrap_or("");
        let marked = subscription["metadata"][DISPUTE_MARK]
            .as_str()
            .unwrap_or("");
        let outcome = current_dispute_outcome(&secret, charge, dispute).await?;
        let path = stripe_url(&format!("/v1/subscriptions/{subscription_id}"));
        match outcome {
            DisputeOutcome::Lost => {
                if status != "canceled" {
                    cancel_subscription(&subscription_id, DISPUTE_LOST_COMMENT).await?;
                }
            }
            DisputeOutcome::Open => {
                if marked.is_empty() && status_grants_access(status) {
                    let form = [
                        ("pause_collection[behavior]".to_string(), "void".to_string()),
                        (format!("metadata[{DISPUTE_MARK}]"), charge.to_string()),
                    ];
                    stripe_post(&secret, &path, &form).await?;
                }
            }
            DisputeOutcome::Cleared => {
                if marked == charge {
                    let form = [
                        ("pause_collection".to_string(), String::new()),
                        (format!("metadata[{DISPUTE_MARK}]"), String::new()),
                    ];
                    stripe_post(&secret, &path, &form).await?;
                }
            }
        }
        tracing::info!(charge, subscription = %subscription_id, ?outcome, "dispute settled");
        match fetch_subscription(&subscription_id).await? {
            Some(fresh) => apply_subscription(state, &fresh).await,
            None => Ok(()),
        }
    })
    .await
}

/// The invoice a disputed payment paid. Since API 2025-03-31 a dispute names
/// only the PaymentIntent, and the invoice is found through the invoice
/// payments that used it.
async fn disputed_invoice(
    secret: &str,
    dispute: &serde_json::Value,
) -> ApiResult<Option<serde_json::Value>> {
    let id_of = |value: &serde_json::Value| {
        value
            .as_str()
            .or_else(|| value.get("id")?.as_str())
            .map(str::to_string)
    };
    let Some(intent) = id_of(&dispute["payment_intent"]) else {
        return Ok(None);
    };
    let paid = stripe_get(
        secret,
        &stripe_url("/v1/invoice_payments"),
        &[
            ("payment[type]", "payment_intent"),
            ("payment[payment_intent]", &intent),
            ("limit", "1"),
        ],
    )
    .await?;
    let Some(invoice) = id_of(&paid["data"][0]["invoice"]) else {
        return Ok(None);
    };
    Ok(Some(
        stripe_get(secret, &stripe_url(&format!("/v1/invoices/{invoice}")), &[]).await?,
    ))
}

/// The dispute's outcome from Stripe's list of the charge's disputes. A key
/// without read access to disputes falls back to the event's own copy.
async fn current_dispute_outcome(
    secret: &str,
    charge: &str,
    dispute: &serde_json::Value,
) -> ApiResult<DisputeOutcome> {
    let response = reqwest::Client::new()
        .get(stripe_url("/v1/disputes"))
        .basic_auth(secret, Option::<&str>::None)
        .query(&[("charge", charge)])
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|error| ApiError::Internal(anyhow::anyhow!("could not reach Stripe: {error}")))?;
    if response.status() == reqwest::StatusCode::FORBIDDEN {
        tracing::warn!(
            charge,
            "the Stripe key cannot read disputes; using the event's copy"
        );
        return Ok(dispute_outcome(dispute["status"].as_str().unwrap_or("")));
    }
    let status = response.status();
    let listed: serde_json::Value = response.json().await.unwrap_or_default();
    if !status.is_success() {
        tracing::error!(%status, ?listed, "Stripe refused a request");
        return Err(ApiError::Internal(anyhow::anyhow!("Stripe refused")));
    }
    let id = dispute["id"].as_str();
    listed["data"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|row| id.is_none() || row["id"].as_str() == id)
        .and_then(|row| row["status"].as_str())
        .map(dispute_outcome)
        .ok_or_else(|| {
            ApiError::Internal(anyhow::anyhow!(
                "the dispute is not listed yet; Stripe redelivers"
            ))
        })
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
    // A payment under dispute holds the plan for as long as the mark is on
    // the subscription (settle_dispute), whatever event brings it here.
    let disputed = subscription
        .get("metadata")
        .and_then(|value| value.get(DISPUTE_MARK))
        .and_then(|value| value.as_str())
        .is_some_and(|value| !value.is_empty());
    let keeps_plan = status_keeps_plan(status, strict);
    let plan = match (keeps_plan && !disputed, plan_for_price(price_id)) {
        (true, Some(plan)) => plan,
        _ => Plan::Free,
    };
    let reason = if disputed && keeps_plan {
        "disputed"
    } else if plan == Plan::Free && !status.is_empty() {
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
        blocked_reason: Option<String>,
    }
    let previous: Option<Previous> = sqlx::query_as(
        "select e.plan, e.user_id, u.email, u.first_name, e.subscription_status,
                e.stripe_subscription_id, e.first_charge_amount, e.first_charge_currency,
                e.blocked_reason
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

    // A second live subscription for an account that already has one: two
    // checkouts paid before the first reached us. Applied, it would bill the
    // account twice and move it to the newer customer, leaving the first
    // subscription out of Manage billing. The newer one is ended instead, the
    // account keeps the one it has, and the owner is told, since its first
    // payment may already have been taken. The kept one is read back first:
    // a stale row must never cost somebody their only subscription. (A
    // second three-day trial is refused by the trial rules below.)
    if !three_day && !same_subscription && status_grants_access(status) {
        if let (Some(previous), Some(duplicate)) = (previous.as_ref(), subscription_id) {
            if let (Some(kept), Some(kept_status)) = (
                previous.stripe_subscription_id.as_deref(),
                previous.subscription_status.as_deref(),
            ) {
                if status_grants_access(kept_status) && still_live(kept).await? {
                    cancel_subscription(duplicate, DUPLICATE_COMMENT).await?;
                    tracing::warn!(
                        kept,
                        duplicate,
                        customer,
                        "cancelled a second subscription for the same account"
                    );
                    let message = orchestrator::mailer::duplicate_subscription_notice_email(
                        previous.email.as_deref().unwrap_or("unknown"),
                        kept,
                        duplicate,
                    );
                    if let Err(error) = state.mailer.send(OWNER_NOTICE_TO, &message).await {
                        tracing::warn!(%error, "could not send the duplicate subscription notice");
                    }
                    return Ok(());
                }
            }
        }
    }

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
                cancel_subscription(subscription_id, TRIAL_REJECTED_COMMENT).await?;
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
    // A plan given back after a dispute is not a new subscription to welcome.
    let was_disputed = previous
        .as_ref()
        .is_some_and(|row| row.blocked_reason.as_deref() == Some("disputed"));
    let email = previous.as_ref().and_then(|row| row.email.clone());
    let first_name = previous
        .as_ref()
        .and_then(|row| row.first_name.clone())
        .unwrap_or_default();

    // Whether the checkout behind it recorded the tick box before Stripe,
    // which the welcome then repeats.
    let consented = subscription
        .get("metadata")
        .and_then(|value| value.get(CONSENT_KEY))
        .and_then(|value| value.as_str())
        .is_some_and(|value| !value.is_empty());

    if plan.allows_scheduling() && !was_paid && !was_disputed {
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
                send_subscription_welcome(state, email, plan, trial_ends, consented).await;
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
            send_subscription_welcome(state, email, plan, None, consented).await;
        }
    }

    // The other direction, which said nothing at all before. The account
    // dropped to free, scheduled scanning was paused or switched off below,
    // and the first the agency knew was noticing a client site had not been
    // checked in a fortnight — on a security product, the worst thing to
    // find late.
    // A plan held over a dispute has not ended: it comes back if the payment
    // stands, and a lost dispute ends it then.
    if !plan.allows_scheduling() && was_paid && reason != "disputed" {
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
    // what the payment-failed email promises. So does a plan held over a
    // dispute.
    if !plan.allows_scheduling() && reason != "payment_failed" && reason != "disputed" {
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
    consented: bool,
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
        consented,
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

/// The customer of this account's newest completed Checkout, read from
/// Stripe. Only needed before the webhook has stored it: Checkout creates
/// the customer when the payment goes through. Sessions are found by the
/// email Checkout was given and kept only when they carry this account.
async fn completed_checkout_customer(
    secret: &str,
    user_id: Uuid,
    email: &str,
) -> ApiResult<Option<String>> {
    let sessions = stripe_get(
        secret,
        &stripe_url("/v1/checkout/sessions"),
        &[
            ("customer_details[email]", email),
            ("status", "complete"),
            ("limit", "10"),
        ],
    )
    .await?;
    let account = user_id.to_string();
    Ok(sessions["data"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|session| session["client_reference_id"].as_str() == Some(account.as_str()))
        .find_map(|session| session["customer"].as_str().map(str::to_string)))
}

/// Whether Stripe holds a subscription for this customer that is paid up,
/// trialing or still being collected. Every subscription on a customer
/// Glarion's checkout created is Glarion's.
async fn has_live_subscription(secret: &str, customer: &str) -> ApiResult<bool> {
    let subscriptions = stripe_get(
        secret,
        &stripe_url("/v1/subscriptions"),
        &[("customer", customer), ("limit", "10")],
    )
    .await?;
    Ok(subscriptions["data"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|subscription| {
            subscription["status"]
                .as_str()
                .is_some_and(status_grants_access)
        }))
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

/// Written to `cancellation_details.comment` on a second subscription for
/// an account that already has one.
const DUPLICATE_COMMENT: &str = "duplicate_subscription";

/// Whether Stripe still holds this subscription as paid up, trialing or
/// being collected. Without a secret key there is nothing to ask, so the
/// stored row is taken at its word.
async fn still_live(id: &str) -> ApiResult<bool> {
    Ok(match fetch_subscription(id).await? {
        Some(fresh) => fresh
            .get("status")
            .and_then(|value| value.as_str())
            .is_some_and(status_grants_access),
        None => true,
    })
}

/// Ends a subscription at once (a refused trial before its first invoice, or
/// a duplicate), with the reason recorded where Stripe's dashboard shows it.
async fn cancel_subscription(id: &str, comment: &str) -> ApiResult<()> {
    let secret = stripe_secret()?;
    let response = reqwest::Client::new()
        .delete(stripe_url(&format!("/v1/subscriptions/{id}")))
        .basic_auth(&secret, Option::<&str>::None)
        .query(&[("cancellation_details[comment]", comment)])
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
        tracing::error!(?payload, comment, "Stripe refused to cancel a subscription");
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
    fn cancellation_feedback_takes_stripes_eight_reasons_and_a_clean_comment() {
        for (code, _) in CANCEL_REASONS {
            assert_eq!(
                clean_cancel_feedback(Some(code), None).unwrap().0,
                Some(code)
            );
        }
        assert_eq!(clean_cancel_feedback(None, None).unwrap(), (None, None));
        assert_eq!(
            clean_cancel_feedback(Some("  "), Some(" \n ")).unwrap(),
            (None, None)
        );
        assert!(clean_cancel_feedback(Some("because"), None).is_err());
        assert_eq!(
            clean_cancel_feedback(Some("other"), Some("\u{1b}[31m too\tslow \r\n"))
                .unwrap()
                .1
                .as_deref(),
            Some("[31m too slow")
        );
        let limit = "é".repeat(CANCEL_COMMENT_MAX);
        assert!(clean_cancel_feedback(None, Some(&limit)).is_ok());
        assert!(clean_cancel_feedback(None, Some(&format!("{limit}x"))).is_err());
    }

    #[test]
    fn prices_are_read_from_subscriptions_and_invoices_in_every_shape() {
        let subscription =
            serde_json::json!({ "items": { "data": [{ "price": { "id": "price_sub" } }] } });
        let old_invoice = serde_json::json!({ "lines": { "data": [{ "price": { "id": "price_old" } }, { "price": "price_bare" }] } });
        let basil_invoice = serde_json::json!({ "lines": { "data": [{ "price": null, "pricing": { "price_details": { "price": "price_new" } } }] } });
        assert_eq!(payload_prices(&subscription), ["price_sub"]);
        assert_eq!(payload_prices(&old_invoice), ["price_old", "price_bare"]);
        assert_eq!(payload_prices(&basil_invoice), ["price_new"]);
        assert!(payload_prices(&serde_json::json!({ "id": "sub_thin" })).is_empty());
    }

    #[test]
    fn a_dispute_is_open_until_stripe_says_how_it_ended() {
        for status in ["won", "warning_closed", "prevented"] {
            assert_eq!(dispute_outcome(status), DisputeOutcome::Cleared);
        }
        assert_eq!(dispute_outcome("lost"), DisputeOutcome::Lost);
        for status in [
            "warning_needs_response",
            "warning_under_review",
            "needs_response",
            "under_review",
            "",
        ] {
            assert_eq!(dispute_outcome(status), DisputeOutcome::Open);
        }
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
