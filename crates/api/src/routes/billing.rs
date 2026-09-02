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
    plan_for_price, price_env_var, status_grants_access, verify_signature, Interval, Plan,
};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

#[derive(Serialize)]
pub struct Subscription {
    pub plan: String,
    pub plan_name: String,
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
}

/// What this account currently has.
pub async fn get_subscription(
    State(state): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<Subscription>> {
    #[derive(sqlx::FromRow)]
    struct Row {
        plan: String,
        subscription_status: Option<String>,
        current_period_end: Option<DateTime<Utc>>,
        stripe_customer_id: Option<String>,
    }

    let row: Option<Row> = sqlx::query_as(
        "select plan, subscription_status, current_period_end, stripe_customer_id
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
        plan: "free".to_string(),
        subscription_status: None,
        current_period_end: None,
        stripe_customer_id: None,
    });

    let plan = Plan::from_db_str(&row.plan);

    Ok(Json(Subscription {
        plan: plan.as_db_str().to_string(),
        plan_name: plan.display_name().to_string(),
        max_targets: plan.max_targets(),
        targets_used: used,
        allows_scheduling: plan.allows_scheduling(),
        allows_full_scan: plan.allows_full_scan(),
        status: row.subscription_status,
        current_period_end: row.current_period_end,
        manageable: row.stripe_customer_id.is_some(),
    }))
}

#[derive(Deserialize)]
pub struct CheckoutRequest {
    pub plan: String,
    #[serde(default)]
    pub interval: String,
}

#[derive(Serialize)]
pub struct RedirectResponse {
    pub url: String,
}

/// Starts a Stripe Checkout session and hands back where to send the
/// browser.
pub async fn start_checkout(
    State(state): State<AppState>,
    user: AuthUser,
    Json(body): Json<CheckoutRequest>,
) -> ApiResult<Json<RedirectResponse>> {
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

    let secret = stripe_secret()?;
    let email = account_email(&state, user.id).await?;
    let customer_id = existing_customer(&state, user.id).await?;

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

    let url = stripe_post(
        &secret,
        "https://api.stripe.com/v1/checkout/sessions",
        &form,
    )
    .await?
    .get("url")
    .and_then(|value| value.as_str())
    .map(str::to_string)
    .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("Stripe returned no checkout url")))?;

    Ok(Json(RedirectResponse { url }))
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

    let form = vec![
        ("customer".to_string(), customer_id),
        ("return_url".to_string(), state.mailer.app_link("/plan")),
    ];

    let url = stripe_post(
        &secret,
        "https://api.stripe.com/v1/billing_portal/sessions",
        &form,
    )
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
    // happening to be idempotent.
    let claimed: Option<(String,)> = sqlx::query_as(
        "insert into stripe_events (id, event_type) values ($1, $2)
         on conflict (id) do nothing
         returning id",
    )
    .bind(event_id)
    .bind(event_type)
    .fetch_optional(&state.pool)
    .await?;

    if claimed.is_none() {
        // Already seen. Answering 200 stops Stripe retrying something that
        // is done.
        return Ok("duplicate");
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
        | "customer.subscription.deleted" => apply_subscription(state, object).await,

        _ => Ok(()),
    }
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

    // A plan is granted only when the price is one we recognise *and* the
    // subscription is in a state that should work. Either failing drops the
    // account to free rather than leaving whatever it had.
    let plan = match (status_grants_access(status), plan_for_price(price_id)) {
        (true, Some(plan)) => plan,
        _ => Plan::Free,
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

    // Read the plan this account is on before the update overwrites it, so a
    // first paid subscription can be told apart from a renewal. Stripe sends
    // customer.subscription.updated on every renewal and every card change,
    // and welcoming someone once a month is not a welcome.
    let previous: Option<(Option<String>, Option<Uuid>, Option<String>)> = sqlx::query_as(
        "select e.plan, e.user_id, u.email
           from entitlements e
           left join users u on u.id = e.user_id
          where e.product = 'glarion'
            and (e.stripe_customer_id = $1 or e.user_id = $2)",
    )
    .bind(customer)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;

    sqlx::query(
        "update entitlements
         set stripe_customer_id = $1,
             plan = $2,
             max_targets = $3,
             subscription_status = $4,
             stripe_subscription_id = $5,
             current_period_end = $6
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
    .execute(&state.pool)
    .await?;

    // Welcome only on the crossing from unpaid to paid. A row that was
    // already on a paid plan is renewing, and one that has just dropped to
    // free is not a moment to congratulate anyone.
    // Whether this account was on a paid plan a moment ago. Both directions
    // of the crossing need it: one to welcome, one to explain the loss.
    let was_paid = previous
        .as_ref()
        .and_then(|(stored, _, _)| stored.as_deref())
        .map(|stored| Plan::from_db_str(stored).allows_scheduling())
        .unwrap_or(false);
    let previous_plan = previous
        .as_ref()
        .and_then(|(stored, _, _)| stored.as_deref())
        .map(Plan::from_db_str)
        .unwrap_or(Plan::Free);

    if plan.allows_scheduling() && !was_paid {
        if let Some((_, _, Some(email))) = previous.as_ref() {
            send_subscription_welcome(state, email, plan).await;
        }
    }

    // The other direction, which said nothing at all before. The account
    // dropped to free, scheduled scanning was switched off below, and the
    // first the agency knew was noticing a client site had not been checked
    // in a fortnight — on a security product, the worst thing to find late.
    if !plan.allows_scheduling() && was_paid {
        if let Some((_, _, Some(email))) = previous.as_ref() {
            // Stripe says why itself when it knows. A subscription cancelled
            // after dunning gives cancellation_details.reason, which is the
            // difference between "your card needs updating" and "you chose to
            // leave" — and getting that backwards reads as a company not
            // paying attention.
            let reason = subscription
                .get("cancellation_details")
                .and_then(|details| details.get("reason"))
                .and_then(|value| value.as_str())
                .unwrap_or("");
            let payment_problem = reason == "payment_failure"
                || matches!(status, "unpaid" | "incomplete_expired" | "incomplete");
            send_subscription_ended(state, email, previous_plan, payment_problem).await;
        }
    }

    // Losing the paid plan has to switch off what the paid plan bought,
    // otherwise a cancelled account keeps being scanned every week for
    // free — and keeps costing us the scans.
    if !plan.allows_scheduling() {
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
async fn send_subscription_welcome(state: &AppState, email: &str, plan: Plan) {
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
