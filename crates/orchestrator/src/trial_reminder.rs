//! The reminder a day before a three-day trial ends.
//!
//! Stripe's own `trial_will_end` arrives three days before the end, which for
//! a three-day trial is the moment it starts, so it cannot be the reminder.
//! This runs on the scheduler's tick instead and reads only what the webhook
//! keeps on `entitlements`: still trialing, not cancelled, a three-day trial
//! (claimed), ending within a day but not within the hour, and not already
//! reminded for this end date.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::mailer::{money, trial_ending_email, Mailer};

#[derive(sqlx::FromRow)]
struct Due {
    user_id: Uuid,
    email: String,
    first_name: Option<String>,
    plan: String,
    trial_ends_at: DateTime<Utc>,
    billing_interval: Option<String>,
    first_charge_amount: Option<i64>,
    first_charge_currency: Option<String>,
}

/// Sends every reminder that is due at `now`. Each row is marked before its
/// message goes out, so two workers never send the same one; a failed send
/// clears the mark and the next tick tries again.
pub async fn send_due(pool: &PgPool, mailer: &Mailer, now: DateTime<Utc>) -> anyhow::Result<()> {
    let due: Vec<Due> = sqlx::query_as(
        "update entitlements e
            set trial_reminder_for = e.trial_ends_at
           from users u
          where u.id = e.user_id
            and e.product = 'glarion'
            and e.subscription_status = 'trialing'
            and not e.cancel_at_period_end
            and e.trial_ends_at > $1 + interval '1 hour'
            and e.trial_ends_at <= $1 + interval '24 hours'
            and e.trial_reminder_for is distinct from e.trial_ends_at
            and exists (select 1 from trial_claims c
                         where c.subscription_id = e.stripe_subscription_id)
        returning e.user_id, u.email, u.first_name, e.plan, e.trial_ends_at,
                  e.billing_interval, e.first_charge_amount, e.first_charge_currency",
    )
    .bind(now)
    .fetch_all(pool)
    .await?;

    for row in due {
        let charge = match (
            row.first_charge_amount,
            row.first_charge_currency.as_deref(),
        ) {
            (Some(amount), Some(currency)) => Some(money(amount, currency)),
            _ => None,
        };
        let message = trial_ending_email(
            row.first_name.as_deref().unwrap_or(""),
            &plan_name(&row.plan),
            row.trial_ends_at,
            charge.as_deref(),
            row.billing_interval.as_deref().unwrap_or("month"),
            &mailer.app_link("/plan"),
        );
        if let Err(error) = mailer.send(&row.email, &message).await {
            tracing::warn!(%error, user_id = %row.user_id, "could not send the trial reminder");
            sqlx::query(
                "update entitlements set trial_reminder_for = null
                  where user_id = $1 and product = 'glarion' and trial_reminder_for = $2",
            )
            .bind(row.user_id)
            .bind(row.trial_ends_at)
            .execute(pool)
            .await?;
        } else {
            tracing::info!(user_id = %row.user_id, "sent the trial reminder");
        }
    }
    Ok(())
}

/// "studio" → "Studio". The plan names are single words.
fn plan_name(plan: &str) -> String {
    let mut chars = plan.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_names_and_amounts_read_like_the_rest_of_the_mail() {
        assert_eq!(plan_name("studio"), "Studio");
        assert_eq!(plan_name(""), "");
        assert_eq!(money(4_758, "eur"), "€47.58");
        assert_eq!(money(3_900, "eur"), "€39");
    }
}
