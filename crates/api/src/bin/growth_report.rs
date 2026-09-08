//! Operator-only aggregate report. No web route and no identifying rows.
use anyhow::Result;
use serde_json::Value;

#[tokio::main]
async fn main() -> Result<()> {
    let url = std::env::var("DATABASE_URL")?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await?;
    let mut tx = pool.begin().await?;
    sqlx::query("set transaction read only")
        .execute(&mut *tx)
        .await?;
    sqlx::query("set local statement_timeout = '5s'")
        .execute(&mut *tx)
        .await?;
    let counts: Value = sqlx::query_scalar(
        "select coalesce(json_agg(t), '[]'::json) from
        (select day, source, event, total from growth_counts
         where day >= (now() at time zone 'UTC')::date - 6 order by day, source, event) t",
    )
    .fetch_one(&mut *tx)
    .await?;
    let accounts: Value = sqlx::query_scalar(
        "select row_to_json(t) from
        (select count(*) filter (where created_at >= now() - interval '7 days') as created_7d,
         count(*) filter (where email_verified_at is not null) as confirmed_current
         from users where email not like 'deleted-%') t",
    )
    .fetch_one(&mut *tx)
    .await?;
    let verified: i64 = sqlx::query_scalar(
        "select count(distinct target_id) from target_verifications
        where verified_at is not null and expires_at > now()",
    )
    .fetch_one(&mut *tx)
    .await?;
    let subscriptions: Value = sqlx::query_scalar(
        "select coalesce(json_agg(t), '[]'::json) from
        (select plan, subscription_status, count(*) as total from entitlements
         where product = 'glarion' and plan <> 'free'
         group by plan, subscription_status order by plan, subscription_status) t",
    )
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "checked_at_utc": chrono::Utc::now(), "operation_counts_7d": counts,
            "accounts_all_sources": accounts, "currently_verified_domains": verified,
            "subscriptions_current_not_settled_payments": subscriptions,
            "caveat": "Operations, not unique visitors or cohort conversions. Channel counts exclude opted-out browsers and may undercount."
        }))?
    );
    Ok(())
}
