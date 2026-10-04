//! Keeps ownership proof current for sites on a schedule.
//!
//! Proof lasts [`VERIFICATION_TTL_DAYS`](crate::verification::VERIFICATION_TTL_DAYS).
//! Without renewal every scheduled site stopped being scanned a month after
//! it was verified, and the only trace was a log line. Here the same record
//! or file the customer published is checked again before it lapses: still
//! there, and the proof is extended; gone, and the owner is told while there
//! is still time to fix it. The proof is always re-read, never assumed.

use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::mailer::{ownership_lapsing_email, Mailer};
use crate::verification::{
    expiry_from, fetch_dns_txt_records, fetch_well_known_file, file_contains_token, token_present,
    VerificationMethod,
};

/// Renewal starts this long before the proof lapses.
const RENEW_WITHIN_HOURS: i64 = 72;
/// Warnings go out when this many hours remain.
const REMINDER_HOURS: [i64; 2] = [72, 24];

#[derive(sqlx::FromRow)]
struct Due {
    id: Uuid,
    domain: String,
    method: String,
    token: String,
    expires_at: DateTime<Utc>,
    email: String,
    first_name: Option<String>,
}

/// True when the scheduler tick that starts at `now` is the one that crosses
/// a reminder point, so each warning is sent once without storing anything.
pub fn reminder_due(expires_at: DateTime<Utc>, now: DateTime<Utc>, tick: Duration) -> bool {
    REMINDER_HOURS.iter().any(|hours| {
        let at = expires_at - Duration::hours(*hours);
        now <= at && at < now + tick
    })
}

/// Hourly is plenty for something that lasts a month, and it keeps a
/// well-known-file check from hitting the customer's site every few minutes.
pub fn attempt_due(now: DateTime<Utc>, tick: Duration) -> bool {
    let hour_start = now.timestamp() - now.timestamp().rem_euclid(3600);
    now.timestamp() - hour_start < tick.num_seconds()
}

async fn still_published(method: &str, domain: &str, token: &str) -> bool {
    match method {
        m if m == VerificationMethod::DnsTxt.as_db_str() => fetch_dns_txt_records(domain)
            .await
            .is_ok_and(|records| token_present(&records, token)),
        m if m == VerificationMethod::WellKnownFile.as_db_str() => fetch_well_known_file(domain)
            .await
            .is_ok_and(|body| file_contains_token(&body, token)),
        _ => false,
    }
}

pub async fn renew_due(
    pool: &PgPool,
    mailer: &Mailer,
    now: DateTime<Utc>,
    tick: Duration,
) -> anyhow::Result<()> {
    let due: Vec<Due> = sqlx::query_as(
        "select v.id, t.domain, v.method, v.token, v.expires_at, u.email, u.first_name
         from targets t
         join users u on u.id = t.user_id
         join lateral (
             select id, method, token, expires_at from target_verifications
             where target_id = t.id and verified_at is not null
             order by verified_at desc limit 1
         ) v on true
         where t.scan_cadence <> 'manual'
           and v.expires_at > $1
           and v.expires_at <= $1 + make_interval(hours => $2)",
    )
    .bind(now)
    .bind(RENEW_WITHIN_HOURS as i32)
    .fetch_all(pool)
    .await?;

    for item in due {
        let warn = reminder_due(item.expires_at, now, tick);
        if !warn && !attempt_due(now, tick) {
            continue;
        }
        if still_published(&item.method, &item.domain, &item.token).await {
            sqlx::query(
                "update target_verifications set verified_at = $1, expires_at = $2 where id = $3",
            )
            .bind(now)
            .bind(expiry_from(now))
            .bind(item.id)
            .execute(pool)
            .await?;
            tracing::info!(domain = %item.domain, "ownership proof renewed");
        } else if warn && mailer.is_configured() {
            let link = mailer.app_link("/targets");
            let message = ownership_lapsing_email(
                item.first_name.as_deref().unwrap_or(""),
                &item.domain,
                item.expires_at,
                &link,
            );
            if let Err(error) = mailer.send(&item.email, &message).await {
                tracing::warn!(error = ?error, domain = %item.domain, "lapsing-proof email not sent");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn each_reminder_point_falls_in_exactly_one_tick() {
        let tick = Duration::seconds(300);
        let expires = Utc.with_ymd_and_hms(2026, 11, 1, 12, 0, 0).unwrap();
        let mut hits = 0;
        let mut now = expires - Duration::hours(80);
        while now < expires {
            if reminder_due(expires, now, tick) {
                hits += 1;
            }
            now += tick;
        }
        assert_eq!(hits, 2);
    }

    #[test]
    fn attempts_run_once_an_hour() {
        let tick = Duration::seconds(300);
        let start = Utc.with_ymd_and_hms(2026, 11, 1, 0, 0, 0).unwrap();
        let attempts = (0..24 * 12)
            .filter(|i| attempt_due(start + tick * *i, tick))
            .count();
        assert_eq!(attempts, 24);
    }
}

#[cfg(test)]
mod email_tests {
    use crate::mailer::ownership_lapsing_email;
    use chrono::TimeZone;

    #[test]
    fn the_lapsing_email_names_the_site_and_escapes_it_once() {
        let at = chrono::Utc.with_ymd_and_hms(2026, 11, 3, 9, 30, 0).unwrap();
        let m = ownership_lapsing_email(
            "Ada",
            "client<site>.example",
            at,
            "https://glarion.app/app#/targets",
        );
        assert!(m.subject.contains("client<site>.example"));
        assert!(m.html.contains("client&lt;site&gt;.example"));
        assert!(!m.html.contains("&amp;lt;"));
        assert!(m.text.contains("3 November 2026, 09:30 UTC"));
    }
}
