//! The loop that queues scheduled scans.
//!
//! Runs alongside the job runner. Its whole job is to turn a standing
//! instruction ("check this weekly") into the same queued job a person
//! would have created by pressing the button — including the authorization
//! record, so the audit trail can always answer who asked for a scan and
//! when.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::schedule::{due, Cadence, NotDue, ScheduleState};

/// How often to look for work. Scans are due at weekly or monthly
/// granularity, so checking every few minutes is already far finer than it
/// needs to be, and being late by minutes costs nothing.
const TICK_SECS: u64 = 300;

#[derive(sqlx::FromRow)]
struct Candidate {
    id: Uuid,
    domain: String,
    scan_cadence: String,
    last_scheduled_at: Option<DateTime<Utc>>,
    verification_id: Option<Uuid>,
    verification_expires_at: Option<DateTime<Utc>>,
    recent_scans: i64,
}

pub async fn run_forever(pool: PgPool) {
    loop {
        if let Err(error) = tick(&pool).await {
            tracing::error!(error = ?error, "scheduler tick failed");
        }
        tokio::time::sleep(std::time::Duration::from_secs(TICK_SECS)).await;
    }
}

async fn tick(pool: &PgPool) -> anyhow::Result<()> {
    let candidates: Vec<Candidate> = sqlx::query_as(
        "select t.id, t.domain, t.scan_cadence, t.last_scheduled_at,
                v.id as verification_id, v.expires_at as verification_expires_at,
                (select count(*) from scan_jobs j
                 where j.target_id = t.id and j.created_at >= now() - interval '24 hours'
                ) as recent_scans
         from targets t
         left join lateral (
             select id, expires_at from target_verifications
             where target_id = t.id and verified_at is not null
             order by verified_at desc limit 1
         ) v on true
         where t.scan_cadence <> 'manual'",
    )
    .fetch_all(pool)
    .await?;

    let now = Utc::now();

    for candidate in candidates {
        let state = ScheduleState {
            cadence: Cadence::from_str_or_manual(&candidate.scan_cadence),
            last_scheduled_at: candidate.last_scheduled_at,
            verification_expires_at: candidate.verification_expires_at,
        };

        match due(&state, now) {
            Ok(()) => {}
            Err(NotDue::VerificationLapsed) => {
                // Logged rather than silently skipped: this is the one
                // reason a paying customer stops receiving reports that
                // they can actually do something about.
                tracing::warn!(
                    target_id = %candidate.id,
                    domain = %candidate.domain,
                    "scheduled scan skipped: ownership proof has lapsed"
                );
                continue;
            }
            Err(_) => continue,
        }

        // The same per-target ceiling a manual scan is held to. A schedule
        // must not be a way around the intensity limits.
        if !crate::policy::within_scan_budget(candidate.recent_scans) {
            tracing::warn!(
                target_id = %candidate.id,
                "scheduled scan skipped: target is at its daily limit"
            );
            continue;
        }

        let Some(verification_id) = candidate.verification_id else {
            continue;
        };

        if let Err(error) = enqueue(pool, &candidate, verification_id).await {
            tracing::error!(
                target_id = %candidate.id,
                error = ?error,
                "could not queue a scheduled scan"
            );
        }
    }

    Ok(())
}

/// Writes the authorization and the job together, then records that the
/// schedule fired.
///
/// One transaction for all three: a job without its authorization would
/// break the rule that every scan can be traced to somebody asking for it,
/// and a job queued without stamping `last_scheduled_at` would be queued
/// again on the next tick, and the one after that.
async fn enqueue(pool: &PgPool, candidate: &Candidate, verification_id: Uuid) -> sqlx::Result<()> {
    let mut tx = pool.begin().await?;

    let authorization_id: Uuid = sqlx::query_scalar(
        "insert into scan_authorizations
             (user_id, target_id, target_verification_id, source)
         select t.user_id, t.id, $2, 'schedule' from targets t where t.id = $1
         returning id",
    )
    .bind(candidate.id)
    .bind(verification_id)
    .fetch_one(&mut *tx)
    .await?;

    // Both tools, under the one authorization. The certificate check is
    // the reason a schedule is worth paying for: expiry is the one failure
    // that is certain, dated, and total, and it is invisible to a scan that
    // only runs when somebody remembers to press the button. Nuclei does
    // not report it — see tools::tls.
    //
    // Queued as separate jobs rather than one combined scan so a hung
    // Nuclei run cannot delay the cheap check that matters most, and so a
    // failure in either is recorded against the tool that failed.
    sqlx::query(
        "insert into scan_jobs (target_id, scan_authorization_id, tool)
         select $1, $2, tool from unnest(array['nuclei', 'tls']) as tool",
    )
    .bind(candidate.id)
    .bind(authorization_id)
    .execute(&mut *tx)
    .await?;

    sqlx::query("update targets set last_scheduled_at = now() where id = $1")
        .bind(candidate.id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    tracing::info!(
        target_id = %candidate.id,
        domain = %candidate.domain,
        "queued a scheduled scan"
    );

    Ok(())
}
