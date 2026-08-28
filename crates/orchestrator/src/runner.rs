//! The scan job runner.
//!
//! Polls for queued jobs, claims one at a time, and executes it.
//!
//! The important design point: **the authorization gate is checked again
//! here, not just at the API.** A job can sit in the queue while its
//! target's verification expires, and the runner is what actually sends
//! packets — so it re-derives permission from the database at the moment of
//! execution rather than trusting that queueing implied consent. A job that
//! fails this second check is marked failed and never runs.

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::finding::Finding;
use crate::tools::nuclei;
use crate::verification::{is_currently_verified, VerificationStatus};

/// How long to wait before polling again when the queue is empty.
const IDLE_POLL_SECS: u64 = 5;

#[derive(sqlx::FromRow)]
struct ClaimedJob {
    id: Uuid,
    target_id: Uuid,
    tool: String,
}

/// Runs until cancelled. Intended to be spawned as its own task or process.
pub async fn run_forever(pool: PgPool) {
    loop {
        match claim_next_job(&pool).await {
            Ok(Some(job)) => {
                let job_id = job.id;
                if let Err(err) = execute(&pool, job).await {
                    tracing::error!(%job_id, error = ?err, "job execution failed");
                }
            }
            Ok(None) => {
                tokio::time::sleep(std::time::Duration::from_secs(IDLE_POLL_SECS)).await;
            }
            Err(err) => {
                tracing::error!(error = ?err, "could not claim a job");
                tokio::time::sleep(std::time::Duration::from_secs(IDLE_POLL_SECS)).await;
            }
        }
    }
}

/// Atomically claims one queued job.
///
/// `for update skip locked` lets several runners share the queue without
/// two of them ever picking up the same job.
async fn claim_next_job(pool: &PgPool) -> sqlx::Result<Option<ClaimedJob>> {
    sqlx::query_as(
        "update scan_jobs
         set status = 'running', started_at = now()
         where id = (
             select id from scan_jobs
             where status = 'queued'
             order by created_at
             for update skip locked
             limit 1
         )
         returning id, target_id, tool",
    )
    .fetch_optional(pool)
    .await
}

async fn execute(pool: &PgPool, job: ClaimedJob) -> anyhow::Result<()> {
    // Re-derive permission at execution time. Queueing is not consent —
    // the verification may have lapsed while this job waited.
    let domain = match authorized_domain(pool, job.target_id).await? {
        Some(domain) => domain,
        None => {
            tracing::warn!(
                job_id = %job.id,
                target_id = %job.target_id,
                "refusing to execute: target ownership is no longer verified"
            );
            fail_job(
                pool,
                job.id,
                "target ownership verification lapsed before this job ran",
            )
            .await?;
            return Ok(());
        }
    };

    let findings = match job.tool.as_str() {
        "nuclei" => match nuclei::run(&domain).await {
            Ok(findings) => findings,
            Err(err) => {
                fail_job(pool, job.id, &err.to_string()).await?;
                return Ok(());
            }
        },
        other => {
            // Unreachable via the API (the allowlist runs there too), but a
            // row could be written by a future code path or by hand.
            fail_job(pool, job.id, &format!("unsupported tool '{other}'")).await?;
            return Ok(());
        }
    };

    store_findings(pool, job.id, &findings).await?;

    sqlx::query("update scan_jobs set status = 'completed', completed_at = now() where id = $1")
        .bind(job.id)
        .execute(pool)
        .await?;

    tracing::info!(job_id = %job.id, findings = findings.len(), "scan completed");
    Ok(())
}

/// Returns the target's domain only if its ownership verification is valid
/// right now. `None` means "do not scan this".
async fn authorized_domain(pool: &PgPool, target_id: Uuid) -> sqlx::Result<Option<String>> {
    #[derive(sqlx::FromRow)]
    struct Row {
        domain: String,
        verified_at: Option<chrono::DateTime<Utc>>,
        expires_at: Option<chrono::DateTime<Utc>>,
    }

    let row: Option<Row> = sqlx::query_as(
        "select t.domain, v.verified_at, v.expires_at
         from targets t
         left join lateral (
             select verified_at, expires_at
             from target_verifications
             where target_id = t.id and verified_at is not null
             order by verified_at desc
             limit 1
         ) v on true
         where t.id = $1",
    )
    .bind(target_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.and_then(|row| {
        let status = VerificationStatus {
            verified_at: row.verified_at,
            expires_at: row.expires_at,
        };
        is_currently_verified(&status, Utc::now()).then_some(row.domain)
    }))
}

async fn store_findings(pool: &PgPool, job_id: Uuid, findings: &[Finding]) -> sqlx::Result<()> {
    for finding in findings {
        sqlx::query(
            "insert into scan_results (scan_job_id, severity, title, description, raw_output)
             values ($1, $2, $3, $4, $5)",
        )
        .bind(job_id)
        .bind(finding.severity.as_db_str())
        .bind(&finding.title)
        .bind(&finding.description)
        .bind(&finding.raw)
        .execute(pool)
        .await?;
    }

    Ok(())
}

async fn fail_job(pool: &PgPool, job_id: Uuid, reason: &str) -> sqlx::Result<()> {
    sqlx::query(
        "update scan_jobs
         set status = 'failed', completed_at = now(), failure_reason = $2
         where id = $1",
    )
    .bind(job_id)
    .bind(reason)
    .execute(pool)
    .await?;

    Ok(())
}
