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
use crate::mailer::{change_email, Mailer};
use crate::schedule::{compare, headline};
use crate::tools::{nuclei, tls};
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
pub async fn run_forever(pool: PgPool, mailer: Mailer) {
    loop {
        match claim_next_job(&pool).await {
            Ok(Some(job)) => {
                let job_id = job.id;
                if let Err(err) = execute(&pool, &mailer, job).await {
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

async fn execute(pool: &PgPool, mailer: &Mailer, job: ClaimedJob) -> anyhow::Result<()> {
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
        "tls" => match tls::run(&domain).await {
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

    // The count that was compared against last time, captured before this
    // job is marked complete so it cannot find itself.
    let previous = previous_actionable_count(pool, job.target_id, &job.tool, job.id).await?;

    store_findings(pool, job.id, &findings).await?;

    sqlx::query("update scan_jobs set status = 'completed', completed_at = now() where id = $1")
        .bind(job.id)
        .execute(pool)
        .await?;

    tracing::info!(job_id = %job.id, findings = findings.len(), "scan completed");

    let current = crate::triage::triage_scan(&findings).actionable.len() as i64;
    report_change(pool, mailer, &job, previous, current).await;

    Ok(())
}

/// Emails the owner when a monitored site has changed.
///
/// Only on a change, and never on a first scan: a message saying "still
/// three issues, same as last week" teaches people to filter the sender,
/// and then the one that mattered goes unread too.
///
/// Failure here is logged, not propagated. The scan itself succeeded, and
/// marking a completed job as failed because an email bounced would lose
/// results somebody is waiting for.
async fn report_change(
    pool: &PgPool,
    mailer: &Mailer,
    job: &ClaimedJob,
    previous: Option<i64>,
    current: i64,
) {
    let change = compare(previous, current);
    if !change.worth_reporting() {
        return;
    }

    #[derive(sqlx::FromRow)]
    struct Recipient {
        email: String,
        domain: String,
        scan_cadence: String,
    }

    let recipient: Option<Recipient> = sqlx::query_as(
        "select u.email, t.domain, t.scan_cadence
         from targets t join users u on u.id = t.user_id
         where t.id = $1",
    )
    .bind(job.target_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let Some(recipient) = recipient else { return };

    // Only sites somebody put on a schedule. A manual scan is watched by
    // whoever pressed the button.
    if recipient.scan_cadence == "manual" {
        return;
    }

    let summary = headline(&recipient.domain, &change);
    let detail = match previous {
        Some(previous) => {
            format!("The last scan found {previous} to fix. This one found {current}.")
        }
        None => format!("This scan found {current} to fix."),
    };
    let link = mailer.app_link(&format!("/scans/{}", job.id));
    let message = change_email(&recipient.domain, &summary, &detail, &link);

    if let Err(error) = mailer.send(&recipient.email, &message).await {
        tracing::error!(error = ?error, "could not send the change notification");
    }
}

/// What the previous completed scan of this target found.
///
/// Excludes the job being finished so a scan cannot compare against itself.
async fn previous_actionable_count(
    pool: &PgPool,
    target_id: Uuid,
    tool: &str,
    current_job: Uuid,
) -> anyhow::Result<Option<i64>> {
    // Same tool, deliberately. A target is scanned by more than one tool
    // per run, and they report on different things: comparing a TLS job
    // against the Nuclei job before it comes out as a change every single
    // time, and a monitor that cries wolf on every run is worse than no
    // monitor, because people stop reading it.
    let previous_job: Option<Uuid> = sqlx::query_scalar(
        "select id from scan_jobs
         where target_id = $1 and tool = $2 and id <> $3 and status = 'completed'
         order by completed_at desc nulls last
         limit 1",
    )
    .bind(target_id)
    .bind(tool)
    .bind(current_job)
    .fetch_optional(pool)
    .await?;

    let Some(previous_job) = previous_job else {
        return Ok(None);
    };

    let findings = load_findings(pool, previous_job).await?;
    Ok(Some(
        crate::triage::triage_scan(&findings).actionable.len() as i64
    ))
}

/// Rebuilds the findings of a stored scan.
async fn load_findings(pool: &PgPool, job_id: Uuid) -> anyhow::Result<Vec<Finding>> {
    #[derive(sqlx::FromRow)]
    struct Row {
        severity: String,
        title: String,
        description: Option<String>,
        raw_output: serde_json::Value,
    }

    let rows: Vec<Row> = sqlx::query_as(
        "select severity, title, description, raw_output
         from scan_results where scan_job_id = $1",
    )
    .bind(job_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| Finding {
            severity: crate::finding::Severity::from_tool_label(&row.severity),
            title: row.title,
            description: row.description,
            raw: row.raw_output,
        })
        .collect())
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
