//! The scan worker process.
//!
//! Two loops share this process: the runner, which executes queued jobs,
//! and the scheduler, which turns recurring instructions into queued jobs.
//! They are deployed apart from the API so scanning load never competes
//! with request serving, and so the number of workers can be scaled
//! independently of the web tier.

use anyhow::{Context, Result};
use orchestrator::mailer::Mailer;
use sqlx::postgres::PgPoolOptions;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,sqlx=warn".into()),
        )
        .init();

    let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL must be set")?;

    // Enough for both loops with room to spare; a worker runs one scan at a
    // time and the scheduler wakes every few minutes.
    let pool = PgPoolOptions::new()
        .max_connections(6)
        .connect(&database_url)
        .await
        .context("could not connect to the database")?;

    let mailer = Mailer::from_env();
    if !mailer.is_configured() {
        // Said out loud rather than left to be discovered by a customer
        // wondering why monitoring never told them anything.
        tracing::warn!("RESEND_API_KEY is unset — change notifications will be logged, not sent.");
    }

    tracing::info!("glarion scan runner started");

    // Separate tasks so a slow scan does not delay the scheduler, and a
    // scheduler tick does not hold up a scan.
    let scheduler = tokio::spawn(orchestrator::scheduler::run_forever(pool.clone()));
    let runner = tokio::spawn(orchestrator::runner::run_forever(pool, mailer));

    // Neither loop returns on its own, so reaching here means one panicked.
    // Exiting lets the supervisor restart the process rather than leaving
    // it half-alive with scans queueing up and nothing running them.
    tokio::select! {
        result = scheduler => tracing::error!(?result, "the scheduler stopped"),
        result = runner => tracing::error!(?result, "the runner stopped"),
    }

    anyhow::bail!("a worker loop stopped unexpectedly")
}
