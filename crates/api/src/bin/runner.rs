//! The scan worker process.
//!
//! Deployed separately from the API so that scanning load never competes
//! with request serving, and so the number of workers can be scaled
//! independently of the web tier.

use anyhow::{Context, Result};
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

    // Fewer connections than the API: a worker runs one job at a time.
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .context("could not connect to the database")?;

    tracing::info!("glarion scan runner started");
    orchestrator::runner::run_forever(pool).await;

    Ok(())
}
