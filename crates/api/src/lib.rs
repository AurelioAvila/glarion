pub mod auth;
pub mod config;
pub mod error;
pub mod rate_limit;
pub mod routes;
pub mod state;

use anyhow::{Context, Result};
use axum::routing::{get, post};
use axum::Router;
use sqlx::postgres::PgPoolOptions;
use std::net::SocketAddr;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::config::Config;
use crate::state::AppState;

pub async fn run() -> Result<()> {
    let config = Config::from_env().context("invalid configuration")?;

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await
        .context("could not connect to the database")?;

    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .context("database migration failed")?;

    let state = AppState::new(pool, config.jwt_secret.clone());

    let origins: Vec<_> = config
        .allowed_origins()
        .iter()
        .filter_map(|origin| origin.parse().ok())
        .collect();

    let app = router(state).layer(
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(origins))
            .allow_headers([
                axum::http::header::AUTHORIZATION,
                axum::http::header::CONTENT_TYPE,
            ])
            .allow_methods([axum::http::Method::GET, axum::http::Method::POST]),
    );

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "glarion api listening");

    // into_make_service_with_connect_info is required for the scan handler's
    // ConnectInfo extractor, which records the caller's IP in the audit trail.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/api/auth/signup", post(routes::accounts::signup))
        .route("/api/auth/login", post(routes::accounts::login))
        .route(
            "/api/targets",
            get(routes::targets::list_targets).post(routes::targets::create_target),
        )
        .route(
            "/api/targets/:id/verification",
            post(routes::targets::start_verification),
        )
        .route(
            "/api/targets/:id/verification/check",
            post(routes::targets::check_verification),
        )
        .route("/api/scans", post(routes::scans::create_scan))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
