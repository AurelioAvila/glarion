pub mod auth;
pub mod billing;
pub mod config;
pub mod error;
pub mod rate_limit;
pub mod routes;
pub mod state;

use anyhow::{Context, Result};
use axum::routing::{get, post, put};
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

    // Said out loud at boot rather than left to be discovered by waiting
    // for a message that will never arrive. Logging instead of sending is
    // the right default for development, but it is a difference worth
    // knowing about before someone signs up and stares at their inbox.
    if state.mailer.is_configured() {
        tracing::info!(
            links_point_at = %state.mailer.public_url,
            "email delivery is configured"
        );
    } else {
        tracing::warn!(
            "RESEND_API_KEY is unset — no email will be sent. Confirmation links are written to this log instead. Set RESEND_API_KEY, MAIL_FROM and PUBLIC_URL to deliver them."
        );
    }

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

    // Relative to the working directory, which is the repository root in
    // development and /app in the container. Overridable because neither
    // assumption should be load-bearing.
    let web_root = std::env::var("WEB_ROOT").unwrap_or_else(|_| "web".to_string());
    let app = with_static_files(app, std::path::Path::new(&web_root));

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
        // Ungated on purpose: it reads only what a site publishes to any
        // visitor. See routes::preview.
        // Unauthenticated by necessity: Stripe calls it. The signature is
        // the only thing guarding it — see routes::billing::webhook.
        .route("/api/billing/webhook", post(routes::billing::webhook))
        .route("/api/billing", get(routes::billing::get_subscription))
        .route(
            "/api/billing/checkout",
            post(routes::billing::start_checkout),
        )
        .route("/api/billing/portal", post(routes::billing::open_portal))
        .route("/api/preview", post(routes::preview::run_preview))
        .route("/api/preview/email", post(routes::preview::email_preview))
        .route("/api/auth/signup", post(routes::accounts::signup))
        .route("/api/auth/login", post(routes::accounts::login))
        .route("/api/auth/verify", post(routes::accounts::verify_email))
        .route(
            "/api/auth/resend-verification",
            post(routes::accounts::resend_verification),
        )
        .route(
            "/api/account",
            axum::routing::delete(routes::accounts::delete_account),
        )
        .route(
            "/api/targets",
            get(routes::targets::list_targets).post(routes::targets::create_target),
        )
        .route(
            "/api/targets/:id/cadence",
            put(routes::targets::set_cadence),
        )
        .route(
            "/api/targets/:id/verification",
            post(routes::targets::start_verification),
        )
        .route(
            "/api/targets/:id/verification/check",
            post(routes::targets::check_verification),
        )
        .route(
            "/api/scans",
            get(routes::results::list_scans).post(routes::scans::create_scan),
        )
        .route("/api/scans/:id", get(routes::results::get_scan))
        .route(
            "/api/scans/:id/report",
            get(routes::results::get_scan_report),
        )
        .route(
            "/api/profile",
            get(routes::profile::get_profile).put(routes::profile::update_profile),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Adds the marketing page and the dashboard to a router, if they are
/// there to add.
///
/// Serving both from the API is what makes this one deployable unit rather
/// than two, and it removes the cross-origin problem entirely: the free
/// check on the landing page calls `/api/preview` on its own origin, so
/// there is no CORS entry to keep in step with wherever the site is
/// hosted this month.
///
/// Absent directory means absent routes rather than a failure to start.
/// The integration tests build the router without a web directory in
/// reach, and an API deployed without the frontend is a legitimate thing
/// to want; neither should be a boot error.
pub fn with_static_files(router: Router, web_root: &std::path::Path) -> Router {
    use axum::http::header::CACHE_CONTROL;
    use tower::ServiceBuilder;
    use tower_http::services::{ServeDir, ServeFile};
    use tower_http::set_header::SetResponseHeaderLayer;

    let landing = web_root.join("landing.html");
    let shell = web_root.join("index.html");

    if !landing.exists() || !shell.exists() {
        tracing::warn!(
            path = %web_root.display(),
            "no web directory found — serving the API only"
        );
        return router;
    }

    // Every static response revalidates rather than trusting a cached copy.
    //
    // Filenames here never change between deploys (no content hash), and
    // with no Cache-Control header at all a browser is free to reuse
    // whatever it already has for hours — which is exactly what happened
    // the first time this shipped: `flyctl deploy` succeeded, curl proved
    // the new bundle was live, and a signed-in browser kept running
    // yesterday's JavaScript regardless. `no-cache` does not mean
    // uncached — it means every load sends a conditional request, and
    // ServeFile/ServeDir already answer that with 304 when nothing
    // changed, so this costs a round trip rather than a full download.
    let revalidate = ServiceBuilder::new().layer(SetResponseHeaderLayer::overriding(
        CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-cache"),
    ));

    router
        // Explicit, because ServeDir would otherwise answer `/` with
        // index.html — which here is the dashboard shell, not the front
        // door. Getting this wrong shows a signed-out visitor a blank
        // application instead of the page that explains it.
        .route_service("/", revalidate.clone().service(ServeFile::new(&landing)))
        // `/app` without a trailing slash, deliberately: the shell asks for
        // /dist/app.js absolutely, but any relative URL a future edit adds
        // would resolve against the wrong base under `/app/`.
        .route_service("/app", revalidate.clone().service(ServeFile::new(&shell)))
        .route_service("/app/", revalidate.clone().service(ServeFile::new(&shell)))
        .fallback_service(
            revalidate.service(
                ServeDir::new(web_root)
                    .append_index_html_on_directories(false)
                    .fallback(ServeFile::new(&landing)),
            ),
        )
}
