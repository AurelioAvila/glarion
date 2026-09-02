pub mod auth;
pub mod billing;
pub mod config;
pub mod error;
pub mod rate_limit;
pub mod routes;
pub mod state;

use anyhow::{Context, Result};
use axum::response::IntoResponse;
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
                axum::http::HeaderName::from_static("x-glarion-csrf"),
            ])
            .allow_credentials(true)
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::PUT,
                axum::http::Method::DELETE,
            ]),
    );

    // Relative to the working directory, which is the repository root in
    // development and /app in the container. Overridable because neither
    // assumption should be load-bearing.
    let web_root = std::env::var("WEB_ROOT").unwrap_or_else(|_| "web".to_string());
    let app = with_static_files(app, std::path::Path::new(&web_root))
        .layer(axum::middleware::from_fn(redirect_www_to_apex));

    // Outermost on purpose: everything downstream, the rate limiters and the
    // scan audit trail included, reads the connection address, and behind a
    // proxy that address is the proxy's for every caller alive.
    let app = if trusts_proxy_client_ip() {
        tracing::info!(
            "trusting {} for the client address",
            rate_limit::CLIENT_IP_HEADER
        );
        app.layer(axum::middleware::from_fn(use_forwarded_client_ip))
    } else {
        app
    };

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

/// Whether a proxy in front of this process overwrites the client-IP header.
///
/// Set in fly.toml and nowhere else. Off by default because believing the
/// header without a proxy that rewrites it hands every caller a private
/// rate-limit bucket, which is worse than sharing one.
fn trusts_proxy_client_ip() -> bool {
    std::env::var("TRUST_PROXY_CLIENT_IP")
        .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

/// Replaces the connection address with the one the trusted proxy reported.
///
/// Rewriting the extension rather than changing every handler keeps the fix
/// in one place: the rate limiters, the login throttle and the scan audit
/// trail all keep extracting `ConnectInfo` and now all see the real caller.
async fn use_forwarded_client_ip(
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if let Some(client) = rate_limit::forwarded_client_ip(request.headers()) {
        // Port zero rather than the proxy's: the address is the client's, the
        // port belonged to a different connection, and nothing reads it.
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(SocketAddr::new(client, 0)));
    }

    next.run(request).await
}

/// Keeps one public origin for search engines, cookies and shared links while
/// preserving the exact path and query a visitor requested.
async fn redirect_www_to_apex(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let is_www = request
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|host| host.eq_ignore_ascii_case("www.glarion.app"));

    if is_www {
        let destination = format!("https://glarion.app{}", request.uri());
        return axum::response::Redirect::permanent(&destination).into_response();
    }

    next.run(request).await
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
        .route("/api/auth/logout", post(routes::accounts::logout))
        .route("/api/auth/verify", post(routes::accounts::verify_email))
        .route(
            "/api/auth/resend-verification",
            post(routes::accounts::resend_verification),
        )
        // Unauthenticated by necessity: someone who cannot sign in is
        // precisely who these are for.
        .route(
            "/api/auth/forgot-password",
            post(routes::accounts::forgot_password),
        )
        .route(
            "/api/auth/reset-password",
            post(routes::accounts::reset_password),
        )
        // Authenticated: starting a move needs the account and its password.
        .route("/api/account/email", post(routes::accounts::change_email))
        // Authenticated, and asks for the current password on top of the
        // session: see the handler for why the session alone is not enough.
        .route(
            "/api/account/password",
            post(routes::accounts::change_password),
        )
        // Unauthenticated by necessity: the link is followed from the new
        // mailbox, which by design is not where the session is. The token is
        // the authorization.
        .route(
            "/api/auth/confirm-email-change",
            post(routes::accounts::confirm_email_change),
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

/// The address a researcher writes to, published where a scanner looks.
///
/// The free check on the front page reports whether a site publishes
/// `.well-known/security.txt`. glarion.app did not, and the first domain a
/// visitor types into our own box is ours — so the page arguing that this
/// product notices what others miss opened by failing one of its own nine
/// checks.
///
/// Generated per request rather than shipped as a file because RFC 9116
/// requires an `Expires` date, and a file carries the one written the day it
/// was committed. A lapsed security.txt is worse than none: a scanner reads
/// it as a contact nobody maintains, so the fix would quietly become the
/// defect a few months later. This one is never stale.
///
/// The contact is the address already in the footer, the privacy policy and
/// the terms, not a `security@` alias — glarion.app publishes no MX records,
/// so mail to one would bounce. Same reason MAIL_REPLY_TO stays unset until
/// there is a monitored inbox behind it: a report that reaches nobody is the
/// failure this file exists to prevent.
async fn security_txt() -> impl IntoResponse {
    let site = std::env::var("PUBLIC_URL")
        .unwrap_or_else(|_| "https://glarion.app".to_string())
        .trim_end_matches('/')
        .to_string();
    let expires = (chrono::Utc::now() + chrono::Duration::days(90)).format("%Y-%m-%dT%H:%M:%SZ");

    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )],
        format!(
            "Contact: mailto:aurelio_11@outlook.it\n\
             Expires: {expires}\n\
             Preferred-Languages: en\n\
             Canonical: {site}/.well-known/security.txt\n\
             Policy: https://github.com/AurelioAvila/glarion/blob/master/SECURITY.md\n"
        ),
    )
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
    use axum::http::header::{
        CACHE_CONTROL, CONTENT_SECURITY_POLICY, REFERRER_POLICY, STRICT_TRANSPORT_SECURITY,
        X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
    };
    use axum::http::{HeaderName, HeaderValue};
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

    let permissions_policy = HeaderName::from_static("permissions-policy");
    let opener_policy = HeaderName::from_static("cross-origin-opener-policy");
    let security_headers = ServiceBuilder::new()
        .layer(SetResponseHeaderLayer::overriding(
            STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self' 'sha256-N+xaTeCDA8wjkvbTZ+/lxDmcQp1jBxLpAaSrBNojwpI='; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; font-src 'self'; upgrade-insecure-requests",
            ),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            REFERRER_POLICY,
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            permissions_policy,
            HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            opener_policy,
            HeaderValue::from_static("same-origin"),
        ));

    router
        // Explicit, because ServeDir would otherwise answer `/` with
        // index.html — which here is the dashboard shell, not the front
        // door. Getting this wrong shows a signed-out visitor a blank
        // application instead of the page that explains it.
        .route_service("/", revalidate.clone().service(ServeFile::new(&landing)))
        // The shareable result: /check?d=example.com is the same page, which
        // reads the query string and runs the check on load. A link an agency
        // can send to its client is the cheapest way this product travels,
        // and until now the only URL it had was the front page.
        //
        // Kept out of search results: every shared link would otherwise put a
        // near-duplicate of the landing page in the index, once per domain
        // anybody ever checked.
        .route_service(
            "/check",
            ServiceBuilder::new()
                .layer(SetResponseHeaderLayer::overriding(
                    HeaderName::from_static("x-robots-tag"),
                    HeaderValue::from_static("noindex"),
                ))
                .layer(revalidate.clone())
                .service(ServeFile::new(&landing)),
        )
        .route("/.well-known/security.txt", get(security_txt))
        // `/app` without a trailing slash, deliberately: the shell asks for
        // /dist/app.js absolutely, but any relative URL a future edit adds
        // would resolve against the wrong base under `/app/`.
        .route_service("/app", revalidate.clone().service(ServeFile::new(&shell)))
        .route_service("/app/", revalidate.clone().service(ServeFile::new(&shell)))
        .fallback_service(
            revalidate.service(ServeDir::new(web_root).append_index_html_on_directories(false)),
        )
        .layer(security_headers)
}
