//! What each URL serves.
//!
//! Small, but pinning a mistake that is easy to make and quiet when made:
//! `ServeDir` answers a directory request with `index.html`, and in this
//! repository `index.html` is the signed-in dashboard shell rather than the
//! front door. Wired the obvious way, `/` serves a blank application to
//! every first-time visitor — a page that looks broken rather than one that
//! explains the product, and nothing fails or logs to say so.
//!
//! No database needed: this exercises routing only.

use api::with_static_files;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use tower::ServiceExt;

/// A web directory with the two pages, distinguishable by their contents.
fn web_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("glarion-static-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(dir.join("dist")).unwrap();
    std::fs::write(dir.join("landing.html"), "THE LANDING PAGE").unwrap();
    std::fs::write(dir.join("index.html"), "THE DASHBOARD SHELL").unwrap();
    std::fs::write(dir.join("privacy.html"), "THE PRIVACY POLICY").unwrap();
    std::fs::write(dir.join("terms.html"), "THE TERMS").unwrap();
    std::fs::write(dir.join("robots.txt"), "User-agent: *\nAllow: /").unwrap();
    std::fs::write(dir.join("sitemap.xml"), "<urlset></urlset>").unwrap();
    std::fs::write(dir.join("landing.js"), "// landing interaction").unwrap();
    std::fs::write(dir.join("glarion-mark.png"), "PNG BRAND MARK").unwrap();
    std::fs::write(dir.join("site.webmanifest"), "GLARION MANIFEST").unwrap();
    std::fs::write(dir.join("dist/app.js"), "// built app").unwrap();
    dir
}

async fn body_of(router: Router, path: &str) -> (StatusCode, String) {
    let response = router
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();

    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();

    (status, String::from_utf8_lossy(&bytes).to_string())
}

#[tokio::test]
async fn the_root_serves_the_landing_page_not_the_dashboard_shell() {
    let dir = web_dir();
    let router = with_static_files(Router::new(), &dir);

    let (status, body) = body_of(router, "/").await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("THE LANDING PAGE"),
        "`/` must serve the landing page; got: {body}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn the_dashboard_is_served_with_and_without_a_trailing_slash() {
    let dir = web_dir();

    for path in ["/app", "/app/"] {
        let router = with_static_files(Router::new(), &dir);
        let (status, body) = body_of(router, path).await;

        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(
            body.contains("THE DASHBOARD SHELL"),
            "{path} must serve the application shell; got: {body}"
        );
    }

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn built_assets_are_served() {
    let dir = web_dir();
    let router = with_static_files(Router::new(), &dir);

    // The shell asks for this path absolutely, so it has to resolve from
    // the root whichever URL the shell itself was served from.
    let (status, body) = body_of(router, "/dist/app.js").await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("built app"));

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn public_documents_are_served_instead_of_the_landing_page() {
    let dir = web_dir();

    for (path, expected) in [
        ("/privacy.html", "THE PRIVACY POLICY"),
        ("/terms.html", "THE TERMS"),
        ("/robots.txt", "User-agent: *"),
        ("/sitemap.xml", "<urlset>"),
        ("/landing.js", "landing interaction"),
        ("/glarion-mark.png", "PNG BRAND MARK"),
        ("/site.webmanifest", "GLARION MANIFEST"),
    ] {
        let router = with_static_files(Router::new(), &dir);
        let (status, body) = body_of(router, path).await;

        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(body.contains(expected), "wrong body for {path}: {body}");
        assert!(!body.contains("THE LANDING PAGE"), "{path} fell back to / ");
    }

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn security_txt_is_published_and_has_not_expired() {
    // The free check reports whether a site publishes this file, so ours
    // failing our own check is the cheapest kind of credibility to lose.
    // The expiry is the part that rots: RFC 9116 wants a date, a scanner
    // treats a past one as an abandoned contact, and a hand-written file
    // would pass on the day it shipped and fail every day after.
    let dir = web_dir();
    let router = with_static_files(Router::new(), &dir);

    let (status, body) = body_of(router, "/.well-known/security.txt").await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Contact: mailto:"), "no contact: {body}");
    assert!(body.contains("Canonical: "), "no canonical URL: {body}");

    let expires = body
        .lines()
        .find_map(|line| line.strip_prefix("Expires: "))
        .expect("RFC 9116 requires an Expires field");
    let expires: chrono::DateTime<chrono::Utc> = expires.parse().expect("Expires must be RFC 3339");
    let now = chrono::Utc::now();
    assert!(expires > now, "already expired: {expires}");
    assert!(
        expires < now + chrono::Duration::days(366),
        "RFC 9116 asks for less than a year out: {expires}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn an_unknown_public_path_is_a_real_404() {
    let dir = web_dir();
    let router = with_static_files(Router::new(), &dir);

    let (status, body) = body_of(router, "/this-page-does-not-exist").await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!body.contains("THE LANDING PAGE"));
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn browser_security_headers_are_present() {
    let dir = web_dir();
    let router = with_static_files(Router::new(), &dir);
    let response = router
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let headers = response.headers();

    assert_eq!(
        headers
            .get(axum::http::header::STRICT_TRANSPORT_SECURITY)
            .and_then(|value| value.to_str().ok()),
        Some("max-age=31536000; includeSubDomains")
    );
    assert_eq!(
        headers
            .get(axum::http::header::X_CONTENT_TYPE_OPTIONS)
            .and_then(|value| value.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        headers
            .get(axum::http::header::X_FRAME_OPTIONS)
            .and_then(|value| value.to_str().ok()),
        Some("DENY")
    );
    let csp = headers
        .get(axum::http::header::CONTENT_SECURITY_POLICY)
        .and_then(|value| value.to_str().ok())
        .expect("CSP must be present");
    assert!(csp.contains("frame-ancestors 'none'"));
    assert!(csp.contains("object-src 'none'"));

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn static_responses_are_never_trusted_without_revalidation() {
    // A regression, not a preference: every static route was once served
    // with no Cache-Control header at all, so a browser that had loaded
    // the app once could keep running yesterday's bundle for hours after
    // a deploy that curl and the server both confirmed had shipped. Every
    // route here has to say "no-cache" — asking to revalidate, not asking
    // to be re-downloaded — so a signed-in browser sees a new deploy on
    // its very next request.
    let dir = web_dir();

    for path in ["/", "/app", "/app/", "/dist/app.js"] {
        let router = with_static_files(Router::new(), &dir);
        let response = router
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-cache"),
            "{path} must revalidate on every load"
        );
    }

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn api_routes_still_win_over_the_static_fallback() {
    let dir = web_dir();

    // The fallback answers anything unmatched with the landing page, which
    // would happily swallow a mistyped API path and return HTML with a 200
    // to something expecting JSON.
    let router = with_static_files(
        Router::new().route("/health", axum::routing::get(|| async { "ok" })),
        &dir,
    );

    let (status, body) = body_of(router, "/health").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok");

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn a_missing_web_directory_leaves_the_api_alone() {
    // An API deployed without the frontend is a legitimate thing to want,
    // and the integration tests build the router with no web directory in
    // reach. Neither should fail to start.
    let router = with_static_files(
        Router::new().route("/health", axum::routing::get(|| async { "ok" })),
        std::path::Path::new("/nonexistent-glarion-web-root"),
    );

    let (status, body) = body_of(router.clone(), "/health").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok");

    // And nothing is invented to serve at the root.
    let (status, _) = body_of(router, "/").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
