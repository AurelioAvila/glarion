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
