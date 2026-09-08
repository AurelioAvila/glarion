use api::{router, state::AppState};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

#[tokio::test]
async fn api_responses_disable_storage_even_when_authentication_fails() {
    // No connection: rejection happens before database access.
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
        .unwrap();
    let app = router(AppState::new(
        pool,
        "test-secret-longer-than-thirty-two-characters".into(),
    ));
    for path in ["/api/profile", "/api/scans", "/api/targets", "/api/billing"] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(response.headers()["cache-control"], "no-store", "{path}");
    }
}
