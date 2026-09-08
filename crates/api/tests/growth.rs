use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use sqlx::PgPool;
use std::net::SocketAddr;
use tower::ServiceExt;

#[tokio::test]
async fn counters_are_private_and_signup_retries_do_not_create_conversions() {
    let url = std::env::var("TEST_DATABASE_URL").expect("use the dedicated local test database");
    let pool = PgPool::connect(&url).await.unwrap();
    sqlx::migrate!("../../migrations").run(&pool).await.unwrap();
    sqlx::query("truncate users, growth_counts, rate_limit_buckets cascade")
        .execute(&pool)
        .await
        .unwrap();
    let app = api::router(api::state::AppState::new(
        pool.clone(),
        "test-secret-at-least-thirty-two-bytes".into(),
    ));
    let signup = r#"{"first_name":"Test","last_name":"Agency","date_of_birth":"1990-01-01","email":"growth@example.test","password":"long-enough-password","password_confirmation":"long-enough-password"}"#;
    for (path, body, expected) in [
        (
            "/api/growth/page",
            r#"{"event":"landing_view"}"#,
            StatusCode::NO_CONTENT,
        ),
        (
            "/api/growth/page",
            r#"{"event":"signup_created"}"#,
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        ("/api/auth/signup", signup, StatusCode::OK),
        ("/api/auth/signup", signup, StatusCode::OK),
    ] {
        let mut req = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header("x-glarion-source", "youtube")
            .body(Body::from(body))
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 90], 9000))));
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), expected);
    }
    let counts: Vec<(String, i64)> =
        sqlx::query_as("select event, total from growth_counts order by event")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        counts,
        vec![("landing_view".into(), 1), ("signup_created".into(), 1)]
    );
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/growth/page")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}
