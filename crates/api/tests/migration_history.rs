use sqlx::{postgres::PgPoolOptions, PgPool};

#[tokio::test]
async fn orphaned_history_is_tolerated_but_present_checksums_are_enforced() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("skipping: TEST_DATABASE_URL not set");
        return;
    };
    let admin = PgPool::connect(&url).await.unwrap();
    let database: String = sqlx::query_scalar("select current_database()")
        .fetch_one(&admin)
        .await
        .unwrap();
    assert!(
        database.ends_with("_test"),
        "dedicated test database required"
    );
    let schema = format!("migration_test_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("create schema {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let search_path = format!("set search_path to {schema}");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .after_connect(move |connection, _| {
            let statement = search_path.clone();
            Box::pin(async move {
                sqlx::query(&statement).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    api::migrate_database(&pool).await.unwrap();
    sqlx::query("insert into _sqlx_migrations (version, description, success, checksum, execution_time) values (11, 'historical growth counts', true, decode('00','hex'), 0)")
        .execute(&pool).await.unwrap();
    api::migrate_database(&pool).await.unwrap();
    let version_13: bool = sqlx::query_scalar(
        "select exists(select 1 from _sqlx_migrations where version = 13 and success)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(version_13);
    sqlx::query("update _sqlx_migrations set checksum = decode('00','hex') where version = 13")
        .execute(&pool)
        .await
        .unwrap();
    let result = api::migrate_database(&pool).await;
    pool.close().await;
    sqlx::query(&format!("drop schema {schema} cascade"))
        .execute(&admin)
        .await
        .unwrap();
    assert!(matches!(
        result,
        Err(sqlx::migrate::MigrateError::VersionMismatch(13))
    ));
}
