//! Anonymous, bounded-cardinality counters. Never collect URLs, IPs, domains,
//! email addresses or account IDs here. Counts are operations, not people.
use crate::{
    error::{ApiError, ApiResult},
    state::AppState,
};
use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use std::{net::SocketAddr, time::Duration};

pub fn source(headers: &HeaderMap) -> Option<&str> {
    if headers.get("dnt").is_some_and(|v| v == "1")
        || headers.get("sec-gpc").is_some_and(|v| v == "1")
    {
        return None;
    }
    let value = headers.get("x-glarion-source")?.to_str().ok()?;
    match value {
        "direct" | "youtube" | "dev" | "search" | "referral" => Some(value),
        _ => None,
    }
}

pub async fn record(state: &AppState, headers: &HeaderMap, event: &str) {
    let Some(source) = source(headers) else {
        return;
    };
    // A metrics outage must not turn a successful business operation into an error.
    let result = tokio::time::timeout(
        Duration::from_millis(200),
        sqlx::query(
            "insert into growth_counts (source, event) values ($1, $2)
            on conflict (day, source, event) do update set total = growth_counts.total + 1",
        )
        .bind(source)
        .bind(event)
        .execute(&state.pool),
    )
    .await;
    if !matches!(result, Ok(Ok(_))) {
        tracing::warn!("growth counter write unavailable; operation preserved");
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PageEvent {
    LandingView,
    SampleReportView,
    SignupView,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageRequest {
    event: PageEvent,
}

pub async fn page(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<PageRequest>,
) -> ApiResult<StatusCode> {
    if source(&headers).is_none() {
        return Ok(StatusCode::NO_CONTENT);
    }
    if !state
        .auth_limiter
        .check_shared(&state.pool, "growth", peer.ip())
        .await
    {
        return Err(ApiError::TooManyRequests);
    }
    let event = match body.event {
        PageEvent::LandingView => "landing_view",
        PageEvent::SampleReportView => "sample_report_view",
        PageEvent::SignupView => "signup_view",
    };
    record(&state, &headers, event).await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn never_accepts_free_text_or_privacy_opt_outs() {
        let mut headers = HeaderMap::new();
        assert_eq!(source(&headers), None);
        headers.insert("x-glarion-source", "someone@example.com".parse().unwrap());
        assert_eq!(source(&headers), None);
        headers.insert("x-glarion-source", "youtube".parse().unwrap());
        assert_eq!(source(&headers), Some("youtube"));
        headers.insert("sec-gpc", "1".parse().unwrap());
        assert_eq!(source(&headers), None);
    }
    #[test]
    fn browser_cannot_report_server_successes() {
        assert!(serde_json::from_str::<PageRequest>(r#"{"event":"signup_created"}"#).is_err());
        assert!(
            serde_json::from_str::<PageRequest>(r#"{"event":"landing_view","email":"x"}"#).is_err()
        );
    }
}
