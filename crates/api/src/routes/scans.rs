//! Scan queueing — and the gate that guards it.
//!
//! This is the most security-sensitive handler in the codebase. A scan may
//! only be queued when *all* of the following hold:
//!
//!   1. The target belongs to the authenticated user.
//!   2. That target's ownership verification is present and unexpired.
//!   3. The requested tool is on the allowlist.
//!   4. The target is within its scan-rate budget.
//!   5. The user explicitly accepted the scan terms for this request.
//!   6. The account is on a plan that includes the full scan.
//!
//! Each of these is checked here, before any row is written. The
//! authorization record is inserted in the same transaction as the job, so
//! a queued job can never exist without the audit trail explaining who
//! authorized it.

use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::Json;
use chrono::{DateTime, Duration, Utc};
use orchestrator::policy::{is_allowed_tool, within_scan_budget, ALLOWED_TOOLS};
use orchestrator::verification::{is_currently_verified, VerificationStatus};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// The most recent completed ownership verification for a target.
#[derive(sqlx::FromRow)]
struct VerificationRow {
    id: Uuid,
    verified_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
pub struct CreateScanRequest {
    pub target_id: Uuid,
    pub tool: String,
    /// Must be explicitly true. The client sending `false` — or omitting a
    /// value — is a refusal, not a default-yes.
    pub accept_terms: bool,
}

#[derive(Serialize)]
pub struct ScanJobResponse {
    pub id: Uuid,
    pub target_id: Uuid,
    pub tool: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

pub async fn create_scan(
    State(state): State<AppState>,
    user: AuthUser,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<CreateScanRequest>,
) -> ApiResult<Json<ScanJobResponse>> {
    // (5) Explicit authorization for this specific request. Checked first so
    // an unconsented request never even triggers lookups.
    if !body.accept_terms {
        return Err(ApiError::BadRequest(
            "you must accept the scan terms to authorize this scan".into(),
        ));
    }

    // (3) Tool allowlist. Checked before any DB work — a bogus tool name is
    // a client bug, not a lookup.
    if !is_allowed_tool(&body.tool) {
        return Err(ApiError::BadRequest(format!(
            "unsupported tool '{}' (allowed: {})",
            body.tool,
            ALLOWED_TOOLS.join(", ")
        )));
    }

    // (1) Ownership of the *record*: someone else's target is reported as
    // not found, so ids cannot be probed.
    let target: Option<(Uuid,)> =
        sqlx::query_as("select id from targets where id = $1 and user_id = $2")
            .bind(body.target_id)
            .bind(user.id)
            .fetch_optional(&state.pool)
            .await?;
    target.ok_or(ApiError::NotFound)?;

    // (2) THE GATE. Ownership of the *domain*. Load the most recent
    // completed verification and require it to still be valid right now.
    let verification: Option<VerificationRow> = sqlx::query_as(
        "select id, verified_at, expires_at from target_verifications
         where target_id = $1 and verified_at is not null
         order by verified_at desc
         limit 1",
    )
    .bind(body.target_id)
    .fetch_optional(&state.pool)
    .await?;

    // No completed verification at all — refuse before looking any further.
    let verification = verification.ok_or(ApiError::TargetNotVerified)?;
    let verification_id = verification.id;

    let status = VerificationStatus {
        verified_at: verification.verified_at,
        expires_at: verification.expires_at,
    };
    if !is_currently_verified(&status, Utc::now()) {
        return Err(ApiError::TargetNotVerified);
    }

    // (6) The plan. Checked on the server rather than only hidden in the
    // interface: a control nobody can see is not a limit, it is a
    // suggestion, and this one is the thing the subscription buys. No
    // entitlement row reads as the free plan, the same fail-closed way the
    // site allowance does — see billing::current_plan.
    if !crate::billing::current_plan(&state.pool, user.id)
        .await?
        .allows_full_scan()
    {
        return Err(ApiError::PlanLimit(
            "the full scan is part of the paid plans — the free check on the site page needs no subscription".into(),
        ));
    }

    // (4) Intensity budget for this target over the trailing window.
    let window_start = Utc::now() - Duration::hours(24);
    let recent: i64 = sqlx::query_scalar(
        "select count(*) from scan_jobs where target_id = $1 and created_at >= $2",
    )
    .bind(body.target_id)
    .bind(window_start)
    .fetch_one(&state.pool)
    .await?;

    if !within_scan_budget(recent) {
        return Err(ApiError::PlanLimit(
            "this target has reached its scan limit for the last 24 hours".into(),
        ));
    }

    // Audit record and job are written together: a job without a matching
    // authorization row must be impossible.
    let mut tx = state.pool.begin().await?;

    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .chars()
        .take(512)
        .collect::<String>();

    let authorization_id: Uuid = sqlx::query_scalar(
        "insert into scan_authorizations
             (user_id, target_id, target_verification_id, ip_address, user_agent)
         values ($1, $2, $3, $4::inet, $5)
         returning id",
    )
    .bind(user.id)
    .bind(body.target_id)
    .bind(verification_id)
    .bind(peer.ip().to_string())
    .bind(&user_agent)
    .fetch_one(&mut *tx)
    .await?;

    let job: (Uuid, String, DateTime<Utc>) = sqlx::query_as(
        "insert into scan_jobs (target_id, scan_authorization_id, tool)
         values ($1, $2, $3)
         returning id, status, created_at",
    )
    .bind(body.target_id)
    .bind(authorization_id)
    .bind(&body.tool)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;

    tracing::info!(
        user_id = %user.id,
        target_id = %body.target_id,
        job_id = %job.0,
        tool = %body.tool,
        "scan authorized and queued"
    );

    Ok(Json(ScanJobResponse {
        id: job.0,
        target_id: body.target_id,
        tool: body.tool,
        status: job.1,
        created_at: job.2,
    }))
}
