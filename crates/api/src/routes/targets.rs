//! Target registration and ownership verification.
//!
//! The flow is: create a target, receive verification instructions, publish
//! the token in DNS (or as a file), then ask us to check. Nothing here
//! touches the target beyond a single DNS lookup or one HTTPS GET of a
//! fixed path — verification is not a scan.

use axum::extract::{Path, State};
use axum::Json;
use chrono::{DateTime, Utc};
use orchestrator::domain::normalize_target;
use orchestrator::verification::{
    self, expiry_from, file_contains_token, is_currently_verified, token_present,
    VerificationMethod, VerificationStatus,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct CreateTargetRequest {
    pub domain: String,
}

#[derive(Serialize)]
pub struct TargetResponse {
    pub id: Uuid,
    pub domain: String,
    pub verified: bool,
    pub verification_expires_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
pub struct VerificationInstructions {
    pub verification_id: Uuid,
    pub token: String,
    pub dns_record_name: String,
    pub dns_record_value: String,
    pub well_known_url: String,
    pub well_known_content: String,
}

#[derive(Deserialize)]
pub struct CheckVerificationRequest {
    /// "dns_txt" or "well_known_file".
    pub method: String,
}

#[derive(Serialize)]
pub struct CheckVerificationResponse {
    pub verified: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub detail: String,
}

pub async fn create_target(
    State(state): State<AppState>,
    user: AuthUser,
    Json(body): Json<CreateTargetRequest>,
) -> ApiResult<Json<TargetResponse>> {
    // Rejects IP literals, loopback/internal names, and malformed hosts —
    // see orchestrator::domain for why this is a safety boundary.
    let domain =
        normalize_target(&body.domain).map_err(|err| ApiError::BadRequest(err.to_string()))?;

    let max_targets: i32 = sqlx::query_scalar(
        "select max_targets from entitlements where user_id = $1 and product = 'glarion'",
    )
    .bind(user.id)
    .fetch_optional(&state.pool)
    .await?
    // No entitlement row means no plan, which means no targets. Fail closed
    // rather than assuming a default allowance.
    .unwrap_or(0);

    let current: i64 = sqlx::query_scalar("select count(*) from targets where user_id = $1")
        .bind(user.id)
        .fetch_one(&state.pool)
        .await?;

    if current >= max_targets as i64 {
        return Err(ApiError::PlanLimit(format!(
            "your plan allows {max_targets} target(s)"
        )));
    }

    let target_id: Option<Uuid> = sqlx::query_scalar(
        "insert into targets (user_id, domain) values ($1, $2)
         on conflict (user_id, domain) do nothing
         returning id",
    )
    .bind(user.id)
    .bind(&domain)
    .fetch_optional(&state.pool)
    .await?;

    let target_id = target_id.ok_or_else(|| ApiError::Conflict("target already exists".into()))?;

    Ok(Json(TargetResponse {
        id: target_id,
        domain,
        verified: false,
        verification_expires_at: None,
    }))
}

pub async fn list_targets(
    State(state): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<Vec<TargetResponse>>> {
    let rows: Vec<TargetWithVerificationRow> = sqlx::query_as(
        "select t.id, t.domain, v.verified_at, v.expires_at
             from targets t
             left join lateral (
                 select verified_at, expires_at
                 from target_verifications
                 where target_id = t.id and verified_at is not null
                 order by verified_at desc
                 limit 1
             ) v on true
             where t.user_id = $1
             order by t.created_at desc",
    )
    .bind(user.id)
    .fetch_all(&state.pool)
    .await?;

    let now = Utc::now();
    let targets = rows
        .into_iter()
        .map(|row| {
            let status = VerificationStatus {
                verified_at: row.verified_at,
                expires_at: row.expires_at,
            };
            TargetResponse {
                id: row.id,
                domain: row.domain,
                verified: is_currently_verified(&status, now),
                verification_expires_at: row.expires_at,
            }
        })
        .collect();

    Ok(Json(targets))
}

/// A target joined with its most recent completed verification, if any.
#[derive(sqlx::FromRow)]
struct TargetWithVerificationRow {
    id: Uuid,
    domain: String,
    verified_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
}

/// Issues a fresh verification token and returns the instructions for
/// proving ownership. Calling this again supersedes any pending token.
pub async fn start_verification(
    State(state): State<AppState>,
    user: AuthUser,
    Path(target_id): Path<Uuid>,
) -> ApiResult<Json<VerificationInstructions>> {
    let domain = owned_target_domain(&state, user.id, target_id).await?;
    let token = verification::generate_token();

    // The row is created without a method: the user picks how to prove
    // ownership at check time, and the same token works for either.
    let verification_id: Uuid = sqlx::query_scalar(
        "insert into target_verifications (target_id, method, token)
         values ($1, 'dns_txt', $2)
         returning id",
    )
    .bind(target_id)
    .bind(&token)
    .fetch_one(&state.pool)
    .await?;

    Ok(Json(VerificationInstructions {
        verification_id,
        dns_record_name: verification::dns_txt_record_name(&domain),
        dns_record_value: token.clone(),
        well_known_url: verification::well_known_url(&domain),
        well_known_content: token.clone(),
        token,
    }))
}

/// Performs the actual ownership check against the most recent pending
/// token for this target.
pub async fn check_verification(
    State(state): State<AppState>,
    user: AuthUser,
    Path(target_id): Path<Uuid>,
    Json(body): Json<CheckVerificationRequest>,
) -> ApiResult<Json<CheckVerificationResponse>> {
    let domain = owned_target_domain(&state, user.id, target_id).await?;

    let method = match body.method.as_str() {
        "dns_txt" => VerificationMethod::DnsTxt,
        "well_known_file" => VerificationMethod::WellKnownFile,
        other => {
            return Err(ApiError::BadRequest(format!(
                "unknown verification method '{other}'"
            )))
        }
    };

    let pending: Option<(Uuid, String)> = sqlx::query_as(
        "select id, token from target_verifications
         where target_id = $1 and verified_at is null
         order by created_at desc
         limit 1",
    )
    .bind(target_id)
    .fetch_optional(&state.pool)
    .await?;

    let (verification_id, token) = pending
        .ok_or_else(|| ApiError::BadRequest("no pending verification — start one first".into()))?;

    let matched = match method {
        VerificationMethod::DnsTxt => {
            let records = verification::fetch_dns_txt_records(&domain)
                .await
                .map_err(ApiError::Internal)?;
            token_present(&records, &token)
        }
        VerificationMethod::WellKnownFile => {
            let body = verification::fetch_well_known_file(&domain)
                .await
                .map_err(ApiError::Internal)?;
            file_contains_token(&body, &token)
        }
    };

    if !matched {
        return Ok(Json(CheckVerificationResponse {
            verified: false,
            expires_at: None,
            detail: "token not found yet — DNS changes can take a few minutes to propagate".into(),
        }));
    }

    let now = Utc::now();
    let expires_at = expiry_from(now);

    sqlx::query(
        "update target_verifications
         set verified_at = $1, expires_at = $2, method = $3
         where id = $4",
    )
    .bind(now)
    .bind(expires_at)
    .bind(method.as_db_str())
    .bind(verification_id)
    .execute(&state.pool)
    .await?;

    Ok(Json(CheckVerificationResponse {
        verified: true,
        expires_at: Some(expires_at),
        detail: "ownership verified".into(),
    }))
}

/// Loads a target's domain, confirming it belongs to this user. Returns
/// `NotFound` (not `Unauthorized`) for someone else's target so the
/// response cannot be used to probe which target ids exist.
async fn owned_target_domain(
    state: &AppState,
    user_id: Uuid,
    target_id: Uuid,
) -> ApiResult<String> {
    sqlx::query_scalar("select domain from targets where id = $1 and user_id = $2")
        .bind(target_id)
        .bind(user_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(ApiError::NotFound)
}
