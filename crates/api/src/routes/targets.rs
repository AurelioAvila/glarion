//! Target registration and ownership verification.
//!
//! The flow is: create a target, receive verification instructions, publish
//! the token in DNS (or as a file), then ask us to check. Nothing here
//! touches the target beyond a single DNS lookup or one HTTPS GET of a
//! fixed path — verification is not a scan.

use axum::extract::{ConnectInfo, Path, State};
use axum::Json;
use chrono::{DateTime, Utc};
use orchestrator::domain::normalize_target;
use orchestrator::schedule::Cadence;
use orchestrator::verification::{
    self, expiry_from, file_contains_token, is_currently_verified, token_present,
    VerificationMethod, VerificationStatus,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct CreateTargetRequest {
    pub domain: String,
    /// Which of the agency's clients this site belongs to. Appears on the
    /// report; optional, because a freelancer scanning their own site has
    /// nobody to name.
    #[serde(default)]
    pub client_name: Option<String>,
}

#[derive(Serialize)]
pub struct TargetResponse {
    pub id: Uuid,
    pub domain: String,
    pub client_name: Option<String>,
    pub verified: bool,
    pub verification_expires_at: Option<DateTime<Utc>>,
    /// "manual", "weekly" or "monthly".
    pub scan_cadence: String,
}

#[derive(Deserialize)]
pub struct SetCadenceRequest {
    pub cadence: String,
}

/// Puts a site on a recurring schedule, or takes it off one.
///
/// A schedule is standing authorization: the customer is saying "keep
/// checking this" rather than approving one scan. That is why it can only
/// be set on a target whose ownership is currently proved — otherwise the
/// instruction would outlive the permission it depends on.
pub async fn set_cadence(
    State(state): State<AppState>,
    user: AuthUser,
    Path(target_id): Path<Uuid>,
    Json(body): Json<SetCadenceRequest>,
) -> ApiResult<Json<TargetResponse>> {
    let cadence = Cadence::from_str_or_manual(&body.cadence);

    // Refuse an unrecognised value rather than quietly storing "manual":
    // somebody asking for a schedule and getting silence is worse than an
    // error they can see.
    if cadence == Cadence::Manual && !body.cadence.trim().eq_ignore_ascii_case("manual") {
        return Err(ApiError::BadRequest(
            "cadence must be manual, weekly or monthly".into(),
        ));
    }

    let row: Option<TargetWithVerificationRow> = sqlx::query_as(
        "select t.id, t.domain, t.client_name, t.scan_cadence, v.verified_at, v.expires_at
         from targets t
         left join lateral (
             select verified_at, expires_at from target_verifications
             where target_id = t.id and verified_at is not null
             order by verified_at desc limit 1
         ) v on true
         where t.id = $1 and t.user_id = $2",
    )
    .bind(target_id)
    .bind(user.id)
    .fetch_optional(&state.pool)
    .await?;

    let row = row.ok_or(ApiError::NotFound)?;
    let now = Utc::now();
    let status = VerificationStatus {
        verified_at: row.verified_at,
        expires_at: row.expires_at,
    };

    if cadence != Cadence::Manual && !is_currently_verified(&status, now) {
        return Err(ApiError::TargetNotVerified);
    }

    // Clearing the stamp when a schedule is switched on makes the first
    // scan happen now rather than a week from now, so turning monitoring on
    // produces a result instead of silence.
    sqlx::query(
        "update targets
         set scan_cadence = $2,
             last_scheduled_at = case when $2 = 'manual' then last_scheduled_at else null end
         where id = $1",
    )
    .bind(target_id)
    .bind(cadence.as_db_str())
    .execute(&state.pool)
    .await?;

    Ok(Json(TargetResponse {
        id: row.id,
        domain: row.domain,
        client_name: row.client_name,
        verified: is_currently_verified(&status, now),
        verification_expires_at: row.expires_at,
        scan_cadence: cadence.as_db_str().to_string(),
    }))
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

    let client_name = body
        .client_name
        .map(|name| name.trim().chars().take(120).collect::<String>())
        .filter(|name| !name.is_empty());

    let target_id: Option<Uuid> = sqlx::query_scalar(
        "insert into targets (user_id, domain, client_name) values ($1, $2, $3)
         on conflict (user_id, domain) do nothing
         returning id",
    )
    .bind(user.id)
    .bind(&domain)
    .bind(&client_name)
    .fetch_optional(&state.pool)
    .await?;

    let target_id = target_id.ok_or_else(|| ApiError::Conflict("target already exists".into()))?;

    Ok(Json(TargetResponse {
        id: target_id,
        domain,
        client_name,
        verified: false,
        verification_expires_at: None,
        scan_cadence: "manual".to_string(),
    }))
}

pub async fn list_targets(
    State(state): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<Vec<TargetResponse>>> {
    let rows: Vec<TargetWithVerificationRow> = sqlx::query_as(
        "select t.id, t.domain, t.client_name, t.scan_cadence, v.verified_at, v.expires_at
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
                client_name: row.client_name,
                verified: is_currently_verified(&status, now),
                verification_expires_at: row.expires_at,
                scan_cadence: row.scan_cadence,
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
    client_name: Option<String>,
    scan_cadence: String,
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
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(target_id): Path<Uuid>,
    Json(body): Json<CheckVerificationRequest>,
) -> ApiResult<Json<CheckVerificationResponse>> {
    // This handler causes outbound traffic to a host the caller chose, so
    // it is metered even though the caller is authenticated and owns the
    // target record.
    if !state.verification_limiter.check(peer.ip()) {
        return Err(ApiError::TooManyRequests);
    }

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

    // A lookup that cannot complete is reported as "not verified yet" with
    // an explanation, not as a server error.
    //
    // From the user's side both outcomes mean "keep waiting", and a 500
    // tells them nothing they can act on — while an unreachable resolver or
    // an unreachable site is a perfectly ordinary thing to hit halfway
    // through setting up DNS. It stays fail-closed either way: nothing here
    // can report success without actually seeing the token.
    let matched = match method {
        VerificationMethod::DnsTxt => match verification::fetch_dns_txt_records(&domain).await {
            Ok(records) => token_present(&records, &token),
            Err(_) => {
                return Ok(Json(CheckVerificationResponse {
                    verified: false,
                    expires_at: None,
                    detail: "We could not reach DNS just now. Please try again in a moment.".into(),
                }))
            }
        },
        VerificationMethod::WellKnownFile => {
            match verification::fetch_well_known_file(&domain).await {
                Ok(body) => file_contains_token(&body, &token),
                Err(_) => {
                    return Ok(Json(CheckVerificationResponse {
                        verified: false,
                        expires_at: None,
                        detail: "We could not fetch that file. Check it is reachable over                                  HTTPS, then try again."
                            .into(),
                    }))
                }
            }
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
