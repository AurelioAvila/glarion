//! The check anyone can run on any domain.
//!
//! This is the only endpoint that touches a host without proof of
//! ownership, and it is allowed to because of what it does: one request to
//! a front page and two to files published for automated readers, reading
//! only what the site broadcasts. See `orchestrator::preview` for why that
//! is a different act from scanning.
//!
//! Being ungated makes the limits the only thing standing between this and
//! a way to make our servers fetch arbitrary URLs on request, so they are
//! tighter here than anywhere else.

use axum::extract::{ConnectInfo, State};
use axum::Json;
use chrono::{DateTime, Duration, Utc};
use orchestrator::mailer::{preview_report_email, ReportLine};
use orchestrator::preview::{preview, PreviewError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// How long one address must wait between free reports.
///
/// This is the limit that matters. A per-IP cap alone leaves the endpoint
/// as a way to send somebody repeated mail from a rotating source, which
/// is mail-bombing with our return address on it.
const RECIPIENT_COOLDOWN_MINUTES: i64 = 30;

/// Total free reports one address may ever receive.
///
/// A count that keeps climbing is the signature of an address being
/// targeted rather than a person using the product. Somebody with a real
/// need beyond this has an account.
const RECIPIENT_LIFETIME_LIMIT: i32 = 12;

#[derive(Deserialize)]
pub struct PreviewRequest {
    pub domain: String,
}

#[derive(Serialize)]
pub struct PreviewObservation {
    pub label: String,
    pub value: String,
    pub is_finding: bool,
}

#[derive(Serialize)]
pub struct PreviewResponse {
    pub domain: String,
    pub observations: Vec<PreviewObservation>,
    pub notes: Vec<String>,
    /// What this check deliberately did not do.
    ///
    /// Sent with every result rather than written into the page, so the
    /// boundary travels with the data: somebody reading a clean preview
    /// should not come away believing the site was fully examined.
    pub caveat: String,
}

const CAVEAT: &str = "This reads only what the site publishes to any visitor. \
    A full scan checks far more, and needs the domain's owner to confirm the request.";

#[derive(Deserialize)]
pub struct EmailPreviewRequest {
    pub domain: String,
    pub email: String,
}

/// Emails the free report to whoever asked for it.
///
/// Deliberately not a marketing capture. The address is used to deliver
/// what was requested and nothing else; anyone who wants to hear from us
/// again opts into that separately, through the newsletter the rest of the
/// portfolio shares.
pub async fn email_preview(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<EmailPreviewRequest>,
) -> ApiResult<Json<MessageResponse>> {
    if !state
        .verification_limiter
        .check_shared(&state.pool, "preview", peer.ip())
        .await
    {
        return Err(ApiError::TooManyRequests);
    }

    let email = normalize_email(&body.email)?;

    // This endpoint deliberately does NOT refuse when the last send failed.
    //
    // It did for one commit, and that was a hole: the check ran before the
    // attempt, so nothing inside this feature could ever clear the flag
    // again. One visitor typing an address the provider rejects would latch
    // it and take the form off the page for everybody until an unrelated
    // account email happened to succeed. A guard that only a different
    // feature can lift is an outage with extra steps.
    //
    // The attempt below always runs, so a provider that recovers is noticed
    // by the next request rather than never.

    // The same answer whatever happens next.
    //
    // Saying "we sent it" versus "that address is rate limited" would turn
    // this into a way to test which addresses have been used, and saying
    // "we could not reach that domain" is the only part worth reporting —
    // which happens before this point.
    let answer = Ok(Json(MessageResponse {
        message: "If that address can receive it, the report is on its way.".to_string(),
    }));

    let result = preview(&body.domain).await.map_err(|error| match error {
        PreviewError::InvalidTarget(message) => ApiError::BadRequest(message),
        PreviewError::Unreachable(domain) => {
            ApiError::BadRequest(format!("We could not reach {domain}."))
        }
    })?;

    let domain = orchestrator::domain::normalize_target(&body.domain)
        .map_err(|err| ApiError::BadRequest(err.to_string()))?;

    if !claim_recipient_slot(&state, &email).await? {
        return answer;
    }

    let lines: Vec<ReportLine> = result
        .observations
        .into_iter()
        .map(|observation| ReportLine {
            label: observation.label,
            value: observation.value,
            is_finding: observation.is_finding,
        })
        .collect();

    let link = state.mailer.app_link("/signup");
    let message = preview_report_email(&domain, &lines, &link);

    if let Err(error) = state.mailer.send(&email, &message).await {
        // Logged rather than surfaced: the caller cannot act on our mail
        // provider having a bad minute, and telling them the address
        // specifically failed would leak that it exists.
        tracing::error!(error = ?error, "could not send a preview report");
    }

    answer
}

/// Records that this address is receiving a report, or refuses.
///
/// The address is stored only as a hash: recognising it again is the whole
/// requirement, and keeping the plaintext would mean holding personal data
/// for a purpose we could not name.
async fn claim_recipient_slot(state: &AppState, email: &str) -> ApiResult<bool> {
    let hash = format!("{:x}", Sha256::digest(email.as_bytes()));

    let existing: Option<(DateTime<Utc>, i32)> = sqlx::query_as(
        "select last_sent_at, send_count from preview_email_sends where email_hash = $1",
    )
    .bind(&hash)
    .fetch_optional(&state.pool)
    .await?;

    if let Some((last_sent_at, count)) = existing {
        if count >= RECIPIENT_LIFETIME_LIMIT {
            return Ok(false);
        }
        if Utc::now() - last_sent_at < Duration::minutes(RECIPIENT_COOLDOWN_MINUTES) {
            return Ok(false);
        }
    }

    sqlx::query(
        "insert into preview_email_sends (email_hash) values ($1)
         on conflict (email_hash) do update
         set last_sent_at = now(), send_count = preview_email_sends.send_count + 1",
    )
    .bind(&hash)
    .execute(&state.pool)
    .await?;

    Ok(true)
}

fn normalize_email(input: &str) -> ApiResult<String> {
    let email = input.trim().to_ascii_lowercase();

    if email.is_empty() || !email.contains('@') || email.len() > 320 {
        return Err(ApiError::BadRequest("a valid email is required".into()));
    }

    Ok(email)
}

#[derive(Serialize)]
pub struct MessageResponse {
    pub message: String,
}

pub async fn run_preview(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<PreviewRequest>,
) -> ApiResult<Json<PreviewResponse>> {
    // The verification budget, not the auth one: this endpoint causes
    // outbound traffic to a host the caller named, which is the same shape
    // of abuse the ownership check has to be protected from.
    if !state
        .verification_limiter
        .check_shared(&state.pool, "preview", peer.ip())
        .await
    {
        return Err(ApiError::TooManyRequests);
    }

    let result = preview(&body.domain).await.map_err(|error| match error {
        PreviewError::InvalidTarget(message) => ApiError::BadRequest(message),
        PreviewError::Unreachable(domain) => {
            ApiError::BadRequest(format!("We could not reach {domain}."))
        }
    })?;

    // Normalised rather than echoed: the caller may have typed a URL, and
    // the response should name the host that was actually looked at.
    let domain = orchestrator::domain::normalize_target(&body.domain)
        .map_err(|err| ApiError::BadRequest(err.to_string()))?;

    Ok(Json(PreviewResponse {
        domain,
        observations: result
            .observations
            .into_iter()
            .map(|observation| PreviewObservation {
                label: observation.label,
                value: observation.value,
                is_finding: observation.is_finding,
            })
            .collect(),
        notes: result.notes,
        caveat: CAVEAT.to_string(),
    }))
}
