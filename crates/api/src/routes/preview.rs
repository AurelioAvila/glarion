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
use orchestrator::preview::{preview, PreviewError};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

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

pub async fn run_preview(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<PreviewRequest>,
) -> ApiResult<Json<PreviewResponse>> {
    // The verification budget, not the auth one: this endpoint causes
    // outbound traffic to a host the caller named, which is the same shape
    // of abuse the ownership check has to be protected from.
    if !state.verification_limiter.check(peer.ip()) {
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
