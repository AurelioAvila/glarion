//! API error type and its HTTP mapping.
//!
//! Internal failures deliberately do not leak their detail to the client —
//! the detail goes to the log, the client gets a generic message. The one
//! error we are explicit about is `TargetNotVerified`, because the caller
//! genuinely needs to know why the scan was refused and what to do about it.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("unauthorized")]
    Unauthorized,

    #[error("{0}")]
    BadRequest(String),

    #[error("not found")]
    NotFound,

    #[error("{0}")]
    Conflict(String),

    /// The scan gate. Kept as its own variant rather than a generic 403 so
    /// that it can never be accidentally constructed from an unrelated
    /// permission check, and so the refusal is greppable in the codebase.
    #[error("target ownership is not currently verified")]
    TargetNotVerified,

    #[error("plan limit reached: {0}")]
    PlanLimit(String),

    #[error("too many requests — try again later")]
    TooManyRequests,

    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        ApiError::Internal(err.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            ApiError::InvalidCredentials => (
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                self.to_string(),
            ),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized", self.to_string()),
            ApiError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request", self.to_string()),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not_found", self.to_string()),
            ApiError::Conflict(_) => (StatusCode::CONFLICT, "conflict", self.to_string()),
            ApiError::TargetNotVerified => (
                StatusCode::FORBIDDEN,
                "target_not_verified",
                self.to_string(),
            ),
            ApiError::PlanLimit(_) => (StatusCode::FORBIDDEN, "plan_limit", self.to_string()),
            ApiError::TooManyRequests => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                self.to_string(),
            ),
            ApiError::Internal(err) => {
                // Log the real cause, return a generic message.
                tracing::error!(error = ?err, "internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "internal error".to_string(),
                )
            }
        };

        (status, Json(json!({ "error": code, "message": message }))).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
