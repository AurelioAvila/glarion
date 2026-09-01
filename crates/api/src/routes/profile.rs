//! The agency's own details, used to brand the reports they send out.

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::AuthUser;
use crate::billing::current_plan;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Bounds on stored branding. These are display strings, not identifiers,
/// so the limits only need to be generous enough for a real business name
/// and tight enough that the column cannot be used as free storage.
const MAX_AGENCY_NAME: usize = 120;
const MAX_LOGO_URL: usize = 2048;

#[derive(Serialize, Deserialize)]
pub struct Profile {
    pub agency_name: Option<String>,
    pub agency_logo_url: Option<String>,
}

pub async fn get_profile(
    State(state): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<Profile>> {
    let row: Option<(Option<String>, Option<String>)> =
        sqlx::query_as("select agency_name, agency_logo_url from users where id = $1")
            .bind(user.id)
            .fetch_optional(&state.pool)
            .await?;

    let (agency_name, agency_logo_url) = row.ok_or(ApiError::NotFound)?;

    Ok(Json(Profile {
        agency_name,
        agency_logo_url,
    }))
}

pub async fn update_profile(
    State(state): State<AppState>,
    user: AuthUser,
    Json(body): Json<Profile>,
) -> ApiResult<Json<Profile>> {
    let agency_name = normalize(body.agency_name, MAX_AGENCY_NAME, "agency name")?;
    let agency_logo_url = normalize(body.agency_logo_url, MAX_LOGO_URL, "logo URL")?;

    // Refused for the same reason an unsafe logo URL is refused below: on a
    // free account the renderer leaves the branding out, so saving it would
    // be a setting that silently does nothing.
    if (agency_name.is_some() || agency_logo_url.is_some())
        && !current_plan(&state.pool, user.id).await?.allows_branding()
    {
        return Err(ApiError::PlanLimit(
            "reports carry your agency name and logo on the paid plans".into(),
        ));
    }

    // Rejected here as well as at render time. The renderer drops an unsafe
    // URL silently, which is the right behaviour when producing a document
    // but a poor experience when saving a setting: the agency would save a
    // logo, see no error, and later notice it never appears.
    if let Some(url) = &agency_logo_url {
        if !is_acceptable_logo_url(url) {
            return Err(ApiError::BadRequest(
                "logo URL must be an https address or an inline image".into(),
            ));
        }
    }

    sqlx::query("update users set agency_name = $2, agency_logo_url = $3 where id = $1")
        .bind(user.id)
        .bind(&agency_name)
        .bind(&agency_logo_url)
        .execute(&state.pool)
        .await?;

    Ok(Json(Profile {
        agency_name,
        agency_logo_url,
    }))
}

/// Trims, rejects over-long values, and treats an empty string as "unset"
/// so clearing a field does not store a blank that later renders as one.
fn normalize(value: Option<String>, max: usize, label: &str) -> ApiResult<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };

    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.chars().count() > max {
        return Err(ApiError::BadRequest(format!(
            "{label} must be at most {max} characters"
        )));
    }

    Ok(Some(trimmed.to_string()))
}

/// Mirrors the renderer's rule. Kept in sync deliberately rather than
/// shared, because the two serve different purposes: this one explains the
/// refusal, the renderer's one guarantees the output is safe even if a
/// value reached the database by some other route.
fn is_acceptable_logo_url(url: &str) -> bool {
    let lowered = url.trim().to_ascii_lowercase();

    lowered.starts_with("https://")
        || lowered.starts_with("data:image/png;base64,")
        || lowered.starts_with("data:image/jpeg;base64,")
        || lowered.starts_with("data:image/svg+xml;base64,")
        || lowered.starts_with("data:image/webp;base64,")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_values_clear_rather_than_store_a_blank() {
        assert_eq!(normalize(Some("   ".into()), 10, "x").unwrap(), None);
        assert_eq!(normalize(None, 10, "x").unwrap(), None);
    }

    #[test]
    fn values_are_trimmed() {
        assert_eq!(
            normalize(Some("  Northgate Studio  ".into()), 120, "x").unwrap(),
            Some("Northgate Studio".to_string())
        );
    }

    #[test]
    fn over_long_values_are_refused() {
        let long = "a".repeat(121);
        assert!(normalize(Some(long), 120, "agency name").is_err());
    }

    #[test]
    fn https_and_inline_images_are_acceptable_logos() {
        assert!(is_acceptable_logo_url("https://cdn.example.com/logo.png"));
        assert!(is_acceptable_logo_url("data:image/png;base64,AAAA"));
        assert!(is_acceptable_logo_url("  HTTPS://EXAMPLE.COM/a.png  "));
    }

    #[test]
    fn script_bearing_and_plaintext_logo_urls_are_refused() {
        assert!(!is_acceptable_logo_url("javascript:alert(1)"));
        assert!(!is_acceptable_logo_url("http://example.com/logo.png"));
        assert!(!is_acceptable_logo_url(
            "data:text/html;base64,PHNjcmlwdD4="
        ));
        assert!(!is_acceptable_logo_url("//example.com/logo.png"));
    }
}
