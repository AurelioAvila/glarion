//! Reading scans back: status while one runs, findings once it finishes,
//! and the rendered report the agency forwards to their client.

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use chrono::{DateTime, Utc};
use orchestrator::finding::{Finding, Severity};
use report::html::{render_html, ReportMeta};
use report::triage::{triage_scan, TriagedScan};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct ListScansQuery {
    pub target_id: Option<Uuid>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct ScanSummary {
    pub id: Uuid,
    pub target_id: Uuid,
    pub domain: String,
    pub tool: String,
    pub status: String,
    pub failure_reason: Option<String>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    /// How many raw results the scanner stored. Kept because it is the
    /// honest total, but it is not the number to show a customer — see
    /// `actionable_count`.
    pub finding_count: i64,
    /// How many of those are worth acting on, after triage.
    ///
    /// This is the number that belongs on a dashboard. The raw count on a
    /// well-run site was 32 where 3 warranted action, and showing 32
    /// contradicts the entire point of triaging: it tells an agency their
    /// client has thirty-two problems when the answer is three.
    ///
    /// Not persisted, because triage runs on read — a rule improved
    /// tomorrow should change this number for scans that already happened.
    #[sqlx(default)]
    pub actionable_count: i64,
}

/// Lists the caller's scans, most recent first.
///
/// Scoped to the authenticated user through the join on `targets`; there is
/// no code path that returns a scan belonging to someone else.
pub async fn list_scans(
    State(state): State<AppState>,
    user: AuthUser,
    Query(query): Query<ListScansQuery>,
) -> ApiResult<Json<Vec<ScanSummary>>> {
    let mut scans: Vec<ScanSummary> = sqlx::query_as(
        "select j.id, j.target_id, t.domain, j.tool, j.status, j.failure_reason,
                j.created_at, j.completed_at,
                (select count(*) from scan_results r where r.scan_job_id = j.id) as finding_count
         from scan_jobs j
         join targets t on t.id = j.target_id
         where t.user_id = $1
           and ($2::uuid is null or j.target_id = $2)
         order by j.created_at desc
         limit 100",
    )
    .bind(user.id)
    .bind(query.target_id)
    .fetch_all(&state.pool)
    .await?;

    fill_actionable_counts(&state, &mut scans).await?;

    Ok(Json(scans))
}

#[derive(Serialize)]
pub struct ScanDetail {
    #[serde(flatten)]
    pub summary: ScanSummary,
    pub triaged: TriagedScan,
}

pub async fn get_scan(
    State(state): State<AppState>,
    user: AuthUser,
    Path(scan_id): Path<Uuid>,
) -> ApiResult<Json<ScanDetail>> {
    let mut summary = load_summary(&state, user.id, scan_id).await?;
    let findings = load_findings(&state, scan_id).await?;
    let triaged = triage_scan(&findings);

    summary.actionable_count = triaged.actionable.len() as i64;

    Ok(Json(ScanDetail { summary, triaged }))
}

/// Fills in `actionable_count` for a batch of scans.
///
/// One query for all of them rather than one per scan: a list of a hundred
/// scans would otherwise be a hundred round trips for a number shown in a
/// summary row.
async fn fill_actionable_counts(state: &AppState, scans: &mut [ScanSummary]) -> ApiResult<()> {
    let ids: Vec<Uuid> = scans
        .iter()
        .filter(|scan| scan.status == "completed" && scan.finding_count > 0)
        .map(|scan| scan.id)
        .collect();

    if ids.is_empty() {
        return Ok(());
    }

    #[derive(sqlx::FromRow)]
    struct Row {
        scan_job_id: Uuid,
        severity: String,
        title: String,
        description: Option<String>,
        raw_output: serde_json::Value,
    }

    let rows: Vec<Row> = sqlx::query_as(
        "select scan_job_id, severity, title, description, raw_output
         from scan_results where scan_job_id = any($1)",
    )
    .bind(&ids)
    .fetch_all(&state.pool)
    .await?;

    let mut by_scan: HashMap<Uuid, Vec<Finding>> = HashMap::new();
    for row in rows {
        by_scan.entry(row.scan_job_id).or_default().push(Finding {
            severity: Severity::from_tool_label(&row.severity),
            title: row.title,
            description: row.description,
            raw: row.raw_output,
        });
    }

    for scan in scans.iter_mut() {
        if let Some(findings) = by_scan.get(&scan.id) {
            scan.actionable_count = triage_scan(findings).actionable.len() as i64;
        }
    }

    Ok(())
}

/// Renders the report as a standalone HTML document.
///
/// Served as a download rather than a page: it is an artefact the agency
/// keeps and forwards, and serving attacker-influenced HTML inline on our
/// own origin would put any escaping mistake in the same origin as the
/// dashboard. The headers below make that a defence in depth rather than a
/// single point of failure.
pub async fn get_scan_report(
    State(state): State<AppState>,
    user: AuthUser,
    Path(scan_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let summary = load_summary(&state, user.id, scan_id).await?;

    if summary.status != "completed" {
        return Err(ApiError::BadRequest(
            "this scan has not finished yet".into(),
        ));
    }

    let profile: Option<(Option<String>, Option<String>)> =
        sqlx::query_as("select agency_name, agency_logo_url from users where id = $1")
            .bind(user.id)
            .fetch_optional(&state.pool)
            .await?;
    let (agency_name, agency_logo_url) = profile.unwrap_or((None, None));

    let client_name: Option<String> =
        sqlx::query_scalar("select client_name from targets where id = $1")
            .bind(summary.target_id)
            .fetch_optional(&state.pool)
            .await?
            .flatten();

    let findings = load_findings(&state, scan_id).await?;

    let meta = ReportMeta {
        // Falling back to the domain rather than to our own name: an
        // unbranded report is a smaller problem than one that quietly
        // advertises us to the agency's client.
        agency_name: agency_name.unwrap_or_else(|| "Security review".to_string()),
        agency_logo_url,
        client_name: client_name.unwrap_or_else(|| summary.domain.clone()),
        target_domain: summary.domain.clone(),
        scanned_at: summary.completed_at.unwrap_or(summary.created_at),
    };

    let html = render_html(&meta, &triage_scan(&findings));

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    // Even a perfectly escaped document is served with script disabled and
    // no network access, so a future escaping bug cannot become script
    // execution or an exfiltration channel.
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; img-src https: data:; \
             sandbox allow-popups",
        ),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );

    let filename = report_filename(&summary.domain, meta.scanned_at);
    if let Ok(value) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
        headers.insert(header::CONTENT_DISPOSITION, value);
    }

    Ok((StatusCode::OK, headers, html))
}

/// Builds a filename safe to put in a Content-Disposition header.
///
/// The domain is caller-supplied, so anything outside a conservative set is
/// replaced rather than escaped — a quote or newline here would let the
/// value break out of the header.
fn report_filename(domain: &str, at: DateTime<Utc>) -> String {
    let safe_domain: String = domain
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .take(80)
        .collect();

    format!(
        "security-review-{safe_domain}-{}.html",
        at.format("%Y-%m-%d")
    )
}

/// Loads a scan, confirming it belongs to this user.
///
/// Returns `NotFound` for someone else's scan so an id cannot be probed.
async fn load_summary(state: &AppState, user_id: Uuid, scan_id: Uuid) -> ApiResult<ScanSummary> {
    sqlx::query_as(
        "select j.id, j.target_id, t.domain, j.tool, j.status, j.failure_reason,
                j.created_at, j.completed_at,
                (select count(*) from scan_results r where r.scan_job_id = j.id) as finding_count
         from scan_jobs j
         join targets t on t.id = j.target_id
         where j.id = $1 and t.user_id = $2",
    )
    .bind(scan_id)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)
}

/// Rebuilds findings from stored rows.
///
/// Triage runs on read rather than being frozen at scan time, so improving
/// a rule improves every past report instead of only future ones.
async fn load_findings(state: &AppState, scan_id: Uuid) -> ApiResult<Vec<Finding>> {
    #[derive(sqlx::FromRow)]
    struct Row {
        severity: String,
        title: String,
        description: Option<String>,
        raw_output: serde_json::Value,
    }

    let rows: Vec<Row> = sqlx::query_as(
        "select severity, title, description, raw_output
         from scan_results where scan_job_id = $1
         order by created_at",
    )
    .bind(scan_id)
    .fetch_all(&state.pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| Finding {
            severity: Severity::from_tool_label(&row.severity),
            title: row.title,
            description: row.description,
            raw: row.raw_output,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 28, 9, 0, 0).unwrap()
    }

    #[test]
    fn filename_includes_the_domain_and_date() {
        assert_eq!(
            report_filename("example.com", at()),
            "security-review-example.com-2026-08-28.html"
        );
    }

    #[test]
    fn filename_cannot_break_out_of_the_header() {
        // A quote or newline in a Content-Disposition value is a header
        // injection, and the domain reaches here from user input.
        let hostile = report_filename("evil\"\r\nSet-Cookie: a=b", at());

        assert!(!hostile.contains('"'));
        assert!(!hostile.contains('\r'));
        assert!(!hostile.contains('\n'));
    }

    #[test]
    fn filename_drops_path_separators() {
        let traversal = report_filename("../../etc/passwd", at());

        assert!(!traversal.contains('/'));
        assert!(!traversal.contains('\\'));
    }

    #[test]
    fn filename_length_is_bounded() {
        let long = report_filename(&"a".repeat(500), at());
        assert!(long.len() < 130);
    }
}
