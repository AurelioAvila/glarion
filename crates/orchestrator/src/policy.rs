//! Scan policy: which tools may run, and how often.
//!
//! These limits exist even for targets whose ownership *is* verified. A
//! verified owner can still, deliberately or not, drive enough traffic at
//! their own host to look like an attack to their hosting provider — and
//! traffic from our IPs getting flagged hurts every customer. So intensity
//! is capped independently of authorization.

/// Tools the MVP is allowed to invoke. An allowlist rather than a
/// denylist: a tool absent from this list cannot be run, so adding a new
/// scanner is a deliberate, reviewable change rather than a config edit.
///
/// All of these are detection-only in the modes we invoke them. Nothing
/// here attempts exploitation, brute-forcing, or fuzzing.
pub const ALLOWED_TOOLS: &[&str] = &["nuclei", "tls"];

/// Maximum scans per target per rolling 24 hours.
pub const MAX_SCANS_PER_TARGET_PER_DAY: i64 = 6;

/// The same cap during a three-day trial.
pub const TRIAL_MAX_SCANS_PER_TARGET_PER_DAY: i64 = 2;

/// One free trial per site: whether this target's site was already scanned
/// during another account's three-day trial. `www.example.com` and
/// `example.com` count as one site. Read from the authorization trail, which
/// outlives accounts. Shared by the scan endpoint and the scheduler, so a
/// schedule is not a way around it.
pub async fn site_used_in_another_trial(
    pool: &sqlx::PgPool,
    target_id: uuid::Uuid,
    user_id: uuid::Uuid,
) -> sqlx::Result<bool> {
    sqlx::query_scalar(
        r"select exists (
             select 1 from scan_authorizations a
             join targets other on other.id = a.target_id
             join trial_claims c on c.user_id = a.user_id
             where regexp_replace(other.domain, '^www\.', '')
                   = (select regexp_replace(domain, '^www\.', '') from targets where id = $1)
               and a.user_id <> $2
               and a.accepted_terms_at >= c.created_at
               and a.accepted_terms_at < c.trial_ends_at
         )",
    )
    .bind(target_id)
    .bind(user_id)
    .fetch_one(pool)
    .await
}

pub fn is_allowed_tool(tool: &str) -> bool {
    ALLOWED_TOOLS.contains(&tool)
}

/// Whether another scan may be queued for a target, given how many have
/// already run in the trailing window.
pub fn within_scan_budget(scans_in_window: i64) -> bool {
    scans_in_window < MAX_SCANS_PER_TARGET_PER_DAY
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_tools_are_allowed() {
        assert!(is_allowed_tool("nuclei"));
        assert!(is_allowed_tool("tls"));
    }

    #[test]
    fn unknown_tools_are_refused() {
        assert!(!is_allowed_tool("sqlmap"));
        assert!(!is_allowed_tool("hydra"));
        assert!(!is_allowed_tool(""));
        // No shell metacharacter smuggling through the tool field.
        assert!(!is_allowed_tool("nuclei; rm -rf /"));
        assert!(!is_allowed_tool("NUCLEI"));
    }

    #[test]
    fn budget_allows_up_to_the_cap() {
        assert!(within_scan_budget(0));
        assert!(within_scan_budget(MAX_SCANS_PER_TARGET_PER_DAY - 1));
    }

    #[test]
    fn budget_refuses_at_and_beyond_the_cap() {
        assert!(!within_scan_budget(MAX_SCANS_PER_TARGET_PER_DAY));
        assert!(!within_scan_budget(MAX_SCANS_PER_TARGET_PER_DAY + 10));
    }
}
