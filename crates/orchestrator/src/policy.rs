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
pub const ALLOWED_TOOLS: &[&str] = &["nuclei", "testssl", "httpx"];

/// Maximum scans per target per rolling 24 hours.
pub const MAX_SCANS_PER_TARGET_PER_DAY: i64 = 6;

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
        assert!(is_allowed_tool("testssl"));
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
