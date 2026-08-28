//! The normalized finding model.
//!
//! Every tool we wrap reports results in its own shape and its own severity
//! vocabulary. Everything is converted into this type at the edge of the
//! tool wrapper, so the rest of the system — storage, scoring, reports —
//! only ever deals with one representation. This is the main thing the
//! product sells over running the tools by hand.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Must match the `scan_results.severity` check constraint.
    pub fn as_db_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Maps a tool's severity label onto ours.
    ///
    /// Unknown labels become `Info` rather than being dropped: a finding we
    /// can't classify is still a finding, and silently discarding it would
    /// be worse than under-ranking it.
    pub fn from_tool_label(label: &str) -> Self {
        match label.trim().to_ascii_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" | "moderate" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub description: Option<String>,
    /// The tool's own output for this finding, preserved verbatim so a
    /// report can always be traced back to what the scanner actually said.
    pub raw: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_severity_labels() {
        assert_eq!(Severity::from_tool_label("critical"), Severity::Critical);
        assert_eq!(Severity::from_tool_label("HIGH"), Severity::High);
        assert_eq!(Severity::from_tool_label(" medium "), Severity::Medium);
        assert_eq!(Severity::from_tool_label("moderate"), Severity::Medium);
        assert_eq!(Severity::from_tool_label("low"), Severity::Low);
    }

    #[test]
    fn unknown_labels_fall_back_to_info_rather_than_being_lost() {
        assert_eq!(Severity::from_tool_label("unknown"), Severity::Info);
        assert_eq!(Severity::from_tool_label(""), Severity::Info);
    }

    #[test]
    fn severity_orders_from_info_to_critical() {
        let mut severities = vec![
            Severity::High,
            Severity::Info,
            Severity::Critical,
            Severity::Low,
        ];
        severities.sort();

        assert_eq!(
            severities,
            vec![
                Severity::Info,
                Severity::Low,
                Severity::High,
                Severity::Critical
            ]
        );
    }

    #[test]
    fn db_strings_match_the_schema_constraint() {
        // These exact strings are in the scan_results check constraint.
        assert_eq!(Severity::Info.as_db_str(), "info");
        assert_eq!(Severity::Critical.as_db_str(), "critical");
    }
}
