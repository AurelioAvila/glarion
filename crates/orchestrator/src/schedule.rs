//! When a target is due for another scan, and what changed when one lands.
//!
//! Manual scanning makes this a tool somebody remembers to use. Recurring
//! scanning is what an agency actually sells to its clients — "we watch
//! your site" — and it is the only version of this product that earns money
//! every month rather than once.
//!
//! Everything here is pure so the awkward parts can be tested without
//! waiting a week: whether a scan is due, and whether a result is different
//! enough from the last one to be worth telling somebody about.

use chrono::{DateTime, Duration, Utc};

/// How often a target is re-checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cadence {
    /// Only when somebody asks.
    Manual,
    Weekly,
    Monthly,
}

impl Cadence {
    pub fn as_db_str(&self) -> &'static str {
        match self {
            Cadence::Manual => "manual",
            Cadence::Weekly => "weekly",
            Cadence::Monthly => "monthly",
        }
    }

    /// Parses a stored or submitted value.
    ///
    /// Unrecognised input becomes `Manual` rather than an error: the
    /// failure mode of guessing wrong should be "we did not scan", never
    /// "we scanned something nobody asked us to".
    pub fn from_str_or_manual(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "weekly" => Cadence::Weekly,
            "monthly" => Cadence::Monthly,
            _ => Cadence::Manual,
        }
    }

    fn interval(&self) -> Option<Duration> {
        match self {
            Cadence::Manual => None,
            Cadence::Weekly => Some(Duration::days(7)),
            Cadence::Monthly => Some(Duration::days(30)),
        }
    }
}

/// What the scheduler needs to know about one target.
pub struct ScheduleState {
    pub cadence: Cadence,
    /// When a scheduled scan was last queued for this target. `None` means
    /// the schedule was only just set up.
    pub last_scheduled_at: Option<DateTime<Utc>>,
    /// When the ownership proof lapses.
    pub verification_expires_at: Option<DateTime<Utc>>,
}

/// Why a target is not being scanned right now.
#[derive(Debug, PartialEq, Eq)]
pub enum NotDue {
    /// No recurring schedule.
    NotScheduled,
    /// Scanned recently enough.
    TooSoon,
    /// The ownership proof has lapsed, or is about to before the scan would
    /// finish. Distinct from the others because it is the only one the
    /// customer has to act on.
    VerificationLapsed,
}

/// Decides whether to queue a scan.
///
/// The lapsed-verification case is checked before the interval, so a target
/// whose proof expired months ago reports the problem rather than "not
/// due" — the difference between an agency being told to re-verify and an
/// agency quietly receiving no more reports.
pub fn due(state: &ScheduleState, now: DateTime<Utc>) -> Result<(), NotDue> {
    let Some(interval) = state.cadence.interval() else {
        return Err(NotDue::NotScheduled);
    };

    match state.verification_expires_at {
        Some(expires) if expires > now => {}
        // Includes the never-verified case: nothing may be scanned on a
        // schedule that could not be scanned on request.
        _ => return Err(NotDue::VerificationLapsed),
    }

    match state.last_scheduled_at {
        // A schedule that has never run starts immediately, so setting one
        // up produces a result rather than a week of silence.
        None => Ok(()),
        Some(last) if now - last >= interval => Ok(()),
        Some(_) => Err(NotDue::TooSoon),
    }
}

/// How a finished scan compares with the one before it.
#[derive(Debug, PartialEq, Eq)]
pub enum Change {
    /// Nothing worth an email.
    None,
    /// More to fix than last time.
    Worse { from: i64, to: i64 },
    /// Fewer, but not zero.
    Better { from: i64, to: i64 },
    /// Was not clear, now is.
    Resolved { from: i64 },
    /// Was clear, now is not.
    Appeared { to: i64 },
}

impl Change {
    /// Whether this is worth sending a message about.
    ///
    /// Only changes are. A weekly email saying "still three issues, same as
    /// last week" trains people to filter the sender, and then the one that
    /// mattered goes unread too.
    pub fn worth_reporting(&self) -> bool {
        !matches!(self, Change::None)
    }
}

/// Compares two scan outcomes.
///
/// `previous` is `None` for a target's first scan, which is deliberately
/// not reported: somebody who has just set a site up is looking at the
/// result already, and an email telling them what they are reading is
/// noise.
pub fn compare(previous: Option<i64>, current: i64) -> Change {
    let Some(previous) = previous else {
        return Change::None;
    };

    match (previous, current) {
        (p, c) if p == c => Change::None,
        (0, c) => Change::Appeared { to: c },
        (p, 0) => Change::Resolved { from: p },
        (p, c) if c > p => Change::Worse { from: p, to: c },
        (p, c) => Change::Better { from: p, to: c },
    }
}

/// The one-line summary used as an email subject.
pub fn headline(domain: &str, change: &Change) -> String {
    match change {
        Change::None => format!("No change on {domain}"),
        Change::Appeared { to } => {
            format!("{to} new {} on {domain}", plural(*to, "issue", "issues"))
        }
        Change::Worse { from, to } => {
            format!("{domain}: {} to fix, up from {from}", to)
        }
        Change::Better { from, to } => {
            format!("{domain}: {} to fix, down from {from}", to)
        }
        Change::Resolved { .. } => format!("{domain} is clear"),
    }
}

fn plural<'a>(count: i64, one: &'a str, many: &'a str) -> &'a str {
    if count == 1 {
        one
    } else {
        many
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-08-28T09:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn scheduled(cadence: Cadence, last_days_ago: Option<i64>) -> ScheduleState {
        ScheduleState {
            cadence,
            last_scheduled_at: last_days_ago.map(|days| now() - Duration::days(days)),
            verification_expires_at: Some(now() + Duration::days(20)),
        }
    }

    #[test]
    fn a_target_with_no_schedule_is_never_due() {
        assert_eq!(
            due(&scheduled(Cadence::Manual, Some(365)), now()),
            Err(NotDue::NotScheduled)
        );
    }

    #[test]
    fn a_new_schedule_runs_immediately() {
        // Otherwise turning monitoring on produces a week of silence, and
        // the customer assumes it is broken.
        assert_eq!(due(&scheduled(Cadence::Weekly, None), now()), Ok(()));
    }

    #[test]
    fn weekly_waits_a_week() {
        assert_eq!(
            due(&scheduled(Cadence::Weekly, Some(6)), now()),
            Err(NotDue::TooSoon)
        );
        assert_eq!(due(&scheduled(Cadence::Weekly, Some(7)), now()), Ok(()));
    }

    #[test]
    fn monthly_waits_a_month() {
        assert_eq!(
            due(&scheduled(Cadence::Monthly, Some(29)), now()),
            Err(NotDue::TooSoon)
        );
        assert_eq!(due(&scheduled(Cadence::Monthly, Some(30)), now()), Ok(()));
    }

    #[test]
    fn a_lapsed_proof_stops_the_schedule_and_says_so() {
        // The whole gate would be pointless if a schedule set up last month
        // kept scanning after the proof expired.
        let state = ScheduleState {
            cadence: Cadence::Weekly,
            last_scheduled_at: Some(now() - Duration::days(30)),
            verification_expires_at: Some(now() - Duration::days(1)),
        };

        assert_eq!(due(&state, now()), Err(NotDue::VerificationLapsed));
    }

    #[test]
    fn a_target_that_was_never_verified_is_never_scheduled() {
        let state = ScheduleState {
            cadence: Cadence::Weekly,
            last_scheduled_at: None,
            verification_expires_at: None,
        };

        assert_eq!(due(&state, now()), Err(NotDue::VerificationLapsed));
    }

    #[test]
    fn lapsed_verification_is_reported_ahead_of_being_too_soon() {
        // Both are true here. The customer can act on one of them.
        let state = ScheduleState {
            cadence: Cadence::Weekly,
            last_scheduled_at: Some(now()),
            verification_expires_at: Some(now() - Duration::days(5)),
        };

        assert_eq!(due(&state, now()), Err(NotDue::VerificationLapsed));
    }

    #[test]
    fn an_unknown_cadence_falls_back_to_not_scanning() {
        // Guessing wrong should mean "we did not scan", never "we scanned
        // something nobody asked us to".
        assert_eq!(Cadence::from_str_or_manual("hourly"), Cadence::Manual);
        assert_eq!(Cadence::from_str_or_manual(""), Cadence::Manual);
        assert_eq!(Cadence::from_str_or_manual("WEEKLY"), Cadence::Weekly);
    }

    #[test]
    fn a_first_scan_is_not_reported_as_a_change() {
        assert_eq!(compare(None, 4), Change::None);
        assert!(!compare(None, 4).worth_reporting());
    }

    #[test]
    fn an_unchanged_count_is_not_reported() {
        // A weekly "still three issues" trains people to filter the sender,
        // and then the message that mattered goes unread too.
        assert_eq!(compare(Some(3), 3), Change::None);
        assert!(!compare(Some(3), 3).worth_reporting());
    }

    #[test]
    fn going_from_clear_to_broken_is_its_own_case() {
        assert_eq!(compare(Some(0), 2), Change::Appeared { to: 2 });
        assert!(compare(Some(0), 2).worth_reporting());
    }

    #[test]
    fn going_from_broken_to_clear_is_its_own_case() {
        assert_eq!(compare(Some(2), 0), Change::Resolved { from: 2 });
    }

    #[test]
    fn more_and_fewer_are_distinguished() {
        assert_eq!(compare(Some(2), 5), Change::Worse { from: 2, to: 5 });
        assert_eq!(compare(Some(5), 2), Change::Better { from: 5, to: 2 });
    }

    #[test]
    fn headlines_read_as_sentences() {
        assert_eq!(
            headline("acme.com", &Change::Appeared { to: 1 }),
            "1 new issue on acme.com"
        );
        assert_eq!(
            headline("acme.com", &Change::Appeared { to: 3 }),
            "3 new issues on acme.com"
        );
        assert_eq!(
            headline("acme.com", &Change::Resolved { from: 4 }),
            "acme.com is clear"
        );
        assert_eq!(
            headline("acme.com", &Change::Worse { from: 2, to: 5 }),
            "acme.com: 5 to fix, up from 2"
        );
    }
}
