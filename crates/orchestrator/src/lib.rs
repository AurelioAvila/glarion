/// How this service identifies itself in an outbound HTTP request.
///
/// One constant rather than a string per call site, because the URL in it
/// is a promise: a site owner who finds this in an access log follows it
/// to a page that says what was requested and why. Two copies of the
/// string are two chances for one of them to point somewhere that 404s,
/// which is what the advertised address did from the day it first shipped.
///
/// Not sent by the vulnerability scanner, which is a separate process with
/// its own default — see `tools::nuclei`. The page says so.
pub const USER_AGENT: &str = "Glarion/1.0 (+https://glarion.app/about-our-checks)";

pub mod domain;
pub mod finding;
pub mod mailer;
pub mod net_guard;
pub mod policy;
pub mod preview;
pub mod runner;
pub mod schedule;
pub mod scheduler;
pub mod tools;
pub mod triage;
pub mod verification;
