//! Every transactional email, filled with sample data, for review.
//!
//!   mail_preview <folder>          writes one .html and one .txt per message
//!   mail_preview --send <address>  sends each message to that one address,
//!                                  through the configured sender (MAIL_FROM)
//!
//! Sending exists so the real sender, DNS and inbox placement can be checked
//! without creating accounts or touching customer data. Every subject is
//! prefixed "[Preview]" and the links are inert samples on the real host.

use chrono::{Duration, Utc};
use orchestrator::mailer::{
    change_email, email_change_alert, email_change_confirmation, ownership_lapsing_email,
    password_changed_email, password_reset_email, preview_report_email, subscription_email,
    subscription_ended_email, trial_ending_email, trial_rejected_email, trial_started_email,
    verification_email, welcome_email, Mailer, Message, ReportLine, TrialTerms,
};

fn samples(site: &str) -> Vec<(&'static str, Message)> {
    let app = format!("{site}/app#");
    let lines = [
        ReportLine {
            label: "Certificate".into(),
            value: "Valid until 17 November 2026 (34 days)".into(),
            is_finding: false,
        },
        ReportLine {
            label: "Email spoofing (DMARC)".into(),
            value: "No policy published".into(),
            is_finding: true,
        },
        ReportLine {
            label: "Security headers".into(),
            value: "Content-Security-Policy missing".into(),
            is_finding: true,
        },
    ];
    vec![
        (
            "verification",
            verification_email("Ada", &format!("{app}/verify/sample")),
        ),
        ("welcome", welcome_email("Ada", &format!("{app}/targets"))),
        (
            "password-reset",
            password_reset_email("Ada", &format!("{app}/reset/sample"), 60),
        ),
        ("password-changed", password_changed_email("Ada")),
        (
            "email-change-confirmation",
            email_change_confirmation("Ada", &format!("{app}/confirm-email/sample"), 60),
        ),
        (
            "email-change-alert",
            email_change_alert("Ada", "ada.new@example.com"),
        ),
        (
            "trial-started",
            subscription_email(
                "Ada",
                "Solo",
                5,
                true,
                &format!("{app}/targets"),
                Some(Utc::now() + Duration::days(14)),
            ),
        ),
        (
            "trial-3-day-started",
            trial_started_email(
                "Ada",
                "Studio",
                Utc::now() + Duration::days(3),
                Some("€47.58"),
                "month",
                TrialTerms {
                    sites: 3,
                    scans_per_site_per_day: 2,
                },
                &format!("{app}/targets"),
            ),
        ),
        (
            "trial-3-day-ending",
            trial_ending_email(
                "Ada",
                "Studio",
                Utc::now() + Duration::hours(23),
                Some("€47.58"),
                "month",
                &format!("{app}/plan"),
            ),
        ),
        (
            "trial-3-day-refused",
            trial_rejected_email("Ada", "Studio", &format!("{app}/plan")),
        ),
        (
            "plan-active",
            subscription_email("Ada", "Studio", 10, true, &format!("{app}/targets"), None),
        ),
        (
            "payment-failed",
            subscription_ended_email("Ada", "Studio", true, &format!("{app}/plan")),
        ),
        (
            "plan-ended",
            subscription_ended_email("Ada", "Studio", false, &format!("{app}/plan")),
        ),
        (
            "ownership-lapsing",
            ownership_lapsing_email(
                "Ada",
                "client-site.example",
                Utc::now() + Duration::days(3),
                &format!("{app}/targets"),
            ),
        ),
        (
            "site-changed",
            change_email(
                "client-site.example",
                "1 new finding on client-site.example",
                "The certificate now expires in 6 days. Renewal usually runs automatically; check that it did.",
                &format!("{app}/targets"),
            ),
        ),
        (
            "free-check-report",
            preview_report_email("client-site.example", &lines, site),
        ),
    ]
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mailer = Mailer::from_env();
    let site = mailer.public_url.clone();
    match args.as_slice() {
        [flag, address] if flag == "--send" => {
            anyhow::ensure!(
                address.contains('@') && !address.contains(','),
                "one address only"
            );
            for (name, mut message) in samples(&site) {
                message.subject = format!("[Preview] {}", message.subject);
                mailer.send(address, &message).await?;
                println!("sent {name}");
            }
        }
        [folder] => {
            std::fs::create_dir_all(folder)?;
            for (name, message) in samples(&site) {
                std::fs::write(format!("{folder}/{name}.html"), &message.html)?;
                std::fs::write(
                    format!("{folder}/{name}.txt"),
                    format!("Subject: {}\n\n{}", message.subject, message.text),
                )?;
            }
            println!("wrote {} previews to {folder}", samples(&site).len());
        }
        _ => anyhow::bail!("usage: mail_preview <folder> | mail_preview --send <address>"),
    }
    Ok(())
}
