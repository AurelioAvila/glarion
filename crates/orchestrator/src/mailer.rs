//! Transactional email.
//!
//! Sends through Resend's HTTPS API, matching the provider already used
//! elsewhere in the portfolio. HTTP rather than SMTP on purpose: several
//! hosts block outbound port 587/465, and a blocked SMTP connection hangs
//! until a timeout instead of failing fast.
//!
//! When no API key is configured — local development — messages are logged
//! instead of sent. That is deliberate and loud: the confirmation link is
//! printed so the flow can be exercised end to end without a mail account,
//! and `is_configured` lets a caller tell the difference rather than
//! assuming delivery happened.

use serde::Serialize;

pub struct Mailer {
    api_key: Option<String>,
    from: String,
    /// Where confirmation links should point. Kept here rather than derived
    /// from the request, because a link built from an attacker-supplied
    /// Host header is how confirmation emails get turned into phishing.
    pub public_url: String,
}

#[derive(Serialize)]
struct ResendPayload<'a> {
    from: &'a str,
    to: [&'a str; 1],
    subject: &'a str,
    html: &'a str,
}

impl Mailer {
    pub fn from_env() -> Self {
        Self {
            api_key: std::env::var("RESEND_API_KEY")
                .ok()
                .filter(|k| !k.is_empty()),
            from: std::env::var("MAIL_FROM")
                .unwrap_or_else(|_| "Glarion <onboarding@resend.dev>".to_string()),
            public_url: std::env::var("PUBLIC_URL")
                .unwrap_or_else(|_| "http://localhost:5173".to_string())
                .trim_end_matches('/')
                .to_string(),
        }
    }

    pub fn is_configured(&self) -> bool {
        self.api_key.is_some()
    }

    /// Sends a message, or logs it when no provider is configured.
    ///
    /// Errors are returned rather than swallowed so a caller can decide
    /// what to tell the user, but note that signup deliberately does not
    /// fail when delivery fails — see the call site for why.
    pub async fn send(&self, to: &str, subject: &str, html: &str) -> anyhow::Result<()> {
        let Some(api_key) = &self.api_key else {
            tracing::warn!(
                to = %to,
                subject = %subject,
                "email not sent: RESEND_API_KEY is unset. Body follows for development."
            );
            tracing::info!("{html}");
            return Ok(());
        };

        let payload = ResendPayload {
            from: &self.from,
            to: [to],
            subject,
            html,
        };

        let response = reqwest::Client::new()
            .post("https://api.resend.com/emails")
            .bearer_auth(api_key)
            .json(&payload)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "email provider refused ({status}): {}",
                truncate(&body, 300)
            );
        }

        Ok(())
    }

    pub fn verification_link(&self, token: &str) -> String {
        format!("{}/#/verify/{token}", self.public_url)
    }
}

fn truncate(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

/// Escapes text for inclusion in an HTML email body.
///
/// Names come from a signup form, so they are attacker-controlled. An
/// unescaped name in an outgoing message is both an injection into our own
/// template and a way to make a message we sent say something we did not
/// write.
fn escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

/// The confirmation message.
///
/// Plain and short on purpose: a first message full of marketing is more
/// likely to be filtered, and this one has exactly one job.
pub fn verification_email(first_name: &str, link: &str) -> String {
    let name = escape(first_name.trim());
    let greeting = if name.is_empty() {
        "Hello,".to_string()
    } else {
        format!("Hello {name},")
    };
    let safe_link = escape(link);

    format!(
        r#"<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:15px;line-height:1.6;color:#16191d">
<p>{greeting}</p>
<p>Confirm this address to finish setting up your Glarion account.</p>
<p><a href="{safe_link}" style="display:inline-block;background:#1f4ed8;color:#ffffff;padding:10px 18px;border-radius:6px;text-decoration:none">Confirm my email</a></p>
<p style="color:#5c6470;font-size:13px">Or paste this into your browser:<br><span style="word-break:break-all">{safe_link}</span></p>
<p style="color:#5c6470;font-size:13px">The link is valid for 24 hours. If you did not create an account, you can ignore this message.</p>
</div>"#
    )
}

/// The message sent when a monitored site changes.
///
/// Deliberately short and specific. This is the only email an agency gets
/// from us once they are set up, so it has to be worth opening: what
/// changed, on which site, and a way to see the detail. A digest of
/// everything that happened would be filtered within a month.
pub fn change_email(domain: &str, summary: &str, detail: &str, link: &str) -> String {
    let safe_domain = escape(domain);
    let safe_summary = escape(summary);
    let safe_detail = escape(detail);
    let safe_link = escape(link);

    format!(
        r#"<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:15px;line-height:1.6;color:#16191d">
<p style="font-size:17px;margin:0 0 4px"><strong>{safe_summary}</strong></p>
<p style="color:#5c6470;margin:0 0 20px">{safe_domain}</p>
<p>{safe_detail}</p>
<p><a href="{safe_link}" style="display:inline-block;background:#16191d;color:#ffffff;padding:10px 18px;border-radius:4px;text-decoration:none">See what changed</a></p>
<p style="color:#5c6470;font-size:13px">You are getting this because this site is on a scanning schedule. Turn it off on the site's page.</p>
</div>"#
    )
}

/// One line of the free emailed report.
pub struct ReportLine {
    pub label: String,
    pub value: String,
    /// Something the owner would want to change, rather than a description.
    pub is_finding: bool,
}

/// The free report, sent to whoever asked for it.
///
/// This is the first thing most people will ever see from us, and it has
/// two jobs that pull against each other: be genuinely useful on its own,
/// and be honest that it is not the whole picture. It does the second by
/// naming what it did *not* look at rather than by hedging what it did —
/// a report that qualifies every line reads as though it is unsure, while
/// one that states its scope reads as though it knows where its edges are.
pub fn preview_report_email(domain: &str, lines: &[ReportLine], upgrade_link: &str) -> String {
    let safe_domain = escape(domain);
    let safe_link = escape(upgrade_link);

    let findings = lines.iter().filter(|line| line.is_finding).count();
    let headline = match findings {
        0 => "Nothing obvious from the outside".to_string(),
        1 => "1 thing worth fixing".to_string(),
        n => format!("{n} things worth fixing"),
    };

    let mut rows = String::new();
    for line in lines {
        let colour = if line.is_finding {
            "#c2412d"
        } else {
            "#16191d"
        };
        let weight = if line.is_finding { "600" } else { "400" };
        rows.push_str(&format!(
            r#"<tr>
<td style="padding:7px 16px 7px 0;color:#5c6470;font-size:13px;white-space:nowrap;vertical-align:top">{}</td>
<td style="padding:7px 0;color:{colour};font-weight:{weight};font-size:14px">{}</td>
</tr>"#,
            escape(&line.label),
            escape(&line.value),
        ));
    }

    format!(
        r#"<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:15px;line-height:1.6;color:#16191d;max-width:560px">
<p style="font-size:19px;font-weight:600;margin:0 0 2px">{headline}</p>
<p style="color:#5c6470;margin:0 0 22px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:14px">{safe_domain}</p>

<table style="border-collapse:collapse;width:100%;margin-bottom:26px">{rows}</table>

<p style="margin:0 0 6px"><strong>What this did not look at</strong></p>
<p style="color:#5c6470;font-size:14px;margin:0 0 22px">
This read only what {safe_domain} publishes to any visitor: its headers, its
certificate, its DNS, and the files it offers to automated readers. It did not
examine the application itself — outdated components with known vulnerabilities,
exposed administrative paths, or misconfigured storage — because that requires
the domain's owner to confirm the request first.
</p>

<p><a href="{safe_link}" style="display:inline-block;background:#16191d;color:#ffffff;padding:11px 20px;border-radius:4px;text-decoration:none;font-weight:600">Run the full check</a></p>

<p style="color:#8b9199;font-size:12px;margin-top:26px">
You received this because this report was requested from your address. We do not
add you to anything by sending it.
</p>
</div>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_cannot_inject_markup_into_the_message() {
        let body = verification_email(
            "<script>alert(1)</script>",
            "https://example.com/#/verify/x",
        );

        assert!(!body.contains("<script>alert(1)</script>"));
        assert!(body.contains("&lt;script&gt;"));
    }

    #[test]
    fn the_link_appears_as_a_button_and_as_text() {
        // Some clients strip buttons, and some people do not trust them.
        let link = "https://glarion.app/#/verify/abc123";
        let body = verification_email("Aurelio", link);

        assert_eq!(body.matches(link).count(), 2);
    }

    #[test]
    fn a_missing_name_still_produces_a_sensible_greeting() {
        let body = verification_email("   ", "https://example.com/x");

        assert!(body.contains("Hello,"));
        assert!(!body.contains("Hello ,"));
    }

    #[test]
    fn links_are_built_from_configured_url_not_from_a_request() {
        let mailer = Mailer {
            api_key: None,
            from: "x@example.com".into(),
            public_url: "https://glarion.app".into(),
        };

        assert_eq!(
            mailer.verification_link("tok"),
            "https://glarion.app/#/verify/tok"
        );
    }

    #[test]
    fn a_change_message_cannot_be_injected_through_the_domain() {
        // The domain came from a signup form, and every other value here is
        // built from scan output.
        let body = change_email(
            "<script>alert(1)</script>",
            "2 new issues",
            "detail",
            "https://example.com",
        );

        assert!(!body.contains("<script>alert(1)</script>"));
        assert!(body.contains("&lt;script&gt;"));
    }

    #[test]
    fn a_change_message_says_how_to_stop_receiving_them() {
        // A recurring email with no way off it is how a sender ends up in a
        // spam folder along with everything else it sends.
        let body = change_email(
            "example.com",
            "1 new issue",
            "detail",
            "https://example.com",
        );

        assert!(body.to_lowercase().contains("turn it off"));
    }

    /// Collapses the whitespace in a rendered body.
    ///
    /// The template wraps its prose across source lines, so asserting on a
    /// sentence would otherwise be asserting on where the author happened
    /// to press return. What matters is that the sentence is there.
    fn flat(html: &str) -> String {
        html.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn line(label: &str, value: &str, is_finding: bool) -> ReportLine {
        ReportLine {
            label: label.to_string(),
            value: value.to_string(),
            is_finding,
        }
    }

    #[test]
    fn the_report_counts_only_what_is_wrong() {
        let lines = vec![
            line("Server", "cloudflare", false),
            line("Content-Security-Policy", "Not set", true),
            line("HSTS", "180 days", true),
        ];

        let body = preview_report_email("example.com", &lines, "https://glarion.app");

        assert!(flat(&body).contains("2 things worth fixing"));
    }

    #[test]
    fn a_clean_report_does_not_claim_the_site_is_clean() {
        // The most dangerous message this system could send is "nothing
        // found" read as "nothing there".
        let lines = vec![line("Server", "nginx", false)];
        let body = preview_report_email("example.com", &lines, "https://glarion.app");

        assert!(flat(&body).contains("Nothing obvious from the outside"));
        assert!(flat(&body).contains("did not look at"));
    }

    #[test]
    fn the_report_names_its_own_limits() {
        let body = preview_report_email("example.com", &[], "https://glarion.app");

        // Stating the scope, rather than hedging every line.
        assert!(flat(&body).contains("did not examine the application itself"));
        assert!(flat(&body).to_lowercase().contains("confirm the request"));
    }

    #[test]
    fn a_report_cannot_be_injected_through_the_domain_or_a_value() {
        // The domain is typed by a stranger, and the values are read off
        // somebody else's server.
        let lines = vec![line("<b>label</b>", "<script>alert(1)</script>", true)];
        let body = preview_report_email("<script>alert(2)</script>", &lines, "https://glarion.app");

        assert!(!body.contains("<script>alert(1)</script>"));
        assert!(!body.contains("<script>alert(2)</script>"));
        assert!(!body.contains("<b>label</b>"));
    }

    #[test]
    fn the_report_says_it_did_not_subscribe_anyone() {
        // Sending a report is not consent to market to somebody.
        let body = preview_report_email("example.com", &[], "https://glarion.app");

        assert!(flat(&body).contains("do not add you to anything"));
    }

    #[test]
    fn trailing_slashes_do_not_produce_a_double_slash() {
        let mailer = Mailer {
            api_key: None,
            from: "x@example.com".into(),
            public_url: "https://glarion.app/".trim_end_matches('/').to_string(),
        };

        assert!(!mailer.verification_link("tok").contains("app//"));
    }
}
