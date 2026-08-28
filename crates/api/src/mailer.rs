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
    fn trailing_slashes_do_not_produce_a_double_slash() {
        let mailer = Mailer {
            api_key: None,
            from: "x@example.com".into(),
            public_url: "https://glarion.app/".trim_end_matches('/').to_string(),
        };

        assert!(!mailer.verification_link("tok").contains("app//"));
    }
}
