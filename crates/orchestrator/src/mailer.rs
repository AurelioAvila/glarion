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
    /// Where a reply goes, when `from` is an address nobody reads.
    ///
    /// The password-changed notice tells the reader to reply straight away if
    /// the change was not theirs. That is the single most time-critical
    /// sentence this system sends, and from a noreply@ address it goes
    /// nowhere — the person doing the right thing, quickly, reaches a bin.
    /// Set MAIL_REPLY_TO to a monitored inbox.
    reply_to: Option<String>,
}

#[derive(Serialize)]
struct ResendPayload<'a> {
    from: &'a str,
    to: [&'a str; 1],
    subject: &'a str,
    html: &'a str,
    text: &'a str,
    /// Omitted entirely when unset, rather than sent empty — Resend rejects a
    /// blank one.
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_to: Option<&'a str>,
}

/// A complete message: what it is called, and both bodies.
///
/// Both, not one. Every message here used to go out as HTML only, which spam
/// filters treat as a signal in itself — and these are precisely the messages
/// that must not be filtered, since one of them is the only way an account
/// can ever be confirmed. Returning the pair from the template also stops the
/// subject from being decided at the call site, which is how two callers end
/// up describing the same email differently.
pub struct Message {
    pub subject: String,
    pub html: String,
    pub text: String,
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
            reply_to: std::env::var("MAIL_REPLY_TO")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
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
    pub async fn send(&self, to: &str, message: &Message) -> anyhow::Result<()> {
        let Some(api_key) = &self.api_key else {
            tracing::warn!(
                to = %to,
                subject = %message.subject,
                "email not sent: RESEND_API_KEY is unset. Body follows for development."
            );
            // The text part, not the HTML: in a terminal a confirmation link
            // buried in inlined table markup is unreadable, and reading that
            // link back out is the whole point of logging it.
            tracing::info!("{}", message.text);
            return Ok(());
        };

        let payload = ResendPayload {
            from: &self.from,
            to: [to],
            subject: &message.subject,
            html: &message.html,
            text: &message.text,
            reply_to: self.reply_to.as_deref(),
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

    /// A link into the dashboard.
    ///
    /// The application is served at `/app`; the root serves the marketing
    /// page, which carries no router. A link built as
    /// `{public_url}/#/verify/…` therefore lands the reader on the landing
    /// page, where the fragment means nothing and nothing happens — which
    /// from their side is indistinguishable from the mail never arriving,
    /// and leaves an account that can never be confirmed.
    ///
    /// Every link into the app goes through here so that path is written
    /// down once rather than in five places that can drift apart.
    pub fn app_link(&self, hash_path: &str) -> String {
        format!("{}/app#{hash_path}", self.public_url)
    }

    pub fn verification_link(&self, token: &str) -> String {
        self.app_link(&format!("/verify/{token}"))
    }

    pub fn reset_link(&self, token: &str) -> String {
        self.app_link(&format!("/reset/{token}"))
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

/// The shared chrome every message wears.
///
/// The bodies used to be bare `<div>`s with a blue button — a blue that
/// appears nowhere in the product, whose accent is green. No doctype, no
/// preheader, no header, no footer. For something sold to agencies as
/// security work, a message that looks like a script's output undercuts the
/// thing being sold, so the frame is decided once, here.
///
/// Tables and inline styles because Outlook drops most of everything else.
struct Chrome<'a> {
    /// The line shown next to the subject in an inbox list. Left to chance,
    /// clients scrape the first words of the body instead, which on a report
    /// is the domain and tells the reader nothing.
    preview: &'a str,
    eyebrow: &'a str,
    heading: &'a str,
    body: &'a str,
    cta: Option<(&'a str, &'a str)>,
    footer: &'a str,
}

const BG: &str = "#0b0b0c";
const RAISE: &str = "#131315";
const SINK: &str = "#08080a";
const RULE: &str = "#22232a";
const INK: &str = "#f0f0f2";
const INK_2: &str = "#9c9ea8";
const INK_3: &str = "#7c7e88";
const CLEAR: &str = "#52c78d";
const ALARM: &str = "#ff6b57";
/// Where the chrome's own links point: the wordmark, the mark, and the three
/// in the footer.
///
/// Read from the same PUBLIC_URL the action links are built from, not written
/// down a second time. It was a constant, which was fine only for as long as
/// the product never moved: the day a real domain is pointed at this app and
/// PUBLIC_URL is updated, the button in an email would lead to the new host
/// while the logo above it and every link below it still advertised
/// glarion.app. Two answers to "where does this product live", in one
/// message, is the sort of thing a reader notices and a sender does not.
///
/// Resolved once. The value cannot change without a restart, and a mail
/// template is not the place to be reading the environment per render.
fn site_url() -> &'static str {
    static SITE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    SITE.get_or_init(|| {
        std::env::var("PUBLIC_URL")
            .unwrap_or_else(|_| "https://glarion.app".to_string())
            .trim_end_matches('/')
            .to_string()
    })
}

/// Renders the frame.
///
/// The brand mark sits *on* its own coloured cell rather than replacing it.
/// Most email clients refuse remote images until the reader asks for them, so
/// a bare logo is a blank gap on first open — which is every open that
/// matters. Keeping the cell's background and the alt text's styling means a
/// blocked image degrades to a green square with a G in it, which is the mark
/// anyway, rather than to nothing.
fn chrome(parts: Chrome<'_>) -> String {
    let Chrome {
        preview,
        eyebrow,
        heading,
        body,
        cta,
        footer,
    } = parts;
    let preview = escape(preview);
    let eyebrow = escape(eyebrow);
    let heading = escape(heading);
    let footer = escape(footer);
    let site = site_url();
    let button = match cta {
        Some((label, url)) => format!(
            r#"<table role="presentation" cellspacing="0" cellpadding="0" style="margin:26px 0 6px"><tr><td style="border-radius:8px;background:{CLEAR}"><a href="{}" style="display:inline-block;padding:12px 22px;color:#06251a;font-size:15px;font-weight:700;text-decoration:none">{} &nbsp;&rarr;</a></td></tr></table>"#,
            escape(url),
            escape(label)
        ),
        None => String::new(),
    };

    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>{preview}</title></head><body style="margin:0;padding:0;background:{BG};font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:{INK}"><div style="display:none;max-height:0;overflow:hidden;opacity:0">{preview}</div><table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:{BG}"><tr><td align="center" style="padding:24px 14px"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:580px;background:{RAISE};border:1px solid {RULE};border-radius:14px;overflow:hidden"><tr><td style="height:3px;background:{CLEAR}"></td></tr><tr><td style="padding:20px 28px 17px;border-bottom:1px solid {RULE}"><table role="presentation" cellspacing="0" cellpadding="0"><tr><td align="center" style="width:30px;height:30px;border-radius:8px;background:{CLEAR};color:#06251a;font-size:14px;font-weight:900"><img src="{site}/glarion-mark.png" width="30" height="30" alt="G" style="display:block;width:30px;height:30px;object-fit:contain"></td><td style="padding-left:10px"><a href="{site}" style="color:{INK};font-size:19px;font-weight:800;text-decoration:none;letter-spacing:-.3px">Glarion</a></td></tr></table></td></tr><tr><td style="padding:28px"><table role="presentation" cellspacing="0" cellpadding="0" style="margin:0 0 14px"><tr><td style="padding:6px 10px;border:1px solid #2a4a3b;border-radius:999px;background:#10231a;color:{CLEAR};font-size:10px;font-weight:800;letter-spacing:1.3px;text-transform:uppercase">{eyebrow}</td></tr></table><h1 style="margin:0 0 15px;color:{INK};font-size:24px;line-height:1.24;letter-spacing:-.4px">{heading}</h1>{body}{button}</td></tr><tr><td style="padding:17px 28px;background:{SINK};border-top:1px solid {RULE}"><p style="margin:0 0 6px;color:{INK_2};font-size:12px;line-height:1.6">{footer}</p><p style="margin:0;color:{INK_3};font-size:11px;line-height:1.5">Glarion &nbsp;&middot;&nbsp; <a href="{site}" style="color:{INK_2}">Website</a> &nbsp;&middot;&nbsp; <a href="{site}/privacy.html" style="color:{INK_2}">Privacy</a> &nbsp;&middot;&nbsp; <a href="{site}/terms.html" style="color:{INK_2}">Terms</a></p></td></tr></table></td></tr></table></body></html>"#
    )
}

fn para(text: &str) -> String {
    format!(
        r#"<p style="margin:0 0 15px;color:{INK_2};font-size:15px;line-height:1.7">{}</p>"#,
        escape(text)
    )
}

/// "Hello Ada," or "Hello," — never "Hello ,".
fn greeting(first_name: &str) -> String {
    let name = first_name.trim();
    if name.is_empty() {
        "Hello,".to_string()
    } else {
        format!("Hello {name},")
    }
}

/// The confirmation message.
///
/// Short on purpose: a first message full of marketing is more likely to be
/// filtered, and this one has exactly one job. The raw link is printed under
/// the button because a client that strips the button would otherwise leave
/// an account that can never be confirmed.
pub fn verification_email(first_name: &str, link: &str) -> Message {
    let hello = greeting(first_name);
    let safe_link = escape(link);
    let tail = format!(
        r#"<p style="margin:22px 0 0;color:{INK_3};font-size:13px;line-height:1.6">Or paste this into your browser:<br><span style="word-break:break-all;color:{INK_2}">{safe_link}</span></p><p style="margin:12px 0 0;color:{INK_3};font-size:13px">The link is valid for 24 hours. If you did not create an account, you can ignore this message.</p>"#
    );
    Message {
        subject: "Confirm your email address".to_string(),
        html: chrome(Chrome {
            preview: "Confirm this address to finish setting up your Glarion account",
            eyebrow: "Confirm your email",
            heading: "Confirm your email address.",
            body: &format!(
                "{}{}{tail}",
                para(&hello),
                para("Confirm this address to finish setting up your Glarion account."),
            ),
            cta: Some(("Confirm my email", link)),
            footer: "This is a one-off confirmation for a Glarion account created with this address.",
        }),
        text: format!(
            "{hello}\n\nConfirm this address to finish setting up your Glarion account:\n{link}\n\nThe link is valid for 24 hours. If you did not create an account, you can ignore this message."
        ),
    }
}

/// The message sent once an address is confirmed.
///
/// Nothing was sent here before: an account went from unconfirmed to usable
/// in silence, so the first thing anyone had to go on was an empty dashboard.
/// It says what to do first, because a monitoring tool with no targets added
/// looks broken rather than empty.
pub fn welcome_email(first_name: &str, link: &str) -> Message {
    let hello = greeting(first_name);
    let steps = format!(
        r#"<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin:22px 0;background:{SINK};border:1px solid {RULE};border-radius:10px"><tr><td style="padding:17px;color:{INK_2};font-size:14px;line-height:1.8"><strong style="color:{INK}">1.</strong> &nbsp;Add a site you look after<br><strong style="color:{INK}">2.</strong> &nbsp;Prove you are allowed to scan it — one DNS record or one file<br><strong style="color:{INK}">3.</strong> &nbsp;Run the first check</td></tr></table>"#
    );
    Message {
        subject: "Your Glarion account is ready".to_string(),
        html: chrome(Chrome {
            preview: "Add your first site and Glarion starts watching it",
            eyebrow: "Account ready",
            heading: "Your account is ready.",
            body: &format!(
                "{}{}{steps}{}",
                para(&hello),
                para("One account covers every site you look after. Add the first one and the check runs in a couple of minutes."),
                para("We only scan domains whose ownership has been proven, which is why step 2 exists — it is also what makes the report something you can hand to a client."),
            ),
            cta: Some(("Add your first site", link)),
            footer: "You are receiving this because you just confirmed a Glarion account.",
        }),
        text: format!(
            "{hello}\n\nYour Glarion account is ready. One account covers every site you look after.\n\n1. Add a site you look after\n2. Prove you are allowed to scan it - one DNS record or one file\n3. Run the first check\n\nWe only scan domains whose ownership has been proven, which is what makes the report something you can hand to a client.\n\nStart here: {link}"
        ),
    }
}

/// The message sent when an account first becomes a paying one.
///
/// Nothing was sent before: someone paid and heard from Stripe's receipt and
/// from nobody else. A receipt is an accounting document — it does not say
/// what the plan allows or where to go next, which is the only thing the
/// person actually wants to know at that moment.
///
/// Deliberately states the two limits that change with the plan, because
/// those are what someone compares against what they thought they bought.
pub fn subscription_email(
    first_name: &str,
    plan_name: &str,
    max_targets: i32,
    scheduling: bool,
    link: &str,
) -> Message {
    let hello = greeting(first_name);
    let cadence = if scheduling {
        "Your sites are re-checked on a schedule, without you asking."
    } else {
        "Scans stay manual on this plan."
    };
    let safe_plan = escape(plan_name);
    let safe_cadence = escape(cadence);
    let limits = format!(
        r#"<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin:22px 0;background:{SINK};border:1px solid {RULE};border-radius:10px"><tr><td style="padding:17px;color:{INK_2};font-size:14px;line-height:1.8">Up to <strong style="color:{INK}">{max_targets}</strong> sites monitored<br>{safe_cadence}</td></tr></table>"#
    );
    let heading = format!("Your {plan_name} plan is active.");
    let preview = format!("Your Glarion {plan_name} plan is active");
    Message {
        subject: "Your Glarion plan is active".to_string(),
        html: chrome(Chrome {
            preview: &preview,
            eyebrow: "Plan active",
            heading: &heading,
            body: &format!(
                "{}{}{limits}{}",
                para(&hello),
                para("Nothing else needs setting up."),
                para("You can change or cancel the plan yourself from your account at any time. Stripe sends the payment receipt separately."),
            ),
            cta: Some(("Open Glarion", link)),
            footer: "This confirms a change to your Glarion subscription. Stripe holds the payment record.",
        }),
        text: format!(
            "{hello}\n\nYour Glarion {safe_plan} plan is active. Nothing else needs setting up.\n\nUp to {max_targets} sites monitored. {cadence}\n\nOpen Glarion: {link}\n\nYou can change or cancel the plan yourself from your account at any time. Stripe sends the payment receipt separately."
        ),
    }
}

/// The link that moves an account to a new address.
///
/// Sent to the new address, never to the old one: the whole question this
/// message settles is whether the person asking can actually receive mail
/// there, and a link sent anywhere else answers a different question.
pub fn email_change_confirmation(first_name: &str, link: &str, valid_minutes: i64) -> Message {
    let hello = greeting(first_name);
    let safe_link = escape(link);
    let tail = format!(
        r#"<p style="margin:22px 0 0;color:{INK_3};font-size:13px;line-height:1.6">Or paste this into your browser:<br><span style="word-break:break-all;color:{INK_2}">{safe_link}</span></p><p style="margin:12px 0 0;color:{INK_3};font-size:13px">The link works once and expires in {valid_minutes} minutes. Until it is followed, the account keeps its current address.</p>"#
    );
    Message {
        subject: "Confirm your new Glarion address".to_string(),
        html: chrome(Chrome {
            preview: "Confirm this address to finish moving your Glarion account to it",
            eyebrow: "Confirm the change",
            heading: "Confirm your new address.",
            body: &format!(
                "{}{}{tail}",
                para(&hello),
                para("Someone asked to move a Glarion account to this address. Confirming finishes the move; everywhere the account is currently signed in will be signed out."),
            ),
            cta: Some(("Confirm this address", link)),
            footer: "If you were not expecting this, ignore it — nothing changes until the link is followed, and whoever asked cannot read this message.",
        }),
        text: format!(
            "{hello}\n\nSomeone asked to move a Glarion account to this address. Confirming finishes the move; everywhere the account is currently signed in will be signed out.\n\n{link}\n\nThe link works once and expires in {valid_minutes} minutes. Until it is followed, the account keeps its current address.\n\nIf you were not expecting this, ignore it - nothing changes until the link is followed."
        ),
    }
}

/// The warning sent to the address being left behind.
///
/// This is the half that makes the flow safe. A stolen session plus a
/// change of address is a complete account takeover — the thief redirects
/// every future reset link to themselves — so the address currently on the
/// account is told the moment a move is requested, while it can still be
/// stopped, and told again nowhere else.
///
/// It carries no link, deliberately. Whoever reads it is the person being
/// pushed out, at their most alarmed, and a button in this message is the
/// single most valuable thing an attacker could forge. Getting in touch
/// cannot be forged.
pub fn email_change_alert(first_name: &str, new_email: &str) -> Message {
    let hello = greeting(first_name);
    let safe_new = escape(new_email);
    Message {
        subject: "Someone asked to change your Glarion address".to_string(),
        html: chrome(Chrome {
            preview: "A request was made to move your Glarion account to another address",
            eyebrow: "Security notice",
            heading: "A change of address was requested.",
            body: &format!(
                "{}{}<table role=\"presentation\" width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" style=\"margin:22px 0;background:{SINK};border:1px solid {RULE};border-radius:10px\"><tr><td style=\"padding:17px;color:{INK_2};font-size:14px;line-height:1.7\">Requested new address<br><strong style=\"color:{INK}\">{safe_new}</strong></td></tr></table>{}",
                para(&hello),
                para("Your Glarion account is being moved to another address. It has not moved yet: the new address has to confirm first, and until it does, this one is still the account's."),
                para("If this was you, nothing else is needed. If it was not, change your password now — someone is signed in who should not be — and reply to this message."),
            ),
            cta: None,
            footer: "This security notice is sent to the address currently on the account whenever a change is requested, and cannot be turned off.",
        }),
        text: format!(
            "{hello}\n\nYour Glarion account is being moved to {new_email}. It has not moved yet: the new address has to confirm first, and until it does, this one is still the account's.\n\nIf this was you, nothing else is needed. If it was not, change your password now - someone is signed in who should not be - and reply to this message."
        ),
    }
}

/// The message sent when a paid plan stops.
///
/// Nothing was sent before. The account dropped to free, scheduled scanning
/// was switched off, and the first the agency knew of it was noticing that a
/// client site had not been checked in a fortnight — on a security product,
/// which is the worst possible thing to discover late.
///
/// The two cases are worded differently on purpose. A failed payment is a
/// card that expired and is fixed in a minute; a cancellation is a decision
/// somebody made. Telling a customer who chose to leave that their "payment
/// did not go through" reads as a company that was not paying attention, and
/// telling someone whose card bounced that their subscription "has ended"
/// makes a recoverable problem sound final.
pub fn subscription_ended_email(
    first_name: &str,
    plan_name: &str,
    payment_problem: bool,
    link: &str,
) -> Message {
    let hello = greeting(first_name);
    let heading = if payment_problem {
        "Your payment did not go through."
    } else {
        "Your plan has ended."
    };
    let explain = if payment_problem {
        format!("We could not take payment for your Glarion {plan_name} plan, so scheduled scanning is paused and your account is back on the free plan. Updating the card puts it back exactly as it was.")
    } else {
        format!("Your Glarion {plan_name} plan has ended, so scheduled scanning is off and your account is back on the free plan. Subscribing again turns it back on.")
    };
    let action = if payment_problem {
        "Update your card"
    } else {
        "Subscribe again"
    };
    let kept = "Nothing has been deleted. Your sites, their verifications and every report stay exactly where they are, and start being checked again the moment the plan does.";

    Message {
        subject: if payment_problem {
            "Your Glarion payment did not go through".to_string()
        } else {
            "Your Glarion plan has ended".to_string()
        },
        html: chrome(Chrome {
            preview: if payment_problem {
                "Scheduled scanning is paused until the card is updated"
            } else {
                "Scheduled scanning is off until the plan is renewed"
            },
            eyebrow: if payment_problem { "Payment failed" } else { "Plan ended" },
            heading,
            body: &format!("{}{}{}", para(&hello), para(&explain), para(kept)),
            cta: Some((action, link)),
            footer: "This email is sent when a Glarion plan changes state. Stripe holds the payment record.",
        }),
        text: format!(
            "{hello}\n\n{explain}\n\n{kept}\n\n{action}: {link}"
        ),
    }
}

/// The message sent when a monitored site changes.
///
/// Deliberately short and specific. This is the only email an agency gets
/// from us once they are set up, so it has to be worth opening: what
/// changed, on which site, and a way to see the detail. A digest of
/// everything that happened would be filtered within a month.
pub fn change_email(domain: &str, summary: &str, detail: &str, link: &str) -> Message {
    let preview = format!("{summary} — {domain}");
    let domain_line = format!(
        r#"<p style="margin:0 0 20px;color:{INK_3};font-size:14px;font-family:ui-monospace,Menlo,Consolas,monospace">{}</p>"#,
        escape(domain)
    );
    Message {
        subject: summary.to_string(),
        html: chrome(Chrome {
            preview: &preview,
            eyebrow: "Site changed",
            heading: summary,
            body: &format!("{domain_line}{}", para(detail)),
            cta: Some(("See what changed", link)),
            footer: "You are getting this because this site is on a scanning schedule. Turn it off on the site's page.",
        }),
        text: format!(
            "{summary}\n{domain}\n\n{detail}\n\nSee what changed: {link}\n\nYou are getting this because this site is on a scanning schedule. Turn it off on the site's page."
        ),
    }
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
pub fn preview_report_email(domain: &str, lines: &[ReportLine], upgrade_link: &str) -> Message {
    let findings = lines.iter().filter(|line| line.is_finding).count();
    let headline = match findings {
        0 => "Nothing obvious from the outside".to_string(),
        1 => "1 thing worth fixing".to_string(),
        n => format!("{n} things worth fixing"),
    };

    let mut rows = String::new();
    let mut plain_rows = String::new();
    for line in lines {
        let colour = if line.is_finding { ALARM } else { INK };
        let weight = if line.is_finding { "600" } else { "400" };
        rows.push_str(&format!(
            r#"<tr><td style="padding:7px 16px 7px 0;color:{INK_3};font-size:13px;white-space:nowrap;vertical-align:top">{}</td><td style="padding:7px 0;color:{colour};font-weight:{weight};font-size:14px">{}</td></tr>"#,
            escape(&line.label),
            escape(&line.value),
        ));
        plain_rows.push_str(&format!(
            "{}{}: {}\n",
            if line.is_finding { "! " } else { "  " },
            line.label,
            line.value
        ));
    }

    let scope = format!(
        "This read only what {domain} publishes to any visitor: its headers, its certificate, its DNS, and the files it offers to automated readers. It did not examine the application itself — outdated components with known vulnerabilities, exposed administrative paths, or misconfigured storage — because that requires the domain's owner to confirm the request first."
    );
    let preview = format!("{headline} on {domain}");
    let body = format!(
        r#"<p style="margin:0 0 20px;color:{INK_3};font-size:14px;font-family:ui-monospace,Menlo,Consolas,monospace">{}</p><table style="border-collapse:collapse;width:100%;margin-bottom:24px">{rows}</table><p style="margin:0 0 6px;color:{INK};font-size:15px;font-weight:700">What this did not look at</p>{}"#,
        escape(domain),
        para(&scope),
    );

    Message {
        subject: format!("Security check: {domain}"),
        html: chrome(Chrome {
            preview: &preview,
            eyebrow: "Free external check",
            heading: &headline,
            body: &body,
            cta: Some(("Run the full check", upgrade_link)),
            footer: "You received this because this report was requested from your address. We do not add you to anything by sending it.",
        }),
        text: format!(
            "{headline}\n{domain}\n\n{plain_rows}\nWhat this did not look at\n{scope}\n\nRun the full check: {upgrade_link}\n\nYou received this because this report was requested from your address. We do not add you to anything by sending it."
        ),
    }
}

/// The password-recovery link.
///
/// Short and free of anything else on purpose. This message is the single
/// most valuable one to forge — it is the one people are trained to click
/// while already anxious about being locked out — so it says only what it is,
/// names how long it lasts, and offers nothing else to click.
pub fn password_reset_email(first_name: &str, link: &str, valid_minutes: i64) -> Message {
    let hello = greeting(first_name);
    let safe_link = escape(link);
    let tail = format!(
        r#"<p style="margin:22px 0 0;color:{INK_3};font-size:13px;line-height:1.6">Or paste this into your browser:<br><span style="word-break:break-all;color:{INK_2}">{safe_link}</span></p><p style="margin:12px 0 0;color:{INK_3};font-size:13px">The link works once and expires in {valid_minutes} minutes. If you did not ask for this, ignore it — your password stays unchanged, and nobody was told whether this address has an account.</p>"#
    );
    Message {
        subject: "Reset your Glarion password".to_string(),
        html: chrome(Chrome {
            preview: "Choose a new password for your Glarion account",
            eyebrow: "Account recovery",
            heading: "Reset your password.",
            body: &format!(
                "{}{}{tail}",
                para(&hello),
                para("Use the link below to choose a new password. Signing in everywhere else stops working as soon as you do."),
            ),
            cta: Some(("Choose a new password", link)),
            footer: "We will never ask you for your password by email, and we will never ask you to send it back to us.",
        }),
        text: format!(
            "{hello}\n\nUse the link below to choose a new password for your Glarion account. Signing in everywhere else stops working as soon as you do.\n\n{link}\n\nThe link works once and expires in {valid_minutes} minutes. If you did not ask for this, ignore it - your password stays unchanged.\n\nWe will never ask you for your password by email."
        ),
    }
}

/// The notice sent once a password has actually changed.
///
/// Carries no link and no token, deliberately. Whoever reads this is not
/// necessarily the person who changed it — that is the entire reason it
/// exists — but by the time it arrives the new password is already set, so a
/// "this wasn't me" button here would be the exact shape an attacker would
/// forge, on the one message a worried reader is most likely to click.
/// Getting in touch is a thing that cannot be phished out of an inbox.
pub fn password_changed_email(first_name: &str) -> Message {
    let hello = greeting(first_name);
    Message {
        subject: "Your Glarion password was changed".to_string(),
        html: chrome(Chrome {
            preview: "The password on your Glarion account was changed",
            eyebrow: "Security notice",
            heading: "Your password was changed.",
            body: &format!(
                "{}{}<table role=\"presentation\" width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" style=\"margin:22px 0;background:{SINK};border:1px solid {RULE};border-radius:10px\"><tr><td style=\"padding:17px;color:{INK_2};font-size:14px;line-height:1.7\">If this was you, nothing else is needed.<br>If it was not, reply to this message straight away — someone else set that password.</td></tr></table>{}",
                para(&hello),
                para("The password on your Glarion account was changed, and every device that was signed in has been signed out."),
                para("We will never ask you for your password by email."),
            ),
            cta: None,
            footer: "This security notice is sent every time the password changes and cannot be turned off.",
        }),
        text: format!(
            "{hello}\n\nThe password on your Glarion account was changed, and every device that was signed in has been signed out.\n\nIf this was you, nothing else is needed. If it was not, reply to this message straight away - someone else set that password.\n\nWe will never ask you for your password by email."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mailer() -> Mailer {
        Mailer {
            api_key: None,
            from: "Glarion <hello@example.com>".to_string(),
            public_url: "https://glarion.example".to_string(),
            reply_to: None,
        }
    }

    /// The bug this pins cost a real account: the root serves the marketing
    /// page, which has no router, so a confirmation link pointing there
    /// opened a page where nothing happened and left an account that could
    /// never be confirmed. Nothing failed, nothing logged, and the mail
    /// showed as delivered — so it read as a spam problem for a day.
    #[test]
    fn links_into_the_app_do_not_point_at_the_marketing_page() {
        let link = mailer().verification_link("abc123");

        assert_eq!(link, "https://glarion.example/app#/verify/abc123");
        assert!(
            !link.contains(".example/#/"),
            "a link to the root lands on the landing page, which cannot route it"
        );
    }

    #[test]
    fn every_app_link_is_built_the_same_way() {
        let mailer = mailer();

        for path in ["/plan", "/signup", "/settings", "/scans/7"] {
            let link = mailer.app_link(path);
            assert!(
                link.starts_with("https://glarion.example/app#"),
                "{path} produced {link}"
            );
        }
    }

    #[test]
    fn a_name_cannot_inject_markup_into_the_message() {
        let body = verification_email(
            "<script>alert(1)</script>",
            "https://example.com/#/verify/x",
        )
        .html;

        assert!(!body.contains("<script>alert(1)</script>"));
        assert!(body.contains("&lt;script&gt;"));
    }

    #[test]
    fn the_link_appears_as_a_button_and_as_text() {
        // Some clients strip buttons, and some people do not trust them.
        let link = "https://glarion.app/#/verify/abc123";
        let body = verification_email("Aurelio", link).html;

        assert_eq!(body.matches(link).count(), 2);
    }

    #[test]
    fn a_missing_name_still_produces_a_sensible_greeting() {
        let body = verification_email("   ", "https://example.com/x").html;

        assert!(body.contains("Hello,"));
        assert!(!body.contains("Hello ,"));
    }

    #[test]
    fn links_are_built_from_configured_url_not_from_a_request() {
        let mailer = Mailer {
            api_key: None,
            from: "x@example.com".into(),
            public_url: "https://glarion.app".into(),
            reply_to: None,
        };

        assert_eq!(
            mailer.verification_link("tok"),
            "https://glarion.app/app#/verify/tok"
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
        )
        .html;

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
        )
        .html;

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

        let body = preview_report_email("example.com", &lines, "https://glarion.app").html;

        assert!(flat(&body).contains("2 things worth fixing"));
    }

    #[test]
    fn a_clean_report_does_not_claim_the_site_is_clean() {
        // The most dangerous message this system could send is "nothing
        // found" read as "nothing there".
        let lines = vec![line("Server", "nginx", false)];
        let body = preview_report_email("example.com", &lines, "https://glarion.app").html;

        assert!(flat(&body).contains("Nothing obvious from the outside"));
        assert!(flat(&body).contains("did not look at"));
    }

    #[test]
    fn the_report_names_its_own_limits() {
        let body = preview_report_email("example.com", &[], "https://glarion.app").html;

        // Stating the scope, rather than hedging every line.
        assert!(flat(&body).contains("did not examine the application itself"));
        assert!(flat(&body).to_lowercase().contains("confirm the request"));
    }

    #[test]
    fn a_report_cannot_be_injected_through_the_domain_or_a_value() {
        // The domain is typed by a stranger, and the values are read off
        // somebody else's server.
        let lines = vec![line("<b>label</b>", "<script>alert(1)</script>", true)];
        let body =
            preview_report_email("<script>alert(2)</script>", &lines, "https://glarion.app").html;

        assert!(!body.contains("<script>alert(1)</script>"));
        assert!(!body.contains("<script>alert(2)</script>"));
        assert!(!body.contains("<b>label</b>"));
    }

    #[test]
    fn the_report_says_it_did_not_subscribe_anyone() {
        // Sending a report is not consent to market to somebody.
        let body = preview_report_email("example.com", &[], "https://glarion.app").html;

        assert!(flat(&body).contains("do not add you to anything"));
    }

    #[test]
    fn trailing_slashes_do_not_produce_a_double_slash() {
        let mailer = Mailer {
            api_key: None,
            from: "x@example.com".into(),
            public_url: "https://glarion.app/".trim_end_matches('/').to_string(),
            reply_to: None,
        };

        assert!(!mailer.verification_link("tok").contains("app//"));
    }

    /// Kept from when the mark was prepended by `with_glarion_header`, which
    /// `chrome` replaced. The claim it makes is the one that still matters:
    /// the approved product mark goes out on transactional mail.
    ///
    /// It gained a second assertion in the move. The old wrapper put a bare
    /// `<img>` at the top of the body, and clients that block remote images —
    /// which is most of them, on a first open from an unknown sender — showed
    /// a blank gap instead of any branding at all. The mark now sits on a
    /// cell that keeps its own colour, so a blocked image still leaves the
    /// mark's shape behind rather than nothing.
    #[test]
    fn transactional_mail_uses_the_approved_product_mark() {
        let html = verification_email("Ada", "https://glarion.example/app#/verify/x").html;

        assert!(html.contains("/glarion-mark.png"));
        assert!(html.contains("width=\"30\""));
        assert!(
            html.contains("background:#52c78d;color:#06251a;font-size:14px;font-weight:900\"><img"),
            "the mark must sit on its own coloured cell, or a blocked image shows nothing"
        );
    }

    #[test]
    fn the_subscription_email_states_the_limits_that_changed() {
        // The two numbers someone checks against what they thought they were
        // buying. A welcome that does not mention them is a welcome that
        // gets a support ticket in reply.
        let message = subscription_email("Marco", "Agency", 40, true, "https://glarion.app/app");
        assert!(message.html.contains("Agency"));
        assert!(message.html.contains("re-checked on a schedule"));
        assert!(message.html.contains("Hello Marco,"));
        // Asserted on the text part: the HTML bolds the number, so "40 sites"
        // is split by a tag there and matching it would be matching markup.
        assert!(message.text.contains("40 sites monitored"));
        assert!(message.text.contains("Hello Marco,"));
    }

    #[test]
    fn a_plan_without_scheduling_does_not_claim_it() {
        let html = subscription_email("", "Studio", 10, false, "https://glarion.app/app").html;
        assert!(html.contains("Scans stay manual"));
        assert!(!html.contains("re-checked on a schedule"));
        // No name is not an error; it just loses the name.
        assert!(html.contains("Hello,"));
        assert!(!html.contains("Hello ,"));
    }

    #[test]
    fn a_name_cannot_carry_markup_into_the_message() {
        let html = subscription_email(
            "<script>x</script>",
            "Studio",
            10,
            false,
            "https://glarion.app",
        )
        .html;
        assert!(!html.contains("<script>"));
    }

    /// Every message must carry both bodies. HTML-only mail is treated as a
    /// spam signal in itself, and one of these is the only way an account can
    /// ever be confirmed — landing in a junk folder makes it unrecoverable.
    #[test]
    fn every_message_has_a_text_part_and_a_subject() {
        let lines = [line("TLS", "expires in 9 days", true)];
        let messages = [
            verification_email("Ada", "https://glarion.app/app#/verify/x"),
            welcome_email("Ada", "https://glarion.app/app#/targets"),
            subscription_email("Ada", "Agency", 40, true, "https://glarion.app/app"),
            change_email(
                "example.com",
                "1 new finding",
                "detail",
                "https://glarion.app/app",
            ),
            preview_report_email("example.com", &lines, "https://glarion.app/app"),
        ];

        for message in messages {
            assert!(
                !message.subject.trim().is_empty(),
                "a message with no subject"
            );
            assert!(
                message.text.len() > 40,
                "text part too thin to be a real alternative: {:?}",
                message.text
            );
            assert!(
                !message.text.contains('<'),
                "the text part must not be markup: {:?}",
                message.text
            );
            assert!(
                message.html.starts_with("<!doctype html>"),
                "a bare fragment renders unpredictably outside a browser"
            );
            // The preheader is what an inbox list shows next to the subject.
            // Without it clients scrape the first words of the body, which on
            // a report is the domain and says nothing.
            assert!(message.html.contains("display:none;max-height:0"));
        }
    }

    #[test]
    fn the_welcome_says_what_to_do_first() {
        // A monitoring tool with nothing added looks broken rather than
        // empty, so the first message after confirming has to point at the
        // one action that makes the product do anything.
        let message = welcome_email("Ada", "https://glarion.app/app#/targets");

        assert!(message.html.contains("Hello Ada,"));
        assert!(message.html.contains("Add your first site"));
        assert!(message.text.contains("Prove you are allowed to scan it"));
    }

    #[test]
    fn a_name_cannot_inject_markup_into_the_welcome() {
        let message = welcome_email("<script>alert(1)</script>", "https://glarion.app/app");

        assert!(!message.html.contains("<script>alert(1)</script>"));
        assert!(message.html.contains("&lt;script&gt;"));
    }

    /// The chrome's links and the action link must name the same host.
    ///
    /// They did not have to before, because both happened to be the same
    /// string. The day a real domain is pointed at this app, PUBLIC_URL moves
    /// and a hard-coded constant would not — leaving a button that goes to
    /// the new host under a logo that still links to the old one.
    #[test]
    fn the_chrome_and_the_action_link_agree_on_where_the_product_lives() {
        let host = site_url();
        let message = verification_email("Ada", &format!("{host}/app#/verify/x"));

        assert!(
            message.html.contains(&format!("href=\"{host}\"")),
            "the wordmark must link to the configured host"
        );
        assert!(
            message.html.contains(&format!("{host}/privacy.html")),
            "and so must the footer"
        );
        assert!(
            message
                .html
                .contains(&format!("src=\"{host}/glarion-mark.png\"")),
            "and the mark must be loaded from it"
        );
        // Every absolute URL in the message, not just the three checked
        // above. Asserting "the old host is absent" would prove nothing while
        // the old host is also the default; asserting that no *other* origin
        // appears at all catches a literal reintroduced anywhere, whatever it
        // is set to.
        let mut rest = message.html.as_str();
        let mut origins = 0;
        while let Some(at) = rest.find("https://") {
            rest = &rest[at..];
            let end = rest.find(['"', '\'', '<', ' ']).unwrap_or(rest.len());
            let url = &rest[..end];
            assert!(
                url.starts_with(host),
                "an absolute URL that PUBLIC_URL did not put there: {url}"
            );
            origins += 1;
            rest = &rest[end..];
        }
        assert!(origins >= 4, "expected the chrome's links to be absolute");
    }

    /// The password-changed notice tells the reader to reply straight away if
    /// the change was not theirs. It is the most time-critical sentence this
    /// system sends, and from a noreply@ address it reaches a bin — the
    /// person doing the right thing, quickly, is the one it fails.
    ///
    /// This pins the shape rather than the address: the message still says
    /// reply, and the transport still has somewhere to carry a reply to.
    #[test]
    fn the_security_notice_asks_for_a_reply_and_a_reply_can_arrive() {
        let message = password_changed_email("Ada");
        assert!(
            message.text.contains("reply to this message"),
            "the notice must keep telling people to get in touch"
        );

        let configured = Mailer {
            api_key: None,
            from: "Glarion <noreply@example.com>".to_string(),
            public_url: "https://glarion.example".to_string(),
            reply_to: Some("security@example.com".to_string()),
        };
        assert_eq!(configured.reply_to.as_deref(), Some("security@example.com"));

        // Unset is the honest default rather than a guessed address: a
        // Reply-To pointing somewhere nobody reads is the same failure with
        // extra steps.
        assert!(mailer().reply_to.is_none());
    }

    /// A plan that stops has to say so, and has to say which kind of stop.
    ///
    /// Telling a customer who chose to leave that their payment "did not go
    /// through" reads as a company not paying attention; telling someone
    /// whose card bounced that their plan "has ended" makes a recoverable
    /// problem sound final. The two wordings must not leak into each other.
    #[test]
    fn a_stopped_plan_says_which_kind_of_stop_it_was() {
        let failed =
            subscription_ended_email("Ada", "Agency", true, "https://glarion.example/app#/plan");
        let chosen =
            subscription_ended_email("Ada", "Agency", false, "https://glarion.example/app#/plan");

        assert!(failed.subject.contains("did not go through"));
        assert!(failed.html.contains("Updating the card"));
        assert!(!failed.html.contains("has ended"));

        assert!(chosen.subject.contains("has ended"));
        assert!(chosen.html.contains("Subscribing again"));
        assert!(!chosen.html.contains("did not go through"));
    }

    /// The sentence that stops a cancellation becoming a support ticket.
    ///
    /// An agency whose scanning has just switched off needs to know its
    /// sites, verifications and reports are still there. Ownership
    /// verification in particular is slow to redo, and someone who thinks
    /// they have lost it does not come back.
    #[test]
    fn a_stopped_plan_promises_nothing_was_destroyed() {
        for payment_problem in [true, false] {
            let message = subscription_ended_email(
                "Ada",
                "Studio",
                payment_problem,
                "https://glarion.example/app",
            );
            assert!(
                message.text.contains("Nothing has been deleted"),
                "the reader must be told their work survives"
            );
            assert!(message.text.contains("verifications"));
        }
    }
}
