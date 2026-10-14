//! Transactional email.
//!
//! Sends through Resend's HTTPS API, matching the provider already used
//! elsewhere in the portfolio. HTTP rather than SMTP on purpose: several
//! hosts block outbound port 587/465, and a blocked SMTP connection hangs
//! until a timeout instead of failing fast.
//!
//! Missing configuration is a send failure, never a successful delivery.
//! Message bodies are not logged because they can contain recovery tokens.

use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};

pub struct Mailer {
    api_key: Option<String>,
    /// No default. A fallback to Resend's shared onboarding@resend.dev
    /// address used to hide a missing MAIL_FROM: Resend only lets that sender
    /// reach the account owner, so every customer email was refused while the
    /// process looked configured. Missing now means "not configured", loudly.
    from: Option<String>,
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
    /// Whether the last attempt reached the provider.
    ///
    /// Deliberately global rather than per-recipient. Signup answers a taken
    /// address exactly as it answers a new one, so that it cannot be used to
    /// test who has an account; a per-address delivery result would
    /// reintroduce that difference the moment delivery started failing. This
    /// says only "mail is working", which is the same for every caller.
    last_send_ok: AtomicBool,
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
        let mailer = Self {
            api_key: std::env::var("RESEND_API_KEY")
                .ok()
                .filter(|k| !k.is_empty()),
            // Must be an address on a domain verified in Resend, with its
            // SPF and DKIM published (glarion.app sends via send.glarion.app).
            from: std::env::var("MAIL_FROM")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            public_url: std::env::var("PUBLIC_URL")
                .unwrap_or_else(|_| "http://localhost:5173".to_string())
                .trim_end_matches('/')
                .to_string(),
            reply_to: std::env::var("MAIL_REPLY_TO")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            // Optimistic until something fails: a process that has sent
            // nothing yet has no reason to tell a visitor mail is broken.
            last_send_ok: AtomicBool::new(true),
        };
        if mailer.api_key.is_some() && mailer.from.is_none() {
            tracing::error!("MAIL_FROM is unset — every email will be refused until it is set");
        }
        mailer
    }

    /// Both the provider key and the sender: either alone sends nothing.
    pub fn is_configured(&self) -> bool {
        self.api_key.is_some() && self.from.is_some()
    }

    /// Whether the most recent attempt reached the provider.
    ///
    /// Lets a handler tell a visitor the truth instead of "check your inbox"
    /// when nothing was sent. See `last_send_ok` for why this is not
    /// per-recipient.
    pub fn last_send_ok(&self) -> bool {
        self.is_configured() && self.last_send_ok.load(Ordering::Relaxed)
    }

    /// Sends a message, returning an error when no provider is configured.
    ///
    /// Errors are returned rather than swallowed so a caller can decide
    /// what to tell the user, but note that signup deliberately does not
    /// fail when delivery fails — see the call site for why.
    pub async fn send(&self, to: &str, message: &Message) -> anyhow::Result<()> {
        let outcome = self.deliver(to, message).await;
        self.last_send_ok.store(outcome.is_ok(), Ordering::Relaxed);
        outcome
    }

    /// The attempt itself. Split out so every exit path, including the `?` on
    /// a transport error, is recorded by `send` rather than by each branch.
    async fn deliver(&self, to: &str, message: &Message) -> anyhow::Result<()> {
        let Some(api_key) = &self.api_key else {
            anyhow::bail!("email provider is not configured");
        };
        let Some(from) = &self.from else {
            anyhow::bail!("MAIL_FROM is not set");
        };

        let payload = ResendPayload {
            from,
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
            anyhow::bail!("email provider refused ({status})");
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

/// The shared frame every message wears: design kit v3
/// (my-apps/email-design-kit/glarion), one continuous deep-violet composition
/// from the header to the footer, no white anywhere. Tables and inline styles
/// because Outlook drops most of everything else; the style block carries only
/// the phone layout and the dark-mode pins.
struct Chrome<'a> {
    /// The line shown next to the subject in an inbox list. Left to chance,
    /// clients scrape the first words of the body instead, which on a report
    /// is the domain and tells the reader nothing.
    preview: &'a str,
    eyebrow: &'a str,
    heading: &'a str,
    body: &'a str,
    cta: Option<(&'a str, &'a str)>,
    /// What follows the button in the kit's order: link fallback, steps, notes.
    after: &'a str,
    /// Why the reader got this message, under the card.
    footer: &'a str,
    /// The question the reader may have, and what to send, at the foot of the card.
    help: (&'a str, &'a str),
    /// The number that matters, on a violet band: (label, big line, sentence).
    moment: Option<(String, String, String)>,
    tone: Tone,
}

/// How loud a message is. It sets the rule over the header, the eyebrow and
/// the edge of the help block; security notices also warm the header and the
/// moment band towards oxblood, so they never look like routine mail.
#[derive(Clone, Copy, PartialEq)]
enum Tone {
    Brand,
    /// Something to act on soon: a failed payment, a proof about to lapse.
    Warning,
    /// Something changed that may be wrong.
    Alarm,
    /// The account itself: password or address.
    Security,
}

// Design kit v3 palette, from the dark side of glarion.app's prism identity.
// Contrast: ink on card 14.8:1, muted on card 8.7:1, lavender on card 6.2:1,
// white on the violet button 6.3:1, alarm on panel 5.3:1.
const BG: &str = "#1a0a22";
const RAISE: &str = "#2d103a";
const SINK: &str = "#24102f";
/// Panels and step cards, raised off either section tint.
const PANEL: &str = "#3a1a4a";
const RULE: &str = "#4d2a5e";
const INK: &str = "#f4eef7";
const INK_3: &str = "#c9b8d2";
/// Hero intro and footer links.
const SOFT: &str = "#e3d6ec";
const NIGHT: &str = "#120618";
const ALARM: &str = "#ff6b57";
const AMBER: &str = "#e0a63a";
const VIOLET: &str = "#7345b2";
const LAVENDER: &str = "#b58fe0";
/// The healthy-signal green of the mark's dot.
const SIGNAL: &str = "#52c78d";
const FONT: &str = "Manrope,'Segoe UI',Arial,sans-serif";
const MONO: &str = "ui-monospace,Menlo,Consolas,monospace";

/// Where the chrome's own links point: the wordmark, the mark, and the three
/// in the footer.
///
/// Read from the same PUBLIC_URL the action links are built from, not written
/// down a second time, so the button and the logo above it can never name two
/// different hosts. Resolved once: the value cannot change without a restart.
fn site_url() -> &'static str {
    static SITE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    SITE.get_or_init(|| {
        std::env::var("PUBLIC_URL")
            .unwrap_or_else(|_| "https://glarion.app".to_string())
            .trim_end_matches('/')
            .to_string()
    })
}

/// The radar mark of the moment band: two rings and a dot. `separate` keeps
/// the radius on the borders, which collapsed tables drop.
fn radar(ring: &str, dot: &str) -> String {
    format!(
        r#"<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="border-collapse:separate"><tr><td align="center" width="64" height="64" style="width:64px;height:64px;border:2px solid {ring};border-radius:34px"><table role="presentation" align="center" cellpadding="0" cellspacing="0" border="0" style="border-collapse:separate"><tr><td align="center" width="40" height="40" style="width:40px;height:40px;border:2px solid {ring};border-radius:22px"><table role="presentation" align="center" cellpadding="0" cellspacing="0" border="0" style="border-collapse:separate"><tr><td width="14" height="14" bgcolor="{dot}" style="width:14px;height:14px;border-radius:7px;background:{dot};font-size:0;line-height:0">&nbsp;</td></tr></table></td></tr></table></td></tr></table>"#
    )
}

/// Renders the frame.
///
/// The mark is a dark ring on a transparent ground, so it sits on its own
/// white disc: on the violet header alone it would vanish. Most email clients
/// refuse remote images until the reader asks for them, and keeping the disc
/// and the alt text's styling means a blocked image degrades to a white disc
/// naming the product rather than to nothing.
fn chrome(parts: Chrome<'_>) -> String {
    let Chrome {
        preview,
        eyebrow,
        heading,
        body,
        cta,
        after,
        footer,
        help,
        moment,
        tone,
    } = parts;
    let preview = escape(preview);
    let eyebrow = escape(eyebrow);
    let heading = escape(heading);
    let footer = escape(footer);
    let (help_title, help_text) = (escape(help.0), escape(help.1));
    // Only messages that invite a reply say "or".
    let write = if help.1.starts_with("Reply") {
        "Or write to"
    } else {
        "Write to"
    };
    let site = site_url();
    let accent = match tone {
        Tone::Brand => LAVENDER,
        Tone::Warning => AMBER,
        Tone::Alarm | Tone::Security => ALARM,
    };
    let security = tone == Tone::Security;
    let (hero_bg, hero_image, moment_image, bands) = if security {
        (
            "#4a1838",
            "linear-gradient(160deg,#3a1230 0%,#5c2030 100%)",
            "linear-gradient(135deg,#5c2030 0%,#3a1230 100%)",
            ["#55243A", "#441C3F", "#34143D"],
        )
    } else {
        (
            "#3b1750",
            "linear-gradient(160deg,#2d103a 0%,#4a1d63 100%)",
            "linear-gradient(135deg,#4a1d63 0%,#2d103a 100%)",
            ["#43205A", "#36184A", "#2A1238"],
        )
    };
    let bands: String = bands
        .iter()
        .map(|band| format!(r#"<tr><td bgcolor="{band}" style="height:6px;font-size:0;line-height:0;background:{band}">&nbsp;</td></tr>"#))
        .collect();
    let dots = format!(
        r#"<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="border-collapse:separate"><tr><td width="8" height="8" bgcolor="{SIGNAL}" style="width:8px;height:8px;border-radius:4px;background:{SIGNAL};font-size:0;line-height:0">&nbsp;</td><td width="6" style="font-size:0">&nbsp;</td><td width="8" height="8" bgcolor="{AMBER}" style="width:8px;height:8px;border-radius:4px;background:{AMBER};font-size:0;line-height:0">&nbsp;</td><td width="6" style="font-size:0">&nbsp;</td><td width="8" height="8" bgcolor="{ALARM}" style="width:8px;height:8px;border-radius:4px;background:{ALARM};font-size:0;line-height:0">&nbsp;</td><td width="8" style="font-size:0">&nbsp;</td><td width="16" height="16" style="width:16px;height:16px;border:2px solid {LAVENDER};border-radius:9px;font-size:0;line-height:0">&nbsp;</td></tr></table>"#
    );
    let moment_band = match moment {
        Some((label, big, line)) => format!(
            r#"<tr><td class="pad" bgcolor="{hero_bg}" style="background:{hero_bg};background-image:{moment_image};padding:22px 36px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td valign="middle"><p style="margin:0 0 4px;font-family:{FONT};font-size:12px;line-height:16px;font-weight:700;letter-spacing:1.2px;text-transform:uppercase;color:{accent}">{}</p><p class="big" style="margin:0 0 4px;font-family:{FONT};font-size:30px;line-height:36px;font-weight:800;letter-spacing:-0.6px;color:#ffffff">{}</p><p style="margin:0;font-family:{FONT};font-size:14px;line-height:20px;color:{SOFT}">{}</p></td><td class="hide-sm" width="80" align="right" valign="middle">{}</td></tr></table></td></tr>"#,
            escape(&label),
            escape(&big),
            escape(&line),
            radar(
                if security { ALARM } else { LAVENDER },
                if security { ALARM } else { SIGNAL }
            ),
        ),
        None => String::new(),
    };
    let after_row = if after.is_empty() {
        String::new()
    } else {
        format!(
            r#"<tr><td class="alt pad" bgcolor="{SINK}" style="background:{SINK};padding:24px 36px 8px">{after}</td></tr>"#
        )
    };
    // The help block takes the tint the next section would have had.
    let (help_class, help_bg) = if after_row.is_empty() && moment_band.is_empty() {
        ("alt", SINK)
    } else {
        ("card", RAISE)
    };
    let button = match cta {
        Some((label, url)) => {
            let (url, label) = (escape(url), escape(label));
            let width = (label.chars().count() * 9 + 68).min(520);
            format!(
                r#"<table role="presentation" cellpadding="0" cellspacing="0" border="0" class="btn" style="margin:4px 0 24px"><tr><td align="center" bgcolor="{VIOLET}" style="border-radius:10px;background:{VIOLET}"><!--[if mso]><v:roundrect xmlns:v="urn:schemas-microsoft-com:vml" xmlns:w="urn:schemas-microsoft-com:office:word" href="{url}" style="height:50px;v-text-anchor:middle;width:{width}px" arcsize="20%" stroke="f" fillcolor="{VIOLET}"><w:anchorlock/><center style="color:#ffffff;font-family:Arial,sans-serif;font-size:16px;font-weight:700">{label}</center></v:roundrect><![endif]--><!--[if !mso]><!--><a href="{url}" style="display:inline-block;padding:15px 34px;font-family:{FONT};font-size:16px;line-height:20px;font-weight:700;color:#ffffff;text-decoration:none;border-radius:10px;background:{VIOLET}">{label}</a><!--<![endif]--></td></tr></table>"#
            )
        }
        None => String::new(),
    };
    let dark = format!(".bg{{background:{BG}!important}}.card{{background:{RAISE}!important}}.alt{{background:{SINK}!important}}.panel{{background:{PANEL}!important}}.ink{{color:{INK}!important}}.muted{{color:{INK_3}!important}}.rule{{border-color:{RULE}!important}}.alarm{{color:{ALARM}!important}}");
    let ogsc = dark
        .replace("}.", "}[data-ogsc] .")
        .replace(".bg{", "[data-ogsc] .bg{");

    format!(
        r##"<!doctype html><html lang="en" dir="ltr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="x-apple-disable-message-reformatting"><meta name="color-scheme" content="light dark"><meta name="supported-color-schemes" content="light dark"><meta name="format-detection" content="telephone=no,date=no,address=no,email=no"><title>{preview}</title><style>@font-face{{font-family:Manrope;src:url('{site}/fonts/manrope.woff2') format('woff2');font-weight:200 800}}body,table,td,p,a{{-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%}}table,td{{mso-table-lspace:0;mso-table-rspace:0;border-collapse:collapse}}img{{border:0;outline:none;text-decoration:none;display:block}}body{{margin:0;padding:0;width:100%!important}}a[x-apple-data-detectors]{{color:inherit!important;text-decoration:none!important}}@media only screen and (max-width:620px){{.wrap{{padding:10px 6px!important}}.pad{{padding-left:20px!important;padding-right:20px!important}}.hero{{padding-top:24px!important;padding-bottom:22px!important}}.h1{{font-size:26px!important;line-height:32px!important}}.big{{font-size:26px!important;line-height:32px!important}}.btn,.btn td,.btn a{{width:100%!important;display:block!important;text-align:center!important;box-sizing:border-box!important}}.hide-sm{{display:none!important}}}}@media (prefers-color-scheme:dark){{{dark}}}{ogsc}</style></head><body class="bg" style="margin:0;padding:0;background:{BG}"><div style="display:none;max-height:0;max-width:0;overflow:hidden;opacity:0;mso-hide:all;font-size:1px;line-height:1px;color:{BG}">{preview}{pad}</div><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" class="bg" bgcolor="{BG}" style="background:{BG}" lang="en" dir="ltr"><tr><td align="center" class="wrap" style="padding:28px 14px"><!--[if mso]><table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" align="center"><tr><td><![endif]--><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" align="center" style="max-width:600px;margin:0 auto"><tr><td bgcolor="{accent}" style="height:6px;font-size:0;line-height:0;background:{accent};border-radius:16px 16px 0 0">&nbsp;</td></tr><tr><td class="hero pad" bgcolor="{hero_bg}" style="background:{hero_bg};background-image:{hero_image};padding:28px 36px 26px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:separate"><tr><td class="mark" width="44" height="44" align="center" valign="middle" style="width:44px;height:44px;border-radius:22px;background:#ffffff;color:#2d103a;font-family:{FONT};font-size:16px;font-weight:800"><a href="{site}" style="text-decoration:none;color:#2d103a"><img src="{site}/glarion-mark-64.png" width="34" height="34" alt="Glarion" style="display:block;width:34px;height:34px;margin:5px;border:0;border-radius:17px"></a></td><td valign="middle" style="padding-left:12px;font-family:{FONT};font-size:14px;line-height:18px;font-weight:800;letter-spacing:1.6px;text-transform:uppercase"><a href="{site}" style="color:#d9c6ea;text-decoration:none">Glarion</a></td><td align="right" valign="middle" class="hide-sm" style="font-family:{FONT};font-size:12px;line-height:16px;font-weight:700;letter-spacing:1.2px;text-transform:uppercase;color:{accent}">{eyebrow}</td></tr></table><h1 class="h1" style="margin:22px 0 10px;font-family:{FONT};font-size:30px;line-height:36px;font-weight:800;letter-spacing:-0.6px;color:#ffffff">{heading}</h1><p style="margin:0;font-family:{FONT};font-size:16px;line-height:25px;color:{SOFT}">{preview}</p></td></tr>{bands}<tr><td class="card pad" bgcolor="{RAISE}" style="background:{RAISE};padding:28px 36px 8px">{body}{button}</td></tr>{moment_band}{after_row}<tr><td class="{help_class} pad" bgcolor="{help_bg}" style="background:{help_bg};padding:22px 36px 26px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" class="panel" bgcolor="{PANEL}" style="background:{PANEL};border-left:4px solid {accent};border-radius:0 12px 12px 0"><tr><td style="padding:14px 20px"><p class="ink" style="margin:0 0 4px;font-family:{FONT};font-size:14px;line-height:21px;font-weight:700;color:{INK}">{help_title}</p><p class="muted" style="margin:0;font-family:{FONT};font-size:14px;line-height:21px;color:{INK_3}">{help_text} {write} <a href="mailto:hello@glarion.app" class="link" style="color:{LAVENDER}">hello@glarion.app</a>. Never send a password by email.</p></td></tr></table></td></tr><tr><td class="pad" bgcolor="{NIGHT}" style="background:{NIGHT};padding:20px 36px 22px;border-radius:0 0 16px 16px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:separate"><tr><td width="32" height="32" align="center" valign="middle" style="width:32px;height:32px;border-radius:16px;background:#ffffff"><img src="{site}/glarion-mark-64.png" width="24" height="24" alt="" style="display:block;width:24px;height:24px;margin:4px;border:0;border-radius:12px"></td><td valign="middle" style="padding-left:10px;font-family:{FONT};font-size:15px;line-height:20px;font-weight:800;color:{SOFT}">Glarion<br><span style="font-size:12px;line-height:18px;font-weight:400;color:#a893b8">Website security monitoring for agencies</span></td><td class="hide-sm" align="right" valign="middle">{dots}</td></tr></table><p style="margin:14px 0 6px;font-family:{FONT};font-size:12px;line-height:18px;color:#a893b8">{footer}</p><p style="margin:0;font-family:{FONT};font-size:12px;line-height:18px;color:{SOFT}"><a href="{site}" style="color:{SOFT}">glarion.app</a> &middot; <a href="{site}/privacy.html" style="color:{SOFT}">Privacy</a> &middot; <a href="{site}/terms.html" style="color:{SOFT}">Terms</a> &middot; <a href="mailto:hello@glarion.app" style="color:{SOFT}">Support</a></p></td></tr></table><!--[if mso]></td></tr></table><![endif]--></td></tr></table></body></html>"##,
        pad = "&#8199;&#847;".repeat(60)
    )
}

fn para(text: &str) -> String {
    format!(
        r#"<p class="ink" style="margin:0 0 18px;font-family:{FONT};font-size:16px;line-height:25px;color:{INK}">{}</p>"#,
        escape(text)
    )
}

/// Small print tied to this message: expiry, where a setting lives.
fn note(text: &str) -> String {
    format!(
        r#"<p class="muted" style="margin:0 0 20px;font-family:{FONT};font-size:13px;line-height:19px;color:{INK_3}">{}</p>"#,
        escape(text)
    )
}

/// The kit's details card: label and value rows on a raised panel.
fn rows(items: &[(&str, &str)]) -> String {
    rows_card(items, None)
}

/// The details card with the figure that matters printed on violet at its foot.
fn rows_card(items: &[(&str, &str)], total: Option<(&str, &str)>) -> String {
    let body: String = items
        .iter()
        .enumerate()
        .map(|(i, (label, value))| {
            let rule = if i > 0 { format!("border-top:1px solid {RULE};") } else { String::new() };
            format!(
                r#"<tr><td class="muted rule" width="40%" valign="top" style="padding:9px 12px 9px 0;{rule}font-family:{FONT};font-size:13px;line-height:20px;color:{INK_3}">{}</td><td class="ink rule" valign="top" style="padding:9px 0;{rule}font-family:{FONT};font-size:15px;line-height:20px;font-weight:700;color:{INK};word-break:break-word">{}</td></tr>"#,
                escape(label),
                escape(value)
            )
        })
        .collect();
    let foot = match total {
        Some((label, value)) => format!(
            r#"<tr><td bgcolor="{VIOLET}" style="background:{VIOLET};padding:12px 20px;border-radius:0 0 11px 11px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td width="40%" style="font-family:{FONT};font-size:13px;line-height:20px;font-weight:700;color:#ffffff">{}</td><td style="font-family:{FONT};font-size:16px;line-height:20px;font-weight:800;color:#ffffff;word-break:break-word">{}</td></tr></table></td></tr>"#,
            escape(label),
            escape(value)
        ),
        None => String::new(),
    };
    format!(
        r#"<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" class="panel" bgcolor="{PANEL}" style="background:{PANEL};border:1px solid {RULE};border-radius:12px;margin:0 0 24px;border-collapse:separate"><tr><td style="padding:6px 20px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">{body}</table></td></tr>{foot}</table>"#
    )
}

/// One raised card with a marker on the left: a ringed number for steps, a
/// tick or a cross for the two outcomes of a security notice.
fn marked_card(marker: &str, ring: &str, text: &str) -> String {
    format!(
        r#"<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" class="panel" bgcolor="{PANEL}" style="background:{PANEL};border:1px solid {RULE};border-radius:12px;margin:0 0 10px;border-collapse:separate"><tr><td width="50" valign="top" style="padding:14px 0 14px 14px"><table role="presentation" cellpadding="0" cellspacing="0" border="0" style="border-collapse:separate"><tr><td align="center" width="34" height="34" style="width:34px;height:34px;border:2px solid {ring};border-radius:19px;font-family:Arial,sans-serif;font-size:14px;line-height:34px;font-weight:700;color:{ring}">{marker}</td></tr></table></td><td class="ink" valign="top" style="padding:16px 16px 14px 10px;font-family:{FONT};font-size:15px;line-height:22px;color:{INK}">{text}</td></tr></table>"#
    )
}

/// The kit's numbered steps, under a small heading. Each step is something the
/// reader can do, with the label it has in the product.
fn steps(heading: &str, items: &[&str]) -> String {
    let body: String = items
        .iter()
        .enumerate()
        .map(|(i, item)| marked_card(&(i + 1).to_string(), LAVENDER, &escape(item)))
        .collect();
    format!(
        r#"<p class="eyebrow" style="margin:0 0 12px;font-family:{FONT};font-size:12px;line-height:16px;font-weight:700;letter-spacing:1.2px;text-transform:uppercase;color:{LAVENDER}">{}</p>{body}<div style="height:12px;font-size:0;line-height:0">&nbsp;</div>"#,
        escape(heading)
    )
}

/// A titled panel for the one thing worth reading twice.
fn panel(title: &str, text: &str) -> String {
    format!(
        r#"<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" class="panel" bgcolor="{PANEL}" style="background:{PANEL};border:1px solid {RULE};border-radius:12px;margin:0 0 24px;border-collapse:separate"><tr><td style="padding:16px 20px"><p class="ink" style="margin:0 0 6px;font-family:{FONT};font-size:15px;line-height:22px;font-weight:700;color:{INK}">{}</p><p class="ink" style="margin:0;font-family:{FONT};font-size:14px;line-height:21px;color:{INK}">{}</p></td></tr></table>"#,
        escape(title),
        escape(text)
    )
}

/// Security notices get "if this was you / if it was not" instead of steps.
fn security(if_you: &str, if_not: &str) -> String {
    format!(
        r#"{}{}<div style="height:12px;font-size:0;line-height:0">&nbsp;</div>"#,
        marked_card(
            "&#10003;",
            SIGNAL,
            &format!("<strong>If this was you:</strong> {}", escape(if_you))
        ),
        marked_card(
            "&#10007;",
            ALARM,
            &format!("<strong>If it was not:</strong> {}", escape(if_not))
        ),
    )
}

/// The raw link under a button that carries a token, for clients that strip
/// buttons. Text rather than a second link, so the address is only clickable
/// where it is a button.
fn fallback(link: &str) -> String {
    format!(
        r#"<p class="muted" style="margin:-8px 0 24px;font-family:{FONT};font-size:13px;line-height:19px;color:{INK_3}">If the button does not open, copy this address into your browser:<br><span class="ink" style="color:{INK};word-break:break-all">{}</span></p>"#,
        escape(link)
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
    Message {
        subject: "Confirm your email for Glarion".to_string(),
        html: chrome(Chrome {
            preview: "One step left: confirm this address, then add the first site you look after",
            eyebrow: "Confirm your email",
            heading: "Confirm your email address",
            body: &format!(
                "{}{}",
                para(&hello),
                para("Confirm this address to finish setting up your Glarion account. You are signed in as soon as you do."),
            ),
            cta: Some(("Confirm my email", link)),
            after: &(fallback(link) + &note("The link is valid for 24 hours and works once. If you did not create an account, ignore this message: nothing happens without the link.")),
            footer: "You received this email because this address was used to create a Glarion account.",
            help: ("Link expired?", "Sign in with your email and password and Glarion offers to send a new one."),
            moment: None,
            tone: Tone::Brand,
        }),
        text: format!(
            "{hello}\n\nConfirm this address to finish setting up your Glarion account:\n{link}\n\nThe link is valid for 24 hours. If you did not create an account, you can ignore this message."
        ),
    }
}

/// The message sent once an address is confirmed.
///
/// It says what to do first, because a monitoring tool with no targets added
/// looks broken rather than empty. Step three names the plan: it used to promise
/// a scan the account it was welcoming could not run.
pub fn welcome_email(first_name: &str, link: &str) -> Message {
    let hello = greeting(first_name);
    Message {
        subject: "Your Glarion account is ready".to_string(),
        html: chrome(Chrome {
            preview: "Add your first site and Glarion starts watching it",
            eyebrow: "Account ready",
            heading: "Your account is ready",
            body: &format!(
                "{}{}",
                para(&hello),
                para("One account covers every site you look after. Add the first one and the free check, everything the site publishes to any visitor, runs in a couple of minutes."),
            ),
            cta: Some(("Add your first site", link)),
            after: &format!(
                "{}{}",
                steps(
                    "Three steps to the first report",
                    &[
                        "Add a site you look after",
                        "Prove you are allowed to scan it: one DNS record or one file",
                        "Run the full scan, on a plan",
                    ]
                ),
                panel(
                    "Why ownership comes first",
                    "We only scan domains whose ownership has been proven, which is why step 2 exists. It is also what makes the report something you can hand to a client. The full scan, the one that goes looking rather than reading, is what a plan pays for."
                ),
            ),
            footer: "You received this email because you just confirmed a Glarion account. It is sent once.",
            help: ("Not sure how to prove ownership?", "Reply with the domain and where its DNS is managed, and we will tell you which record to add."),
            moment: Some((
                "Free check".to_string(),
                "A couple of minutes".to_string(),
                "Headers, certificate, DNS and email security of the first site you add, with nothing to install.".to_string(),
            )),
            tone: Tone::Brand,
        }),
        text: format!(
            "{hello}\n\nYour Glarion account is ready. One account covers every site you look after.\n\n1. Add a site you look after\n2. Prove you are allowed to scan it: one DNS record or one file\n3. Run the full scan, on a plan\n\nThe free check reads what a site publishes to any visitor and costs nothing. The full scan goes looking instead, and that is what a plan pays for. We only scan domains whose ownership has been proven, which is what makes the report something you can hand to a client.\n\nStart here: {link}"
        ),
    }
}

/// Sent when a scheduled site's ownership proof is about to lapse and the
/// record or file that proves it can no longer be found.
///
/// Scheduled scans need current proof. Without this message a site simply
/// stopped being checked a month after it was verified, and the customer
/// learned about it from the absence of a report.
pub fn ownership_lapsing_email(
    first_name: &str,
    domain: &str,
    expires_at: chrono::DateTime<chrono::Utc>,
    link: &str,
) -> Message {
    let hello = greeting(first_name);
    let when = expires_at.format("%-d %B %Y, %H:%M UTC").to_string();
    Message {
        subject: format!("Scheduled scans of {domain} stop on {}", expires_at.format("%-d %B")),
        html: chrome(Chrome {
            preview: "The ownership record or file is missing, so the next scheduled scan cannot run",
            eyebrow: "Action needed",
            heading: "Ownership proof is about to lapse",
            body: &format!(
                "{}{}{}",
                para(&hello),
                para(&format!("We checked {domain} again and could not find the DNS record or file that proves you may scan it. After the date below, its scheduled scans stop.")),
                rows(&[("Site", domain), ("Proof lapses", &when)]),
            ),
            cta: Some(("Open your sites", link)),
            after: &note("If the record or file was removed by mistake, put it back and nothing else is needed: we check again every hour. If the site has moved, verify it again from Glarion."),
            footer: "You received this email because this site is on a scan schedule in your Glarion account.",
            help: ("Record still in place?", "Reply with the domain and we will check what Glarion sees."),
            moment: None,
            tone: Tone::Warning,
        }),
        text: format!(
            "{hello}\n\nWe checked {domain} again and could not find the DNS record or file that proves you may scan it. Proof lapses on {when}; after that, its scheduled scans stop.\n\nIf it was removed by mistake, put it back: we check again every hour. If the site has moved, verify it again from Glarion.\n\n{link}"
        ),
    }
}

/// The message sent when an account first becomes a paying one.
///
/// A receipt is an accounting document: it does not say what the plan allows
/// or where to go next, which is the only thing the person wants to know at
/// that moment. The two limits that change with the plan are stated, because
/// those are what someone compares against what they thought they bought.
///
/// `trial_ends` is set while the subscription is still in its free trial:
/// nothing has been charged yet, so "your plan is active" and "Stripe sends
/// the receipt" would both be untrue. The trial version names the day the
/// first payment is taken instead.
pub fn subscription_email(
    first_name: &str,
    plan_name: &str,
    max_targets: i32,
    scheduling: bool,
    link: &str,
    trial_ends: Option<chrono::DateTime<chrono::Utc>>,
) -> Message {
    let hello = greeting(first_name);
    let cadence = if scheduling {
        "Your sites are re-checked on a schedule, without you asking."
    } else {
        "Scans stay manual on this plan."
    };
    let sites = format!("Up to {max_targets}");
    let schedule = if scheduling {
        "Weekly or monthly, your choice"
    } else {
        "Manual"
    };
    if let Some(ends) = trial_ends {
        let when = ends.format("%-d %B %Y").to_string();
        let heading = format!("Your {plan_name} trial has started");
        let preview = format!("Everything on the {plan_name} plan is yours until {when}");
        let charge = format!("Everything on the {plan_name} plan is available until {when}. The first payment is taken that day unless you cancel before then, which you can do yourself from your account.");
        return Message {
            subject: "Your Glarion trial has started".to_string(),
            html: chrome(Chrome {
                preview: &preview,
                eyebrow: "Trial started",
                heading: &heading,
                body: &format!(
                    "{}{}{}",
                    para(&hello),
                    para(&charge),
                    rows_card(&[("Plan", plan_name), ("Sites monitored", &sites), ("Scheduled checks", schedule)], Some(("First payment", &when))),
                ),
                cta: Some(("Open Glarion", link)),
                after: &note(&format!("{cadence} Nothing has been charged yet. To cancel before the first payment, open Pricing in Glarion and choose Manage billing.")),
                footer: "You received this email because you started a Glarion trial with this address.",
                help: ("Billing question?", "Reply to this email from the address on the account."),
                moment: Some((format!("{plan_name} trial"), format!("Up to {max_targets} sites"), format!("Everything on the plan until {when}. {cadence}"))),
                tone: Tone::Brand,
            }),
            text: format!(
                "{hello}\n\nYour Glarion {plan_name} trial has started. Everything on the plan is available until {when}. The first payment is taken that day unless you cancel before then, which you can do yourself from your account.\n\nUp to {max_targets} sites monitored. {cadence}\n\nOpen Glarion: {link}\n\nNothing has been charged yet. To cancel before the first payment, open Pricing in Glarion and choose Manage billing."
            ),
        };
    }
    let heading = format!("Your {plan_name} plan is active");
    let preview = "Nothing else needs setting up. Here is what the plan covers.".to_string();
    Message {
        subject: "Your Glarion plan is active".to_string(),
        html: chrome(Chrome {
            preview: &preview,
            eyebrow: "Plan active",
            heading: &heading,
            body: &format!(
                "{}{}{}",
                para(&hello),
                para(&format!("Your {plan_name} plan is active. {cadence} Nothing else needs setting up.")),
                rows_card(&[("Plan", plan_name), ("Scheduled checks", schedule)], Some(("Sites monitored", &sites))),
            ),
            cta: Some(("Open Glarion", link)),
            after: &note("You can change or cancel the plan yourself at any time: open Pricing in Glarion and choose Manage billing."),
            footer: "You received this email because a Glarion subscription on this address changed.",
            help: ("Billing question?", "Reply to this email from the address on the account."),
            moment: Some((format!("{plan_name} plan"), format!("Up to {max_targets} sites"), cadence.to_string())),
            tone: Tone::Brand,
        }),
        text: format!(
            "{hello}\n\nYour Glarion {plan_name} plan is active. Nothing else needs setting up.\n\nUp to {max_targets} sites monitored. {cadence}\n\nOpen Glarion: {link}\n\nYou can change or cancel the plan yourself at any time: open Pricing in Glarion and choose Manage billing."
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
    Message {
        subject: "Confirm your new Glarion address".to_string(),
        html: chrome(Chrome {
            preview: "Confirm this address to finish moving your Glarion account to it",
            eyebrow: "Confirm the change",
            heading: "Confirm your new address",
            body: &format!(
                "{}{}",
                para(&hello),
                para("Someone asked to move a Glarion account to this address. Confirming finishes the move; everywhere the account is currently signed in will be signed out."),
            ),
            cta: Some(("Confirm this address", link)),
            after: &(fallback(link) + &note(&format!("The link works once and expires in {valid_minutes} minutes. Until it is followed, the account keeps its current address."))),
            footer: "If you were not expecting this, ignore it: nothing changes until the link is followed, and whoever asked cannot read this message.",
            help: ("Not expecting this?", "Ignore it. Nothing moves without the link."),
            moment: None,
            tone: Tone::Brand,
        }),
        text: format!(
            "{hello}\n\nSomeone asked to move a Glarion account to this address. Confirming finishes the move; everywhere the account is currently signed in will be signed out.\n\n{link}\n\nThe link works once and expires in {valid_minutes} minutes. Until it is followed, the account keeps its current address.\n\nIf you were not expecting this, ignore it: nothing changes until the link is followed."
        ),
    }
}

/// The warning sent to the address being left behind.
///
/// A stolen session plus a change of address is a complete account takeover,
/// so the address currently on the account is told the moment a move is
/// requested, while it can still be stopped. It carries no action link: a
/// button in this message is the single most valuable thing to forge.
pub fn email_change_alert(first_name: &str, new_email: &str) -> Message {
    let hello = greeting(first_name);
    Message {
        subject: "Someone asked to change your Glarion address".to_string(),
        html: chrome(Chrome {
            preview: "A request was made to move your Glarion account to another address",
            eyebrow: "Security notice",
            heading: "A change of address was requested",
            body: &format!(
                "{}{}{}{}",
                para(&hello),
                para("Your Glarion account is being moved to another address. It has not moved yet: the new address has to confirm first, and until it does, this one is still the account's."),
                rows(&[("Requested new address", new_email)]),
                security(
                    "nothing else is needed.",
                    "change your password now, because someone is signed in who should not be, and reply to this message."
                ),
            ),
            cta: None,
            after: "",
            footer: "This security notice is sent to the address currently on the account whenever a change is requested, and cannot be turned off.",
            help: ("Did not ask for this?", "Reply to this message straight away and we will help you secure the account."),
            moment: None,
            tone: Tone::Security,
        }),
        text: format!(
            "{hello}\n\nYour Glarion account is being moved to {new_email}. It has not moved yet: the new address has to confirm first, and until it does, this one is still the account's.\n\nIf this was you, nothing else is needed. If it was not, change your password now, because someone is signed in who should not be, and reply to this message."
        ),
    }
}

/// The message sent when a paid plan stops.
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
        "Your payment did not go through"
    } else {
        "Your plan has ended"
    };
    let explain = if payment_problem {
        format!("We could not take payment for your Glarion {plan_name} plan, so scheduled scanning is paused and your account is back on the free plan. Updating the card puts it back exactly as it was: open Pricing in Glarion and choose Manage billing.")
    } else {
        format!("Your Glarion {plan_name} plan has ended, so scheduled scanning is off and your account is back on the free plan. Subscribing again turns it back on.")
    };
    let action = if payment_problem {
        "Open Pricing in Glarion"
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
            body: &format!("{}{}", para(&hello), para(&explain)),
            cta: Some((action, link)),
            after: &panel("What you keep", kept),
            footer: "You received this email because a Glarion plan on this address changed state. Stripe holds the payment record.",
            help: ("Card updated but still paused?", "Reply to this email from the address on the account."),
            moment: None,
            tone: if payment_problem { Tone::Warning } else { Tone::Brand },
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
/// changed, on which site, and a way to see the detail.
pub fn change_email(domain: &str, summary: &str, detail: &str, link: &str) -> Message {
    let preview = format!("{summary} on {domain}");
    let domain_line = format!(
        r#"<p class="muted" style="margin:-6px 0 18px;font-family:{MONO};font-size:14px;line-height:20px;color:{INK_3}">{}</p>"#,
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
            after: "",
            footer: "You are getting this because this site is on a scanning schedule. Turn it off on the site's page.",
            help: ("Expected change?", "Open the site's page to see the latest scan, or reply if the result looks wrong."),
            moment: None,
            tone: Tone::Alarm,
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
/// naming what it did *not* look at rather than by hedging what it did.
pub fn preview_report_email(domain: &str, lines: &[ReportLine], site_url: &str) -> Message {
    let pricing_link = format!("{site_url}/pricing.html");
    let sample_link = format!("{site_url}/sample-report.html");
    let findings = lines.iter().filter(|line| line.is_finding).count();
    let headline = match findings {
        0 => "Nothing obvious from the outside".to_string(),
        1 => "1 thing worth fixing".to_string(),
        n => format!("{n} things worth fixing"),
    };

    let last = lines.len().saturating_sub(1);
    let mut rows_html = String::new();
    let mut plain_rows = String::new();
    for (i, line) in lines.iter().enumerate() {
        let (colour, class) = if line.is_finding {
            (ALARM, "alarm")
        } else {
            (INK, "ink")
        };
        let rule = if i < last {
            format!("border-bottom:1px solid {RULE};")
        } else {
            String::new()
        };
        rows_html.push_str(&format!(
            r#"<tr><td class="muted rule" width="38%" valign="top" style="padding:10px 12px 10px 0;{rule}font-family:{FONT};font-size:13px;line-height:20px;color:{INK_3}">{}</td><td class="{class} rule" valign="top" style="padding:10px 0;{rule}font-family:{FONT};font-size:15px;line-height:20px;font-weight:700;color:{colour};word-break:break-word">{}</td></tr>"#,
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
        "This read only what {domain} publishes to any visitor: its headers, its certificate, its DNS, and the files it offers to automated readers. It did not examine the application itself: outdated components with known vulnerabilities, exposed administrative paths, or misconfigured storage. That is the full scan: it needs the domain's owner to confirm the request, and it needs a plan, from €19 a month."
    );
    let preview =
        format!("What any visitor can see on {domain}, and what this check did not look at");
    let body = format!(
        r#"<p class="muted" style="margin:-6px 0 18px;font-family:{MONO};font-size:14px;line-height:20px;color:{INK_3}">{}</p>{}<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" class="panel" bgcolor="{PANEL}" style="background:{PANEL};border:1px solid {RULE};border-radius:12px;margin:0 0 24px;border-collapse:separate"><tr><td style="padding:6px 20px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">{rows_html}</table></td></tr></table>"#,
        escape(domain),
        para("This is your requested partial public check. It is useful on its own, but it is not a full security scan."),
    );
    let after = format!(
        r#"{}<p class="muted" style="margin:0 0 20px;font-family:{FONT};font-size:13px;line-height:19px;color:{INK_3}">Want to see the format before choosing a plan? <a class="link" href="{sample_link}" style="color:{LAVENDER};font-weight:700">View a sample full report</a>. The sample uses fictional findings.</p>"#,
        panel("What this did not look at", &scope),
    );

    Message {
        subject: format!("Your partial website check: {domain}"),
        html: chrome(Chrome {
            preview: &preview,
            eyebrow: "Your partial public check",
            heading: &headline,
            body: &body,
            // The button opens pricing, where the paid full scan is explained.
            cta: Some(("Compare paid plans for the full scan", &pricing_link)),
            after: &after,
            footer: "You received this because this report was requested from your address. We do not add you to anything by sending it.",
            help: ("Questions about a result?", "Reply with the line that puzzles you and we will explain what it means for the site."),
            moment: None,
            tone: Tone::Brand,
        }),
        text: format!(
            "{headline}\n{domain}\n\nThis is your requested partial public check. It is useful on its own, but it is not a full security scan.\n\n{plain_rows}\nWhat this did not look at\n{scope}\n\nCompare paid plans for the full scan: {pricing_link}\nView a sample full report (fictional findings): {sample_link}\n\nYou received this because this report was requested from your address. We do not add you to anything by sending it."
        ),
    }
}

/// The password-recovery link.
///
/// Short and free of anything else on purpose. This message is the single
/// most valuable one to forge, so it says only what it is, names how long it
/// lasts, and offers nothing else to click.
pub fn password_reset_email(first_name: &str, link: &str, valid_minutes: i64) -> Message {
    let hello = greeting(first_name);
    Message {
        subject: "Reset your Glarion password".to_string(),
        html: chrome(Chrome {
            preview: "Choose a new password for your Glarion account",
            eyebrow: "Account recovery",
            heading: "Reset your password",
            body: &format!(
                "{}{}",
                para(&hello),
                para("Use the button to choose a new password. Signing in everywhere else stops working as soon as you do."),
            ),
            cta: Some(("Choose a new password", link)),
            after: &(fallback(link) + &note(&format!("The link works once and expires in {valid_minutes} minutes. If you did not ask for this, ignore it: your password stays unchanged, and nobody was told whether this address has an account."))),
            footer: "We will never ask you for your password by email, and we will never ask you to send it back to us.",
            help: ("Link expired?", "Ask for a new one with Forgot your password? on the sign-in page."),
            moment: None,
            tone: Tone::Security,
        }),
        text: format!(
            "{hello}\n\nUse the link below to choose a new password for your Glarion account. Signing in everywhere else stops working as soon as you do.\n\n{link}\n\nThe link works once and expires in {valid_minutes} minutes. If you did not ask for this, ignore it: your password stays unchanged.\n\nWe will never ask you for your password by email."
        ),
    }
}

/// The notice sent once a password has actually changed.
///
/// Carries no link and no token, deliberately: whoever reads this is not
/// necessarily the person who changed it, and a "this wasn't me" button here
/// would be the exact shape an attacker would forge. Getting in touch is a
/// thing that cannot be phished out of an inbox.
pub fn password_changed_email(first_name: &str) -> Message {
    let hello = greeting(first_name);
    Message {
        subject: "Your Glarion password was changed".to_string(),
        html: chrome(Chrome {
            preview: "The password on your Glarion account was changed",
            eyebrow: "Security notice",
            heading: "Your password was changed",
            body: &format!(
                "{}{}{}{}",
                para(&hello),
                para("The password on your Glarion account was changed, and every device that was signed in has been signed out."),
                security(
                    "nothing else is needed. Sign in again with the new password.",
                    "reply to this message straight away. Someone else set that password."
                ),
                note("We will never ask you for your password by email."),
            ),
            cta: None,
            after: "",
            footer: "This security notice is sent every time the password changes and cannot be turned off.",
            help: ("Did not change it?", "Reply to this message straight away from this address."),
            moment: None,
            tone: Tone::Security,
        }),
        text: format!(
            "{hello}\n\nThe password on your Glarion account was changed, and every device that was signed in has been signed out.\n\nIf this was you, nothing else is needed. If it was not, reply to this message straight away: someone else set that password.\n\nWe will never ask you for your password by email."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mailer() -> Mailer {
        Mailer {
            api_key: None,
            from: Some("Glarion <hello@example.com>".to_string()),
            public_url: "https://glarion.example".to_string(),
            reply_to: None,
            last_send_ok: AtomicBool::new(true),
        }
    }

    /// A key without a sender used to fall back to onboarding@resend.dev,
    /// which Resend only delivers to the account owner: every customer mail
    /// was refused while the process reported itself configured.
    #[tokio::test]
    async fn a_key_without_a_sender_is_refused_before_any_request() {
        let sender = Mailer {
            api_key: Some("re_test".into()),
            from: None,
            public_url: "https://glarion.example".into(),
            reply_to: None,
            last_send_ok: AtomicBool::new(true),
        };
        assert!(!sender.is_configured());
        let error = sender
            .send(
                "audit@example.invalid",
                &welcome_email("Ada", "https://glarion.example/app#/targets"),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("MAIL_FROM"));
        assert!(!sender.last_send_ok());
    }

    /// The bug this pins cost a real account: the root serves the marketing
    /// page, which has no router, so a confirmation link pointing there
    /// opened a page where nothing happened and left an account that could
    /// never be confirmed. Nothing failed, nothing logged, and the mail
    /// showed as delivered — so it read as a spam problem for a day.
    #[tokio::test]
    async fn missing_configuration_is_a_failure_without_message_content() {
        let sender = mailer();
        assert!(
            !sender.last_send_ok(),
            "missing configuration is unhealthy before the first attempt"
        );
        let message = password_reset_email("Test", "https://example.invalid/SECRET", 60);
        let error = sender
            .send("audit@example.invalid", &message)
            .await
            .unwrap_err();
        assert!(!sender.last_send_ok());
        assert_eq!(error.to_string(), "email provider is not configured");
    }

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

        // The button twice (VML for Outlook's Word engine, the anchor for
        // everyone else) and the copyable text once.
        assert_eq!(body.matches(link).count(), 3);
        assert_eq!(body.matches(&format!("href=\"{link}\"")).count(), 2);
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
            from: Some("x@example.com".into()),
            public_url: "https://glarion.app".into(),
            reply_to: None,
            last_send_ok: AtomicBool::new(true),
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
        let message = preview_report_email("example.com", &[], "https://glarion.app");
        let body = message.html;

        // Stating the scope, rather than hedging every line.
        assert!(flat(&body).contains("did not examine the application itself"));
        assert!(flat(&body).to_lowercase().contains("confirm the request"));
        assert!(body.contains("https://glarion.app/pricing.html"));
        assert!(body.contains("https://glarion.app/sample-report.html"));
        assert!(message.text.contains("https://glarion.app/pricing.html"));
        assert!(message
            .text
            .contains("https://glarion.app/sample-report.html"));
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
            from: Some("x@example.com".into()),
            public_url: "https://glarion.app/".trim_end_matches('/').to_string(),
            reply_to: None,
            last_send_ok: AtomicBool::new(true),
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

        assert!(html.contains("/glarion-mark-64.png"));
        assert!(html.contains("width=\"34\""));
        assert!(
            html.contains("border-radius:22px;background:#ffffff;color:#2d103a;"),
            "the mark must sit on its own coloured cell, or a blocked image shows nothing"
        );
        assert!(
            html.contains("alt=\"Glarion\""),
            "a blocked image still names the product"
        );
    }

    #[test]
    fn the_subscription_email_states_the_limits_that_changed() {
        // The two numbers someone checks against what they thought they were
        // buying. A welcome that does not mention them is a welcome that
        // gets a support ticket in reply.
        let message =
            subscription_email("Marco", "Agency", 40, true, "https://glarion.app/app", None);
        assert!(message.html.contains("Agency"));
        assert!(message.html.contains("re-checked on a schedule"));
        assert!(message.html.contains("Hello Marco,"));
        // Asserted on the text part: the HTML bolds the number, so "40 sites"
        // is split by a tag there and matching it would be matching markup.
        assert!(message.text.contains("40 sites monitored"));
        assert!(message.text.contains("Hello Marco,"));
    }

    #[test]
    fn a_trial_does_not_claim_a_payment_was_taken() {
        use chrono::TimeZone;
        let ends = chrono::Utc.with_ymd_and_hms(2026, 10, 20, 9, 0, 0).unwrap();
        let message = subscription_email(
            "Ada",
            "Solo",
            5,
            true,
            "https://glarion.app/app",
            Some(ends),
        );
        assert!(message.subject.contains("trial"));
        assert!(message.text.contains("20 October 2026"));
        assert!(message.html.contains("20 October 2026"));
        assert!(!message.text.contains("plan is active"));
        assert!(!message
            .text
            .contains("Stripe sends the payment receipt separately"));
    }

    #[test]
    fn a_plan_without_scheduling_does_not_claim_it() {
        let html =
            subscription_email("", "Studio", 10, false, "https://glarion.app/app", None).html;
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
            None,
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
            subscription_email("Ada", "Agency", 40, true, "https://glarion.app/app", None),
            subscription_email(
                "Ada",
                "Solo",
                5,
                true,
                "https://glarion.app/app",
                Some(chrono::Utc::now()),
            ),
            change_email(
                "example.com",
                "1 new finding",
                "detail",
                "https://glarion.app/app",
            ),
            preview_report_email("example.com", &lines, "https://glarion.app"),
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
                .contains(&format!("src=\"{host}/glarion-mark-64.png\"")),
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
            from: Some("Glarion <noreply@example.com>".to_string()),
            public_url: "https://glarion.example".to_string(),
            reply_to: Some("security@example.com".to_string()),
            last_send_ok: AtomicBool::new(true),
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
