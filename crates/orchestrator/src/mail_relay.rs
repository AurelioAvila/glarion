//! The way out for transactional mail: Resend first, then SMTP2GO, then
//! Mailjet, all over HTTPS, all on their free plans.
//!
//! The Rust twin of `email-relay.ts`, which the other products carry; the
//! decisions are the same:
//!
//! - A provider without its key is skipped, so with only `RESEND_API_KEY` set
//!   this is the old single Resend call.
//! - The next provider gets a message only when the previous one did not take
//!   it: quota (429), refusal (any other 4xx, an unverified domain included),
//!   5xx, timeout or network error. A 2xx is taken, even with an unreadable
//!   body, unless the body says refused. A 409 from Resend means the same key
//!   is in flight there, so nothing else is tried.
//! - One idempotency key per message, sent to Resend, which dedupes on it; an
//!   ambiguous Resend answer (timeout, network error, 5xx) is asked once more
//!   with the same key before moving on, so a first request that did arrive
//!   is answered with the first message rather than sent twice.
//! - `EMAIL_SINK=1` sends nothing and writes the HTML to `EMAIL_SINK_DIR`.
//! - Logs carry provider, outcome, status, the provider's error code and the
//!   key, never addresses, subjects or bodies.

use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;

/// Where each provider is reached. Overridable only so tests can point at a
/// local stub instead of the network.
#[derive(Clone, Debug)]
pub struct Endpoints {
    pub resend: String,
    pub smtp2go: String,
    pub mailjet: String,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            resend: "https://api.resend.com/emails".into(),
            smtp2go: "https://api.smtp2go.com/v3/email/send".into(),
            mailjet: "https://api.mailjet.com/v3.1/send".into(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Relay {
    pub resend: Option<String>,
    pub smtp2go: Option<String>,
    /// API key and secret.
    pub mailjet: Option<(String, String)>,
    /// `EMAIL_PROVIDERS`, lowercased; empty means resend, smtp2go, mailjet.
    pub order: Vec<String>,
    /// `<PROVIDER>_DOMAINS`: when set, that provider sends only for these sender domains.
    pub domains: Vec<(String, Vec<String>)>,
    /// `EMAIL_SINK`: the folder previews go to instead of any provider.
    pub sink: Option<PathBuf>,
    pub endpoints: Endpoints,
}

/// One message on its way out.
pub struct Outgoing<'a> {
    pub from: &'a str,
    pub to: &'a str,
    pub subject: &'a str,
    pub html: &'a str,
    pub text: &'a str,
    pub reply_to: Option<&'a str>,
    pub key: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Sent,
    Rejected,
    Ambiguous,
    Conflict,
}

struct Request {
    url: String,
    headers: Vec<(&'static str, String)>,
    basic: Option<(String, String)>,
    body: Value,
}

const DEFAULT_ORDER: [&str; 3] = ["resend", "smtp2go", "mailjet"];
const BODY_LIMIT: usize = 16_384;
const TIMEOUT: Duration = Duration::from_secs(10);

fn non_empty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// The bare address in "Name <a@b.c>" or "a@b.c".
fn bare(address: &str) -> &str {
    match (address.rfind('<'), address.rfind('>')) {
        (Some(start), Some(end)) if start < end => &address[start + 1..end],
        _ => address.trim(),
    }
}

fn display_name(address: &str) -> Option<&str> {
    let name = address.split('<').next()?.trim().trim_matches('"').trim();
    (address.contains('<') && !name.is_empty()).then_some(name)
}

/// Only short identifier-like codes are logged: a provider message can echo the recipient.
fn safe_code(value: Option<&Value>) -> Option<String> {
    let code = value?.as_str()?;
    (!code.is_empty()
        && code.len() <= 80
        && code
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.:-".contains(c)))
    .then(|| code.to_string())
}

impl Relay {
    pub fn from_env() -> Self {
        let mailjet = match (
            non_empty("MAILJET_API_KEY"),
            non_empty("MAILJET_API_SECRET"),
        ) {
            (Some(key), Some(secret)) => Some((key, secret)),
            _ => None,
        };
        let order = non_empty("EMAIL_PROVIDERS")
            .map(|value| {
                value
                    .split(',')
                    .map(|name| name.trim().to_lowercase())
                    .filter(|name| !name.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        let domains = DEFAULT_ORDER
            .iter()
            .filter_map(|name| {
                let list = non_empty(&format!("{}_DOMAINS", name.to_uppercase()))?;
                Some((
                    name.to_string(),
                    list.split(',').map(|d| d.trim().to_lowercase()).collect(),
                ))
            })
            .collect();
        let sink = non_empty("EMAIL_SINK")
            .filter(|value| {
                ["1", "true", "yes", "dry-run"].contains(&value.to_lowercase().as_str())
            })
            .map(|_| {
                non_empty("EMAIL_SINK_DIR")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| std::env::temp_dir().join("email-sink"))
            });
        Self {
            resend: non_empty("RESEND_API_KEY"),
            smtp2go: non_empty("SMTP2GO_API_KEY"),
            mailjet,
            order,
            domains,
            sink,
            endpoints: Endpoints::default(),
        }
    }

    fn order(&self) -> Vec<String> {
        if self.order.is_empty() {
            DEFAULT_ORDER.iter().map(|name| name.to_string()).collect()
        } else {
            self.order.clone()
        }
    }

    /// Providers in chain order that have their keys.
    pub fn ready(&self) -> Vec<String> {
        self.order()
            .into_iter()
            .filter(|name| match name.as_str() {
                "resend" => self.resend.is_some(),
                "smtp2go" => self.smtp2go.is_some(),
                "mailjet" => self.mailjet.is_some(),
                _ => false,
            })
            .collect()
    }

    /// Whether anything would leave the process: a provider key, or the sink.
    pub fn is_configured(&self) -> bool {
        self.sink.is_some() || !self.ready().is_empty()
    }

    fn domain_enabled(&self, name: &str, from: &str) -> bool {
        let domain = bare(from).rsplit('@').next().unwrap_or("").to_lowercase();
        self.domains
            .iter()
            .find(|(provider, _)| provider == name)
            .is_none_or(|(_, list)| list.contains(&domain))
    }

    fn request(&self, name: &str, mail: &Outgoing<'_>) -> Option<Request> {
        if !self.domain_enabled(name, mail.from) {
            return None;
        }
        match name {
            "resend" => {
                let key = self.resend.as_ref()?;
                let mut body = json!({ "from": mail.from, "to": [mail.to], "subject": mail.subject, "html": mail.html, "text": mail.text });
                if let Some(reply) = mail.reply_to {
                    body["reply_to"] = json!(reply);
                }
                Some(Request {
                    url: self.endpoints.resend.clone(),
                    headers: vec![
                        ("Authorization", format!("Bearer {key}")),
                        ("Idempotency-Key", mail.key.to_string()),
                    ],
                    basic: None,
                    body,
                })
            }
            "smtp2go" => {
                let key = self.smtp2go.as_ref()?;
                let mut body = json!({ "sender": mail.from, "to": [mail.to], "subject": mail.subject, "html_body": mail.html, "text_body": mail.text });
                if let Some(reply) = mail.reply_to {
                    body["custom_headers"] = json!([{ "header": "Reply-To", "value": reply }]);
                }
                Some(Request {
                    url: self.endpoints.smtp2go.clone(),
                    headers: vec![("X-Smtp2go-Api-Key", key.clone())],
                    basic: None,
                    body,
                })
            }
            "mailjet" => {
                let (key, secret) = self.mailjet.as_ref()?;
                let mut from = json!({ "Email": bare(mail.from) });
                if let Some(name) = display_name(mail.from) {
                    from["Name"] = json!(name);
                }
                let mut message = json!({ "From": from, "To": [{ "Email": bare(mail.to) }], "Subject": mail.subject, "HTMLPart": mail.html, "TextPart": mail.text, "CustomID": mail.key.chars().take(250).collect::<String>() });
                if let Some(reply) = mail.reply_to {
                    message["ReplyTo"] = json!({ "Email": bare(reply) });
                }
                Some(Request {
                    url: self.endpoints.mailjet.clone(),
                    headers: vec![],
                    basic: Some((key.clone(), secret.clone())),
                    body: json!({ "Messages": [message] }),
                })
            }
            _ => None,
        }
    }

    async fn attempt(
        client: &reqwest::Client,
        name: &str,
        request: &Request,
    ) -> (Outcome, Option<u16>, Option<String>) {
        let mut builder = client
            .post(&request.url)
            .timeout(TIMEOUT)
            .json(&request.body);
        for (header, value) in &request.headers {
            builder = builder.header(*header, value);
        }
        if let Some((user, pass)) = &request.basic {
            builder = builder.basic_auth(user, Some(pass));
        }
        let response = match builder.send().await {
            Ok(response) => response,
            Err(error) => {
                let code = if error.is_timeout() {
                    "timeout"
                } else {
                    "network_error"
                };
                return (Outcome::Ambiguous, None, Some(code.to_string()));
            }
        };
        let status = response.status().as_u16();
        let body: Option<Value> = response
            .bytes()
            .await
            .ok()
            .filter(|bytes| bytes.len() <= BODY_LIMIT)
            .and_then(|bytes| serde_json::from_slice(&bytes).ok());
        let code = match name {
            "resend" => safe_code(body.as_ref().and_then(|b| b.get("name"))),
            "smtp2go" => safe_code(body.as_ref().and_then(|b| b.pointer("/data/error_code"))),
            _ => safe_code(
                body.as_ref()
                    .and_then(|b| b.pointer("/Messages/0/Errors/0/ErrorCode")),
            ),
        };
        let refused = match (name, &body) {
            ("smtp2go", Some(b)) => b.pointer("/data/succeeded").and_then(Value::as_u64) == Some(0),
            ("mailjet", Some(b)) => {
                b.pointer("/Messages/0/Status").and_then(Value::as_str) == Some("error")
            }
            _ => false,
        };
        let outcome = match status {
            200..=299 if refused => Outcome::Rejected,
            200..=299 => Outcome::Sent,
            409 => Outcome::Conflict,
            500.. => Outcome::Ambiguous,
            _ => Outcome::Rejected,
        };
        (outcome, Some(status), code)
    }

    /// Sends through the first provider that takes the message; returns its name.
    pub async fn send(&self, mail: &Outgoing<'_>) -> anyhow::Result<String> {
        if let Some(dir) = &self.sink {
            std::fs::create_dir_all(dir)?;
            let stem = format!(
                "{}-{}",
                chrono::Utc::now().format("%Y%m%dT%H%M%S%.3f"),
                mail.key
            );
            std::fs::write(dir.join(format!("{stem}.html")), mail.html)?;
            std::fs::write(dir.join(format!("{stem}.txt")), mail.text)?;
            tracing::info!(
                key = mail.key,
                "mail_sink: EMAIL_SINK is on, nothing was sent"
            );
            return Ok("sink".into());
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let mut tried = Vec::new();
        for name in self.order() {
            let Some(request) = self.request(&name, mail) else {
                continue;
            };
            let mut result = Self::attempt(&client, &name, &request).await;
            // Same key, same provider: a first request that did arrive is answered with the first message.
            if result.0 == Outcome::Ambiguous && name == "resend" {
                result = Self::attempt(&client, &name, &request).await;
            }
            let (outcome, status, code) = result;
            tracing::info!(key = mail.key, provider = %name, outcome = ?outcome, status = ?status, code = ?code, "mail_attempt");
            match outcome {
                Outcome::Sent => return Ok(name),
                Outcome::Conflict => {
                    anyhow::bail!("email provider {name} already has this message in flight")
                }
                _ => tried.push(format!(
                    "{name} {outcome:?} {}",
                    status.map_or_else(|| code.clone().unwrap_or_default(), |s| s.to_string())
                )),
            }
        }
        if tried.is_empty() {
            anyhow::bail!("email provider is not configured");
        }
        tracing::error!(key = mail.key, attempts = ?tried, "mail_undelivered");
        anyhow::bail!("email provider refused ({})", tried.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A local HTTP stub: answers each request with the next scripted (path prefix, status, body)
    /// and records what was asked. Nothing leaves the machine.
    async fn stub(
        script: Vec<(&'static str, u16, &'static str)>,
    ) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            let mut script = script.into_iter();
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = vec![0u8; 65536];
                let mut read = 0;
                loop {
                    let n = socket.read(&mut buf[read..]).await.unwrap_or(0);
                    read += n;
                    let text = String::from_utf8_lossy(&buf[..read]).to_string();
                    if let Some(split) = text.find("\r\n\r\n") {
                        let length = text
                            .lines()
                            .find_map(|l| {
                                l.to_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        if read >= split + 4 + length || n == 0 {
                            break;
                        }
                    }
                    if n == 0 {
                        break;
                    }
                }
                let request = String::from_utf8_lossy(&buf[..read]).to_string();
                log.lock().unwrap().push(request);
                let (_, status, body) = script.next().unwrap_or(("", 500, "{}"));
                let reply = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(reply.as_bytes()).await;
            }
        });
        (base, seen)
    }

    fn relay(base: &str) -> Relay {
        Relay {
            resend: Some("re_test".into()),
            smtp2go: Some("api-test".into()),
            mailjet: Some(("key".into(), "secret".into())),
            endpoints: Endpoints {
                resend: format!("{base}/resend"),
                smtp2go: format!("{base}/smtp2go"),
                mailjet: format!("{base}/mailjet"),
            },
            ..Relay::default()
        }
    }

    const MAIL: Outgoing<'static> = Outgoing {
        from: "Glarion <noreply@glarion.app>",
        to: "ada@example.com",
        subject: "Secret subject",
        html: "<p>link</p>",
        text: "link",
        reply_to: Some("hello@glarion.app"),
        key: "glarion-test-key",
    };

    fn paths(seen: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
        seen.lock()
            .unwrap()
            .iter()
            .map(|r| r.split_whitespace().nth(1).unwrap_or("").to_string())
            .collect()
    }

    #[tokio::test]
    async fn resend_out_of_quota_goes_to_smtp2go_once() {
        let (base, seen) = stub(vec![
            ("/resend", 429, r#"{"name":"daily_quota_exceeded"}"#),
            (
                "/smtp2go",
                200,
                r#"{"data":{"succeeded":1,"failed":0,"email_id":"x"}}"#,
            ),
        ])
        .await;
        assert_eq!(relay(&base).send(&MAIL).await.unwrap(), "smtp2go");
        assert_eq!(paths(&seen), ["/resend", "/smtp2go"]);
        let requests = seen.lock().unwrap();
        assert!(requests[0]
            .to_lowercase()
            .contains("idempotency-key: glarion-test-key"));
        assert!(requests[1]
            .to_lowercase()
            .contains("x-smtp2go-api-key: api-test"));
    }

    #[tokio::test]
    async fn a_resend_5xx_is_asked_again_with_the_same_key_then_moves_on() {
        let (base, seen) = stub(vec![
            ("/resend", 503, "{}"),
            ("/resend", 502, "{}"),
            (
                "/smtp2go",
                200,
                r#"{"data":{"succeeded":1,"failed":0,"email_id":"x"}}"#,
            ),
        ])
        .await;
        assert_eq!(relay(&base).send(&MAIL).await.unwrap(), "smtp2go");
        assert_eq!(paths(&seen), ["/resend", "/resend", "/smtp2go"]);
    }

    #[tokio::test]
    async fn a_2xx_is_taken_even_when_unreadable() {
        let (base, seen) = stub(vec![("/resend", 200, "not json")]).await;
        assert_eq!(relay(&base).send(&MAIL).await.unwrap(), "resend");
        assert_eq!(paths(&seen), ["/resend"]);
    }

    #[tokio::test]
    async fn a_409_stops_the_chain() {
        let (base, seen) = stub(vec![(
            "/resend",
            409,
            r#"{"name":"concurrent_idempotent_requests"}"#,
        )])
        .await;
        assert!(relay(&base).send(&MAIL).await.is_err());
        assert_eq!(paths(&seen), ["/resend"]);
    }

    #[tokio::test]
    async fn every_refusal_is_one_clear_error_without_the_address() {
        let (base, seen) = stub(vec![
            (
                "/resend",
                403,
                r#"{"name":"validation_error","message":"ada@example.com"}"#,
            ),
            ("/smtp2go", 200, r#"{"data":{"succeeded":0,"failed":1}}"#),
            (
                "/mailjet",
                400,
                r#"{"Messages":[{"Status":"error","Errors":[{"ErrorCode":"mj-0013"}]}]}"#,
            ),
        ])
        .await;
        let error = relay(&base).send(&MAIL).await.unwrap_err().to_string();
        assert!(error.starts_with("email provider refused"), "{error}");
        assert!(!error.contains("ada@example.com"));
        assert_eq!(paths(&seen), ["/resend", "/smtp2go", "/mailjet"]);
        let mailjet = &seen.lock().unwrap()[2];
        assert!(
            mailjet.contains(r#""From":{"Email":"noreply@glarion.app","Name":"Glarion"}"#),
            "{mailjet}"
        );
    }

    #[tokio::test]
    async fn providers_without_keys_are_skipped() {
        let (base, seen) = stub(vec![("/resend", 429, "{}")]).await;
        let only_resend = Relay {
            smtp2go: None,
            mailjet: None,
            ..relay(&base)
        };
        assert!(only_resend.send(&MAIL).await.is_err());
        assert_eq!(paths(&seen), ["/resend"]);
        assert_eq!(only_resend.ready(), ["resend"]);
        let none = Relay::default();
        assert_eq!(
            none.send(&MAIL).await.unwrap_err().to_string(),
            "email provider is not configured"
        );
    }

    #[tokio::test]
    async fn the_domain_allowlist_and_the_sink() {
        let (base, seen) = stub(vec![(
            "/smtp2go",
            200,
            r#"{"data":{"succeeded":1,"email_id":"x"}}"#,
        )])
        .await;
        let picky = Relay {
            domains: vec![("resend".into(), vec!["other.example".into()])],
            ..relay(&base)
        };
        assert_eq!(picky.send(&MAIL).await.unwrap(), "smtp2go");
        assert_eq!(paths(&seen), ["/smtp2go"]);

        let dir = std::env::temp_dir().join(format!("glarion-sink-{}", uuid::Uuid::new_v4()));
        let sink = Relay {
            sink: Some(dir.clone()),
            ..relay("http://127.0.0.1:9")
        };
        assert_eq!(sink.send(&MAIL).await.unwrap(), "sink");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
