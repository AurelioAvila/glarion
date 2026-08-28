//! Runtime configuration, read once at startup.
//!
//! Every value here is required. We deliberately refuse to boot rather than
//! fall back to a default — a missing JWT secret or DATABASE_URL silently
//! defaulting to something would be a security failure, not a convenience.

use anyhow::{Context, Result};

pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    /// Origins allowed to call this API from a browser. Parsed from a
    /// comma-separated env var and *added to* the built-in first-party
    /// origins, never replacing them (same convention as the PC Tweaker
    /// backend — a misconfigured env var must not lock out our own site).
    pub extra_cors_origins: Vec<String>,
    pub port: u16,
}

/// First-party origins that are always allowed regardless of env config.
const FIRST_PARTY_ORIGINS: &[&str] = &["https://glarion.app", "https://www.glarion.app"];

impl Config {
    pub fn from_env() -> Result<Self> {
        let database_url = required("DATABASE_URL")?;

        let jwt_secret = required("JWT_SECRET")?;
        // A short secret makes HS256 brute-forceable offline. Refuse to boot
        // rather than run with a weak signing key.
        if jwt_secret.len() < 32 {
            anyhow::bail!("JWT_SECRET must be at least 32 characters");
        }

        let extra_cors_origins = std::env::var("CORS_EXTRA_ORIGINS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();

        let port = std::env::var("PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .context("PORT must be a valid port number")?;

        Ok(Self {
            database_url,
            jwt_secret,
            extra_cors_origins,
            port,
        })
    }

    /// Full allowlist: first-party origins plus anything configured.
    pub fn allowed_origins(&self) -> Vec<String> {
        FIRST_PARTY_ORIGINS
            .iter()
            .map(|s| s.to_string())
            .chain(self.extra_cors_origins.iter().cloned())
            .collect()
    }
}

fn required(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("{key} must be set"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_origins_always_include_first_party() {
        let config = Config {
            database_url: "postgres://x".into(),
            jwt_secret: "x".repeat(32),
            extra_cors_origins: vec!["https://staging.example.com".into()],
            port: 8080,
        };

        let origins = config.allowed_origins();
        assert!(origins.contains(&"https://glarion.app".to_string()));
        assert!(origins.contains(&"https://staging.example.com".to_string()));
    }

    #[test]
    fn allowed_origins_survive_empty_env_config() {
        let config = Config {
            database_url: "postgres://x".into(),
            jwt_secret: "x".repeat(32),
            extra_cors_origins: vec![],
            port: 8080,
        };

        assert!(config
            .allowed_origins()
            .contains(&"https://glarion.app".to_string()));
    }
}
