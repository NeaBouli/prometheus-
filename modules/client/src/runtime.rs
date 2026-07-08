//! Runtime mode guards for development, beta, and mainnet profiles.
//!
//! Development mode may use explicit stubs. Beta and mainnet must fail fast
//! when a security-critical path would fall back to placeholder behavior.

use std::env;

use anyhow::{bail, Result};

/// Environment variable used to select the runtime mode.
pub const RUNTIME_MODE_ENV: &str = "PROMETHEUS_RUNTIME";

/// Runtime profile for the light client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeMode {
    /// Local development and tests. Stubs are allowed only when explicitly enabled.
    Development,
    /// Beta builds with external users. Security-critical stubs are forbidden.
    Beta,
    /// Mainnet builds. Security-critical stubs are forbidden.
    Mainnet,
}

impl RuntimeMode {
    /// Read the current runtime mode from `PROMETHEUS_RUNTIME`.
    ///
    /// Unknown or missing values fall back to development mode so existing local
    /// tests remain deterministic and offline.
    pub fn from_env() -> Self {
        Self::parse(&env::var(RUNTIME_MODE_ENV).unwrap_or_default())
    }

    /// Parse a runtime mode string.
    pub fn parse(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "beta" => Self::Beta,
            "mainnet" | "production" | "prod" => Self::Mainnet,
            _ => Self::Development,
        }
    }

    /// Whether this runtime mode forbids placeholder security behavior.
    pub fn forbids_stubs(self) -> bool {
        matches!(self, Self::Beta | Self::Mainnet)
    }
}

/// Enforce that a security-critical stub is not used in beta/mainnet.
pub fn require_stub_allowed(component: &str) -> Result<()> {
    require_stub_allowed_for(RuntimeMode::from_env(), component)
}

/// Enforce stub policy for an explicit runtime mode.
pub fn require_stub_allowed_for(mode: RuntimeMode, component: &str) -> Result<()> {
    if mode.forbids_stubs() {
        bail!(
            "{} stub is disabled for {:?}; use real implementation or set {}=development for local-only testing",
            component,
            mode,
            RUNTIME_MODE_ENV
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_default_mode_as_development() {
        assert_eq!(RuntimeMode::parse(""), RuntimeMode::Development);
        assert_eq!(RuntimeMode::parse("development"), RuntimeMode::Development);
    }

    #[test]
    fn test_beta_and_mainnet_forbid_stubs() {
        assert!(RuntimeMode::parse("beta").forbids_stubs());
        assert!(RuntimeMode::parse("mainnet").forbids_stubs());
        assert!(RuntimeMode::parse("production").forbids_stubs());
    }

    #[test]
    fn test_stub_gate_allows_development_only() {
        assert!(require_stub_allowed_for(RuntimeMode::Development, "test component").is_ok());
        assert!(require_stub_allowed_for(RuntimeMode::Beta, "test component").is_err());
        assert!(require_stub_allowed_for(RuntimeMode::Mainnet, "test component").is_err());
    }
}
