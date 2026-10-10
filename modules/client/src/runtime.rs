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
    /// Missing, invalid, or unreadable values use the restrictive Beta policy;
    /// only an explicit Development selection permits security-critical stubs.
    pub fn from_env() -> Self {
        Self::parse(&env::var(RUNTIME_MODE_ENV).unwrap_or_default())
    }

    /// Read `PROMETHEUS_RUNTIME` without any fallback.
    ///
    /// Missing, empty, or unrecognised values return `None` so fail-closed
    /// gates can reject them instead of defaulting to development.
    pub fn explicit_from_env() -> Option<Self> {
        env::var(RUNTIME_MODE_ENV)
            .ok()
            .as_deref()
            .and_then(Self::try_parse)
    }

    /// Parse a runtime mode string, falling back to the restrictive Beta policy.
    pub fn parse(value: &str) -> Self {
        Self::try_parse(value).unwrap_or(Self::Beta)
    }

    /// Strictly parse a runtime mode string; empty or unknown values are `None`.
    pub fn try_parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "development" => Some(Self::Development),
            "beta" => Some(Self::Beta),
            "mainnet" | "production" | "prod" => Some(Self::Mainnet),
            _ => None,
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
    fn test_parse_missing_and_invalid_modes_fail_closed() {
        for value in ["", "unknown", "dev", " development", "development\n"] {
            let mode = RuntimeMode::parse(value);
            assert_eq!(mode, RuntimeMode::Beta);
            assert!(require_stub_allowed_for(mode, "test component").is_err());
        }
        assert_eq!(RuntimeMode::parse("development"), RuntimeMode::Development);
    }

    #[test]
    fn test_env_selection_and_stub_gate_in_isolated_processes() {
        const EXPECTED: &str = "PROMETHEUS_RUNTIME_TEST_EXPECTED";
        if let Ok(expected) = env::var(EXPECTED) {
            assert_eq!(format!("{:?}", RuntimeMode::from_env()), expected);
            assert_eq!(
                require_stub_allowed("test component").is_ok(),
                expected == "Development"
            );
            return;
        }
        for (value, expected) in [
            (None, "Beta"),
            (Some(""), "Beta"),
            (Some("unknown"), "Beta"),
            (Some("development"), "Development"),
            (Some("beta"), "Beta"),
            (Some("mainnet"), "Mainnet"),
        ] {
            let mut command =
                std::process::Command::new(env::current_exe().expect("test executable"));
            command
                .args([
                    "--exact",
                    "runtime::tests::test_env_selection_and_stub_gate_in_isolated_processes",
                ])
                .env(EXPECTED, expected);
            match value {
                Some(value) => {
                    command.env(RUNTIME_MODE_ENV, value);
                }
                None => {
                    command.env_remove(RUNTIME_MODE_ENV);
                }
            }
            let output = command.output().expect("isolated runtime test");
            assert!(output.status.success(), "isolated runtime selection failed");
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("1 passed"),
                "child must run the selected test"
            );
        }
    }

    #[test]
    fn test_try_parse_rejects_missing_and_malformed_modes() {
        assert_eq!(
            RuntimeMode::try_parse("development"),
            Some(RuntimeMode::Development)
        );
        assert_eq!(RuntimeMode::try_parse("beta"), Some(RuntimeMode::Beta));
        assert_eq!(
            RuntimeMode::try_parse("mainnet"),
            Some(RuntimeMode::Mainnet)
        );
        for malformed in [
            "",
            "dev",
            " development",
            "development\n",
            "testnet",
            "unknown",
        ] {
            assert_eq!(RuntimeMode::try_parse(malformed), None, "{malformed:?}");
        }
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
