//! Experimental, opt-in companion for operators running Kaspa mining infrastructure.
//!
//! This module only validates configuration and observes a local Testnet-10 node.
//! It does not scan the host, submit reports, manage mining software, or award PROM.

use std::fs;
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::blockchain::connection::KaspaConnection;
use crate::runtime::RuntimeMode;

const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MIN_POLL_INTERVAL_SECS: u64 = 10;
const MAX_POLL_INTERVAL_SECS: u64 = 3600;

/// Supported companion role. Validator and honeypot operation require separate
/// threat models and are intentionally not accepted by this configuration.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CompanionRole {
    /// Observe local Kaspa node health without scanning or reporting.
    Light,
}

/// Network supported by the first experimental companion profile.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CompanionNetwork {
    /// Kaspa public Testnet-10.
    Testnet10,
}

/// Features which remain disabled until their real implementations and
/// transports have passed a separate production review.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
struct DisabledFeatures {
    scanning: bool,
    reporting: bool,
}

/// Strict configuration for the experimental miner companion.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinerCompanionConfig {
    enabled: bool,
    role: CompanionRole,
    network: CompanionNetwork,
    rpc_url: String,
    #[serde(default = "default_poll_interval_secs")]
    poll_interval_secs: u64,
    #[serde(default)]
    features: DisabledFeatures,
}

/// Validated values used by the runtime. The endpoint is deliberately private
/// so callers cannot accidentally include it in status output or telemetry.
pub struct ValidatedMinerCompanionConfig {
    rpc_url: String,
    poll_interval: Duration,
    role: CompanionRole,
    network: CompanionNetwork,
}

impl ValidatedMinerCompanionConfig {
    /// Build the credential-free local Kaspa connection without exposing the
    /// configured endpoint to logs or public status structures.
    pub fn create_connection(&self) -> Result<KaspaConnection> {
        KaspaConnection::new(&self.rpc_url)
    }

    /// Return the validated BlockDAG health polling interval.
    pub fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    /// Build a public status report without endpoint or operator identity data.
    pub fn preflight_report(&self) -> MinerCompanionPreflight {
        MinerCompanionPreflight {
            status: "ready-for-development-rpc-observer",
            runtime: "development-only",
            role: self.role,
            network: self.network,
            rpc_scope: "loopback-only",
            scanning: "disabled",
            reporting: "disabled",
            rewards: "not-implemented",
        }
    }
}

/// Public preflight report. It contains no endpoint, wallet, worker, or pool data.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MinerCompanionPreflight {
    /// Machine-readable readiness state for the bounded observer.
    pub status: &'static str,
    /// Runtime profile in which the companion is permitted.
    pub runtime: &'static str,
    /// Enabled companion role.
    pub role: CompanionRole,
    /// Kaspa network selected by the strict profile.
    pub network: CompanionNetwork,
    /// Allowed RPC endpoint scope without exposing the endpoint itself.
    pub rpc_scope: &'static str,
    /// Host scanning state.
    pub scanning: &'static str,
    /// Threat-reporting state.
    pub reporting: &'static str,
    /// Reward implementation state.
    pub rewards: &'static str,
}

impl MinerCompanionConfig {
    /// Parse a strict TOML configuration from disk with a small size limit.
    pub fn from_toml_file(path: &Path) -> Result<Self> {
        let file = fs::File::open(path).context("failed to read companion config")?;
        let mut bytes = Vec::new();
        file.take(MAX_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)
            .context("failed to read companion config")?;
        if bytes.len() as u64 > MAX_CONFIG_BYTES {
            bail!("companion config exceeds the 64 KiB size limit");
        }

        let contents =
            std::str::from_utf8(&bytes).map_err(|_| anyhow::anyhow!("invalid companion config"))?;
        toml::from_str(contents).map_err(|_| anyhow::anyhow!("invalid companion config"))
    }

    /// Validate the opt-in and privacy boundary before any network activity.
    pub fn validate(&self, runtime: RuntimeMode) -> Result<ValidatedMinerCompanionConfig> {
        if !self.enabled {
            bail!("miner companion is disabled; explicit opt-in is required");
        }
        if runtime != RuntimeMode::Development {
            bail!("miner companion is experimental and cannot run in beta or mainnet mode");
        }
        if self.features.scanning || self.features.reporting {
            bail!("scanning and reporting are not available in the experimental companion");
        }
        if !(MIN_POLL_INTERVAL_SECS..=MAX_POLL_INTERVAL_SECS).contains(&self.poll_interval_secs) {
            bail!("poll_interval_secs must be between 10 and 3600");
        }

        let rpc_url = validate_loopback_wrpc_url(&self.rpc_url)?;
        Ok(ValidatedMinerCompanionConfig {
            rpc_url: rpc_url.into(),
            poll_interval: Duration::from_secs(self.poll_interval_secs),
            role: self.role,
            network: self.network,
        })
    }
}

fn default_poll_interval_secs() -> u64 {
    30
}

fn validate_loopback_wrpc_url(value: &str) -> Result<&str> {
    let url = Url::parse(value).map_err(|_| anyhow::anyhow!("rpc_url is not a valid URL"))?;
    if !matches!(url.scheme(), "ws" | "wss") {
        bail!("rpc_url must use ws or wss");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("rpc_url must not contain credentials");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("rpc_url must not contain a query or fragment");
    }

    let is_loopback = match url.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => IpAddr::V4(address).is_loopback(),
        Some(url::Host::Ipv6(address)) => IpAddr::V6(address).is_loopback(),
        None => false,
    };
    if !is_loopback {
        bail!("rpc_url must use a loopback host in the experimental companion");
    }

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn valid_config() -> MinerCompanionConfig {
        MinerCompanionConfig {
            enabled: true,
            role: CompanionRole::Light,
            network: CompanionNetwork::Testnet10,
            rpc_url: "ws://127.0.0.1:17210".to_string(),
            poll_interval_secs: 30,
            features: DisabledFeatures::default(),
        }
    }

    #[test]
    fn accepts_explicit_local_development_profile() {
        let validated = valid_config().validate(RuntimeMode::Development).unwrap();
        assert_eq!(validated.poll_interval(), Duration::from_secs(30));
        assert!(validated.create_connection().is_ok());
    }

    #[test]
    fn rejects_disabled_profile() {
        let mut config = valid_config();
        config.enabled = false;
        assert!(config.validate(RuntimeMode::Development).is_err());
    }

    #[test]
    fn rejects_beta_and_mainnet_profiles() {
        let config = valid_config();
        assert!(config.validate(RuntimeMode::Beta).is_err());
        assert!(config.validate(RuntimeMode::Mainnet).is_err());
    }

    #[test]
    fn rejects_scanning_and_reporting() {
        let mut config = valid_config();
        config.features.scanning = true;
        assert!(config.validate(RuntimeMode::Development).is_err());

        config.features.scanning = false;
        config.features.reporting = true;
        assert!(config.validate(RuntimeMode::Development).is_err());
    }

    #[test]
    fn rejects_credentials_and_remote_hosts() {
        let mut config = valid_config();
        config.rpc_url = "ws://user:password@127.0.0.1:17210".to_string();
        assert!(config.validate(RuntimeMode::Development).is_err());

        config.rpc_url = "wss://public.example:17210".to_string();
        assert!(config.validate(RuntimeMode::Development).is_err());
    }

    #[test]
    fn accepts_ipv4_ipv6_and_localhost_loopback() {
        for rpc_url in [
            "ws://127.0.0.1:17210",
            "ws://[::1]:17210",
            "wss://localhost:17210",
        ] {
            let mut config = valid_config();
            config.rpc_url = rpc_url.to_string();
            assert!(config.validate(RuntimeMode::Development).is_ok());
        }
    }

    #[test]
    fn rejects_unsafe_url_components_and_poll_intervals() {
        let mut config = valid_config();
        config.rpc_url = "http://127.0.0.1:17210".to_string();
        assert!(config.validate(RuntimeMode::Development).is_err());

        config.rpc_url = "ws://127.0.0.1:17210?token=secret".to_string();
        assert!(config.validate(RuntimeMode::Development).is_err());

        config.rpc_url = "ws://127.0.0.1:17210".to_string();
        config.poll_interval_secs = 9;
        assert!(config.validate(RuntimeMode::Development).is_err());
    }

    #[test]
    fn strict_toml_rejects_unsupported_roles_and_unknown_fields() {
        let unsupported_role = r#"
            enabled = true
            role = "validator"
            network = "testnet10"
            rpc_url = "ws://127.0.0.1:17210"
        "#;
        assert!(toml::from_str::<MinerCompanionConfig>(unsupported_role).is_err());

        let reward_field = r#"
            enabled = true
            role = "light"
            network = "testnet10"
            rpc_url = "ws://127.0.0.1:17210"
            reward_address = "kaspatest:example"
        "#;
        assert!(toml::from_str::<MinerCompanionConfig>(reward_field).is_err());
    }

    #[test]
    fn config_parse_errors_do_not_echo_local_contents() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "unsupported_secret = \"do-not-echo-this-value\"").unwrap();

        let error = match MinerCompanionConfig::from_toml_file(file.path()) {
            Ok(_) => panic!("invalid config unexpectedly parsed"),
            Err(error) => error,
        };
        let message = error.to_string();
        assert_eq!(message, "invalid companion config");
        assert!(!message.contains("do-not-echo-this-value"));
    }

    #[test]
    fn rejects_non_utf8_and_oversized_configs_without_echoing_contents() {
        let mut non_utf8 = NamedTempFile::new().unwrap();
        non_utf8.write_all(&[0xff, 0xfe]).unwrap();
        let non_utf8_error = match MinerCompanionConfig::from_toml_file(non_utf8.path()) {
            Ok(_) => panic!("non-UTF-8 config unexpectedly parsed"),
            Err(error) => error,
        };
        assert_eq!(non_utf8_error.to_string(), "invalid companion config");

        let mut oversized = NamedTempFile::new().unwrap();
        oversized
            .write_all(&vec![b'x'; MAX_CONFIG_BYTES as usize + 1])
            .unwrap();
        let oversized_error = match MinerCompanionConfig::from_toml_file(oversized.path()) {
            Ok(_) => panic!("oversized config unexpectedly parsed"),
            Err(error) => error,
        };
        assert_eq!(
            oversized_error.to_string(),
            "companion config exceeds the 64 KiB size limit"
        );
    }

    #[test]
    fn preflight_report_contains_no_endpoint_or_identity_data() {
        let validated = valid_config().validate(RuntimeMode::Development).unwrap();
        let json = serde_json::to_string(&validated.preflight_report()).unwrap();
        assert!(!json.contains("127.0.0.1"));
        assert!(!json.contains("rpc_url"));
        assert!(json.contains("not-implemented"));
    }
}
