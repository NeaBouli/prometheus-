//! Strict configuration and factories for the opt-in GH-213 RuleStorage CLI.
//!
//! This module only composes already reviewed Development/Testnet-10
//! boundaries. It contains no signer, private-key, wallet, transaction,
//! broadcast, deployment, Mainnet, key-governance, or production authority.
//! Final file components are descriptor-validated with `NOFOLLOW`; ancestor
//! directories remain an explicit owner-controlled development trust boundary.

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustix::fs::{self, FileType, Mode, OFlags};
use rustix::process;
use secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};
use url::{Host, Url};

use crate::blockchain::connection::KaspaConnection;
use crate::blockchain::rule_checkpoint::PosixRuleCheckpointStore;
use crate::blockchain::rule_coordinator::{RuleCoordinator, RuleCoordinatorConfig};
use crate::blockchain::rule_fetch::LocalIpfsGatewaySource;
use crate::blockchain::rule_signed_snapshot::{
    RuleSnapshotEnvelopeError, RuleSnapshotTimeSource, SignedRuleSnapshotProvider,
    MAX_ENVELOPE_BYTES,
};
use crate::runtime::{require_stub_allowed, require_stub_allowed_for, RuntimeMode};

const MAX_CONFIG_BYTES: usize = 64 * 1024;
const COMPONENT: &str = "RuleStorage sync CLI";

/// Generic redacted failure for configuration, preflight, and factories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleSyncCliError;

impl fmt::Display for RuleSyncCliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RuleStorage sync CLI configuration rejected")
    }
}

impl std::error::Error for RuleSyncCliError {}

/// The only network accepted by this development surface.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RuleSyncNetwork {
    Testnet10,
}

/// Strict explicit configuration. Every field is required.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSyncConfig {
    enabled: bool,
    network: RuleSyncNetwork,
    owner_xonly_public_key: String,
    minimum_sequence: u64,
    signed_envelope_path: PathBuf,
    rpc_url: String,
    ipfs_gateway_url: String,
    checkpoint_dir: PathBuf,
    success_interval_secs: u64,
    initial_failure_backoff_ms: u64,
    max_failure_backoff_ms: u64,
    attempt_timeout_ms: u64,
}

impl fmt::Debug for RuleSyncConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleSyncConfig").finish_non_exhaustive()
    }
}

/// Validated private runtime values. Debug output is intentionally redacted.
pub struct ValidatedRuleSyncConfig {
    mode: RuntimeMode,
    network: RuleSyncNetwork,
    owner_xonly_public_key: [u8; 32],
    minimum_sequence: u64,
    signed_envelope_path: PathBuf,
    rpc_url: String,
    ipfs_gateway_url: String,
    checkpoint_dir: PathBuf,
    coordinator_config: RuleCoordinatorConfig,
}

impl fmt::Debug for ValidatedRuleSyncConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedRuleSyncConfig")
            .finish_non_exhaustive()
    }
}

/// Data-minimal machine-readable offline preflight result.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RuleSyncPreflight {
    pub status: &'static str,
    pub runtime: &'static str,
    pub network: RuleSyncNetwork,
    pub rpc_scope: &'static str,
    pub ipfs_scope: &'static str,
    pub envelope: &'static str,
    pub checkpoint: &'static str,
    pub chain_writes: &'static str,
}

/// Separately trusted wall clock used by the operator-invoked CLI.
#[derive(Debug, Default)]
pub struct SystemRuleSnapshotClock;

impl RuleSnapshotTimeSource for SystemRuleSnapshotClock {
    fn current_unix_seconds(&self) -> Result<u64, RuleSnapshotEnvelopeError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| RuleSnapshotEnvelopeError)
    }
}

impl RuleSyncConfig {
    /// Read a private, bounded, ASCII-only TOML file without following symlinks.
    pub fn from_toml_file(path: &Path) -> Result<Self, RuleSyncCliError> {
        let bytes = read_owner_file(path, MAX_CONFIG_BYTES)?;
        if !bytes.is_ascii() {
            return Err(RuleSyncCliError);
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| RuleSyncCliError)?;
        toml::from_str(text).map_err(|_| RuleSyncCliError)
    }

    /// Validate all static policy without network access or checkpoint mutation.
    pub fn validate(&self, mode: RuntimeMode) -> Result<ValidatedRuleSyncConfig, RuleSyncCliError> {
        require_development(mode)?;
        if !self.enabled || self.network != RuleSyncNetwork::Testnet10 {
            return Err(RuleSyncCliError);
        }
        let owner_xonly_public_key = decode_xonly_key(&self.owner_xonly_public_key)?;
        if self.minimum_sequence == 0
            || !self.signed_envelope_path.is_absolute()
            || !self.checkpoint_dir.is_absolute()
        {
            return Err(RuleSyncCliError);
        }
        validate_loopback_rpc_url(&self.rpc_url)?;
        validate_loopback_ipfs_url(&self.ipfs_gateway_url)?;
        let coordinator_config = RuleCoordinatorConfig::new(
            Duration::from_secs(self.success_interval_secs),
            Duration::from_millis(self.initial_failure_backoff_ms),
            Duration::from_millis(self.max_failure_backoff_ms),
            Duration::from_millis(self.attempt_timeout_ms),
        )
        .map_err(|_| RuleSyncCliError)?;

        Ok(ValidatedRuleSyncConfig {
            mode,
            network: self.network,
            owner_xonly_public_key,
            minimum_sequence: self.minimum_sequence,
            signed_envelope_path: self.signed_envelope_path.clone(),
            rpc_url: self.rpc_url.clone(),
            ipfs_gateway_url: self.ipfs_gateway_url.clone(),
            checkpoint_dir: self.checkpoint_dir.clone(),
            coordinator_config,
        })
    }
}

impl ValidatedRuleSyncConfig {
    /// Return the validated bounded scheduling policy.
    pub fn coordinator_config(&self) -> RuleCoordinatorConfig {
        self.coordinator_config
    }

    /// Build the existing Development/Testnet-10 coordinator.
    pub fn create_coordinator(&self) -> Result<RuleCoordinator, RuleSyncCliError> {
        RuleCoordinator::new_for_mode(self.mode, self.coordinator_config)
            .map_err(|_| RuleSyncCliError)
    }

    /// Build an unconnected local Testnet-10 RPC client.
    pub fn create_connection(&self) -> Result<KaspaConnection, RuleSyncCliError> {
        require_development(self.mode)?;
        KaspaConnection::new(&self.rpc_url).map_err(|_| RuleSyncCliError)
    }

    /// Build the credential-free loopback-only content source without fetching.
    pub fn create_content_source(&self) -> Result<LocalIpfsGatewaySource, RuleSyncCliError> {
        LocalIpfsGatewaySource::new_for_mode(self.mode, &self.ipfs_gateway_url)
            .map_err(|_| RuleSyncCliError)
    }

    /// Open the existing GH-207 checkpoint store. Offline preflight never calls this.
    pub fn open_checkpoint_store(&self) -> Result<PosixRuleCheckpointStore, RuleSyncCliError> {
        PosixRuleCheckpointStore::open_for_mode(self.mode, &self.checkpoint_dir)
            .map_err(|_| RuleSyncCliError)
    }

    /// Read and verify one immutable envelope at CLI startup.
    ///
    /// A running coordinator rechecks time and runtime mode on every fetch but
    /// intentionally does not reload a replaced file; an operator restart is
    /// required to select another envelope.
    pub fn create_signed_provider(
        &self,
        clock: Arc<dyn RuleSnapshotTimeSource>,
    ) -> Result<SignedRuleSnapshotProvider, RuleSyncCliError> {
        let envelope = read_owner_file(&self.signed_envelope_path, MAX_ENVELOPE_BYTES)?;
        SignedRuleSnapshotProvider::new_for_mode(
            self.mode,
            &envelope,
            &self.owner_xonly_public_key,
            self.minimum_sequence,
            clock,
        )
        .map_err(|_| RuleSyncCliError)
    }

    /// Verify all offline inputs without connecting or touching checkpoint state.
    pub fn offline_preflight(
        &self,
        clock: Arc<dyn RuleSnapshotTimeSource>,
    ) -> Result<RuleSyncPreflight, RuleSyncCliError> {
        require_development(self.mode)?;
        let _provider = self.create_signed_provider(clock)?;
        let _content_source = self.create_content_source()?;
        let _connection = self.create_connection()?;
        let _coordinator = self.create_coordinator()?;
        Ok(RuleSyncPreflight {
            status: "ready-for-development-rule-sync",
            runtime: "development-only",
            network: self.network,
            rpc_scope: "loopback-ip-literal-only",
            ipfs_scope: "loopback-ip-literal-only",
            envelope: "verified",
            checkpoint: "deferred-to-run",
            chain_writes: "none",
        })
    }
}

fn require_development(mode: RuntimeMode) -> Result<(), RuleSyncCliError> {
    require_stub_allowed(COMPONENT).map_err(|_| RuleSyncCliError)?;
    require_stub_allowed_for(mode, COMPONENT).map_err(|_| RuleSyncCliError)?;
    if mode != RuntimeMode::Development {
        return Err(RuleSyncCliError);
    }
    Ok(())
}

fn decode_xonly_key(value: &str) -> Result<[u8; 32], RuleSyncCliError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RuleSyncCliError);
    }
    let decoded = hex::decode(value).map_err(|_| RuleSyncCliError)?;
    let key: [u8; 32] = decoded.try_into().map_err(|_| RuleSyncCliError)?;
    XOnlyPublicKey::from_slice(&key).map_err(|_| RuleSyncCliError)?;
    Ok(key)
}

fn validate_loopback_rpc_url(value: &str) -> Result<(), RuleSyncCliError> {
    let url = Url::parse(value).map_err(|_| RuleSyncCliError)?;
    if !matches!(url.scheme(), "ws" | "wss")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
        || !is_loopback_ip_literal(url.host())
    {
        return Err(RuleSyncCliError);
    }
    Ok(())
}

fn validate_loopback_ipfs_url(value: &str) -> Result<(), RuleSyncCliError> {
    let url = Url::parse(value).map_err(|_| RuleSyncCliError)?;
    if url.scheme() != "http"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/ipfs/"
        || !is_loopback_ip_literal(url.host())
    {
        return Err(RuleSyncCliError);
    }
    Ok(())
}

fn is_loopback_ip_literal(host: Option<Host<&str>>) -> bool {
    match host {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    }
}

fn read_owner_file(path: &Path, maximum: usize) -> Result<Vec<u8>, RuleSyncCliError> {
    let file = fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| RuleSyncCliError)?;
    let stat = fs::fstat(&file).map_err(|_| RuleSyncCliError)?;
    let mode = stat.st_mode as u32;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != process::geteuid().as_raw()
        || stat.st_nlink != 1
        || mode & 0o177 != 0
        || mode & 0o400 != 0o400
        || mode & 0o7000 != 0
        || stat.st_size <= 0
        || stat.st_size as usize > maximum
    {
        return Err(RuleSyncCliError);
    }
    let mut bytes = Vec::with_capacity((stat.st_size as usize).min(maximum));
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RuleSyncCliError)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(RuleSyncCliError);
    }
    Ok(bytes)
}
