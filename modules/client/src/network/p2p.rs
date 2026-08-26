//! Strict configuration and bounded sender for the Development-only GH-226
//! v1 ThreatHint submission CLI.
//!
//! This module only composes the existing reviewed `prometheus-guardian-p2p`
//! transport. It introduces no new libp2p transport, discovery, relay,
//! AutoNAT, or public-address operation: exactly one canonical static Guardian
//! peer id and one literal QUIC multiaddress are accepted, and the node runs
//! dial-only with zero listeners. The default route mode accepts only a
//! literal-loopback route. The explicit `controlled-remote-testnet10` opt-in
//! (GH-229) accepts exactly one bounded direct literal-IP route to the same
//! static peer while rejecting loopback, link-local, documentation,
//! benchmarking, broadcast/reserved, IPv4-mapped, wildcard, and multicast
//! ranges. It contains no signer,
//! private-key, wallet, seed, transaction, ballot, ThreatHint-v2, deployment,
//! Mainnet, key-governance, or production authority. Beta and Mainnet are
//! rejected before any network activity regardless of the proof bytes a
//! canonical hint claims. An acknowledgement only reports a remote
//! local-boundary outcome; it is never proof, consensus, membership, or
//! reward authority. There is no retry and no persistence.

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use prometheus_guardian_p2p::transport_identity::load_or_create_transport_identity;
use prometheus_guardian_p2p::{
    GuardianP2p, GuardianP2pConfig, StaticPeer, ThreatHintAckStatus, ThreatHintBytes,
    TransportError, TransportEvent, MAX_THREAT_HINT_BYTES,
};
use rustix::fs::{self, FileType, Mode, OFlags};
use rustix::process;
use serde::{Deserialize, Serialize};
use tokio::time;

use crate::runtime::{require_stub_allowed, require_stub_allowed_for, RuntimeMode};

const MAX_CONFIG_BYTES: usize = 16 * 1024;
/// Mirrors the guardian-p2p transport-identity bound for read-only preflight
/// metadata checks; loading and creating remain inside guardian-p2p.
const MAX_IDENTITY_FILE_BYTES: u64 = 1_024;
const MIN_SUBMISSION_TIMEOUT_SECS: u64 = 1;
const MAX_SUBMISSION_TIMEOUT_SECS: u64 = 60;
const MAX_IN_FLIGHT_REQUESTS: usize = 4;
const COMPONENT: &str = "ThreatHint v1 submit CLI";

/// Generic redacted failure for configuration, preflight, and factories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreatHintP2pError;

impl fmt::Display for ThreatHintP2pError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ThreatHint v1 submit CLI request rejected")
    }
}

impl std::error::Error for ThreatHintP2pError {}

/// The only network accepted by this development surface.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ThreatHintNetwork {
    Testnet10,
}

/// Optional route policy for the single static Guardian peer. The default is
/// loopback; `controlled-remote-testnet10` is an explicit Development-only
/// GH-229 opt-in for one bounded direct literal-IP route to the same peer.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ThreatHintRouteMode {
    /// Accept only one canonical literal-loopback QUIC route.
    #[default]
    Loopback,
    /// Accept only one canonical bounded direct literal-IP QUIC route.
    ControlledRemoteTestnet10,
}

impl ThreatHintRouteMode {
    /// Stable data-minimal route scope reported in preflight and submissions.
    const fn route_scope(self) -> &'static str {
        match self {
            Self::Loopback => "single-static-loopback-quic-peer",
            Self::ControlledRemoteTestnet10 => "single-static-controlled-remote-quic-peer",
        }
    }
}

/// Strict explicit configuration. Every field is required; unknown fields,
/// including any wallet, seed, or signing material, are denied.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreatHintSubmitConfig {
    enabled: bool,
    network: ThreatHintNetwork,
    #[serde(default)]
    route_mode: ThreatHintRouteMode,
    guardian_peer_id: String,
    guardian_address: String,
    identity_path: PathBuf,
    submission_timeout_secs: u64,
}

impl fmt::Debug for ThreatHintSubmitConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ThreatHintSubmitConfig")
            .finish_non_exhaustive()
    }
}

/// Validated private runtime values. Debug output is intentionally redacted.
pub struct ValidatedThreatHintConfig {
    mode: RuntimeMode,
    network: ThreatHintNetwork,
    route_mode: ThreatHintRouteMode,
    guardian: StaticPeer,
    identity_path: PathBuf,
    submission_timeout: Duration,
}

impl fmt::Debug for ValidatedThreatHintConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedThreatHintConfig")
            .finish_non_exhaustive()
    }
}

/// Data-minimal machine-readable offline preflight result. It carries no
/// paths, addresses, keys, raw hint bytes, hashes, or operator identity.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ThreatHintPreflight {
    pub status: &'static str,
    pub runtime: &'static str,
    pub network: ThreatHintNetwork,
    pub route_scope: &'static str,
    pub identity: &'static str,
    pub hint: &'static str,
    pub ack_scope: &'static str,
    pub chain_writes: &'static str,
    pub network_activity: &'static str,
}

/// Stable data-only outcome of one bounded submission.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ThreatHintSubmissionStatus {
    Accepted,
    Duplicate,
    Rejected,
    Busy,
    TransportFailure,
}

impl ThreatHintSubmissionStatus {
    /// Stable machine-readable status name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Duplicate => "duplicate",
            Self::Rejected => "rejected",
            Self::Busy => "busy",
            Self::TransportFailure => "transport-failure",
        }
    }
}

/// Data-minimal machine-readable submission report. It carries no paths,
/// addresses, keys, raw hint bytes, hashes, or operator identity.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ThreatHintSubmitReport {
    pub status: ThreatHintSubmissionStatus,
    pub runtime: &'static str,
    pub network: ThreatHintNetwork,
    pub route_scope: &'static str,
    pub ack_scope: &'static str,
    pub ack_authority: &'static str,
    pub retries: u8,
    pub persisted: bool,
}

impl ThreatHintSubmitConfig {
    /// Read a private, bounded, ASCII-only TOML file without following symlinks.
    pub fn from_toml_file(path: &Path) -> Result<Self, ThreatHintP2pError> {
        let bytes = read_owner_file(path, MAX_CONFIG_BYTES)?;
        if !bytes.is_ascii() {
            return Err(ThreatHintP2pError);
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| ThreatHintP2pError)?;
        toml::from_str(text).map_err(|_| ThreatHintP2pError)
    }

    /// Validate all static policy without network access or identity mutation.
    ///
    /// Beta and Mainnet are rejected here, before any hint bytes are read or
    /// any network activity occurs, regardless of the claimed proof system.
    pub fn validate(
        &self,
        mode: RuntimeMode,
    ) -> Result<ValidatedThreatHintConfig, ThreatHintP2pError> {
        require_development(mode)?;
        if !self.enabled || self.network != ThreatHintNetwork::Testnet10 {
            return Err(ThreatHintP2pError);
        }
        if !(MIN_SUBMISSION_TIMEOUT_SECS..=MAX_SUBMISSION_TIMEOUT_SECS)
            .contains(&self.submission_timeout_secs)
        {
            return Err(ThreatHintP2pError);
        }
        validate_identity_path(&self.identity_path)?;
        let guardian = parse_static_route(
            &self.guardian_peer_id,
            &self.guardian_address,
            self.route_mode,
        )?;

        Ok(ValidatedThreatHintConfig {
            mode,
            network: self.network,
            route_mode: self.route_mode,
            guardian,
            identity_path: self.identity_path.clone(),
            submission_timeout: Duration::from_secs(self.submission_timeout_secs),
        })
    }
}

impl ValidatedThreatHintConfig {
    /// Verify all offline inputs without dialing and without creating or
    /// loading the transport identity.
    pub fn offline_preflight(
        &self,
        hint_path: &Path,
    ) -> Result<ThreatHintPreflight, ThreatHintP2pError> {
        require_development(self.mode)?;
        let _hint = read_canonical_hint(hint_path)?;
        let identity = preflight_identity_path(&self.identity_path)?;
        Ok(ThreatHintPreflight {
            status: "ready-for-development-threat-hint-submit",
            runtime: "development-only",
            network: self.network,
            route_scope: self.route_mode.route_scope(),
            identity,
            hint: "canonical-v1",
            ack_scope: "remote-local-boundary-only",
            chain_writes: "none",
            network_activity: "none",
        })
    }

    /// Submit one canonical v1 ThreatHint to the single static peer.
    ///
    /// The total network phase is bounded by the configured timeout, the real
    /// transport event loop is driven, and the outcome is reduced to a stable
    /// data-only status. There is no retry and no persistence.
    pub async fn submit(
        &self,
        hint_path: &Path,
    ) -> Result<ThreatHintSubmitReport, ThreatHintP2pError> {
        require_development(self.mode)?;
        let hint = read_canonical_hint(hint_path)?;
        let keypair = load_or_create_transport_identity(&self.identity_path)
            .map_err(|_| ThreatHintP2pError)?;

        let mut transport_config = GuardianP2pConfig::default();
        transport_config.static_peers.push(self.guardian.clone());
        transport_config.request_timeout = self.submission_timeout;
        transport_config.max_concurrent_requests = MAX_IN_FLIGHT_REQUESTS;
        let mut node =
            GuardianP2p::new(keypair, transport_config).map_err(|_| ThreatHintP2pError)?;

        let status = match node.send_threat_hint(self.guardian.peer_id, hint) {
            Ok(request_id) => {
                let drive = async {
                    loop {
                        match node.next_event().await {
                            TransportEvent::OutboundThreatHintAck {
                                request_id: received,
                                status,
                                ..
                            } if received == request_id => {
                                break status_from_ack(status);
                            }
                            TransportEvent::OutboundThreatHintFailure {
                                request_id: received,
                                ..
                            } if received == request_id => {
                                break ThreatHintSubmissionStatus::TransportFailure;
                            }
                            _ => {}
                        }
                    }
                };
                time::timeout(self.submission_timeout, drive)
                    .await
                    .unwrap_or(ThreatHintSubmissionStatus::TransportFailure)
            }
            // `OutboundBusy` is a local sender-capacity failure, not the
            // Guardian's authenticated `busy` acknowledgement.
            Err(TransportError::OutboundBusy { .. }) => {
                ThreatHintSubmissionStatus::TransportFailure
            }
            Err(_) => ThreatHintSubmissionStatus::TransportFailure,
        };

        Ok(ThreatHintSubmitReport {
            status,
            runtime: "development-only",
            network: self.network,
            route_scope: self.route_mode.route_scope(),
            ack_scope: "remote-local-boundary-only",
            ack_authority: "none",
            retries: 0,
            persisted: false,
        })
    }
}

fn require_development(mode: RuntimeMode) -> Result<(), ThreatHintP2pError> {
    require_stub_allowed(COMPONENT).map_err(|_| ThreatHintP2pError)?;
    require_stub_allowed_for(mode, COMPONENT).map_err(|_| ThreatHintP2pError)?;
    if mode != RuntimeMode::Development {
        return Err(ThreatHintP2pError);
    }
    Ok(())
}

/// Parse exactly one canonical static Guardian peer route: a canonical peer id
/// and a canonical `/ip4|ip6/<literal>/udp/<port>/quic-v1/p2p/<peer>` route.
/// The route mode bounds the literal: loopback-only by default, or the GH-229
/// controlled-remote literal policy on explicit opt-in. DNS, TCP, wildcard,
/// unspecified, multicast, relay, and any other form fail.
fn parse_static_route(
    peer_text: &str,
    address_text: &str,
    route_mode: ThreatHintRouteMode,
) -> Result<StaticPeer, ThreatHintP2pError> {
    if peer_text.is_empty() || address_text.is_empty() {
        return Err(ThreatHintP2pError);
    }
    let peer = StaticPeer {
        peer_id: peer_text.parse().map_err(|_| ThreatHintP2pError)?,
        address: address_text.parse().map_err(|_| ThreatHintP2pError)?,
    };
    if peer.peer_id.to_string() != peer_text || peer.address.to_string() != address_text {
        return Err(ThreatHintP2pError);
    }
    let accepted = match route_mode {
        ThreatHintRouteMode::Loopback => is_single_loopback_quic_route(address_text, peer_text),
        ThreatHintRouteMode::ControlledRemoteTestnet10 => {
            is_single_controlled_remote_quic_route(address_text, peer_text)
        }
    };
    if !accepted {
        return Err(ThreatHintP2pError);
    }
    Ok(peer)
}

/// The literal of one direct QUIC-v1 route after canonical text checks.
enum RouteLiteral {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

/// Strictly match the canonical text form of one direct literal QUIC-v1 route
/// and return its parsed literal. The canonical round-trip check in
/// `parse_static_route` runs first, so the text shape is fully determined
/// here.
fn canonical_quic_route_literal(address: &str, peer_text: &str) -> Option<RouteLiteral> {
    let segments: Vec<&str> = address.split('/').collect();
    if segments.len() != 8
        || !segments[0].is_empty()
        || segments[3] != "udp"
        || segments[5] != "quic-v1"
        || segments[6] != "p2p"
        || segments[7] != peer_text
    {
        return None;
    }
    match segments[4].parse::<u16>() {
        Ok(0) | Err(_) => return None,
        Ok(_) => {}
    }
    match segments[1] {
        "ip4" => segments[2].parse::<Ipv4Addr>().ok().map(RouteLiteral::V4),
        "ip6" => segments[2].parse::<Ipv6Addr>().ok().map(RouteLiteral::V6),
        _ => None,
    }
}

/// Accept exactly one direct literal-loopback QUIC-v1 route.
fn is_single_loopback_quic_route(address: &str, peer_text: &str) -> bool {
    match canonical_quic_route_literal(address, peer_text) {
        Some(RouteLiteral::V4(ip)) => ip.is_loopback(),
        Some(RouteLiteral::V6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Accept exactly one direct literal QUIC-v1 route for the GH-229 controlled
/// remote opt-in: no loopback, link-local, documentation, benchmarking,
/// broadcast/reserved, IPv4-mapped, wildcard, unspecified, or multicast
/// literal. RFC1918, CGNAT, ULA, and normal global literals are allowed.
fn is_single_controlled_remote_quic_route(address: &str, peer_text: &str) -> bool {
    match canonical_quic_route_literal(address, peer_text) {
        Some(RouteLiteral::V4(ip)) => is_allowed_remote_ipv4(ip),
        Some(RouteLiteral::V6(ip)) => is_allowed_remote_ipv6(ip),
        None => false,
    }
}

fn is_allowed_remote_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, d] = ip.octets();
    !(a == 0 // 0/8 "this network"
        || a == 127 // 127/8 loopback
        || (a == 169 && b == 254) // 169.254/16 link-local
        || (a == 192 && b == 0 && c == 0 && d != 9 && d != 10) // IETF protocol assignments
        || (a == 192 && b == 0 && c == 2) // 192.0.2/24 documentation
        || (a == 192 && b == 88 && c == 99) // deprecated 6to4 relay anycast
        || (a == 198 && ((b == 51 && c == 100) || b == 18 || b == 19)) // TEST-NET-2, 198.18/15
        || (a == 203 && b == 0 && c == 113) // 203.0.113/24 documentation
        || a >= 224) // 224/4 multicast and 240/4 reserved including broadcast
}

fn is_allowed_remote_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    let unique_local = (segments[0] & 0xfe00) == 0xfc00;
    let special_or_transition = segments[0] == 0x2001
        && (segments[1] <= 0x01ff || segments[1] == 0x0db8)
        || segments[0] == 0x2002
        || segments[0] == 0x3ffe;
    let normal_global_unicast = (segments[0] & 0xe000) == 0x2000 && !special_or_transition;
    unique_local || normal_global_unicast
}

fn validate_identity_path(path: &Path) -> Result<(), ThreatHintP2pError> {
    if !is_absolute_file_path(path) {
        return Err(ThreatHintP2pError);
    }
    Ok(())
}

fn is_absolute_file_path(path: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|component| component == Component::ParentDir)
        && matches!(path.components().next_back(), Some(Component::Normal(_)))
}

/// Read-only identity metadata check for offline preflight. It never creates,
/// loads, or modifies the identity; guardian-p2p owns that on submit.
fn preflight_identity_path(path: &Path) -> Result<&'static str, ThreatHintP2pError> {
    let parent = path.parent().ok_or(ThreatHintP2pError)?;
    validate_owner_only_parent(parent)?;
    match path.symlink_metadata() {
        Ok(metadata) => {
            let mode = metadata.mode();
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.uid() != process::geteuid().as_raw()
                || metadata.nlink() != 1
                || mode & 0o177 != 0
                || mode & 0o400 == 0
                || mode & 0o7000 != 0
                || metadata.size() == 0
                || metadata.size() > MAX_IDENTITY_FILE_BYTES
            {
                return Err(ThreatHintP2pError);
            }
            Ok("owner-only-existing")
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok("owner-only-create-on-submit")
        }
        Err(_) => Err(ThreatHintP2pError),
    }
}

/// Read one canonical v1 hint from an owner-only file with a strict size cap,
/// preserving the exact canonical bytes.
fn read_canonical_hint(path: &Path) -> Result<ThreatHintBytes, ThreatHintP2pError> {
    let bytes = read_owner_file(path, MAX_THREAT_HINT_BYTES)?;
    ThreatHintBytes::new(bytes).map_err(|_| ThreatHintP2pError)
}

fn read_owner_file(path: &Path, maximum: usize) -> Result<Vec<u8>, ThreatHintP2pError> {
    if !is_absolute_file_path(path) {
        return Err(ThreatHintP2pError);
    }
    let parent = path.parent().ok_or(ThreatHintP2pError)?;
    validate_owner_only_parent(parent)?;
    let file = fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| ThreatHintP2pError)?;
    let stat = fs::fstat(&file).map_err(|_| ThreatHintP2pError)?;
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
        return Err(ThreatHintP2pError);
    }
    let mut bytes = Vec::with_capacity((stat.st_size as usize).min(maximum));
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ThreatHintP2pError)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(ThreatHintP2pError);
    }
    Ok(bytes)
}

fn validate_owner_only_parent(parent: &Path) -> Result<(), ThreatHintP2pError> {
    let metadata = parent.symlink_metadata().map_err(|_| ThreatHintP2pError)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != process::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(ThreatHintP2pError);
    }
    Ok(())
}

fn status_from_ack(status: ThreatHintAckStatus) -> ThreatHintSubmissionStatus {
    match status {
        ThreatHintAckStatus::Accepted => ThreatHintSubmissionStatus::Accepted,
        ThreatHintAckStatus::Duplicate => ThreatHintSubmissionStatus::Duplicate,
        ThreatHintAckStatus::Rejected => ThreatHintSubmissionStatus::Rejected,
        ThreatHintAckStatus::Busy => ThreatHintSubmissionStatus::Busy,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};

    use tempfile::TempDir;

    use super::*;

    const VALID_HINT: &[u8] = br#"{"schema_version":1,"threat_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","confidence_bps":9000,"indicator_type":"file_hash","proof_system":"groth16_kip16_v1","proof":"010203","report_nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","observed_at":1}"#;

    fn owner_only_dir() -> TempDir {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("owner-only directory");
        directory
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("write fixture");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("owner-only fixture");
    }

    fn generated_peer_text(directory: &Path) -> String {
        let keypair = load_or_create_transport_identity(&directory.join("peer.identity"))
            .expect("fixture identity");
        keypair.public().to_peer_id().to_string()
    }

    fn config_text(peer: &str, identity_path: &Path, address: &str, timeout_secs: u64) -> String {
        config_text_with_route_mode(peer, identity_path, address, timeout_secs, None)
    }

    fn config_text_with_route_mode(
        peer: &str,
        identity_path: &Path,
        address: &str,
        timeout_secs: u64,
        route_mode: Option<&str>,
    ) -> String {
        let mode_line = route_mode
            .map(|mode| format!("route_mode = \"{mode}\"\n"))
            .unwrap_or_default();
        format!(
            "enabled = true\nnetwork = \"testnet10\"\n{mode_line}guardian_peer_id = \"{peer}\"\nguardian_address = \"{address}\"\nidentity_path = \"{}\"\nsubmission_timeout_secs = {timeout_secs}\n",
            identity_path.display()
        )
    }

    struct Fixture {
        _directory: TempDir,
        config_path: PathBuf,
        hint_path: PathBuf,
        identity_path: PathBuf,
        peer: String,
        address: String,
    }

    fn fixture() -> Fixture {
        let directory = owner_only_dir();
        let base = directory.path();
        let identity_path = base.join("client.identity");
        let peer = generated_peer_text(base);
        let address = format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p/{peer}");
        let config_path = base.join("threat-hint.toml");
        write_private(
            &config_path,
            config_text(&peer, &identity_path, &address, 10).as_bytes(),
        );
        let hint_path = base.join("hint.json");
        write_private(&hint_path, VALID_HINT);
        Fixture {
            _directory: directory,
            config_path,
            hint_path,
            identity_path,
            peer,
            address,
        }
    }

    impl Fixture {
        fn load(&self) -> ThreatHintSubmitConfig {
            ThreatHintSubmitConfig::from_toml_file(&self.config_path).expect("valid config")
        }
    }

    #[test]
    fn valid_fixture_validates_in_development() {
        let fixture = fixture();
        fixture
            .load()
            .validate(RuntimeMode::Development)
            .expect("development validation");
    }

    #[test]
    fn rejects_unknown_fields_and_wallet_or_seed_material() {
        let fixture = fixture();
        for extra in [
            "wallet_seed = \"00\"",
            "signing_key = \"00\"",
            "keystore_path = \"/tmp/x\"",
            "unknown_field = true",
        ] {
            let directory = owner_only_dir();
            let path = directory.path().join("config.toml");
            let mut text = config_text(&fixture.peer, &fixture.identity_path, &fixture.address, 10);
            text.push_str(extra);
            text.push('\n');
            write_private(&path, text.as_bytes());
            assert!(
                ThreatHintSubmitConfig::from_toml_file(&path).is_err(),
                "unknown or secret-bearing field must fail: {extra}"
            );
        }
    }

    #[test]
    fn rejects_disabled_and_out_of_range_timeout() {
        let fixture = fixture();
        for timeout in [0, 61] {
            let directory = owner_only_dir();
            let path = directory.path().join("config.toml");
            write_private(
                &path,
                config_text(
                    &fixture.peer,
                    &fixture.identity_path,
                    &fixture.address,
                    timeout,
                )
                .as_bytes(),
            );
            assert!(ThreatHintSubmitConfig::from_toml_file(&path)
                .expect("parses")
                .validate(RuntimeMode::Development)
                .is_err());
        }

        let directory = owner_only_dir();
        let path = directory.path().join("config.toml");
        let disabled = config_text(&fixture.peer, &fixture.identity_path, &fixture.address, 10)
            .replace("enabled = true", "enabled = false");
        write_private(&path, disabled.as_bytes());
        assert!(ThreatHintSubmitConfig::from_toml_file(&path)
            .expect("parses")
            .validate(RuntimeMode::Development)
            .is_err());

        assert_eq!(MIN_SUBMISSION_TIMEOUT_SECS, 1);
        assert_eq!(MAX_SUBMISSION_TIMEOUT_SECS, 60);
        for timeout in [1, 60] {
            let directory = owner_only_dir();
            let path = directory.path().join("config.toml");
            write_private(
                &path,
                config_text(
                    &fixture.peer,
                    &fixture.identity_path,
                    &fixture.address,
                    timeout,
                )
                .as_bytes(),
            );
            ThreatHintSubmitConfig::from_toml_file(&path)
                .expect("parses")
                .validate(RuntimeMode::Development)
                .expect("inclusive timeout boundary");
        }
    }

    #[test]
    fn beta_and_mainnet_reject_before_any_network_activity() {
        // The gate runs in validate() before the hint is read and before any
        // transport exists. The fixture hint claims a non-stub groth16_kip16_v1
        // proof; that claim is never inspected and cannot bypass the gate.
        let fixture = fixture();
        let config = fixture.load();
        for mode in [RuntimeMode::Beta, RuntimeMode::Mainnet] {
            assert!(config.validate(mode).is_err());
        }
    }

    #[test]
    fn rejects_relative_paths() {
        let fixture = fixture();
        assert!(ThreatHintSubmitConfig::from_toml_file(Path::new("relative.toml")).is_err());

        let directory = owner_only_dir();
        let path = directory.path().join("config.toml");
        let relative_identity = config_text(
            &fixture.peer,
            Path::new("relative/identity"),
            &fixture.address,
            10,
        );
        write_private(&path, relative_identity.as_bytes());
        assert!(ThreatHintSubmitConfig::from_toml_file(&path)
            .expect("parses")
            .validate(RuntimeMode::Development)
            .is_err());

        let validated = fixture
            .load()
            .validate(RuntimeMode::Development)
            .expect("valid");
        assert!(validated
            .offline_preflight(Path::new("relative-hint.json"))
            .is_err());

        let parent_alias = fixture
            .config_path
            .parent()
            .expect("config parent")
            .join("nested")
            .join("..")
            .join("threat-hint.toml");
        assert!(ThreatHintSubmitConfig::from_toml_file(&parent_alias).is_err());

        let directory = owner_only_dir();
        let path = directory.path().join("config.toml");
        let parent_identity = directory.path().join("nested").join("..").join("identity");
        write_private(
            &path,
            config_text(&fixture.peer, &parent_identity, &fixture.address, 10).as_bytes(),
        );
        assert!(ThreatHintSubmitConfig::from_toml_file(&path)
            .expect("parses")
            .validate(RuntimeMode::Development)
            .is_err());
    }

    #[test]
    fn rejects_group_readable_and_symlinked_config() {
        let fixture = fixture();

        let group_readable = owner_only_dir();
        let path = group_readable.path().join("config.toml");
        fs::copy(&fixture.config_path, &path).expect("copy config");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("mode 0640");
        assert!(ThreatHintSubmitConfig::from_toml_file(&path).is_err());

        let symlinked = owner_only_dir();
        let link = symlinked.path().join("config.toml");
        symlink(&fixture.config_path, &link).expect("config symlink");
        assert!(ThreatHintSubmitConfig::from_toml_file(&link).is_err());

        let hard_linked = owner_only_dir();
        let source = hard_linked.path().join("source.toml");
        let link = hard_linked.path().join("config.toml");
        fs::copy(&fixture.config_path, &source).expect("copy config");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).expect("mode 0600");
        fs::hard_link(&source, &link).expect("config hard link");
        assert!(ThreatHintSubmitConfig::from_toml_file(&link).is_err());

        let loose_parent = owner_only_dir();
        let inner = loose_parent.path().join("inner");
        fs::create_dir(&inner).expect("inner directory");
        fs::set_permissions(&inner, fs::Permissions::from_mode(0o755)).expect("mode 0755");
        let path = inner.join("config.toml");
        fs::copy(&fixture.config_path, &path).expect("copy config");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode 0600");
        assert!(ThreatHintSubmitConfig::from_toml_file(&path).is_err());
    }

    #[test]
    fn rejects_oversized_config() {
        let directory = owner_only_dir();
        let path = directory.path().join("config.toml");
        let mut text = config_text(
            &generated_peer_text(directory.path()),
            &directory.path().join("identity"),
            "/ip4/127.0.0.1/udp/4001/quic-v1",
            10,
        );
        text.push_str(&"#".repeat(MAX_CONFIG_BYTES));
        write_private(&path, text.as_bytes());
        assert!(ThreatHintSubmitConfig::from_toml_file(&path).is_err());

        let path = directory.path().join("non-ascii.toml");
        write_private(&path, b"enabled = true\n# \xff\n");
        assert!(ThreatHintSubmitConfig::from_toml_file(&path).is_err());
    }

    #[test]
    fn rejects_noncanonical_or_unsafe_routes() {
        let fixture = fixture();
        let other_dir = owner_only_dir();
        let other_peer = generated_peer_text(other_dir.path());
        let identity = fixture.identity_path.clone();
        let peer = fixture.peer.clone();

        let invalid_addresses = [
            format!("/ip4/8.8.8.8/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip4/0.0.0.0/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip4/224.0.0.1/udp/4001/quic-v1/p2p/{peer}"),
            format!("/dns4/example.invalid/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip4/127.0.0.1/udp/0/quic-v1/p2p/{peer}"),
            "/ip4/127.0.0.1/udp/4001/quic-v1".to_owned(),
            format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p/{other_peer}"),
            format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p/{other_peer}/p2p-circuit/p2p/{peer}"),
            format!("/ip4/127.0.0.1/tcp/4001/p2p/{peer}"),
            format!("/ip4/127.0.0.1/udp/4001/quic/p2p/{peer}"),
        ];
        for address in invalid_addresses {
            let directory = owner_only_dir();
            let path = directory.path().join("config.toml");
            write_private(
                &path,
                config_text(&peer, &identity, &address, 10).as_bytes(),
            );
            assert!(
                ThreatHintSubmitConfig::from_toml_file(&path)
                    .expect("parses")
                    .validate(RuntimeMode::Development)
                    .is_err(),
                "unsafe route must fail: {address}"
            );
        }

        let ipv6 = format!("/ip6/::1/udp/4001/quic-v1/p2p/{peer}");
        let directory = owner_only_dir();
        let path = directory.path().join("config.toml");
        write_private(&path, config_text(&peer, &identity, &ipv6, 10).as_bytes());
        ThreatHintSubmitConfig::from_toml_file(&path)
            .expect("parses")
            .validate(RuntimeMode::Development)
            .expect("literal loopback IPv6 route is valid");
    }

    /// Write a remote-mode config and return its validation result.
    fn validate_remote_config(peer: &str, identity: &Path, address: &str) -> bool {
        let directory = owner_only_dir();
        let path = directory.path().join("config.toml");
        write_private(
            &path,
            config_text_with_route_mode(
                peer,
                identity,
                address,
                10,
                Some("controlled-remote-testnet10"),
            )
            .as_bytes(),
        );
        ThreatHintSubmitConfig::from_toml_file(&path)
            .expect("parses")
            .validate(RuntimeMode::Development)
            .is_ok()
    }

    #[test]
    fn controlled_remote_accepts_bounded_literal_routes() {
        let fixture = fixture();
        let peer = fixture.peer.clone();
        let identity = fixture.identity_path.clone();
        for address in [
            format!("/ip4/10.8.0.1/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip4/172.16.5.4/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip4/192.168.1.20/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip4/100.64.0.1/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip4/100.127.255.254/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip4/8.8.8.8/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip6/fd00::1/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip6/fc00::ffff/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip6/2606:4700:4700::1111/udp/4001/quic-v1/p2p/{peer}"),
        ] {
            assert!(
                validate_remote_config(&peer, &identity, &address),
                "bounded remote route must validate: {address}"
            );
        }
    }

    #[test]
    fn controlled_remote_rejects_forbidden_ranges_and_shapes() {
        let fixture = fixture();
        let other_dir = owner_only_dir();
        let other_peer = generated_peer_text(other_dir.path());
        let peer = fixture.peer.clone();
        let identity = fixture.identity_path.clone();

        let forbidden = [
            // Loopback: full 127/8 and ::1.
            format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip4/127.53.0.9/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip6/::1/udp/4001/quic-v1/p2p/{peer}"),
            // IPv4-mapped IPv6 in canonical text form, loopback and global.
            format!("/ip6/::ffff:7f00:1/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip6/::ffff:808:808/udp/4001/quic-v1/p2p/{peer}"),
            // Link-local: 169.254/16 and fe80::/10.
            format!("/ip4/169.254.0.1/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip4/169.254.255.254/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip6/fe80::1/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip6/febf::ffff/udp/4001/quic-v1/p2p/{peer}"),
            // Documentation: all three IPv4 nets and 2001:db8::/32.
            format!("/ip4/192.0.2.1/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip4/192.0.0.1/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip4/192.88.99.1/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip4/198.51.100.1/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip4/203.0.113.1/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip6/2001:db8::1/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip6/2001:db8:ffff::ffff/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip6/100::1/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip6/2001::1/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip6/2002:7f00:1::1/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip6/3ffe::1/udp/4001/quic-v1/p2p/{peer}"),
            // 0/8 "this network" including the unspecified wildcard.
            format!("/ip4/0.0.0.0/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip4/0.1.2.3/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip6/::/udp/4001/quic-v1/p2p/{peer}"),
            // 198.18/15 benchmarking.
            format!("/ip4/198.18.0.1/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip4/198.19.255.254/udp/4001/quic-v1/p2p/{peer}"),
            // 224/4 multicast and 240/4 reserved including broadcast.
            format!("/ip4/224.0.0.1/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip4/239.255.255.255/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip4/240.0.0.1/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip4/255.255.255.255/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip6/ff02::1/udp/4001/quic-v1/p2p/{peer}"),
            // Shape violations: DNS, TCP, plain quic, relay, missing or
            // mismatched /p2p/, zero port, and trailing components.
            format!("/dns4/guardian.example.invalid/udp/4001/quic-v1/p2p/{peer}"),
            format!("/ip4/10.8.0.1/tcp/4001/p2p/{peer}"),
            format!("/ip4/10.8.0.1/udp/4001/quic/p2p/{peer}"),
            format!("/ip4/10.8.0.1/udp/4001/quic-v1/p2p/{other_peer}/p2p-circuit/p2p/{peer}"),
            "/ip4/10.8.0.1/udp/4001/quic-v1".to_owned(),
            format!("/ip4/10.8.0.1/udp/4001/quic-v1/p2p/{other_peer}"),
            format!("/ip4/10.8.0.1/udp/0/quic-v1/p2p/{peer}"),
            format!("/ip4/10.8.0.1/udp/4001/quic-v1/p2p/{peer}/ws"),
        ];
        for address in forbidden {
            assert!(
                !validate_remote_config(&peer, &identity, &address),
                "forbidden remote route must fail: {address}"
            );
        }

        // Dotted IPv4-mapped text is noncanonical and fails before policy.
        let dotted = format!("/ip6/::ffff:127.0.0.1/udp/4001/quic-v1/p2p/{peer}");
        assert!(!validate_remote_config(&peer, &identity, &dotted));
        let dotted = format!("/ip6/::ffff:8.8.8.8/udp/4001/quic-v1/p2p/{peer}");
        assert!(!validate_remote_config(&peer, &identity, &dotted));
    }

    #[test]
    fn route_mode_defaults_to_loopback_and_rejects_unknown_values() {
        let fixture = fixture();
        let remote = format!(
            "/ip4/10.8.0.1/udp/4001/quic-v1/p2p/{peer}",
            peer = fixture.peer
        );

        // Absent field keeps exact loopback behavior: the bounded remote
        // literal stays rejected.
        let directory = owner_only_dir();
        let path = directory.path().join("config.toml");
        write_private(
            &path,
            config_text(&fixture.peer, &fixture.identity_path, &remote, 10).as_bytes(),
        );
        assert!(ThreatHintSubmitConfig::from_toml_file(&path)
            .expect("parses")
            .validate(RuntimeMode::Development)
            .is_err());

        // Explicit loopback mode behaves identically to the absent default.
        let path = directory.path().join("explicit.toml");
        write_private(
            &path,
            config_text_with_route_mode(
                &fixture.peer,
                &fixture.identity_path,
                &remote,
                10,
                Some("loopback"),
            )
            .as_bytes(),
        );
        assert!(ThreatHintSubmitConfig::from_toml_file(&path)
            .expect("parses")
            .validate(RuntimeMode::Development)
            .is_err());

        // Unknown wire values are rejected at parse time.
        let path = directory.path().join("unknown.toml");
        write_private(
            &path,
            config_text_with_route_mode(
                &fixture.peer,
                &fixture.identity_path,
                &fixture.address,
                10,
                Some("public"),
            )
            .as_bytes(),
        );
        assert!(ThreatHintSubmitConfig::from_toml_file(&path).is_err());
    }

    #[test]
    fn remote_mode_reports_controlled_scope_and_stays_redacted() {
        let fixture = fixture();
        let remote = format!(
            "/ip4/10.8.0.1/udp/4001/quic-v1/p2p/{peer}",
            peer = fixture.peer
        );
        let directory = owner_only_dir();
        let config_path = directory.path().join("config.toml");
        write_private(
            &config_path,
            config_text_with_route_mode(
                &fixture.peer,
                &fixture.identity_path,
                &remote,
                10,
                Some("controlled-remote-testnet10"),
            )
            .as_bytes(),
        );
        let validated = ThreatHintSubmitConfig::from_toml_file(&config_path)
            .expect("parses")
            .validate(RuntimeMode::Development)
            .expect("valid remote config");

        let preflight = validated
            .offline_preflight(&fixture.hint_path)
            .expect("remote preflight");
        assert_eq!(
            preflight.route_scope,
            "single-static-controlled-remote-quic-peer"
        );
        let output = serde_json::to_string(&preflight).expect("serialize preflight");
        for forbidden in [
            fixture.peer.as_str(),
            "10.8.0.1",
            fixture.identity_path.to_string_lossy().as_ref(),
        ] {
            assert!(
                !output.contains(forbidden),
                "remote report must not expose {forbidden:?}: {output}"
            );
        }

        // Beta and Mainnet reject the remote mode before identity mutation or
        // any network activity, exactly like the loopback default.
        let config = ThreatHintSubmitConfig::from_toml_file(&config_path).expect("parses");
        for mode in [RuntimeMode::Beta, RuntimeMode::Mainnet] {
            assert!(config.validate(mode).is_err());
        }
        assert!(
            !fixture.identity_path.exists(),
            "rejected remote runs must not create the transport identity"
        );
    }

    #[test]
    fn hint_file_is_strict() {
        let fixture = fixture();
        let validated = fixture
            .load()
            .validate(RuntimeMode::Development)
            .expect("valid");

        let mut noncanonical = VALID_HINT.to_vec();
        noncanonical.push(b'\n');
        let oversized = vec![b'x'; MAX_THREAT_HINT_BYTES + 1];
        for (name, bytes) in [
            ("malformed.json", &b"not json"[..]),
            ("noncanonical.json", &noncanonical[..]),
            ("oversized.json", &oversized[..]),
            ("empty.json", &b""[..]),
        ] {
            let directory = owner_only_dir();
            let path = directory.path().join(name);
            write_private(&path, bytes);
            assert!(
                validated.offline_preflight(&path).is_err(),
                "invalid hint must fail: {name}"
            );
        }

        let group_readable = owner_only_dir();
        let path = group_readable.path().join("hint.json");
        write_private(&path, VALID_HINT);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("mode 0644");
        assert!(validated.offline_preflight(&path).is_err());

        let symlinked = owner_only_dir();
        let link = symlinked.path().join("hint.json");
        symlink(&fixture.hint_path, &link).expect("hint symlink");
        assert!(validated.offline_preflight(&link).is_err());

        let hard_linked = owner_only_dir();
        let source = hard_linked.path().join("source.json");
        let link = hard_linked.path().join("hint.json");
        write_private(&source, VALID_HINT);
        fs::hard_link(&source, &link).expect("hint hard link");
        assert!(validated.offline_preflight(&link).is_err());
    }

    #[test]
    fn preflight_is_offline_and_non_mutating() {
        let fixture = fixture();
        let validated = fixture
            .load()
            .validate(RuntimeMode::Development)
            .expect("valid");

        let report = validated
            .offline_preflight(&fixture.hint_path)
            .expect("preflight");
        assert_eq!(report.status, "ready-for-development-threat-hint-submit");
        assert_eq!(report.identity, "owner-only-create-on-submit");
        assert_eq!(report.network_activity, "none");
        assert!(
            !fixture.identity_path.exists(),
            "preflight must not create the transport identity"
        );

        let keypair = load_or_create_transport_identity(&fixture.identity_path).expect("identity");
        drop(keypair);
        let report = validated
            .offline_preflight(&fixture.hint_path)
            .expect("preflight with existing identity");
        assert_eq!(report.identity, "owner-only-existing");
    }

    #[test]
    fn preflight_rejects_unsafe_identity_metadata() {
        let directory = owner_only_dir();
        let peer = generated_peer_text(directory.path());
        let identity_path = directory.path().join("client.identity");
        write_private(&identity_path, b"identity-placeholder");
        fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o644)).expect("mode 0644");

        let config_path = directory.path().join("config.toml");
        let hint_path = directory.path().join("hint.json");
        let address = format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p/{peer}");
        write_private(
            &config_path,
            config_text(&peer, &identity_path, &address, 10).as_bytes(),
        );
        write_private(&hint_path, VALID_HINT);

        let validated = ThreatHintSubmitConfig::from_toml_file(&config_path)
            .expect("parses")
            .validate(RuntimeMode::Development)
            .expect("valid");
        assert!(validated.offline_preflight(&hint_path).is_err());
    }

    #[test]
    fn status_strings_and_reports_are_stable_and_redacted() {
        assert_eq!(ThreatHintSubmissionStatus::Accepted.as_str(), "accepted");
        assert_eq!(ThreatHintSubmissionStatus::Duplicate.as_str(), "duplicate");
        assert_eq!(ThreatHintSubmissionStatus::Rejected.as_str(), "rejected");
        assert_eq!(ThreatHintSubmissionStatus::Busy.as_str(), "busy");
        assert_eq!(
            ThreatHintSubmissionStatus::TransportFailure.as_str(),
            "transport-failure"
        );
        assert_eq!(
            status_from_ack(ThreatHintAckStatus::Accepted),
            ThreatHintSubmissionStatus::Accepted
        );
        assert_eq!(
            status_from_ack(ThreatHintAckStatus::Duplicate),
            ThreatHintSubmissionStatus::Duplicate
        );
        assert_eq!(
            status_from_ack(ThreatHintAckStatus::Rejected),
            ThreatHintSubmissionStatus::Rejected
        );
        assert_eq!(
            status_from_ack(ThreatHintAckStatus::Busy),
            ThreatHintSubmissionStatus::Busy
        );

        let fixture = fixture();
        let validated = fixture
            .load()
            .validate(RuntimeMode::Development)
            .expect("valid");
        let preflight = serde_json::to_string(
            &validated
                .offline_preflight(&fixture.hint_path)
                .expect("preflight"),
        )
        .expect("serialize preflight");
        let submit = serde_json::to_string(&ThreatHintSubmitReport {
            status: ThreatHintSubmissionStatus::Accepted,
            runtime: "development-only",
            network: ThreatHintNetwork::Testnet10,
            route_scope: "single-static-loopback-quic-peer",
            ack_scope: "remote-local-boundary-only",
            ack_authority: "none",
            retries: 0,
            persisted: false,
        })
        .expect("serialize submit report");
        for output in [preflight, submit] {
            for forbidden in [
                fixture.peer.as_str(),
                fixture.hint_path.to_string_lossy().as_ref(),
                fixture.identity_path.to_string_lossy().as_ref(),
                "127.0.0.1",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ] {
                assert!(
                    !output.contains(forbidden),
                    "report must not expose {forbidden:?}: {output}"
                );
            }
        }
    }
}
