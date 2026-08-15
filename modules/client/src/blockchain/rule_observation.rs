//! Development-only Testnet-10 `RuleStorage` UTXO observation boundary.
//!
//! Verifies that one caller-supplied, owner-pinned manifest is consistent with
//! one caller-supplied set of RPC-shaped UTXO observations, then decodes the
//! exact constructor-args JSON the manifest binds (via GH-193
//! [`decode_rule_state`]) only after every observation and hash check passes.
//!
//! The owner trust root is the `expected_manifest_sha256` supplied separately
//! by the caller; a self-hash inside the manifest alone would be insufficient.
//! The manifest must hash to that expected value, and both manifest and
//! observation documents must be strict canonical compact JSON (parse followed
//! by serialize must reproduce the exact input bytes, unknown fields are
//! rejected, and a size cap is enforced before parsing).
//!
//! Because the pinned `rusty-kaspa` v2.0.1 RPC surface only supports
//! `get_utxos_by_addresses`, unrelated entries may appear in the observation.
//! Exactly one entry must match the manifest outpoint; zero, duplicate, or
//! conflicting matches are rejected. The matched entry must equal the manifest
//! exactly on amount, script public key (version and script), block DAA
//! score, and covenant ID, must not be coinbase, and must satisfy the DAA
//! maturity floor `observed_virtual_daa_score - block_daa_score >=
//! minimum_virtual_daa_maturity` with checked subtraction.
//!
//! This boundary proves **only** owner-pin manifest-to-caller-observation
//! consistency. It does **not** prove manifest authority, RPC truth,
//! transaction history, finality, IPFS/content availability, or production
//! readiness. The virtual-DAA delta is a maturity proxy, not finality.
//!
//! The pure verifier accepts caller-supplied observations. The development-only
//! live adapter acquires UTXOs and virtual DAA from a connected
//! [`KaspaConnection`] for one explicit Testnet-10 address, converts only fields
//! returned by the pinned RPC API, and invokes the same verifier. This adds no
//! RPC-truth, finality, manifest-authority, or production claim.
//!
//! This is a development-only path: every public entry point calls
//! `require_stub_allowed` and therefore rejects beta/mainnet. The `_for_mode`
//! helper can only make tests stricter; it can never weaken the process-wide
//! beta/mainnet env gate.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use kaspa_addresses::{Address, Prefix};
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_rpc_core::RpcUtxosByAddressesEntry;
use kaspa_wrpc_client::prelude::{NetworkId, NetworkType};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::time::timeout;

use crate::runtime::{require_stub_allowed, require_stub_allowed_for, RuntimeMode};

use super::connection::KaspaConnection;
use super::rule_state::{decode_rule_state, RuleStateMetadata, MAX_STATE_JSON_BYTES};

/// Maximum bytes accepted for the manifest JSON document, checked before parsing.
pub const MAX_MANIFEST_JSON_BYTES: usize = 16 * 1024;
/// Maximum bytes accepted for the observation JSON document, checked before parsing.
pub const MAX_OBSERVATION_JSON_BYTES: usize = 256 * 1024;
/// Maximum number of UTXO entries accepted in one observation.
pub const MAX_OBSERVATION_ENTRIES: usize = 256;

/// Exact schema version pinned for both documents.
pub const OBSERVATION_SCHEMA_VERSION: u64 = 1;
/// Exact `kind` pinned for the manifest document.
pub const MANIFEST_KIND: &str = "prometheus.rule_storage.manifest.v1";
/// Exact `kind` pinned for the observation document.
pub const OBSERVATION_KIND: &str = "prometheus.rule_storage.observation.v1";
/// Exact network both documents are pinned to.
pub const OBSERVATION_NETWORK_ID: &str = "testnet-10";

const LIVE_OBSERVATION_RPC_TIMEOUT: Duration = Duration::from_secs(10);

/// The single public observation error.
///
/// Deliberately generic: Display/Debug/logging never contain manifest or
/// observation hashes, outpoints, covenant IDs, script bytes, amounts,
/// scores, or any decoded state value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleObservationError;

impl std::fmt::Display for RuleObservationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid RuleStorage UTXO observation")
    }
}

impl std::error::Error for RuleObservationError {}

/// Node fields required to construct one canonical GH-197 observation.
///
/// Production snapshots copy these values directly from pinned rusty-kaspa RPC
/// responses. The public shape also permits deterministic dependency-injected
/// tests without network access.
pub struct RuleObservationSnapshot {
    /// Network reported by `get_block_dag_info`.
    pub network_id: NetworkId,
    /// Current virtual DAA score reported by the node.
    pub virtual_daa_score: u64,
    /// UTXOs returned for exactly the requested address.
    pub utxos: Vec<RpcUtxosByAddressesEntry>,
}

/// Boxed future returned by [`RuleObservationSource`].
pub type RuleObservationFuture<'a> = Pin<
    Box<dyn Future<Output = Result<RuleObservationSnapshot, RuleObservationError>> + Send + 'a>,
>;

/// Dependency-injected source for RuleStorage observations.
///
/// Implementations other than [`KaspaConnection`] are caller-trusted test or
/// embedding boundaries and do not constitute evidence that live RPC ran.
pub trait RuleObservationSource {
    /// Fetch one node snapshot for exactly `address`.
    fn observe_address<'a>(&'a self, address: &'a Address) -> RuleObservationFuture<'a>;
}

impl RuleObservationSource for KaspaConnection {
    fn observe_address<'a>(&'a self, address: &'a Address) -> RuleObservationFuture<'a> {
        Box::pin(async move {
            if !self.is_connected().await {
                return Err(RuleObservationError);
            }

            let client = self.rpc_client();
            let dag = {
                let client = timeout(LIVE_OBSERVATION_RPC_TIMEOUT, client.lock())
                    .await
                    .map_err(|_| RuleObservationError)?;
                timeout(LIVE_OBSERVATION_RPC_TIMEOUT, client.get_block_dag_info())
                    .await
                    .map_err(|_| RuleObservationError)?
                    .map_err(|_| RuleObservationError)?
            };
            let utxos = {
                let client = timeout(LIVE_OBSERVATION_RPC_TIMEOUT, client.lock())
                    .await
                    .map_err(|_| RuleObservationError)?;
                timeout(
                    LIVE_OBSERVATION_RPC_TIMEOUT,
                    client.get_utxos_by_addresses(vec![address.clone()]),
                )
                .await
                .map_err(|_| RuleObservationError)?
                .map_err(|_| RuleObservationError)?
            };

            Ok(RuleObservationSnapshot {
                network_id: dag.network,
                virtual_daa_score: dag.virtual_daa_score,
                utxos,
            })
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Outpoint {
    transaction_id: String,
    index: u32,
}

#[derive(Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct ScriptPublicKey {
    version: u16,
    script_hex: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u64,
    kind: String,
    network_id: String,
    outpoint: Outpoint,
    covenant_id: String,
    script_public_key: ScriptPublicKey,
    amount_sompi: u64,
    block_daa_score: u64,
    minimum_virtual_daa_maturity: u64,
    constructor_json_sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationEntry {
    outpoint: Outpoint,
    amount_sompi: u64,
    script_public_key: ScriptPublicKey,
    block_daa_score: u64,
    is_coinbase: bool,
    covenant_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    schema_version: u64,
    kind: String,
    network_id: String,
    observed_virtual_daa_score: u64,
    entries: Vec<ObservationEntry>,
}

/// Verify one owner-pinned manifest against caller-supplied UTXO observations
/// and decode the manifest-bound constructor state.
///
/// `expected_manifest_sha256` is the owner trust root: exactly 64 lowercase
/// hex characters, compared against SHA-256 of the exact canonical manifest
/// bytes. `constructor_json` is the exact Silverc `--constructor-args` JSON
/// document; its SHA-256 must equal the manifest binding before GH-193
/// decoding runs.
///
/// Development-only: rejects beta/mainnet via `require_stub_allowed`.
pub fn verify_rule_storage_observation(
    expected_manifest_sha256: &str,
    manifest_json: &str,
    observation_json: &str,
    constructor_json: &str,
) -> Result<RuleStateMetadata, RuleObservationError> {
    require_stub_allowed("RuleStorage UTXO observation").map_err(|_| RuleObservationError)?;
    verify_validated(
        expected_manifest_sha256,
        manifest_json,
        observation_json,
        constructor_json,
    )
}

/// Verify under an explicit runtime mode; identical policy to
/// [`verify_rule_storage_observation`]. The explicit mode can only be
/// stricter; it never weakens the process-wide env gate.
pub fn verify_rule_storage_observation_for_mode(
    mode: RuntimeMode,
    expected_manifest_sha256: &str,
    manifest_json: &str,
    observation_json: &str,
    constructor_json: &str,
) -> Result<RuleStateMetadata, RuleObservationError> {
    require_stub_allowed("RuleStorage UTXO observation").map_err(|_| RuleObservationError)?;
    require_stub_allowed_for(mode, "RuleStorage UTXO observation")
        .map_err(|_| RuleObservationError)?;
    verify_validated(
        expected_manifest_sha256,
        manifest_json,
        observation_json,
        constructor_json,
    )
}

/// Acquire one live Testnet-10 address observation and run the GH-197 verifier.
///
/// The supplied connection must already be connected. Every failure is reduced
/// to the generic [`RuleObservationError`], so node, address, outpoint, script,
/// and covenant details are never exposed through diagnostics. The path is
/// development-only and performs no wallet, signing, transaction, broadcast,
/// deployment, IPFS, activation, or production action.
pub async fn verify_rule_storage_observation_live(
    connection: &KaspaConnection,
    address: &str,
    expected_manifest_sha256: &str,
    manifest_json: &str,
    constructor_json: &str,
) -> Result<RuleStateMetadata, RuleObservationError> {
    verify_rule_storage_observation_live_with_source(
        connection,
        address,
        expected_manifest_sha256,
        manifest_json,
        constructor_json,
    )
    .await
}

/// Identical to [`verify_rule_storage_observation_live`] with an explicit mode.
///
/// The explicit mode can only tighten the process-wide runtime gate.
pub async fn verify_rule_storage_observation_live_for_mode(
    mode: RuntimeMode,
    connection: &KaspaConnection,
    address: &str,
    expected_manifest_sha256: &str,
    manifest_json: &str,
    constructor_json: &str,
) -> Result<RuleStateMetadata, RuleObservationError> {
    require_stub_allowed("live RuleStorage UTXO observation").map_err(|_| RuleObservationError)?;
    require_stub_allowed_for(mode, "live RuleStorage UTXO observation")
        .map_err(|_| RuleObservationError)?;
    verify_rule_storage_observation_live_inner(
        connection,
        address,
        expected_manifest_sha256,
        manifest_json,
        constructor_json,
    )
    .await
}

/// Run the live adapter with an injected source for deterministic tests.
pub async fn verify_rule_storage_observation_live_with_source(
    source: &dyn RuleObservationSource,
    address: &str,
    expected_manifest_sha256: &str,
    manifest_json: &str,
    constructor_json: &str,
) -> Result<RuleStateMetadata, RuleObservationError> {
    require_stub_allowed("live RuleStorage UTXO observation").map_err(|_| RuleObservationError)?;
    verify_rule_storage_observation_live_inner(
        source,
        address,
        expected_manifest_sha256,
        manifest_json,
        constructor_json,
    )
    .await
}

async fn verify_rule_storage_observation_live_inner(
    source: &dyn RuleObservationSource,
    address: &str,
    expected_manifest_sha256: &str,
    manifest_json: &str,
    constructor_json: &str,
) -> Result<RuleStateMetadata, RuleObservationError> {
    verify_observation_live_shared(
        source,
        address,
        expected_manifest_sha256,
        manifest_json,
        constructor_json,
    )
    .await
    .map(|(metadata, _)| metadata)
}

/// The single shared live/injected observation path: parse and check the
/// address, invoke the injected [`RuleObservationSource`], enforce the exact
/// Testnet-10 node network, returned-address equality, and entry cap, convert
/// the returned UTXOs into one canonical observation, and run the unchanged
/// GH-197 verification. Returns the decoded metadata and the verified manifest
/// outpoint for the crate-internal GH-205 composition layer.
///
/// Callers are responsible for the runtime-mode gate; the public live entry
/// points gate before delegating here.
pub(crate) async fn verify_observation_live_shared(
    source: &dyn RuleObservationSource,
    address: &str,
    expected_manifest_sha256: &str,
    manifest_json: &str,
    constructor_json: &str,
) -> Result<(RuleStateMetadata, VerifiedManifestOutpoint), RuleObservationError> {
    let address = Address::try_from(address).map_err(|_| RuleObservationError)?;
    let expected_network = NetworkId::with_suffix(NetworkType::Testnet, 10);
    // Address prefixes identify the testnet family; the snapshot check below
    // enforces the exact Testnet-10 suffix reported by the connected node.
    if address.prefix != Prefix::from(expected_network) {
        return Err(RuleObservationError);
    }

    let snapshot = source.observe_address(&address).await?;
    if snapshot.network_id != expected_network || snapshot.utxos.len() > MAX_OBSERVATION_ENTRIES {
        return Err(RuleObservationError);
    }

    let observation_json = build_live_observation_json(&address, &snapshot)?;
    verify_observation_shared(
        expected_manifest_sha256,
        manifest_json,
        &observation_json,
        constructor_json,
    )
}

fn build_live_observation_json(
    address: &Address,
    snapshot: &RuleObservationSnapshot,
) -> Result<String, RuleObservationError> {
    let mut entries = Vec::with_capacity(snapshot.utxos.len());
    for entry in &snapshot.utxos {
        if entry.address.as_ref() != Some(address) {
            return Err(RuleObservationError);
        }

        entries.push(ObservationEntry {
            outpoint: Outpoint {
                transaction_id: entry.outpoint.transaction_id.to_string(),
                index: entry.outpoint.index,
            },
            amount_sompi: entry.utxo_entry.amount,
            script_public_key: ScriptPublicKey {
                version: entry.utxo_entry.script_public_key.version(),
                script_hex: hex::encode(entry.utxo_entry.script_public_key.script()),
            },
            block_daa_score: entry.utxo_entry.block_daa_score,
            is_coinbase: entry.utxo_entry.is_coinbase,
            covenant_id: entry
                .utxo_entry
                .covenant_id
                .map(|covenant_id| covenant_id.to_string()),
        });
    }

    serde_json::to_string(&Observation {
        schema_version: OBSERVATION_SCHEMA_VERSION,
        kind: OBSERVATION_KIND.to_string(),
        network_id: OBSERVATION_NETWORK_ID.to_string(),
        observed_virtual_daa_score: snapshot.virtual_daa_score,
        entries,
    })
    .map_err(|_| RuleObservationError)
}

/// Run the full verification pipeline in dependency order: owner hash root,
/// manifest, observation, entry selection and equality, maturity, constructor
/// hash, then GH-193 decode.
fn verify_validated(
    expected_manifest_sha256: &str,
    manifest_json: &str,
    observation_json: &str,
    constructor_json: &str,
) -> Result<RuleStateMetadata, RuleObservationError> {
    verify_observation_shared(
        expected_manifest_sha256,
        manifest_json,
        observation_json,
        constructor_json,
    )
    .map(|(metadata, _)| metadata)
}

/// The verified manifest outpoint of a successful observation verification.
///
/// Crate-internal only, used by the GH-205 composition layer to reject
/// duplicate verified manifest outpoints across one sync request. Never
/// exposed through errors, Display, Debug, or logs.
#[derive(PartialEq, Eq, Hash)]
pub(crate) struct VerifiedManifestOutpoint {
    /// Verified manifest `outpoint.transaction_id`.
    pub transaction_id: String,
    /// Verified manifest `outpoint.index`.
    pub index: u32,
}

/// Identical verification pipeline to [`verify_validated`], additionally
/// returning the verified manifest outpoint for the crate-internal
/// composition layer. Public API and validation behavior are unchanged.
pub(crate) fn verify_observation_shared(
    expected_manifest_sha256: &str,
    manifest_json: &str,
    observation_json: &str,
    constructor_json: &str,
) -> Result<(RuleStateMetadata, VerifiedManifestOutpoint), RuleObservationError> {
    let expected_hash = parse_hash(expected_manifest_sha256)?;

    let manifest = parse_canonical::<Manifest>(manifest_json, MAX_MANIFEST_JSON_BYTES)?;
    validate_manifest_shape(&manifest)?;
    if Sha256::digest(manifest_json.as_bytes())[..] != expected_hash {
        return Err(RuleObservationError);
    }

    let observation = parse_canonical::<Observation>(observation_json, MAX_OBSERVATION_JSON_BYTES)?;
    validate_observation_shape(&observation)?;

    let entry = select_entry(&manifest, &observation)?;
    check_entry_against_manifest(&manifest, entry)?;
    check_maturity(&manifest, &observation)?;

    // Bound attacker-controlled state before hashing as well as before GH-193
    // parsing; otherwise an oversized document still incurs unbounded work.
    if constructor_json.len() > MAX_STATE_JSON_BYTES {
        return Err(RuleObservationError);
    }
    let constructor_hash = Sha256::digest(constructor_json.as_bytes());
    if hex::encode(constructor_hash) != manifest.constructor_json_sha256 {
        return Err(RuleObservationError);
    }
    let metadata = decode_rule_state(constructor_json).map_err(|_| RuleObservationError)?;
    let outpoint = VerifiedManifestOutpoint {
        transaction_id: manifest.outpoint.transaction_id,
        index: manifest.outpoint.index,
    };
    Ok((metadata, outpoint))
}

/// Parse a strict canonical compact JSON document: bounded before parsing,
/// unknown fields rejected by the pinned structs, and parse followed by
/// serialize must reproduce the exact input bytes.
fn parse_canonical<T>(json: &str, max_bytes: usize) -> Result<T, RuleObservationError>
where
    T: serde::de::DeserializeOwned + Serialize,
{
    if json.len() > max_bytes {
        return Err(RuleObservationError);
    }
    // serde_json rejects trailing data after the top-level value.
    let parsed: T = serde_json::from_str(json).map_err(|_| RuleObservationError)?;
    let reserialized = serde_json::to_string(&parsed).map_err(|_| RuleObservationError)?;
    if reserialized != json {
        return Err(RuleObservationError);
    }
    Ok(parsed)
}

/// Validate the pinned scalar fields and hex shapes of the manifest.
fn validate_manifest_shape(manifest: &Manifest) -> Result<(), RuleObservationError> {
    if manifest.schema_version != OBSERVATION_SCHEMA_VERSION || manifest.kind != MANIFEST_KIND {
        return Err(RuleObservationError);
    }
    if manifest.network_id != OBSERVATION_NETWORK_ID {
        return Err(RuleObservationError);
    }
    if !is_hash_hex(&manifest.outpoint.transaction_id) || !is_hash_hex(&manifest.covenant_id) {
        return Err(RuleObservationError);
    }
    if !is_script_hex(&manifest.script_public_key.script_hex) {
        return Err(RuleObservationError);
    }
    if !is_hash_hex(&manifest.constructor_json_sha256) {
        return Err(RuleObservationError);
    }
    if manifest.minimum_virtual_daa_maturity == 0 {
        return Err(RuleObservationError);
    }
    Ok(())
}

/// Validate the pinned scalar fields, entry bounds, and hex shapes of every
/// observation entry. Unrelated entries are allowed but must still be
/// structurally well formed.
fn validate_observation_shape(observation: &Observation) -> Result<(), RuleObservationError> {
    if observation.schema_version != OBSERVATION_SCHEMA_VERSION
        || observation.kind != OBSERVATION_KIND
    {
        return Err(RuleObservationError);
    }
    if observation.network_id != OBSERVATION_NETWORK_ID {
        return Err(RuleObservationError);
    }
    if observation.entries.is_empty() || observation.entries.len() > MAX_OBSERVATION_ENTRIES {
        return Err(RuleObservationError);
    }
    let mut seen_outpoints = HashSet::with_capacity(observation.entries.len());
    for entry in &observation.entries {
        if !is_hash_hex(&entry.outpoint.transaction_id)
            || !is_script_hex(&entry.script_public_key.script_hex)
        {
            return Err(RuleObservationError);
        }
        if !seen_outpoints.insert((entry.outpoint.transaction_id.as_str(), entry.outpoint.index)) {
            return Err(RuleObservationError);
        }
        if let Some(covenant_id) = &entry.covenant_id {
            if !is_hash_hex(covenant_id) {
                return Err(RuleObservationError);
            }
        }
    }
    Ok(())
}

/// Select the unique entry matching the manifest outpoint. Zero matches,
/// duplicates, and conflicting matches are all rejected.
fn select_entry<'a>(
    manifest: &Manifest,
    observation: &'a Observation,
) -> Result<&'a ObservationEntry, RuleObservationError> {
    let mut matched: Option<&ObservationEntry> = None;
    for entry in &observation.entries {
        if entry.outpoint.transaction_id == manifest.outpoint.transaction_id
            && entry.outpoint.index == manifest.outpoint.index
        {
            if matched.is_some() {
                return Err(RuleObservationError);
            }
            matched = Some(entry);
        }
    }
    matched.ok_or(RuleObservationError)
}

/// Require exact equality between the matched entry and the manifest on
/// amount, script public key, block DAA score, and covenant ID, and require a
/// non-coinbase covenant UTXO.
fn check_entry_against_manifest(
    manifest: &Manifest,
    entry: &ObservationEntry,
) -> Result<(), RuleObservationError> {
    if entry.amount_sompi != manifest.amount_sompi
        || entry.script_public_key != manifest.script_public_key
        || entry.block_daa_score != manifest.block_daa_score
    {
        return Err(RuleObservationError);
    }
    if entry.is_coinbase {
        return Err(RuleObservationError);
    }
    if entry.covenant_id.as_deref() != Some(manifest.covenant_id.as_str()) {
        return Err(RuleObservationError);
    }
    Ok(())
}

/// Require the DAA maturity floor with checked subtraction. The delta is a
/// maturity proxy, not finality.
fn check_maturity(
    manifest: &Manifest,
    observation: &Observation,
) -> Result<(), RuleObservationError> {
    let delta = observation
        .observed_virtual_daa_score
        .checked_sub(manifest.block_daa_score)
        .ok_or(RuleObservationError)?;
    if delta < manifest.minimum_virtual_daa_maturity {
        return Err(RuleObservationError);
    }
    Ok(())
}

/// Decode an expected 32-byte hash supplied as exactly 64 lowercase hex.
fn parse_hash(value: &str) -> Result<[u8; 32], RuleObservationError> {
    if !is_hash_hex(value) {
        return Err(RuleObservationError);
    }
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| RuleObservationError)?;
    Ok(bytes)
}

/// Exactly 64 lowercase hex characters.
fn is_hash_hex(value: &str) -> bool {
    value.len() == 64 && is_lower_hex(value)
}

/// Nonempty, even-length, lowercase hex.
fn is_script_hex(value: &str) -> bool {
    !value.is_empty() && value.len().is_multiple_of(2) && is_lower_hex(value)
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_is_generic() {
        let err = RuleObservationError;
        assert_eq!(err.to_string(), "invalid RuleStorage UTXO observation");
        assert_eq!(format!("{err:?}"), "RuleObservationError");
    }

    #[test]
    fn test_hex_shape_validators() {
        assert!(is_hash_hex(&"ab".repeat(32)));
        assert!(!is_hash_hex(&"ab".repeat(31)));
        assert!(!is_hash_hex(&"AB".repeat(32)));
        assert!(!is_hash_hex(&"zz".repeat(32)));
        assert!(is_script_hex("51"));
        assert!(!is_script_hex(""));
        assert!(!is_script_hex("5"));
        assert!(!is_script_hex("5g"));
    }
}
