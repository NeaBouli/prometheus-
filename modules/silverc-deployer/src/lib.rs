//! Keyless SilverScript covenant-genesis operator primitives.
//!
//! The operator constructs the complete Toccata v1 transaction and exports only
//! a public Schnorr digest. An external vault or HSM returns the signature. No
//! private-key, seed, wallet, keystore, token, or password input exists here.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use kaspa_addresses::{Address, Prefix, Version as AddressVersion};
use kaspa_bip32::secp256k1::{schnorr::Signature, Message, XOnlyPublicKey, SECP256K1};
use kaspa_consensus_core::config::params::Params;
use kaspa_consensus_core::hashing::sighash::{
    calc_schnorr_signature_hash, SigHashReusedValuesUnsync,
};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::mass::MassCalculator;
use kaspa_consensus_core::network::{NetworkId, NetworkType};
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    CovenantBinding, ScriptPublicKey, SignableTransaction, Transaction, TransactionId,
    TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_rpc_core::{api::rpc::RpcApi, RpcError, RpcUtxosByAddressesEntry};
use kaspa_txscript::{extract_script_pub_key_address, pay_to_script_hash_script};
use kaspa_wrpc_client::client::{ConnectOptions, ConnectStrategy};
use kaspa_wrpc_client::{KaspaRpcClient, Resolver, WrpcEncoding};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::time::timeout;
use url::Url;

pub const TRANSACTION_VERSION: u16 = 1;
pub const FUNDING_COMPUTE_BUDGET: u16 = 10;
pub const CONTRACT_OUTPUT_INDEX: u32 = 0;
pub const FUNDING_INPUT_INDEX: u16 = 0;
pub const SIGNING_REQUEST_KIND: &str = "prometheus.silverc.genesis.signing_request";
pub const SIGNATURE_RESPONSE_KIND: &str = "prometheus.silverc.genesis.signature_response";
pub const PUBLIC_TESTNET_RESOLVER: &str = "kaspa-resolver://public";
pub const FULL_DEPLOYMENT_PROFILE: &str = "full";
pub const H001_CANARY_DEPLOYMENT_PROFILE: &str = "testnet-10-validator-staking-h001";
pub const H001_CANARY_CONTRACT: &str = "ValidatorStakingH001";
pub const FULL_BUNDLE_MANIFEST_SHA256: &str =
    "e6cec2aa5d740c47c972fe92d4607ffd8a7a3c3f26b353475451d50b2670aefd";
pub const FULL_DEPLOYMENT_CONTRACTS: [&str; 7] = [
    "ValidatorStakingH001",
    "ValidatorStakingState",
    "GuardianReputationState",
    "RuleStorageState",
    "CommunityDonationsState",
    "DevIncentivePoolState",
    "GovernanceAutoTuningState",
];

const SCHNORR_SCRIPT_LEN: usize = 66;
const RPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const SECRET_MARKERS: &[&str] = &[
    "private", "secret", "seed", "mnemonic", "password", "passwd", "wallet", "keystore", "token",
];
const ALLOWED_FALSE_SECRET_SAFETY_FIELDS: &[&str] = &[
    "accepts_private_keys",
    "accepts_seed_phrases",
    "accepts_wallet_secrets",
];
const DEPLOY_REQUEST_SAFETY_FIELDS: &[&str] = &[
    "accepts_private_keys",
    "signs_transactions",
    "assembles_chain_transaction",
    "broadcasts_transactions",
    "deploys_contracts",
    "updates_status_files",
];
const DEPLOY_REQUEST_SAFETY_SCOPE: &str = "deploy_request_builder_only";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScriptSpec {
    pub version: u16,
    pub script_hex: String,
}

impl ScriptSpec {
    fn to_script_public_key(&self) -> Result<ScriptPublicKey> {
        let script = hex::decode(&self.script_hex).context("invalid script_public_key hex")?;
        if script.is_empty() {
            bail!("script_public_key must not be empty");
        }
        Ok(ScriptPublicKey::from_vec(self.version, script))
    }

    fn from_script_public_key(script: &ScriptPublicKey) -> Self {
        Self {
            version: script.version(),
            script_hex: hex::encode(script.script()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutpointSpec {
    pub transaction_id: String,
    pub index: u32,
}

impl OutpointSpec {
    fn to_outpoint(&self) -> Result<TransactionOutpoint> {
        Ok(TransactionOutpoint {
            transaction_id: TransactionId::from_str(&self.transaction_id)
                .context("invalid funding transaction_id")?,
            index: self.index,
        })
    }

    fn from_outpoint(outpoint: TransactionOutpoint) -> Self {
        Self {
            transaction_id: outpoint.transaction_id.to_string(),
            index: outpoint.index,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FundingUtxoSpec {
    pub amount: u64,
    pub script_public_key: ScriptSpec,
    pub block_daa_score: u64,
    pub is_coinbase: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeOutputSpec {
    pub value: u64,
    pub script_public_key: ScriptSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisFundingSpec {
    pub schema_version: u32,
    pub kind: String,
    pub network_id: String,
    pub request_sha256: String,
    pub contract_name: String,
    pub funding_outpoint: OutpointSpec,
    pub funding_utxo: FundingUtxoSpec,
    pub genesis_output_value: u64,
    pub minimum_fee_sompi: u64,
    pub maximum_fee_sompi: u64,
    pub change_output: Option<ChangeOutputSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractRequest {
    pub name: String,
    pub artifact_sha256: String,
    pub script_sha256: String,
    pub script_len: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeploymentProfile {
    pub name: String,
    pub kind: String,
    pub network_id: String,
    pub selected_contracts: Vec<String>,
    pub full_bundle_fixture_count: usize,
    pub full_bundle_manifest_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployRequest {
    pub schema_version: u32,
    pub request_type: String,
    pub status: String,
    pub network: String,
    pub rpc_url: String,
    pub deployer_address: String,
    pub deployment_profile: DeploymentProfile,
    pub contract: ContractRequest,
    pub safety_scope: String,
    pub request_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SilvercArtifact {
    pub contract_name: String,
    pub compiler_version: String,
    pub script: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningRequest {
    pub schema_version: u32,
    pub kind: String,
    pub status: String,
    pub request_sha256: String,
    pub contract_name: String,
    pub network: String,
    pub network_id: String,
    pub rpc_url: String,
    pub deployer_address: String,
    pub funding_outpoint: OutpointSpec,
    pub funding_amount: u64,
    pub funding_script_public_key: ScriptSpec,
    pub funding_block_daa_score: u64,
    pub funding_is_coinbase: bool,
    pub genesis_output_value: u64,
    pub change_output_value: u64,
    pub fee_sompi: u64,
    pub minimum_fee_sompi: u64,
    pub maximum_fee_sompi: u64,
    pub transaction_version: u16,
    pub compute_budget: u16,
    pub toccata_activation_daa_score: u64,
    pub storage_mass: u64,
    pub authorizing_input: u16,
    pub contract_output_index: u32,
    pub unsigned_transaction_id: String,
    pub covenant_id: String,
    pub deployed_instance_id: String,
    pub contract_address: String,
    pub contract_script_sha256: String,
    pub contract_script_public_key: ScriptSpec,
    pub sighash_type: String,
    pub sighash_hex: String,
    pub expected_xonly_public_key_hex: String,
    pub external_signer_contract: BTreeMap<String, String>,
    pub safety: BTreeMap<String, bool>,
    pub signing_request_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureResponse {
    pub schema_version: u32,
    pub kind: String,
    pub status: String,
    pub request_sha256: String,
    pub signing_request_sha256: String,
    pub contract_name: String,
    pub transaction_id: String,
    pub input_index: u16,
    pub sighash_type: String,
    pub sighash_hex: String,
    pub xonly_public_key_hex: String,
    pub schnorr_signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureVerification {
    pub schema_version: u32,
    pub kind: String,
    pub status: String,
    pub request_sha256: String,
    pub signing_request_sha256: String,
    pub contract_name: String,
    pub transaction_id: String,
    pub covenant_id: String,
    pub signature_sha256: String,
    pub signature_validation: String,
    pub transaction_validation: String,
    pub safety: BTreeMap<String, bool>,
}

fn legacy_broadcast_record_source() -> String {
    "local_rpc_submission".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BroadcastResult {
    pub schema_version: u32,
    pub result_type: String,
    pub status: String,
    pub network: String,
    pub network_id: String,
    pub request_sha256: String,
    pub signing_request_sha256: String,
    pub contract_name: String,
    pub deployer_address: String,
    pub deployed_instance_id: String,
    pub deploy_tx_id: String,
    pub covenant_id: String,
    pub submitted_at_unix_seconds: u64,
    #[serde(default = "legacy_broadcast_record_source")]
    pub record_source: String,
    pub confirmation_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BroadcastJournal {
    pub schema_version: u32,
    pub journal_type: String,
    pub status: String,
    pub network: String,
    pub network_id: String,
    pub request_sha256: String,
    pub signing_request_sha256: String,
    pub contract_name: String,
    pub deployer_address: String,
    pub deployed_instance_id: String,
    pub expected_deploy_tx_id: String,
    pub covenant_id: String,
    pub acknowledged_signing_request_sha256: String,
    pub created_at_unix_seconds: u64,
    pub updated_at_unix_seconds: u64,
    #[serde(default)]
    pub submission_started_at_unix_seconds: Option<u64>,
    pub result: Option<BroadcastResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodePreflight {
    pub schema_version: u32,
    pub evidence_type: String,
    pub status: String,
    pub network: String,
    pub network_id: String,
    pub rpc_target: String,
    pub rpc_url: String,
    pub server_version: String,
    pub rpc_api_version: u16,
    pub rpc_api_revision: u16,
    pub is_synced: bool,
    pub has_utxo_index: bool,
    pub virtual_daa_score: u64,
    pub toccata_activation_daa_score: u64,
    pub toccata_active: bool,
    pub observed_at_unix_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployPreflight {
    pub schema_version: u32,
    pub evidence_type: String,
    pub status: String,
    pub request_sha256: String,
    pub contract_name: String,
    pub funding_outpoint: OutpointSpec,
    pub funding_amount: u64,
    pub funding_script_public_key: ScriptSpec,
    pub funding_block_daa_score: u64,
    pub funding_is_coinbase: bool,
    pub funding_covenant_id: Option<String>,
    pub funding_utxo_unspent: bool,
    pub node: NodePreflight,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeObservation {
    pub schema_version: u32,
    pub evidence_type: String,
    pub status: String,
    pub network: String,
    pub network_id: String,
    pub request_sha256: String,
    pub signing_request_sha256: String,
    pub contract_name: String,
    pub deployed_instance_id: String,
    pub deploy_tx_id: String,
    pub output_index: u32,
    pub contract_address: String,
    pub covenant_id: String,
    pub amount: u64,
    pub block_daa_score: u64,
    pub observed_virtual_daa_score: u64,
    pub daa_depth: u64,
    pub observed_at_unix_seconds: u64,
    pub explorer_block_hash_required: bool,
}

#[derive(Debug)]
pub struct PreparedGenesis {
    pub transaction: SignableTransaction,
    pub signing_request: SigningRequest,
}

#[derive(Debug)]
pub struct VerifiedSignedTransaction {
    pub transaction: SignableTransaction,
    pub verification: SignatureVerification,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn unix_seconds() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX epoch")?
        .as_secs())
}

fn canonical_json(value: &Value) -> Result<Vec<u8>> {
    fn write_value(value: &Value, output: &mut String) -> Result<()> {
        match value {
            Value::Null => output.push_str("null"),
            Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
            Value::Number(value) => output.push_str(&value.to_string()),
            Value::String(value) => output.push_str(&serde_json::to_string(value)?),
            Value::Array(values) => {
                output.push('[');
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    write_value(value, output)?;
                }
                output.push(']');
            }
            Value::Object(values) => {
                output.push('{');
                let mut keys = values.keys().collect::<Vec<_>>();
                keys.sort_unstable();
                for (index, key) in keys.into_iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    output.push_str(&serde_json::to_string(key)?);
                    output.push(':');
                    write_value(&values[key], output)?;
                }
                output.push('}');
            }
        }
        Ok(())
    }

    let mut output = String::new();
    write_value(value, &mut output)?;
    Ok(output.into_bytes())
}

fn reject_secret_fields(value: &Value, path: &str) -> Result<()> {
    match value {
        Value::Object(values) => {
            for (key, value) in values {
                let normalized = key.to_ascii_lowercase();
                if SECRET_MARKERS
                    .iter()
                    .any(|marker| normalized.contains(marker))
                    && (!ALLOWED_FALSE_SECRET_SAFETY_FIELDS.contains(&normalized.as_str())
                        || value != &Value::Bool(false))
                {
                    bail!("{path}.{key}: secret-like fields are forbidden");
                }
                reject_secret_fields(value, &format!("{path}.{key}"))?;
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                reject_secret_fields(value, &format!("{path}[{index}]"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn request_network_for(network_id: NetworkId) -> &'static str {
    match network_id.network_type() {
        NetworkType::Mainnet => "mainnet",
        NetworkType::Testnet => "testnet",
        _ => "sandbox",
    }
}

fn consensus_params(network_id: NetworkId) -> Result<Params> {
    match (network_id.network_type(), network_id.suffix()) {
        (NetworkType::Testnet, Some(10))
        | (NetworkType::Mainnet, None)
        | (NetworkType::Devnet, None) => Ok(network_id.into()),
        (NetworkType::Simnet, None) => {
            bail!("rusty-kaspa v2.0.1 does not activate Toccata on simnet")
        }
        (NetworkType::Testnet, Some(suffix)) => {
            bail!("rusty-kaspa v2.0.1 does not provide consensus parameters for testnet-{suffix}")
        }
        (NetworkType::Testnet, None) => {
            bail!("testnet network_id requires the supported suffix testnet-10")
        }
        (network, suffix) => {
            bail!("unsupported network_id profile: {network:?} suffix {suffix:?}")
        }
    }
}

fn validate_rpc_url(value: &str) -> Result<()> {
    if value == PUBLIC_TESTNET_RESOLVER {
        return Ok(());
    }
    let normalized = value.to_ascii_lowercase();
    if SECRET_MARKERS
        .iter()
        .any(|marker| normalized.contains(marker))
    {
        bail!("rpc_url must not contain secret-like text");
    }
    let (_, authority) = value
        .split_once("://")
        .ok_or_else(|| anyhow!("rpc_url must use ws:// or wss:// for Kaspa wRPC"))?;
    if authority.is_empty() || authority.starts_with('/') {
        bail!("rpc_url must include a host");
    }
    let url = Url::parse(value).context("invalid rpc_url")?;
    if !matches!(url.scheme(), "ws" | "wss") {
        bail!("rpc_url must use ws:// or wss:// for Kaspa wRPC");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("rpc_url must not contain credentials");
    }
    if url.host_str().is_none() {
        bail!("rpc_url must include a host");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("rpc_url must not contain query strings or fragments");
    }
    Ok(())
}

fn validate_resolver_network(network_id: NetworkId) -> Result<()> {
    if network_id.network_type() != NetworkType::Testnet || network_id.suffix() != Some(10) {
        bail!("the official public resolver is restricted to testnet-10 deployments");
    }
    Ok(())
}

fn safety_map() -> BTreeMap<String, bool> {
    BTreeMap::from([
        ("accepts_private_keys".to_string(), false),
        ("accepts_seed_phrases".to_string(), false),
        ("accepts_wallet_secrets".to_string(), false),
        ("signs_transactions".to_string(), false),
    ])
}

fn external_signer_contract_map() -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "algorithm".to_string(),
            "BIP340_SCHNORR_SECP256K1".to_string(),
        ),
        ("input".to_string(), "32_byte_sighash_hex".to_string()),
        ("output".to_string(), "64_byte_signature_hex".to_string()),
        (
            "key_location".to_string(),
            "external_vault_or_hsm_only".to_string(),
        ),
    ])
}

fn validate_lower_hex(value: &str, expected_bytes: usize, label: &str) -> Result<Vec<u8>> {
    if value.len() != expected_bytes * 2 || value != value.to_ascii_lowercase() {
        bail!("{label} must be canonical lowercase {expected_bytes}-byte hex");
    }
    let bytes = hex::decode(value).with_context(|| format!("invalid {label} hex"))?;
    if bytes.len() != expected_bytes {
        bail!("{label} must be canonical lowercase {expected_bytes}-byte hex");
    }
    Ok(bytes)
}

fn deployer_address_and_funding_script(
    deployer_address: &str,
    network_id: NetworkId,
    funding_script: &ScriptSpec,
) -> Result<(Address, ScriptPublicKey)> {
    let deployer_address = Address::try_from(deployer_address)?;
    if deployer_address.prefix != Prefix::from(network_id)
        || deployer_address.version != AddressVersion::PubKey
        || deployer_address.payload.len() != 32
    {
        bail!("deployer_address must be a Schnorr P2PK address for network_id");
    }
    let funding_script_public_key = funding_script.to_script_public_key()?;
    let funding_address =
        extract_script_pub_key_address(&funding_script_public_key, Prefix::from(network_id))
            .context("funding script_public_key is not a supported Kaspa address script")?;
    if funding_address != deployer_address {
        bail!("funding script_public_key does not belong to deployer_address");
    }
    Ok((deployer_address, funding_script_public_key))
}

fn validate_live_funding_utxo(
    entries: Vec<RpcUtxosByAddressesEntry>,
    expected_address: &Address,
    expected_outpoint: TransactionOutpoint,
    expected_amount: u64,
    expected_script_public_key: &ScriptPublicKey,
    expected_block_daa_score: u64,
    expected_is_coinbase: bool,
) -> Result<RpcUtxosByAddressesEntry> {
    let entry = entries
        .into_iter()
        .find(|entry| {
            entry.outpoint.transaction_id == expected_outpoint.transaction_id
                && entry.outpoint.index == expected_outpoint.index
        })
        .ok_or_else(|| anyhow!("funding outpoint is absent or already spent"))?;
    if entry.address.as_ref() != Some(expected_address) {
        bail!("funding UTXO address does not match deployer_address");
    }
    if entry.utxo_entry.amount != expected_amount
        || entry.utxo_entry.script_public_key != *expected_script_public_key
        || entry.utxo_entry.block_daa_score != expected_block_daa_score
        || entry.utxo_entry.is_coinbase != expected_is_coinbase
    {
        bail!("live funding UTXO does not match the approved funding specification");
    }
    if entry.utxo_entry.is_coinbase {
        bail!("coinbase funding UTXOs are not accepted by this operator");
    }
    if entry.utxo_entry.covenant_id.is_some() {
        bail!("covenant-bound UTXOs are not accepted as genesis funding");
    }
    Ok(entry)
}

fn read_public_json<T: DeserializeOwned>(path: &Path) -> Result<(T, Value)> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid JSON in {}", path.display()))?;
    reject_secret_fields(&value, "$")?;
    Ok((serde_json::from_value(value.clone())?, value))
}

fn validate_deployment_profile(request: &DeployRequest) -> Result<()> {
    let profile = &request.deployment_profile;
    validate_lower_hex(
        &profile.full_bundle_manifest_sha256,
        32,
        "deployment_profile.full_bundle_manifest_sha256",
    )?;
    let selected: BTreeSet<_> = profile.selected_contracts.iter().collect();
    if profile.full_bundle_fixture_count == 0
        || profile.selected_contracts.is_empty()
        || selected.len() != profile.selected_contracts.len()
        || !profile.selected_contracts.contains(&request.contract.name)
    {
        bail!("deployment profile contract selection is invalid");
    }
    if profile.full_bundle_fixture_count != FULL_DEPLOYMENT_CONTRACTS.len()
        || profile.full_bundle_manifest_sha256 != FULL_BUNDLE_MANIFEST_SHA256
    {
        bail!("deployment profile release-manifest binding mismatch");
    }

    match profile.name.as_str() {
        FULL_DEPLOYMENT_PROFILE => {
            if profile.kind != "full"
                || profile.network_id != "operator-selected"
                || !profile
                    .selected_contracts
                    .iter()
                    .map(String::as_str)
                    .eq(FULL_DEPLOYMENT_CONTRACTS.iter().copied())
                || request.status != "READY_FOR_KEYLESS_GENESIS_OPERATOR"
            {
                bail!("full deployment profile/status mismatch");
            }
        }
        H001_CANARY_DEPLOYMENT_PROFILE => {
            if profile.kind != "canary"
                || profile.network_id != "testnet-10"
                || profile.full_bundle_fixture_count != 7
                || profile.selected_contracts.len() != 1
                || profile.selected_contracts[0] != H001_CANARY_CONTRACT
                || request.contract.name != H001_CANARY_CONTRACT
                || request.status != "CANARY_READY_FOR_KEYLESS_GENESIS_OPERATOR"
                || request.network != "testnet"
                || request.rpc_url != PUBLIC_TESTNET_RESOLVER
            {
                bail!("H-001 canary deployment profile/status/network mismatch");
            }
        }
        _ => bail!("unsupported deployment profile"),
    }
    Ok(())
}

pub fn load_deploy_request(path: &Path) -> Result<DeployRequest> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid JSON in {}", path.display()))?;
    reject_secret_fields(&value, "$")?;
    let safety = value
        .get("safety")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("deploy request is missing safety object"))?;
    if safety.len() != DEPLOY_REQUEST_SAFETY_FIELDS.len()
        || DEPLOY_REQUEST_SAFETY_FIELDS
            .iter()
            .any(|key| safety.get(*key) != Some(&Value::Bool(false)))
    {
        bail!("deploy request safety capabilities must match the required false-only profile");
    }
    let provided_hash = value
        .as_object_mut()
        .and_then(|object| object.remove("request_sha256"))
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| anyhow!("deploy request is missing request_sha256"))?;
    if provided_hash != sha256_hex(&canonical_json(&value)?) {
        bail!("deploy request_sha256 mismatch");
    }
    value
        .as_object_mut()
        .expect("validated object")
        .insert("request_sha256".to_string(), Value::String(provided_hash));
    let request: DeployRequest = serde_json::from_value(value)?;
    if request.schema_version != 1
        || request.request_type != "prometheus_silverc_deploy_request"
        || request.safety_scope != DEPLOY_REQUEST_SAFETY_SCOPE
    {
        bail!("unsupported deploy request schema/type/status/safety_scope");
    }
    validate_deployment_profile(&request)?;
    validate_rpc_url(&request.rpc_url)?;
    if request.rpc_url == PUBLIC_TESTNET_RESOLVER && request.network != "testnet" {
        bail!("the official public resolver is restricted to testnet requests");
    }
    Ok(request)
}

pub fn load_funding_spec(path: &Path) -> Result<GenesisFundingSpec> {
    let (funding, _): (GenesisFundingSpec, Value) = read_public_json(path)?;
    if funding.schema_version != 1 || funding.kind != "prometheus.silverc.genesis_funding" {
        bail!("unsupported genesis funding schema/type");
    }
    if funding.funding_utxo.is_coinbase {
        bail!("coinbase funding UTXOs are not accepted by this operator");
    }
    Ok(funding)
}

pub fn load_artifact(path: &Path, request: &DeployRequest) -> Result<SilvercArtifact> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    if sha256_hex(&bytes) != request.contract.artifact_sha256 {
        bail!("Silverc artifact_sha256 mismatch");
    }
    let value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid JSON in {}", path.display()))?;
    reject_secret_fields(&value, "$")?;
    let artifact: SilvercArtifact = serde_json::from_value(value)?;
    if artifact.contract_name != request.contract.name {
        bail!("Silverc artifact contract_name mismatch");
    }
    if artifact.script.len() != request.contract.script_len
        || sha256_hex(&artifact.script) != request.contract.script_sha256
    {
        bail!("Silverc compiled script hash/length mismatch");
    }
    if artifact.script.is_empty() {
        bail!("Silverc compiled script must not be empty");
    }
    Ok(artifact)
}

fn signing_request_hash(request: &SigningRequest) -> Result<String> {
    let mut value = serde_json::to_value(request)?;
    value
        .as_object_mut()
        .expect("signing request serializes as object")
        .remove("signing_request_sha256");
    Ok(sha256_hex(&canonical_json(&value)?))
}

pub fn validate_signing_request(request: &SigningRequest) -> Result<()> {
    if request.schema_version != 1
        || request.kind != SIGNING_REQUEST_KIND
        || request.status != "READY_FOR_EXTERNAL_SCHNORR_SIGNATURE"
    {
        bail!("unsupported signing request schema/type/status");
    }
    if request.signing_request_sha256 != signing_request_hash(request)? {
        bail!("signing_request_sha256 mismatch");
    }
    if request.transaction_version != TRANSACTION_VERSION
        || request.compute_budget != FUNDING_COMPUTE_BUDGET
        || request.funding_is_coinbase
        || request.authorizing_input != FUNDING_INPUT_INDEX
        || request.contract_output_index != CONTRACT_OUTPUT_INDEX
        || request.sighash_type != "SIG_HASH_ALL"
        || request.external_signer_contract != external_signer_contract_map()
        || request.safety != safety_map()
    {
        bail!("signing request genesis/safety profile mismatch");
    }
    validate_rpc_url(&request.rpc_url)?;
    let network_id = NetworkId::from_str(&request.network_id)?;
    if request.rpc_url == PUBLIC_TESTNET_RESOLVER {
        validate_resolver_network(network_id)?;
    }
    let params = consensus_params(network_id)?;
    if request.network != request_network_for(network_id) {
        bail!("signing request network does not match network_id");
    }
    if request.toccata_activation_daa_score != params.toccata_activation.daa_score() {
        bail!("signing request Toccata activation does not match consensus parameters");
    }
    let (deployer_address, _) = deployer_address_and_funding_script(
        &request.deployer_address,
        network_id,
        &request.funding_script_public_key,
    )?;
    let expected_public_key = validate_lower_hex(
        &request.expected_xonly_public_key_hex,
        32,
        "expected_xonly_public_key",
    )?;
    if expected_public_key != deployer_address.payload.as_slice() {
        bail!("expected_xonly_public_key does not match deployer_address");
    }
    request.funding_outpoint.to_outpoint()?;
    TransactionId::from_str(&request.unsigned_transaction_id)
        .context("invalid unsigned_transaction_id")?;
    validate_lower_hex(&request.covenant_id, 32, "covenant_id")?;
    validate_lower_hex(
        &request.contract_script_sha256,
        32,
        "contract_script_sha256",
    )?;
    validate_lower_hex(&request.sighash_hex, 32, "sighash")?;
    let contract_script_public_key = request.contract_script_public_key.to_script_public_key()?;
    let expected_contract_address =
        extract_script_pub_key_address(&contract_script_public_key, Prefix::from(network_id))?;
    if expected_contract_address.prefix != Prefix::from(network_id)
        || expected_contract_address.version != AddressVersion::ScriptHash
    {
        bail!("contract_script_public_key must be a network-matched P2SH script");
    }
    if expected_contract_address.to_string() != request.contract_address {
        bail!("contract_address does not match contract_script_public_key");
    }
    if request.deployed_instance_id
        != format!(
            "{}:{}",
            request.unsigned_transaction_id, request.contract_output_index
        )
    {
        bail!("deployed_instance_id does not match transaction output");
    }
    let output_total = request
        .genesis_output_value
        .checked_add(request.change_output_value)
        .ok_or_else(|| anyhow!("signing request output value overflow"))?;
    let fee = request
        .funding_amount
        .checked_sub(output_total)
        .ok_or_else(|| anyhow!("signing request outputs exceed funding amount"))?;
    if request.genesis_output_value == 0
        || fee != request.fee_sompi
        || request.maximum_fee_sompi < request.minimum_fee_sompi
        || fee < request.minimum_fee_sompi
        || fee > request.maximum_fee_sompi
    {
        bail!("signing request value/fee profile mismatch");
    }
    Ok(())
}

pub fn load_signing_request(path: &Path) -> Result<SigningRequest> {
    let (request, _): (SigningRequest, Value) = read_public_json(path)?;
    validate_signing_request(&request)?;
    Ok(request)
}

pub fn load_signature_response(path: &Path) -> Result<SignatureResponse> {
    let (response, _): (SignatureResponse, Value) = read_public_json(path)?;
    validate_signature_response(&response)?;
    Ok(response)
}

fn validate_signature_response(response: &SignatureResponse) -> Result<()> {
    if response.schema_version != 1
        || response.kind != SIGNATURE_RESPONSE_KIND
        || response.status != "SIGNED_BY_EXTERNAL_OPERATOR"
    {
        bail!("unsupported signature response schema/type/status");
    }
    Ok(())
}

fn expected_storage_mass(transaction: &SignableTransaction, params: &Params) -> Result<u64> {
    let calculator = MassCalculator::new_with_consensus_params(params);
    calculator
        .calc_contextual_masses(&transaction.as_verifiable())
        .map(|mass| mass.storage_mass)
        .ok_or_else(|| anyhow!("transaction storage mass is incomputable"))
}

pub fn prepare_genesis(
    request: &DeployRequest,
    artifact: &SilvercArtifact,
    funding: &GenesisFundingSpec,
) -> Result<PreparedGenesis> {
    if funding.request_sha256 != request.request_sha256
        || funding.contract_name != request.contract.name
        || artifact.contract_name != request.contract.name
    {
        bail!("request, artifact, and funding contract bindings do not match");
    }
    let network_id = NetworkId::from_str(&funding.network_id).context("invalid network_id")?;
    if request.rpc_url == PUBLIC_TESTNET_RESOLVER {
        validate_resolver_network(network_id)?;
    }
    let params = consensus_params(network_id)?;
    if request.network != request_network_for(network_id) {
        bail!("request network does not match funding network_id");
    }

    let funding_outpoint = funding.funding_outpoint.to_outpoint()?;
    let (deployer_address, funding_script_public_key) = deployer_address_and_funding_script(
        &request.deployer_address,
        network_id,
        &funding.funding_utxo.script_public_key,
    )?;
    if let Some(change) = &funding.change_output {
        let change_script = change.script_public_key.to_script_public_key()?;
        let change_address =
            extract_script_pub_key_address(&change_script, Prefix::from(network_id))
                .context("change script_public_key is not a supported Kaspa address script")?;
        if change_address != deployer_address {
            bail!("change output must return to deployer_address");
        }
        if change.value == 0 {
            bail!("change output value must be nonzero when present");
        }
    }

    let change_value = funding
        .change_output
        .as_ref()
        .map_or(0, |change| change.value);
    let output_total = funding
        .genesis_output_value
        .checked_add(change_value)
        .ok_or_else(|| anyhow!("output value overflow"))?;
    let fee_sompi = funding
        .funding_utxo
        .amount
        .checked_sub(output_total)
        .ok_or_else(|| anyhow!("funding amount is smaller than genesis plus change outputs"))?;
    if funding.genesis_output_value == 0 {
        bail!("genesis_output_value must be nonzero");
    }
    if funding.maximum_fee_sompi < funding.minimum_fee_sompi {
        bail!("maximum_fee_sompi must not be below minimum_fee_sompi");
    }
    if fee_sompi < funding.minimum_fee_sompi {
        bail!("implicit transaction fee is below minimum_fee_sompi");
    }
    if fee_sompi > funding.maximum_fee_sompi {
        bail!("implicit transaction fee exceeds maximum_fee_sompi");
    }

    let contract_script_public_key = pay_to_script_hash_script(&artifact.script);
    let unbound_contract_output = TransactionOutput {
        value: funding.genesis_output_value,
        script_public_key: contract_script_public_key.clone(),
        covenant: None,
    };
    let covenant_id = kaspa_consensus_core::hashing::covenant_id::covenant_id(
        funding_outpoint,
        std::iter::once((CONTRACT_OUTPUT_INDEX, &unbound_contract_output)),
    );
    let mut outputs = vec![TransactionOutput {
        covenant: Some(CovenantBinding {
            authorizing_input: FUNDING_INPUT_INDEX,
            covenant_id,
        }),
        ..unbound_contract_output
    }];
    if let Some(change) = &funding.change_output {
        outputs.push(TransactionOutput {
            value: change.value,
            script_public_key: change.script_public_key.to_script_public_key()?,
            covenant: None,
        });
    }

    let input = TransactionInput::new_with_compute_budget(
        funding_outpoint,
        Vec::new(),
        0,
        FUNDING_COMPUTE_BUDGET,
    );
    let tx = Transaction::new(
        TRANSACTION_VERSION,
        vec![input],
        outputs,
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        Vec::new(),
    );
    let funding_utxo = UtxoEntry::new(
        funding.funding_utxo.amount,
        funding_script_public_key.clone(),
        funding.funding_utxo.block_daa_score,
        false,
        None,
    );
    let transaction = SignableTransaction::with_entries(tx, vec![funding_utxo]);
    let storage_mass = expected_storage_mass(&transaction, &params)?;
    transaction.tx.set_storage_mass(storage_mass);
    let unsigned_transaction_id = transaction.tx.id().to_string();
    let sighash = calc_schnorr_signature_hash(
        &transaction.as_verifiable(),
        0,
        SIG_HASH_ALL,
        &SigHashReusedValuesUnsync::new(),
    );
    let contract_address =
        extract_script_pub_key_address(&contract_script_public_key, Prefix::from(network_id))?;

    let mut signing_request = SigningRequest {
        schema_version: 1,
        kind: SIGNING_REQUEST_KIND.to_string(),
        status: "READY_FOR_EXTERNAL_SCHNORR_SIGNATURE".to_string(),
        request_sha256: request.request_sha256.clone(),
        contract_name: request.contract.name.clone(),
        network: request.network.clone(),
        network_id: funding.network_id.clone(),
        rpc_url: request.rpc_url.clone(),
        deployer_address: request.deployer_address.clone(),
        funding_outpoint: OutpointSpec::from_outpoint(funding_outpoint),
        funding_amount: funding.funding_utxo.amount,
        funding_script_public_key: ScriptSpec::from_script_public_key(&funding_script_public_key),
        funding_block_daa_score: funding.funding_utxo.block_daa_score,
        funding_is_coinbase: funding.funding_utxo.is_coinbase,
        genesis_output_value: funding.genesis_output_value,
        change_output_value: change_value,
        fee_sompi,
        minimum_fee_sompi: funding.minimum_fee_sompi,
        maximum_fee_sompi: funding.maximum_fee_sompi,
        transaction_version: TRANSACTION_VERSION,
        compute_budget: FUNDING_COMPUTE_BUDGET,
        toccata_activation_daa_score: params.toccata_activation.daa_score(),
        storage_mass,
        authorizing_input: FUNDING_INPUT_INDEX,
        contract_output_index: CONTRACT_OUTPUT_INDEX,
        unsigned_transaction_id: unsigned_transaction_id.clone(),
        covenant_id: covenant_id.to_string(),
        deployed_instance_id: format!("{unsigned_transaction_id}:{CONTRACT_OUTPUT_INDEX}"),
        contract_address: contract_address.to_string(),
        contract_script_sha256: request.contract.script_sha256.clone(),
        contract_script_public_key: ScriptSpec::from_script_public_key(&contract_script_public_key),
        sighash_type: "SIG_HASH_ALL".to_string(),
        sighash_hex: sighash.to_string(),
        expected_xonly_public_key_hex: hex::encode(&deployer_address.payload),
        external_signer_contract: external_signer_contract_map(),
        safety: safety_map(),
        signing_request_sha256: String::new(),
    };
    signing_request.signing_request_sha256 = signing_request_hash(&signing_request)?;
    Ok(PreparedGenesis {
        transaction,
        signing_request,
    })
}

fn validate_prepared_rebuild(prepared: &PreparedGenesis, expected: &SigningRequest) -> Result<()> {
    validate_signing_request(expected)?;
    if prepared.signing_request.signing_request_sha256 != expected.signing_request_sha256
        || signing_request_hash(&prepared.signing_request)? != signing_request_hash(expected)?
    {
        bail!("rebuilt genesis transaction does not match signing request");
    }
    Ok(())
}

pub fn verify_signature_response(
    prepared: PreparedGenesis,
    signing_request: &SigningRequest,
    response: &SignatureResponse,
) -> Result<VerifiedSignedTransaction> {
    validate_prepared_rebuild(&prepared, signing_request)?;
    validate_signature_response(response)?;
    if response.request_sha256 != signing_request.request_sha256
        || response.signing_request_sha256 != signing_request.signing_request_sha256
        || response.contract_name != signing_request.contract_name
        || response.transaction_id != signing_request.unsigned_transaction_id
        || response.input_index != FUNDING_INPUT_INDEX
        || response.sighash_type != signing_request.sighash_type
        || response.sighash_hex != signing_request.sighash_hex
        || response.xonly_public_key_hex != signing_request.expected_xonly_public_key_hex
    {
        bail!("signature response is not bound to the prepared signing request");
    }
    let public_key_bytes =
        hex::decode(&response.xonly_public_key_hex).context("invalid x-only public key hex")?;
    let signature_bytes =
        hex::decode(&response.schnorr_signature_hex).context("invalid Schnorr signature hex")?;
    if public_key_bytes.len() != 32 || signature_bytes.len() != 64 {
        bail!("external signer must return a 32-byte public key and 64-byte signature");
    }
    let public_key = XOnlyPublicKey::from_slice(&public_key_bytes)?;
    let signature = Signature::from_slice(&signature_bytes)?;
    let sighash_bytes = hex::decode(&response.sighash_hex).context("invalid sighash hex")?;
    let message = Message::from_digest_slice(&sighash_bytes)?;
    SECP256K1
        .verify_schnorr(&signature, &message, &public_key)
        .context("external Schnorr signature verification failed")?;

    let mut transaction = prepared.transaction;
    let mut signature_script = Vec::with_capacity(SCHNORR_SCRIPT_LEN);
    signature_script.push(65);
    signature_script.extend_from_slice(&signature_bytes);
    signature_script.push(SIG_HASH_ALL.to_u8());
    transaction.tx.inputs[0].signature_script = signature_script;
    kaspa_consensus_core::sign::verify(&transaction.as_verifiable())
        .context("signed transaction verification failed")?;
    let params = consensus_params(NetworkId::from_str(&signing_request.network_id)?)?;
    if transaction.tx.storage_mass() != expected_storage_mass(&transaction, &params)? {
        bail!("signed transaction mass does not match prepared mass commitment");
    }

    Ok(VerifiedSignedTransaction {
        transaction,
        verification: SignatureVerification {
            schema_version: 1,
            kind: "prometheus.silverc.genesis.signature_verification".to_string(),
            status: "EXTERNAL_SIGNATURE_AND_TRANSACTION_VERIFIED".to_string(),
            request_sha256: signing_request.request_sha256.clone(),
            signing_request_sha256: signing_request.signing_request_sha256.clone(),
            contract_name: signing_request.contract_name.clone(),
            transaction_id: signing_request.unsigned_transaction_id.clone(),
            covenant_id: signing_request.covenant_id.clone(),
            signature_sha256: sha256_hex(&signature_bytes),
            signature_validation: "bip340_schnorr_passed".to_string(),
            transaction_validation: "kaspa_consensus_sign_verify_passed".to_string(),
            safety: safety_map(),
        },
    })
}

fn validate_verified_transaction_binding(
    verified: &VerifiedSignedTransaction,
    signing_request: &SigningRequest,
) -> Result<()> {
    validate_signing_request(signing_request)?;
    if verified.transaction.entries.len() != verified.transaction.tx.inputs.len()
        || verified.transaction.entries.iter().any(Option::is_none)
    {
        bail!("verified transaction is missing required UTXO entries");
    }
    if verified.verification.schema_version != 1
        || verified.verification.kind != "prometheus.silverc.genesis.signature_verification"
        || verified.verification.status != "EXTERNAL_SIGNATURE_AND_TRANSACTION_VERIFIED"
        || verified.verification.request_sha256 != signing_request.request_sha256
        || verified.verification.signing_request_sha256 != signing_request.signing_request_sha256
        || verified.verification.transaction_id != signing_request.unsigned_transaction_id
        || verified.verification.covenant_id != signing_request.covenant_id
        || verified.verification.signature_validation != "bip340_schnorr_passed"
        || verified.verification.transaction_validation != "kaspa_consensus_sign_verify_passed"
        || verified.verification.safety != safety_map()
        || verified.transaction.tx.id().to_string() != signing_request.unsigned_transaction_id
    {
        bail!("verified transaction is not bound to signing request");
    }
    kaspa_consensus_core::sign::verify(&verified.transaction.as_verifiable())
        .context("signed transaction verification failed before network access")?;
    Ok(())
}

fn rpc_timeout(operation: &str) -> anyhow::Error {
    anyhow!(
        "Kaspa wRPC {operation} timed out after {} seconds",
        RPC_REQUEST_TIMEOUT.as_secs()
    )
}

async fn connect_rpc(
    rpc_url: &str,
    network_id: NetworkId,
    encoding: WrpcEncoding,
) -> Result<KaspaRpcClient> {
    validate_rpc_url(rpc_url)?;
    let resolved_url = if rpc_url == PUBLIC_TESTNET_RESOLVER {
        validate_resolver_network(network_id)?;
        let resolver = Resolver::new(None, true);
        let resolved = timeout(RPC_REQUEST_TIMEOUT, resolver.get_url(encoding, network_id))
            .await
            .map_err(|_| rpc_timeout("resolve official public endpoint"))?
            .context("failed to resolve official public Kaspa wRPC endpoint")?;
        validate_resolved_public_rpc_url(&resolved)?;
        resolved
    } else {
        rpc_url.to_string()
    };
    let client = KaspaRpcClient::new(encoding, Some(&resolved_url), None, Some(network_id), None)?;
    let options = ConnectOptions {
        block_async_connect: true,
        connect_timeout: Some(Duration::from_secs(15)),
        strategy: ConnectStrategy::Fallback,
        ..Default::default()
    };
    client
        .connect(Some(options))
        .await
        .context("failed to connect to Kaspa wRPC")?;
    Ok(client)
}

fn validate_resolved_public_rpc_url(value: &str) -> Result<()> {
    validate_rpc_url(value)?;
    let url = Url::parse(value).context("invalid resolved public rpc_url")?;
    if url.scheme() != "wss" {
        bail!("official public resolver must return a wss:// endpoint");
    }
    Ok(())
}

async fn inspect_node(
    client: &KaspaRpcClient,
    rpc_target: &str,
    expected_network_id: NetworkId,
    params: &Params,
    require_utxo_index: bool,
) -> Result<NodePreflight> {
    let info = timeout(RPC_REQUEST_TIMEOUT, client.get_server_info())
        .await
        .map_err(|_| rpc_timeout("get_server_info"))?
        .context("failed to query Kaspa server information")?;
    if info.network_id != expected_network_id {
        bail!(
            "Kaspa node network mismatch: expected {expected_network_id}, got {}",
            info.network_id
        );
    }
    if !info.is_synced {
        bail!("Kaspa node is not synced");
    }
    if require_utxo_index && !info.has_utxo_index {
        bail!("Kaspa node UTXO index is required for deployment observation");
    }
    if !params.toccata_activation.is_active(info.virtual_daa_score) {
        bail!(
            "Toccata is not active: node DAA {} is below activation DAA {}",
            info.virtual_daa_score,
            params.toccata_activation.daa_score()
        );
    }
    Ok(NodePreflight {
        schema_version: 1,
        evidence_type: "prometheus_silverc_toccata_node_preflight".to_string(),
        status: if rpc_target == PUBLIC_TESTNET_RESOLVER {
            "TOCCATA_PUBLIC_RESOLVER_NODE_READY"
        } else {
            "TOCCATA_NODE_READY"
        }
        .to_string(),
        network: request_network_for(expected_network_id).to_string(),
        network_id: expected_network_id.to_string(),
        rpc_target: rpc_target.to_string(),
        rpc_url: client.url().ok_or_else(|| {
            anyhow!("connected Kaspa client did not expose its resolved wRPC URL")
        })?,
        server_version: info.server_version,
        rpc_api_version: info.rpc_api_version,
        rpc_api_revision: info.rpc_api_revision,
        is_synced: info.is_synced,
        has_utxo_index: info.has_utxo_index,
        virtual_daa_score: info.virtual_daa_score,
        toccata_activation_daa_score: params.toccata_activation.daa_score(),
        toccata_active: true,
        observed_at_unix_seconds: unix_seconds()?,
    })
}

pub async fn preflight_node(
    rpc_url: &str,
    network_id: NetworkId,
    encoding: WrpcEncoding,
    require_utxo_index: bool,
) -> Result<NodePreflight> {
    let params = consensus_params(network_id)?;
    let client = connect_rpc(rpc_url, network_id, encoding).await?;
    let result = inspect_node(&client, rpc_url, network_id, &params, require_utxo_index).await;
    let _ = client.disconnect().await;
    result
}

pub async fn preflight_deploy_node(
    request: &DeployRequest,
    funding: &GenesisFundingSpec,
    encoding: WrpcEncoding,
) -> Result<DeployPreflight> {
    if funding.request_sha256 != request.request_sha256
        || funding.contract_name != request.contract.name
    {
        bail!("deploy request and funding bindings do not match");
    }
    let network_id = NetworkId::from_str(&funding.network_id).context("invalid network_id")?;
    if request.network != request_network_for(network_id) {
        bail!("request network does not match funding network_id");
    }
    let (deployer_address, funding_script_public_key) = deployer_address_and_funding_script(
        &request.deployer_address,
        network_id,
        &funding.funding_utxo.script_public_key,
    )?;
    let funding_outpoint = funding.funding_outpoint.to_outpoint()?;
    let params = consensus_params(network_id)?;
    let client = connect_rpc(&request.rpc_url, network_id, encoding).await?;
    let node = match inspect_node(&client, &request.rpc_url, network_id, &params, true).await {
        Ok(node) => node,
        Err(error) => {
            let _ = client.disconnect().await;
            return Err(error);
        }
    };
    let entries_result = timeout(
        RPC_REQUEST_TIMEOUT,
        client.get_utxos_by_addresses(vec![deployer_address.clone()]),
    )
    .await
    .map_err(|_| rpc_timeout("get_utxos_by_addresses for funding preflight"))?;
    let _ = client.disconnect().await;
    let entry = validate_live_funding_utxo(
        entries_result.context("failed to query funding UTXO")?,
        &deployer_address,
        funding_outpoint,
        funding.funding_utxo.amount,
        &funding_script_public_key,
        funding.funding_utxo.block_daa_score,
        funding.funding_utxo.is_coinbase,
    )?;
    Ok(DeployPreflight {
        schema_version: 1,
        evidence_type: "prometheus_silverc_genesis_deploy_preflight".to_string(),
        status: "TOCCATA_FUNDING_UTXO_READY".to_string(),
        request_sha256: request.request_sha256.clone(),
        contract_name: request.contract.name.clone(),
        funding_outpoint: funding.funding_outpoint.clone(),
        funding_amount: entry.utxo_entry.amount,
        funding_script_public_key: ScriptSpec::from_script_public_key(
            &entry.utxo_entry.script_public_key,
        ),
        funding_block_daa_score: entry.utxo_entry.block_daa_score,
        funding_is_coinbase: entry.utxo_entry.is_coinbase,
        funding_covenant_id: entry.utxo_entry.covenant_id.map(|value| value.to_string()),
        funding_utxo_unspent: true,
        node,
    })
}

fn deployed_contract_entry(
    entries: Vec<RpcUtxosByAddressesEntry>,
    signing_request: &SigningRequest,
) -> Result<Option<RpcUtxosByAddressesEntry>> {
    let expected_tx_id = TransactionId::from_str(&signing_request.unsigned_transaction_id)?;
    let Some(entry) = entries.into_iter().find(|entry| {
        entry.outpoint.transaction_id == expected_tx_id
            && entry.outpoint.index == signing_request.contract_output_index
    }) else {
        return Ok(None);
    };
    if entry.utxo_entry.amount != signing_request.genesis_output_value
        || entry.utxo_entry.covenant_id.map(|value| value.to_string())
            != Some(signing_request.covenant_id.clone())
        || ScriptSpec::from_script_public_key(&entry.utxo_entry.script_public_key)
            != signing_request.contract_script_public_key
    {
        bail!("node UTXO does not match verified amount, covenant ID, or contract script");
    }
    Ok(Some(entry))
}

fn broadcast_result(
    signing_request: &SigningRequest,
    status: &str,
    record_source: &str,
    confirmation_required: bool,
    submitted_at_unix_seconds: u64,
) -> BroadcastResult {
    BroadcastResult {
        schema_version: 1,
        result_type: "prometheus_silverc_genesis_submission".to_string(),
        status: status.to_string(),
        network: signing_request.network.clone(),
        network_id: signing_request.network_id.clone(),
        request_sha256: signing_request.request_sha256.clone(),
        signing_request_sha256: signing_request.signing_request_sha256.clone(),
        contract_name: signing_request.contract_name.clone(),
        deployer_address: signing_request.deployer_address.clone(),
        deployed_instance_id: signing_request.deployed_instance_id.clone(),
        deploy_tx_id: signing_request.unsigned_transaction_id.clone(),
        covenant_id: signing_request.covenant_id.clone(),
        submitted_at_unix_seconds,
        record_source: record_source.to_string(),
        confirmation_required,
    }
}

pub fn prepare_broadcast_journal(
    verified: &VerifiedSignedTransaction,
    signing_request: &SigningRequest,
    acknowledgement: &str,
) -> Result<BroadcastJournal> {
    validate_verified_transaction_binding(verified, signing_request)?;
    if acknowledgement != signing_request.signing_request_sha256 {
        bail!("broadcast acknowledgement must equal signing_request_sha256");
    }
    let now = unix_seconds()?;
    Ok(BroadcastJournal {
        schema_version: 1,
        journal_type: "prometheus_silverc_genesis_broadcast_journal".to_string(),
        status: "verified_pending_submission".to_string(),
        network: signing_request.network.clone(),
        network_id: signing_request.network_id.clone(),
        request_sha256: signing_request.request_sha256.clone(),
        signing_request_sha256: signing_request.signing_request_sha256.clone(),
        contract_name: signing_request.contract_name.clone(),
        deployer_address: signing_request.deployer_address.clone(),
        deployed_instance_id: signing_request.deployed_instance_id.clone(),
        expected_deploy_tx_id: signing_request.unsigned_transaction_id.clone(),
        covenant_id: signing_request.covenant_id.clone(),
        acknowledged_signing_request_sha256: acknowledgement.to_string(),
        created_at_unix_seconds: now,
        updated_at_unix_seconds: now,
        submission_started_at_unix_seconds: None,
        result: None,
    })
}

fn validate_broadcast_result_binding(
    result: &BroadcastResult,
    journal: &BroadcastJournal,
) -> Result<()> {
    let valid_state = matches!(
        (
            result.status.as_str(),
            result.record_source.as_str(),
            result.confirmation_required
        ),
        ("submitted_unconfirmed", "local_rpc_submission", true)
            | ("reconciled_mempool", "known_transaction_mempool", true)
            | (
                "reconciled_confirmed",
                "known_transaction_contract_utxo",
                false
            )
    );
    if result.schema_version != 1
        || result.result_type != "prometheus_silverc_genesis_submission"
        || !valid_state
        || result.network != journal.network
        || result.network_id != journal.network_id
        || result.request_sha256 != journal.request_sha256
        || result.signing_request_sha256 != journal.signing_request_sha256
        || result.contract_name != journal.contract_name
        || result.deployer_address != journal.deployer_address
        || result.deployed_instance_id != journal.deployed_instance_id
        || result.deploy_tx_id != journal.expected_deploy_tx_id
        || result.covenant_id != journal.covenant_id
        || result.signing_request_sha256 != journal.acknowledged_signing_request_sha256
    {
        bail!("broadcast result is not bound to the verified broadcast journal");
    }
    Ok(())
}

fn validate_broadcast_journal_binding(
    journal: &BroadcastJournal,
    expected: &BroadcastJournal,
) -> Result<()> {
    if journal.schema_version != 1
        || journal.journal_type != "prometheus_silverc_genesis_broadcast_journal"
        || journal.network != expected.network
        || journal.network_id != expected.network_id
        || journal.request_sha256 != expected.request_sha256
        || journal.signing_request_sha256 != expected.signing_request_sha256
        || journal.contract_name != expected.contract_name
        || journal.deployer_address != expected.deployer_address
        || journal.deployed_instance_id != expected.deployed_instance_id
        || journal.expected_deploy_tx_id != expected.expected_deploy_tx_id
        || journal.covenant_id != expected.covenant_id
        || journal.acknowledged_signing_request_sha256
            != expected.acknowledged_signing_request_sha256
        || journal.updated_at_unix_seconds < journal.created_at_unix_seconds
        || journal
            .submission_started_at_unix_seconds
            .is_some_and(|started| started < journal.created_at_unix_seconds)
    {
        bail!("existing broadcast journal does not match the verified transaction");
    }
    match (
        journal.status.as_str(),
        journal.submission_started_at_unix_seconds,
        journal.result.as_ref(),
    ) {
        ("verified_pending_submission", None, None) => Ok(()),
        ("submission_in_progress", Some(_), None) => Ok(()),
        ("submission_recorded", _, Some(result)) => {
            validate_broadcast_result_binding(result, journal)
        }
        _ => bail!("broadcast journal status/result state is invalid"),
    }
}

pub fn broadcast_journal_path(result_out: &Path) -> PathBuf {
    let mut path = result_out.as_os_str().to_os_string();
    path.push(".intent.json");
    path.into()
}

fn broadcast_lock_path(result_out: &Path) -> PathBuf {
    let mut path = result_out.as_os_str().to_os_string();
    path.push(".lock");
    path.into()
}

pub fn acquire_broadcast_lock(result_out: &Path) -> Result<File> {
    let path = broadcast_lock_path(result_out);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .with_context(|| format!("failed to open broadcast lock {}", path.display()))?;
    file.try_lock().map_err(|error| {
        anyhow!(
            "another broadcast process holds {}: {error}",
            path.display()
        )
    })?;
    Ok(file)
}

pub fn load_broadcast_journal(
    path: &Path,
    expected: &BroadcastJournal,
) -> Result<BroadcastJournal> {
    let (journal, _): (BroadcastJournal, Value) = read_public_json(path)?;
    validate_broadcast_journal_binding(&journal, expected)?;
    Ok(journal)
}

pub fn load_broadcast_result(path: &Path, journal: &BroadcastJournal) -> Result<BroadcastResult> {
    let (result, _): (BroadcastResult, Value) = read_public_json(path)?;
    validate_broadcast_result_binding(&result, journal)?;
    Ok(result)
}

pub fn finalize_broadcast_journal(
    mut journal: BroadcastJournal,
    result: BroadcastResult,
) -> Result<BroadcastJournal> {
    validate_broadcast_result_binding(&result, &journal)?;
    journal.status = "submission_recorded".to_string();
    journal.updated_at_unix_seconds = unix_seconds()?;
    journal.result = Some(result);
    Ok(journal)
}

fn mark_submission_in_progress(journal: &mut BroadcastJournal, path: &Path) -> Result<u64> {
    if journal.status != "verified_pending_submission"
        || journal.submission_started_at_unix_seconds.is_some()
        || journal.result.is_some()
    {
        bail!("broadcast journal is not eligible for a first submission attempt");
    }
    let started_at = unix_seconds()?;
    journal.status = "submission_in_progress".to_string();
    journal.updated_at_unix_seconds = started_at;
    journal.submission_started_at_unix_seconds = Some(started_at);
    write_public_json(path, journal)?;
    Ok(started_at)
}

fn require_first_submission_attempt(journal: &BroadcastJournal) -> Result<()> {
    if journal.status == "submission_in_progress" {
        bail!(
            "prior submission state is ambiguous; expected transaction is not yet visible in the configured node mempool or covenant UTXO set, so automatic resubmission is forbidden"
        );
    }
    if journal.status != "verified_pending_submission" {
        bail!("broadcast journal is not eligible for transaction submission");
    }
    Ok(())
}

pub async fn broadcast_verified_transaction(
    verified: VerifiedSignedTransaction,
    signing_request: &SigningRequest,
    acknowledgement: &str,
    encoding: WrpcEncoding,
    journal: &mut BroadcastJournal,
    journal_path: &Path,
) -> Result<BroadcastResult> {
    validate_verified_transaction_binding(&verified, signing_request)?;
    if acknowledgement != signing_request.signing_request_sha256 {
        bail!("broadcast acknowledgement must equal signing_request_sha256");
    }
    let expected_journal = prepare_broadcast_journal(&verified, signing_request, acknowledgement)?;
    validate_broadcast_journal_binding(journal, &expected_journal)?;
    let network_id = NetworkId::from_str(&signing_request.network_id)?;
    let params = consensus_params(network_id)?;
    let (deployer_address, funding_script_public_key) = deployer_address_and_funding_script(
        &signing_request.deployer_address,
        network_id,
        &signing_request.funding_script_public_key,
    )?;
    let funding_outpoint = signing_request.funding_outpoint.to_outpoint()?;
    let contract_address = Address::try_from(signing_request.contract_address.as_str())?;
    let expected_tx_id = TransactionId::from_str(&signing_request.unsigned_transaction_id)?;
    let client = connect_rpc(&signing_request.rpc_url, network_id, encoding).await?;
    if let Err(error) =
        inspect_node(&client, &signing_request.rpc_url, network_id, &params, true).await
    {
        let _ = client.disconnect().await;
        return Err(error);
    }

    let deployed_entries = timeout(
        RPC_REQUEST_TIMEOUT,
        client.get_utxos_by_addresses(vec![contract_address]),
    )
    .await
    .map_err(|_| rpc_timeout("get_utxos_by_addresses for broadcast reconciliation"))?;
    let deployed_entry = deployed_entries
        .context("failed to reconcile deployed contract UTXO")
        .and_then(|entries| deployed_contract_entry(entries, signing_request));
    match deployed_entry {
        Ok(Some(_)) => {
            let _ = client.disconnect().await;
            return Ok(broadcast_result(
                signing_request,
                "reconciled_confirmed",
                "known_transaction_contract_utxo",
                false,
                journal
                    .submission_started_at_unix_seconds
                    .unwrap_or(journal.created_at_unix_seconds),
            ));
        }
        Ok(None) => {}
        Err(error) => {
            let _ = client.disconnect().await;
            return Err(error);
        }
    }

    let mempool_result = timeout(
        RPC_REQUEST_TIMEOUT,
        client.get_mempool_entry(expected_tx_id, true, false),
    )
    .await
    .map_err(|_| rpc_timeout("get_mempool_entry for broadcast reconciliation"))?;
    match mempool_result {
        Ok(_) => {
            let _ = client.disconnect().await;
            return Ok(broadcast_result(
                signing_request,
                "reconciled_mempool",
                "known_transaction_mempool",
                true,
                journal
                    .submission_started_at_unix_seconds
                    .unwrap_or(journal.created_at_unix_seconds),
            ));
        }
        Err(RpcError::TransactionNotFound(_)) => {}
        Err(error) => {
            let _ = client.disconnect().await;
            return Err(error).context("failed to reconcile expected transaction in mempool");
        }
    }

    if let Err(error) = require_first_submission_attempt(journal) {
        let _ = client.disconnect().await;
        return Err(error);
    }

    let funding_entries = timeout(
        RPC_REQUEST_TIMEOUT,
        client.get_utxos_by_addresses(vec![deployer_address.clone()]),
    )
    .await
    .map_err(|_| rpc_timeout("get_utxos_by_addresses before broadcast"))?;
    let funding_validation = funding_entries
        .context("failed to query funding UTXO before broadcast")
        .and_then(|entries| {
            validate_live_funding_utxo(
                entries,
                &deployer_address,
                funding_outpoint,
                signing_request.funding_amount,
                &funding_script_public_key,
                signing_request.funding_block_daa_score,
                signing_request.funding_is_coinbase,
            )
        });
    if let Err(error) = funding_validation {
        let _ = client.disconnect().await;
        return Err(error);
    }
    let submission_started_at = mark_submission_in_progress(journal, journal_path)?;
    let result = timeout(
        RPC_REQUEST_TIMEOUT,
        client.submit_transaction((&verified.transaction.tx).into(), false),
    )
    .await
    .map_err(|_| rpc_timeout("submit_transaction"))?
    .context("Kaspa transaction submission failed");
    let _ = client.disconnect().await;
    let submitted_id = result?.to_string();
    if submitted_id != signing_request.unsigned_transaction_id {
        bail!("RPC returned a transaction ID different from the verified transaction");
    }
    Ok(broadcast_result(
        signing_request,
        "submitted_unconfirmed",
        "local_rpc_submission",
        true,
        submission_started_at,
    ))
}

pub async fn observe_deployed_utxo(
    verified: &VerifiedSignedTransaction,
    signing_request: &SigningRequest,
    encoding: WrpcEncoding,
) -> Result<NodeObservation> {
    validate_verified_transaction_binding(verified, signing_request)?;
    let network_id = NetworkId::from_str(&signing_request.network_id)?;
    let params = consensus_params(network_id)?;
    let address = Address::try_from(signing_request.contract_address.as_str())?;
    if address.prefix != Prefix::from(network_id) {
        bail!("contract address prefix does not match network_id");
    }
    let client = connect_rpc(&signing_request.rpc_url, network_id, encoding).await?;
    if let Err(error) =
        inspect_node(&client, &signing_request.rpc_url, network_id, &params, true).await
    {
        let _ = client.disconnect().await;
        return Err(error);
    }
    let entries_result = timeout(
        RPC_REQUEST_TIMEOUT,
        client.get_utxos_by_addresses(vec![address]),
    )
    .await
    .map_err(|_| rpc_timeout("get_utxos_by_addresses for deployment observation"))?;
    let dag_result = timeout(RPC_REQUEST_TIMEOUT, client.get_block_dag_info())
        .await
        .map_err(|_| rpc_timeout("get_block_dag_info for deployment observation"))?;
    let _ = client.disconnect().await;
    let entries = entries_result.context("failed to query deployed contract UTXO")?;
    let dag = dag_result.context("failed to query virtual DAA score")?;
    let entry = deployed_contract_entry(entries, signing_request)?
        .ok_or_else(|| anyhow!("deployed contract UTXO is not visible on the configured node"))?;
    Ok(NodeObservation {
        schema_version: 1,
        evidence_type: "prometheus_silverc_genesis_node_observation".to_string(),
        status: "confirmed_utxo_observed".to_string(),
        network: signing_request.network.clone(),
        network_id: signing_request.network_id.clone(),
        request_sha256: signing_request.request_sha256.clone(),
        signing_request_sha256: signing_request.signing_request_sha256.clone(),
        contract_name: signing_request.contract_name.clone(),
        deployed_instance_id: signing_request.deployed_instance_id.clone(),
        deploy_tx_id: signing_request.unsigned_transaction_id.clone(),
        output_index: signing_request.contract_output_index,
        contract_address: signing_request.contract_address.clone(),
        covenant_id: signing_request.covenant_id.clone(),
        amount: entry.utxo_entry.amount,
        block_daa_score: entry.utxo_entry.block_daa_score,
        observed_virtual_daa_score: dag.virtual_daa_score,
        daa_depth: dag
            .virtual_daa_score
            .saturating_sub(entry.utxo_entry.block_daa_score),
        observed_at_unix_seconds: unix_seconds()?,
        explorer_block_hash_required: true,
    })
}

fn public_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn write_synced_temporary(path: &Path, bytes: &[u8]) -> Result<(PathBuf, PathBuf)> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let mut temporary = path.as_os_str().to_os_string();
    temporary.push(format!(
        ".tmp-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before UNIX epoch")?
            .as_nanos()
    ));
    let temporary = PathBuf::from(temporary);
    let write_result = (|| -> Result<(PathBuf, PathBuf)> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .with_context(|| format!("failed to create {}", temporary.display()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok((temporary.clone(), parent.to_path_buf()))
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

pub fn create_public_json<T: Serialize>(path: &Path, value: &T) -> Result<bool> {
    let bytes = public_json_bytes(value)?;
    let (temporary, parent) = write_synced_temporary(path, &bytes)?;
    let linked = match fs::hard_link(&temporary, path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            return Err(error)
                .with_context(|| format!("failed to exclusively create {}", path.display()));
        }
    };
    fs::remove_file(&temporary)?;
    if linked {
        File::open(parent)?.sync_all()?;
    }
    Ok(linked)
}

pub fn write_public_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = public_json_bytes(value)?;
    let (temporary, parent) = write_synced_temporary(path, &bytes)?;
    let rename_result = fs::rename(&temporary, path)
        .with_context(|| format!("failed to atomically replace {}", path.display()));
    if rename_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    rename_result?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_bip32::secp256k1::{rand::thread_rng, Keypair};

    fn full_deployment_profile() -> DeploymentProfile {
        DeploymentProfile {
            name: FULL_DEPLOYMENT_PROFILE.to_string(),
            kind: "full".to_string(),
            network_id: "operator-selected".to_string(),
            selected_contracts: FULL_DEPLOYMENT_CONTRACTS
                .iter()
                .map(|name| (*name).to_string())
                .collect(),
            full_bundle_fixture_count: FULL_DEPLOYMENT_CONTRACTS.len(),
            full_bundle_manifest_sha256: FULL_BUNDLE_MANIFEST_SHA256.to_string(),
        }
    }

    fn fixture() -> (DeployRequest, SilvercArtifact, GenesisFundingSpec, Keypair) {
        let keypair = Keypair::new(SECP256K1, &mut thread_rng());
        let address = Address::new(
            Prefix::Testnet,
            AddressVersion::PubKey,
            &keypair.x_only_public_key().0.serialize(),
        );
        let funding_spk = kaspa_txscript::pay_to_address_script(&address);
        let script = vec![0x51, 0x75, 0x51];
        let request = DeployRequest {
            schema_version: 1,
            request_type: "prometheus_silverc_deploy_request".to_string(),
            status: "READY_FOR_KEYLESS_GENESIS_OPERATOR".to_string(),
            network: "testnet".to_string(),
            rpc_url: "ws://127.0.0.1:17210".to_string(),
            deployer_address: address.to_string(),
            deployment_profile: full_deployment_profile(),
            contract: ContractRequest {
                name: H001_CANARY_CONTRACT.to_string(),
                artifact_sha256: "a".repeat(64),
                script_sha256: sha256_hex(&script),
                script_len: script.len(),
            },
            safety_scope: DEPLOY_REQUEST_SAFETY_SCOPE.to_string(),
            request_sha256: "b".repeat(64),
        };
        let artifact = SilvercArtifact {
            contract_name: H001_CANARY_CONTRACT.to_string(),
            compiler_version: "test".to_string(),
            script,
        };
        let funding = GenesisFundingSpec {
            schema_version: 1,
            kind: "prometheus.silverc.genesis_funding".to_string(),
            network_id: "testnet-10".to_string(),
            request_sha256: request.request_sha256.clone(),
            contract_name: request.contract.name.clone(),
            funding_outpoint: OutpointSpec {
                transaction_id: "11".repeat(32),
                index: 3,
            },
            funding_utxo: FundingUtxoSpec {
                amount: 100_000,
                script_public_key: ScriptSpec::from_script_public_key(&funding_spk),
                block_daa_score: 10,
                is_coinbase: false,
            },
            genesis_output_value: 80_000,
            minimum_fee_sompi: 1_000,
            maximum_fee_sompi: 3_000,
            change_output: Some(ChangeOutputSpec {
                value: 18_000,
                script_public_key: ScriptSpec::from_script_public_key(&funding_spk),
            }),
        };
        (request, artifact, funding, keypair)
    }

    fn deterministic_fixture() -> (DeployRequest, SilvercArtifact, GenesisFundingSpec) {
        let public_key =
            hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();
        let address = Address::new(Prefix::Testnet, AddressVersion::PubKey, &public_key);
        let funding_spk = kaspa_txscript::pay_to_address_script(&address);
        let script = vec![0x51, 0x75, 0x51];
        let request = DeployRequest {
            schema_version: 1,
            request_type: "prometheus_silverc_deploy_request".to_string(),
            status: "READY_FOR_KEYLESS_GENESIS_OPERATOR".to_string(),
            network: "testnet".to_string(),
            rpc_url: "wss://tn10.example.invalid".to_string(),
            deployer_address: address.to_string(),
            deployment_profile: full_deployment_profile(),
            contract: ContractRequest {
                name: H001_CANARY_CONTRACT.to_string(),
                artifact_sha256: "aa".repeat(32),
                script_sha256: sha256_hex(&script),
                script_len: script.len(),
            },
            safety_scope: DEPLOY_REQUEST_SAFETY_SCOPE.to_string(),
            request_sha256: "bb".repeat(32),
        };
        let artifact = SilvercArtifact {
            contract_name: request.contract.name.clone(),
            compiler_version: "deterministic-test".to_string(),
            script,
        };
        let funding = GenesisFundingSpec {
            schema_version: 1,
            kind: "prometheus.silverc.genesis_funding".to_string(),
            network_id: "testnet-10".to_string(),
            request_sha256: request.request_sha256.clone(),
            contract_name: request.contract.name.clone(),
            funding_outpoint: OutpointSpec {
                transaction_id: "11".repeat(32),
                index: 3,
            },
            funding_utxo: FundingUtxoSpec {
                amount: 100_000,
                script_public_key: ScriptSpec::from_script_public_key(&funding_spk),
                block_daa_score: 467_579_700,
                is_coinbase: false,
            },
            genesis_output_value: 80_000,
            minimum_fee_sompi: 1_000,
            maximum_fee_sompi: 3_000,
            change_output: Some(ChangeOutputSpec {
                value: 18_000,
                script_public_key: ScriptSpec::from_script_public_key(&funding_spk),
            }),
        };
        (request, artifact, funding)
    }

    fn sign(prepared: &PreparedGenesis, keypair: &Keypair) -> SignatureResponse {
        let message = Message::from_digest_slice(
            &hex::decode(&prepared.signing_request.sighash_hex).unwrap(),
        )
        .unwrap();
        let signature = keypair.sign_schnorr(message);
        SignatureResponse {
            schema_version: 1,
            kind: SIGNATURE_RESPONSE_KIND.to_string(),
            status: "SIGNED_BY_EXTERNAL_OPERATOR".to_string(),
            request_sha256: prepared.signing_request.request_sha256.clone(),
            signing_request_sha256: prepared.signing_request.signing_request_sha256.clone(),
            contract_name: prepared.signing_request.contract_name.clone(),
            transaction_id: prepared.signing_request.unsigned_transaction_id.clone(),
            input_index: 0,
            sighash_type: "SIG_HASH_ALL".to_string(),
            sighash_hex: prepared.signing_request.sighash_hex.clone(),
            xonly_public_key_hex: hex::encode(keypair.x_only_public_key().0.serialize()),
            schnorr_signature_hex: hex::encode(signature.serialize()),
        }
    }

    fn live_funding_entry(
        request: &DeployRequest,
        funding: &GenesisFundingSpec,
    ) -> RpcUtxosByAddressesEntry {
        RpcUtxosByAddressesEntry {
            address: Some(Address::try_from(request.deployer_address.as_str()).unwrap()),
            outpoint: funding.funding_outpoint.to_outpoint().unwrap().into(),
            utxo_entry: kaspa_rpc_core::RpcUtxoEntry::new(
                funding.funding_utxo.amount,
                funding
                    .funding_utxo
                    .script_public_key
                    .to_script_public_key()
                    .unwrap(),
                funding.funding_utxo.block_daa_score,
                funding.funding_utxo.is_coinbase,
                None,
            ),
        }
    }

    #[test]
    fn prepares_official_toccata_genesis_signing_request() {
        let (request, artifact, funding, _) = fixture();
        let prepared = prepare_genesis(&request, &artifact, &funding).unwrap();
        assert_eq!(prepared.signing_request.transaction_version, 1);
        assert_eq!(prepared.signing_request.compute_budget, 10);
        assert_eq!(prepared.signing_request.authorizing_input, 0);
        assert_eq!(prepared.signing_request.contract_output_index, 0);
        assert_eq!(prepared.signing_request.fee_sompi, 2_000);
        assert_eq!(
            prepared.transaction.tx.inputs[0]
                .compute_commit
                .compute_budget(),
            Some(10)
        );
        assert!(prepared.transaction.tx.inputs[0]
            .signature_script
            .is_empty());
        assert!(prepared.transaction.tx.outputs[0].covenant.is_some());
        assert!(prepared.transaction.tx.outputs[1].covenant.is_none());
        let params = consensus_params(NetworkId::from_str("testnet-10").unwrap()).unwrap();
        let expected = MassCalculator::new_with_consensus_params(&params)
            .calc_contextual_masses(&prepared.transaction.as_verifiable())
            .unwrap()
            .storage_mass;
        assert_eq!(prepared.transaction.tx.storage_mass(), expected);
        validate_signing_request(&prepared.signing_request).unwrap();
    }

    #[test]
    fn deterministic_genesis_interoperability_vector() {
        let (request, artifact, funding) = deterministic_fixture();
        let prepared = prepare_genesis(&request, &artifact, &funding).unwrap();
        assert_eq!(
            prepared.signing_request.unsigned_transaction_id,
            "fd07b8003c95aa36ed49f5dff112364a85575fe9416983dedd5d68822a3f2a4e"
        );
        assert_eq!(
            prepared.signing_request.covenant_id,
            "f9f4da7d12907c13258922f4356cea9f4b2c796d7699221424ca41e565f7d506"
        );
        assert_eq!(
            prepared.signing_request.sighash_hex,
            "d157a37034df308150a88d66dd1fbd91f7f6a0fbb6d256842400c8215bf9d15b"
        );
        assert_eq!(
            prepared.signing_request.signing_request_sha256,
            "39871130d3566f55a28587f7cb57412651aa8263e13fcc682d2ee45869c59403"
        );
        assert_eq!(prepared.signing_request.storage_mass, 95_555_555);
    }

    #[test]
    fn verifies_external_signature_without_accepting_key_material() {
        let (request, artifact, funding, keypair) = fixture();
        let prepared = prepare_genesis(&request, &artifact, &funding).unwrap();
        let signing_request = prepared.signing_request.clone();
        let response = sign(&prepared, &keypair);
        let verified = verify_signature_response(prepared, &signing_request, &response).unwrap();
        assert_eq!(
            verified.verification.status,
            "EXTERNAL_SIGNATURE_AND_TRANSACTION_VERIFIED"
        );
        assert_eq!(
            verified.transaction.tx.inputs[0].signature_script.len(),
            SCHNORR_SCRIPT_LEN
        );
        assert_eq!(
            verified.verification.signature_validation,
            "bip340_schnorr_passed"
        );
    }

    #[test]
    fn rejects_signature_from_wrong_key() {
        let (request, artifact, funding, _) = fixture();
        let prepared = prepare_genesis(&request, &artifact, &funding).unwrap();
        let signing_request = prepared.signing_request.clone();
        let wrong_key = Keypair::new(SECP256K1, &mut thread_rng());
        let mut response = sign(&prepared, &wrong_key);
        response.xonly_public_key_hex = signing_request.expected_xonly_public_key_hex.clone();
        let error = verify_signature_response(prepared, &signing_request, &response)
            .expect_err("wrong signature must fail");
        assert!(error.to_string().contains("signature verification failed"));
    }

    #[test]
    fn rejects_signature_response_with_unapproved_status() {
        let (request, artifact, funding, keypair) = fixture();
        let prepared = prepare_genesis(&request, &artifact, &funding).unwrap();
        let signing_request = prepared.signing_request.clone();
        let mut response = sign(&prepared, &keypair);
        response.status = "UNVERIFIED".to_string();
        let error = verify_signature_response(prepared, &signing_request, &response)
            .expect_err("unapproved response status must fail");
        assert!(error
            .to_string()
            .contains("unsupported signature response schema/type/status"));
    }

    #[test]
    fn rejects_signing_request_tamper() {
        let (request, artifact, funding, _) = fixture();
        let mut prepared = prepare_genesis(&request, &artifact, &funding).unwrap();
        prepared.signing_request.fee_sompi += 1;
        let error = validate_signing_request(&prepared.signing_request).unwrap_err();
        assert!(error
            .to_string()
            .contains("signing_request_sha256 mismatch"));
    }

    #[test]
    fn rejects_rehashed_signing_request_network_mismatch() {
        let (request, artifact, funding, _) = fixture();
        let mut signing_request = prepare_genesis(&request, &artifact, &funding)
            .unwrap()
            .signing_request;
        signing_request.network = "mainnet".to_string();
        signing_request.signing_request_sha256 = signing_request_hash(&signing_request).unwrap();
        let error = validate_signing_request(&signing_request)
            .expect_err("self-consistent network mismatch must fail");
        assert!(error.to_string().contains("network does not match"));
    }

    #[test]
    fn rejects_rehashed_signing_request_fee_outside_cap() {
        let (request, artifact, funding, _) = fixture();
        let mut signing_request = prepare_genesis(&request, &artifact, &funding)
            .unwrap()
            .signing_request;
        signing_request.maximum_fee_sompi = signing_request.fee_sompi - 1;
        signing_request.signing_request_sha256 = signing_request_hash(&signing_request).unwrap();
        let error = validate_signing_request(&signing_request)
            .expect_err("self-consistent fee-cap violation must fail");
        assert!(error.to_string().contains("value/fee profile mismatch"));
    }

    #[test]
    fn rejects_rehashed_signing_request_signer_profile_tamper() {
        let (request, artifact, funding, _) = fixture();
        let mut signing_request = prepare_genesis(&request, &artifact, &funding)
            .unwrap()
            .signing_request;
        signing_request
            .external_signer_contract
            .insert("algorithm".to_string(), "UNAPPROVED".to_string());
        signing_request.signing_request_sha256 = signing_request_hash(&signing_request).unwrap();
        let error = validate_signing_request(&signing_request)
            .expect_err("self-consistent signer-profile tamper must fail");
        assert!(error
            .to_string()
            .contains("genesis/safety profile mismatch"));
    }

    #[test]
    fn rejects_rehashed_signing_request_non_p2sh_contract() {
        let (request, artifact, funding, _) = fixture();
        let mut signing_request = prepare_genesis(&request, &artifact, &funding)
            .unwrap()
            .signing_request;
        signing_request.contract_script_public_key =
            signing_request.funding_script_public_key.clone();
        signing_request.contract_address = signing_request.deployer_address.clone();
        signing_request.signing_request_sha256 = signing_request_hash(&signing_request).unwrap();
        let error = validate_signing_request(&signing_request)
            .expect_err("self-consistent non-P2SH contract target must fail");
        assert!(error.to_string().contains("network-matched P2SH"));
    }

    #[test]
    fn rejects_unsupported_testnet_suffix_without_panicking() {
        let (request, artifact, mut funding, _) = fixture();
        funding.network_id = "testnet-12".to_string();
        let error = prepare_genesis(&request, &artifact, &funding)
            .expect_err("unsupported suffix must fail");
        assert!(error
            .to_string()
            .contains("does not provide consensus parameters for testnet-12"));
    }

    #[test]
    fn rejects_change_address_mismatch() {
        let (request, artifact, mut funding, _) = fixture();
        let other = Address::new(
            Prefix::Testnet,
            AddressVersion::PubKey,
            &Keypair::new(SECP256K1, &mut thread_rng())
                .x_only_public_key()
                .0
                .serialize(),
        );
        funding.change_output.as_mut().unwrap().script_public_key =
            ScriptSpec::from_script_public_key(&kaspa_txscript::pay_to_address_script(&other));
        let error = prepare_genesis(&request, &artifact, &funding)
            .expect_err("mismatched change address must fail");
        assert!(error
            .to_string()
            .contains("change output must return to deployer_address"));
    }

    #[test]
    fn rejects_underfunded_fee() {
        let (request, artifact, mut funding, _) = fixture();
        funding.minimum_fee_sompi = 2_001;
        let error =
            prepare_genesis(&request, &artifact, &funding).expect_err("underfunded fee must fail");
        assert!(error.to_string().contains("below minimum_fee_sompi"));
    }

    #[test]
    fn rejects_fee_above_operator_cap() {
        let (request, artifact, mut funding, _) = fixture();
        funding.maximum_fee_sompi = 1_999;
        let error = prepare_genesis(&request, &artifact, &funding)
            .expect_err("fee above operator cap must fail");
        assert!(error.to_string().contains("exceeds maximum_fee_sompi"));
    }

    #[test]
    fn rejects_inverted_fee_bounds() {
        let (request, artifact, mut funding, _) = fixture();
        funding.minimum_fee_sompi = 3_001;
        funding.maximum_fee_sompi = 3_000;
        let error = prepare_genesis(&request, &artifact, &funding)
            .expect_err("inverted fee bounds must fail");
        assert!(error
            .to_string()
            .contains("maximum_fee_sompi must not be below"));
    }

    #[test]
    fn rejects_simnet_without_toccata_activation() {
        let (mut request, artifact, mut funding, _) = fixture();
        request.network = "sandbox".to_string();
        funding.network_id = "simnet".to_string();
        let error =
            prepare_genesis(&request, &artifact, &funding).expect_err("simnet must fail closed");
        assert!(error.to_string().contains("does not activate Toccata"));
    }

    #[test]
    fn accepts_only_the_exact_public_testnet_resolver_target() {
        validate_rpc_url(PUBLIC_TESTNET_RESOLVER).unwrap();
        validate_resolver_network(NetworkId::from_str("testnet-10").unwrap()).unwrap();

        for target in [
            "kaspa-resolver://public/extra",
            "kaspa-resolver://user@public",
            "kaspa-resolver://public?node=other",
            "https://resolver.example.invalid",
            "ws:///missing-host",
            "wss://node.example.invalid/token-path",
        ] {
            assert!(validate_rpc_url(target).is_err(), "accepted {target}");
        }
    }

    #[test]
    fn public_resolver_is_restricted_to_testnet_10() {
        assert!(NetworkId::from_str("testnet").is_err());
        for network in ["mainnet", "testnet-11", "testnet-12", "devnet"] {
            let network_id = NetworkId::from_str(network).unwrap();
            let error = validate_resolver_network(network_id)
                .expect_err("public resolver must remain testnet-10-only");
            assert!(error.to_string().contains("restricted to testnet-10"));
        }
    }

    #[test]
    fn h001_canary_profile_is_exact_and_non_promotable() {
        let (mut request, _, _, _) = fixture();
        request.status = "CANARY_READY_FOR_KEYLESS_GENESIS_OPERATOR".to_string();
        request.rpc_url = PUBLIC_TESTNET_RESOLVER.to_string();
        request.contract.name = H001_CANARY_CONTRACT.to_string();
        request.deployment_profile = DeploymentProfile {
            name: H001_CANARY_DEPLOYMENT_PROFILE.to_string(),
            kind: "canary".to_string(),
            network_id: "testnet-10".to_string(),
            selected_contracts: vec![H001_CANARY_CONTRACT.to_string()],
            full_bundle_fixture_count: 7,
            full_bundle_manifest_sha256: FULL_BUNDLE_MANIFEST_SHA256.to_string(),
        };
        validate_deployment_profile(&request).unwrap();

        let mut promoted = request.clone();
        promoted.status = "READY_FOR_KEYLESS_GENESIS_OPERATOR".to_string();
        assert!(validate_deployment_profile(&promoted).is_err());

        let mut fabricated_full = request.clone();
        fabricated_full.status = "READY_FOR_KEYLESS_GENESIS_OPERATOR".to_string();
        fabricated_full.deployment_profile.name = FULL_DEPLOYMENT_PROFILE.to_string();
        fabricated_full.deployment_profile.kind = "full".to_string();
        fabricated_full.deployment_profile.network_id = "operator-selected".to_string();
        assert!(validate_deployment_profile(&fabricated_full).is_err());

        fabricated_full.deployment_profile.selected_contracts = FULL_DEPLOYMENT_CONTRACTS
            .iter()
            .map(|name| (*name).to_string())
            .collect();
        validate_deployment_profile(&fabricated_full).unwrap();

        let mut wrong_manifest = fabricated_full.clone();
        wrong_manifest
            .deployment_profile
            .full_bundle_manifest_sha256 = "dd".repeat(32);
        assert!(validate_deployment_profile(&wrong_manifest).is_err());

        let mut wrong_order = fabricated_full;
        wrong_order.deployment_profile.selected_contracts.swap(0, 1);
        assert!(validate_deployment_profile(&wrong_order).is_err());

        let mut wrong_contract = request.clone();
        wrong_contract.contract.name = "ValidatorStakingState".to_string();
        assert!(validate_deployment_profile(&wrong_contract).is_err());

        let mut wrong_network = request;
        wrong_network.network = "mainnet".to_string();
        assert!(validate_deployment_profile(&wrong_network).is_err());
    }

    #[test]
    fn h001_canary_public_request_file_round_trip_is_profile_bound() {
        let (mut request, _, _, _) = fixture();
        request.status = "CANARY_READY_FOR_KEYLESS_GENESIS_OPERATOR".to_string();
        request.rpc_url = PUBLIC_TESTNET_RESOLVER.to_string();
        request.contract.name = H001_CANARY_CONTRACT.to_string();
        request.deployment_profile = DeploymentProfile {
            name: H001_CANARY_DEPLOYMENT_PROFILE.to_string(),
            kind: "canary".to_string(),
            network_id: "testnet-10".to_string(),
            selected_contracts: vec![H001_CANARY_CONTRACT.to_string()],
            full_bundle_fixture_count: 7,
            full_bundle_manifest_sha256: FULL_BUNDLE_MANIFEST_SHA256.to_string(),
        };
        let temp_dir = std::env::temp_dir().join(format!(
            "prometheus-h001-canary-request-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();

        let mut value = serde_json::to_value(&request).unwrap();
        value.as_object_mut().unwrap().insert(
            "safety".to_string(),
            serde_json::json!({
                "accepts_private_keys": false,
                "signs_transactions": false,
                "assembles_chain_transaction": false,
                "broadcasts_transactions": false,
                "deploys_contracts": false,
                "updates_status_files": false
            }),
        );
        value.as_object_mut().unwrap().remove("request_sha256");
        let request_hash = sha256_hex(&canonical_json(&value).unwrap());
        value
            .as_object_mut()
            .unwrap()
            .insert("request_sha256".to_string(), Value::String(request_hash));
        let request_path = temp_dir.join("canary.deploy-request.json");
        write_public_json(&request_path, &value).unwrap();
        let loaded = load_deploy_request(&request_path).unwrap();
        assert_eq!(loaded.deployment_profile, request.deployment_profile);

        value["deployment_profile"]["selected_contracts"] =
            serde_json::json!(["ValidatorStakingState"]);
        value.as_object_mut().unwrap().remove("request_sha256");
        let tampered_hash = sha256_hex(&canonical_json(&value).unwrap());
        value
            .as_object_mut()
            .unwrap()
            .insert("request_sha256".to_string(), Value::String(tampered_hash));
        let tampered_path = temp_dir.join("tampered.deploy-request.json");
        write_public_json(&tampered_path, &value).unwrap();
        assert!(load_deploy_request(&tampered_path).is_err());
        fs::remove_dir_all(temp_dir).unwrap();
    }

    #[test]
    fn resolved_public_endpoint_must_remain_tls_and_public() {
        validate_resolved_public_rpc_url("wss://node.example.invalid/kaspa/testnet-10/wrpc/borsh")
            .unwrap();
        for endpoint in [
            "ws://node.example.invalid/kaspa/testnet-10/wrpc/borsh",
            "wss://user@node.example.invalid/kaspa/testnet-10/wrpc/borsh",
            "wss://node.example.invalid/kaspa/testnet-10/wrpc/borsh?token=value",
        ] {
            assert!(
                validate_resolved_public_rpc_url(endpoint).is_err(),
                "accepted {endpoint}"
            );
        }
    }

    #[test]
    fn accepts_exact_live_funding_utxo() {
        let (request, _, funding, _) = fixture();
        let address = Address::try_from(request.deployer_address.as_str()).unwrap();
        let outpoint = funding.funding_outpoint.to_outpoint().unwrap();
        let script = funding
            .funding_utxo
            .script_public_key
            .to_script_public_key()
            .unwrap();
        let entry = validate_live_funding_utxo(
            vec![live_funding_entry(&request, &funding)],
            &address,
            outpoint,
            funding.funding_utxo.amount,
            &script,
            funding.funding_utxo.block_daa_score,
            false,
        )
        .unwrap();
        assert_eq!(entry.outpoint.transaction_id, outpoint.transaction_id);
        assert_eq!(entry.outpoint.index, outpoint.index);
    }

    #[test]
    fn rejects_missing_or_spent_live_funding_utxo() {
        let (request, _, funding, _) = fixture();
        let address = Address::try_from(request.deployer_address.as_str()).unwrap();
        let script = funding
            .funding_utxo
            .script_public_key
            .to_script_public_key()
            .unwrap();
        let error = validate_live_funding_utxo(
            Vec::new(),
            &address,
            funding.funding_outpoint.to_outpoint().unwrap(),
            funding.funding_utxo.amount,
            &script,
            funding.funding_utxo.block_daa_score,
            false,
        )
        .expect_err("missing funding outpoint must fail");
        assert!(error.to_string().contains("absent or already spent"));
    }

    #[test]
    fn rejects_covenant_bound_live_funding_utxo() {
        let (request, _, funding, _) = fixture();
        let address = Address::try_from(request.deployer_address.as_str()).unwrap();
        let outpoint = funding.funding_outpoint.to_outpoint().unwrap();
        let script = funding
            .funding_utxo
            .script_public_key
            .to_script_public_key()
            .unwrap();
        let mut entry = live_funding_entry(&request, &funding);
        entry.utxo_entry.covenant_id = Some(TransactionId::from_str(&"22".repeat(32)).unwrap());
        let error = validate_live_funding_utxo(
            vec![entry],
            &address,
            outpoint,
            funding.funding_utxo.amount,
            &script,
            funding.funding_utxo.block_daa_score,
            false,
        )
        .expect_err("covenant-bound funding must fail");
        assert!(error
            .to_string()
            .contains("covenant-bound UTXOs are not accepted"));
    }

    #[tokio::test]
    async fn preflight_rejects_request_funding_mismatch_before_network_access() {
        let (mut request, _, funding, _) = fixture();
        request.request_sha256 = "c".repeat(64);
        let error = preflight_deploy_node(&request, &funding, WrpcEncoding::Borsh)
            .await
            .expect_err("mismatched preflight inputs must fail");
        assert!(error.to_string().contains("bindings do not match"));
    }

    #[tokio::test]
    async fn broadcast_rejects_verified_binding_before_network_access() {
        let (request, artifact, funding, keypair) = fixture();
        let prepared = prepare_genesis(&request, &artifact, &funding).unwrap();
        let signing_request = prepared.signing_request.clone();
        let response = sign(&prepared, &keypair);
        let mut verified =
            verify_signature_response(prepared, &signing_request, &response).unwrap();
        let mut journal = prepare_broadcast_journal(
            &verified,
            &signing_request,
            &signing_request.signing_request_sha256,
        )
        .unwrap();
        verified.verification.request_sha256 = "c".repeat(64);
        let error = broadcast_verified_transaction(
            verified,
            &signing_request,
            &signing_request.signing_request_sha256,
            WrpcEncoding::Borsh,
            &mut journal,
            Path::new("/tmp/prometheus-unused-broadcast-journal.json"),
        )
        .await
        .expect_err("mismatched broadcast binding must fail");
        assert!(error
            .to_string()
            .contains("verified transaction is not bound"));
    }

    #[tokio::test]
    async fn observe_rejects_verified_binding_before_network_access() {
        let (request, artifact, funding, keypair) = fixture();
        let prepared = prepare_genesis(&request, &artifact, &funding).unwrap();
        let signing_request = prepared.signing_request.clone();
        let response = sign(&prepared, &keypair);
        let mut verified =
            verify_signature_response(prepared, &signing_request, &response).unwrap();
        verified.verification.request_sha256 = "c".repeat(64);
        let error = observe_deployed_utxo(&verified, &signing_request, WrpcEncoding::Borsh)
            .await
            .expect_err("mismatched observation binding must fail before RPC access");
        assert!(error
            .to_string()
            .contains("verified transaction is not bound"));
    }

    #[test]
    fn canonical_json_matches_python_sort_keys_shape() {
        let value = serde_json::json!({"z": [3, {"b": true, "a": "x"}], "a": 1});
        assert_eq!(
            String::from_utf8(canonical_json(&value).unwrap()).unwrap(),
            r#"{"a":1,"z":[3,{"a":"x","b":true}]}"#
        );
    }

    #[test]
    fn allows_only_false_secret_named_safety_flags() {
        reject_secret_fields(
            &serde_json::json!({
                "accepts_private_keys": false,
                "accepts_seed_phrases": false,
                "accepts_wallet_secrets": false
            }),
            "$",
        )
        .unwrap();
        let error = reject_secret_fields(&serde_json::json!({"accepts_private_keys": true}), "$")
            .expect_err("positive private-key capability must fail");
        assert!(error
            .to_string()
            .contains("secret-like fields are forbidden"));
    }

    #[test]
    fn artifact_loader_rejects_secret_like_extra_fields() {
        let (mut request, artifact, _, _) = fixture();
        let temp_dir = std::env::temp_dir().join(format!(
            "prometheus-silverc-secret-artifact-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let artifact_path = temp_dir.join("artifact.json");
        let mut value = serde_json::to_value(artifact).unwrap();
        value.as_object_mut().unwrap().insert(
            "private_key".to_string(),
            Value::String("forbidden".to_string()),
        );
        write_public_json(&artifact_path, &value).unwrap();
        request.contract.artifact_sha256 = sha256_hex(&fs::read(&artifact_path).unwrap());

        let error = load_artifact(&artifact_path, &request)
            .expect_err("secret-like artifact field must fail closed");
        assert!(error
            .to_string()
            .contains("secret-like fields are forbidden"));
        fs::remove_dir_all(temp_dir).unwrap();
    }

    #[test]
    fn broadcast_journal_is_exclusive_bound_and_recoverable() {
        let (request, artifact, funding, keypair) = fixture();
        let prepared = prepare_genesis(&request, &artifact, &funding).unwrap();
        let signing_request = prepared.signing_request.clone();
        let response = sign(&prepared, &keypair);
        let verified = verify_signature_response(prepared, &signing_request, &response).unwrap();
        let journal = prepare_broadcast_journal(
            &verified,
            &signing_request,
            &signing_request.signing_request_sha256,
        )
        .unwrap();
        let temp_dir = std::env::temp_dir().join(format!(
            "prometheus-silverc-journal-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let result_path = temp_dir.join("broadcast-result.json");
        let journal_path = broadcast_journal_path(&result_path);

        let lock = acquire_broadcast_lock(&result_path).unwrap();
        let lock_error =
            acquire_broadcast_lock(&result_path).expect_err("concurrent broadcast lock must fail");
        assert!(lock_error
            .to_string()
            .contains("another broadcast process holds"));
        drop(lock);
        drop(acquire_broadcast_lock(&result_path).unwrap());

        assert!(create_public_json(&journal_path, &journal).unwrap());
        assert!(!create_public_json(&journal_path, &journal).unwrap());
        let mut loaded = load_broadcast_journal(&journal_path, &journal).unwrap();
        assert_eq!(loaded, journal);
        let submission_started_at =
            mark_submission_in_progress(&mut loaded, &journal_path).unwrap();
        assert_eq!(loaded.status, "submission_in_progress");
        assert_eq!(
            loaded.submission_started_at_unix_seconds,
            Some(submission_started_at)
        );
        let retry_error = require_first_submission_attempt(&loaded)
            .expect_err("ambiguous retry must never authorize a second submission");
        assert!(retry_error
            .to_string()
            .contains("automatic resubmission is forbidden"));
        let loaded = load_broadcast_journal(&journal_path, &journal).unwrap();

        let result = broadcast_result(
            &signing_request,
            "submitted_unconfirmed",
            "local_rpc_submission",
            true,
            submission_started_at,
        );
        let finalized = finalize_broadcast_journal(loaded, result.clone()).unwrap();
        write_public_json(&journal_path, &finalized).unwrap();
        write_public_json(&result_path, &result).unwrap();
        assert_eq!(
            load_broadcast_journal(&journal_path, &journal).unwrap(),
            finalized
        );
        assert_eq!(
            load_broadcast_result(&result_path, &finalized).unwrap(),
            result
        );

        let legacy_result_path = temp_dir.join("legacy-broadcast-result.json");
        let mut legacy_value = serde_json::to_value(&result).unwrap();
        legacy_value
            .as_object_mut()
            .unwrap()
            .remove("record_source");
        write_public_json(&legacy_result_path, &legacy_value).unwrap();
        assert_eq!(
            load_broadcast_result(&legacy_result_path, &finalized)
                .unwrap()
                .record_source,
            "local_rpc_submission"
        );

        let mut mismatched = journal.clone();
        mismatched.expected_deploy_tx_id = "ff".repeat(32);
        let error = load_broadcast_journal(&journal_path, &mismatched)
            .expect_err("mismatched journal binding must fail");
        assert!(error
            .to_string()
            .contains("does not match the verified transaction"));
        fs::remove_dir_all(temp_dir).unwrap();
    }

    #[test]
    fn public_file_handoff_round_trip() {
        let (mut request, artifact, mut funding, keypair) = fixture();
        let temp_dir = std::env::temp_dir().join(format!(
            "prometheus-silverc-deployer-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let artifact_path = temp_dir.join("artifact.json");
        write_public_json(&artifact_path, &artifact).unwrap();
        request.contract.artifact_sha256 = sha256_hex(&fs::read(&artifact_path).unwrap());

        let request_path = temp_dir.join("deploy-request.json");
        let mut request_value = serde_json::to_value(&request).unwrap();
        request_value.as_object_mut().unwrap().insert(
            "safety".to_string(),
            serde_json::json!({
                "accepts_private_keys": false,
                "signs_transactions": false,
                "assembles_chain_transaction": false,
                "broadcasts_transactions": false,
                "deploys_contracts": false,
                "updates_status_files": false
            }),
        );
        request_value
            .as_object_mut()
            .unwrap()
            .remove("request_sha256");
        request.request_sha256 = sha256_hex(&canonical_json(&request_value).unwrap());
        request_value.as_object_mut().unwrap().insert(
            "request_sha256".to_string(),
            Value::String(request.request_sha256.clone()),
        );
        write_public_json(&request_path, &request_value).unwrap();

        funding.request_sha256 = request.request_sha256.clone();
        let funding_path = temp_dir.join("funding.json");
        write_public_json(&funding_path, &funding).unwrap();

        let loaded_request = load_deploy_request(&request_path).unwrap();
        let mut incomplete_safety_request = request_value.clone();
        incomplete_safety_request["safety"]
            .as_object_mut()
            .unwrap()
            .remove("updates_status_files");
        incomplete_safety_request
            .as_object_mut()
            .unwrap()
            .remove("request_sha256");
        let incomplete_hash = sha256_hex(&canonical_json(&incomplete_safety_request).unwrap());
        incomplete_safety_request
            .as_object_mut()
            .unwrap()
            .insert("request_sha256".to_string(), Value::String(incomplete_hash));
        let incomplete_path = temp_dir.join("incomplete-safety-request.json");
        write_public_json(&incomplete_path, &incomplete_safety_request).unwrap();
        let error = load_deploy_request(&incomplete_path)
            .expect_err("rehashed request with incomplete safety profile must fail");
        assert!(error.to_string().contains("required false-only profile"));

        let loaded_artifact = load_artifact(&artifact_path, &loaded_request).unwrap();
        let loaded_funding = load_funding_spec(&funding_path).unwrap();
        let prepared = prepare_genesis(&loaded_request, &loaded_artifact, &loaded_funding).unwrap();
        let response = sign(&prepared, &keypair);

        let signing_request_path = temp_dir.join("signing-request.json");
        let signature_response_path = temp_dir.join("signature-response.json");
        write_public_json(&signing_request_path, &prepared.signing_request).unwrap();
        write_public_json(&signature_response_path, &response).unwrap();

        let signing_request = load_signing_request(&signing_request_path).unwrap();
        let signature_response = load_signature_response(&signature_response_path).unwrap();
        let rebuilt = prepare_genesis(&loaded_request, &loaded_artifact, &loaded_funding).unwrap();
        let verified =
            verify_signature_response(rebuilt, &signing_request, &signature_response).unwrap();
        assert_eq!(
            verified.verification.status,
            "EXTERNAL_SIGNATURE_AND_TRANSACTION_VERIFIED"
        );
        assert_eq!(
            verified.verification.signing_request_sha256,
            signing_request.signing_request_sha256
        );

        fs::remove_dir_all(temp_dir).unwrap();
    }
}
