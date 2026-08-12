//! Keyless `GovernanceAutoTuningState.reportMetrics` transition primitives.
//!
//! The covenant state value is preserved exactly. A separate public P2PK input
//! pays the bounded fee, and both BIP340 signatures remain external.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::str::FromStr;

use anyhow::{anyhow, bail, Context, Result};
use kaspa_addresses::Prefix;
use kaspa_bip32::secp256k1::{schnorr::Signature, Message, XOnlyPublicKey, SECP256K1};
use kaspa_consensus_core::hashing::sighash::{
    calc_schnorr_signature_hash, SigHashReusedValuesUnsync,
};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::mass::units::{ComputeBudget, Gram, ScriptUnits};
use kaspa_consensus_core::mass::MassCalculator;
use kaspa_consensus_core::network::NetworkId;
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    CovenantBinding, PopulatedTransaction, SignableTransaction, Transaction, TransactionId,
    TransactionInput, TransactionOutput, UtxoEntry, VerifiableTransaction,
};
use kaspa_consensus_core::Hash;
use kaspa_rpc_core::{api::rpc::RpcApi, RpcUtxosByAddressesEntry};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{
    estimate_script_units_upper_bound, extract_script_pub_key_address, pay_to_script_hash_script,
    EngineCtx, EngineFlags, TxScriptEngine,
};
use kaspa_wrpc_client::WrpcEncoding;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{
    compile_contract, CompileOptions, CompiledContract, CovenantDeclCallOptions,
};
use tokio::time::timeout;

use super::{
    canonical_json, connect_rpc, consensus_params, deployer_address_and_funding_script,
    expected_storage_mass, external_signer_contract_map, fee_mass_profile, inspect_node,
    is_expected_transaction_not_found, read_public_json, reject_import_output_collisions,
    reject_secret_fields, rpc_timeout, sha256_hex, unix_seconds, validate_lower_hex,
    validate_resolver_network, validate_rpc_url, write_public_json, NodePreflight, OutpointSpec,
    ScriptSpec, PINNED_FEE_RATE_SOMPI_PER_KG, PUBLIC_TESTNET_RESOLVER, RPC_REQUEST_TIMEOUT,
    TRANSACTION_VERSION,
};

pub const ORACLE_CONTRACT_NAME: &str = "GovernanceAutoTuningState";
pub const ORACLE_ENTRYPOINT: &str = "reportMetrics";
pub const ORACLE_TRANSITION_SPEC_KIND: &str =
    "prometheus.metrics_oracle.report_metrics.transition_spec";
pub const ORACLE_SIGNING_REQUEST_KIND: &str =
    "prometheus.metrics_oracle.report_metrics.signing_request";
pub const ORACLE_SIGNATURE_VERIFICATION_KIND: &str =
    "prometheus.metrics_oracle.report_metrics.signature_verification";
pub const PINNED_SILVERSCRIPT_COMMIT: &str = "d25bd3427a093c17327ca3d6b9e1aa5f7688c863";
pub const STATE_INPUT_INDEX: usize = 0;
pub const SPONSOR_INPUT_INDEX: usize = 1;
pub const SUCCESSOR_OUTPUT_INDEX: u32 = 0;
pub const SPONSOR_CHANGE_OUTPUT_INDEX: u32 = 1;
pub const SPONSOR_COMPUTE_BUDGET: u16 = 10;

const ORACLE_SIGNATURE_WITH_HASH_TYPE_LEN: usize = 65;
const P2PK_SIGNATURE_SCRIPT_LEN: usize = 66;
const MAX_FP_RATE: i64 = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GovernanceState {
    pub metrics_oracle_pk: String,
    pub min_stake_kas: i64,
    pub min_guardian_rep: i64,
    pub min_confidence_ki: i64,
    pub validator_consensus: i64,
    pub reward_base: i64,
    pub last_tuning_block: i64,
    pub active_validators: i64,
    pub active_guardians: i64,
    pub proposals_per_day: i64,
    pub fp_rate: i64,
    pub last_metrics_block: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MetricsReport {
    pub new_active_validators: i64,
    pub new_active_guardians: i64,
    pub new_proposals_per_day: i64,
    pub new_fp_rate: i64,
    pub block_height: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CovenantUtxoSpec {
    pub amount: u64,
    pub script_public_key: ScriptSpec,
    pub covenant_id: String,
    pub block_daa_score: u64,
    pub is_coinbase: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StateInputSpec {
    pub outpoint: OutpointSpec,
    pub utxo: CovenantUtxoSpec,
    pub state: GovernanceState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SponsorUtxoSpec {
    pub amount: u64,
    pub script_public_key: ScriptSpec,
    pub block_daa_score: u64,
    pub is_coinbase: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SponsorChangeSpec {
    pub value: u64,
    pub script_public_key: ScriptSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FeeSponsorSpec {
    pub address: String,
    pub xonly_public_key_hex: String,
    pub outpoint: OutpointSpec,
    pub utxo: SponsorUtxoSpec,
    pub change_output: SponsorChangeSpec,
    pub minimum_fee_sompi: u64,
    pub maximum_fee_sompi: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OracleTransitionSpec {
    pub schema_version: u32,
    pub kind: String,
    pub network_id: String,
    pub rpc_url: String,
    pub tx_request_sha256: String,
    pub contract_instance_id: String,
    pub silverscript_commit: String,
    pub source_sha256: String,
    pub state_input: StateInputSpec,
    pub fee_sponsor: FeeSponsorSpec,
    pub report: MetricsReport,
    pub safety: BTreeMap<String, bool>,
    pub transition_spec_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SigningInput {
    pub role: String,
    pub input_index: u16,
    pub sighash_type: String,
    pub sighash_hex: String,
    pub expected_xonly_public_key_hex: String,
    pub external_signer_contract: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OracleSigningRequest {
    pub schema_version: u32,
    pub kind: String,
    pub status: String,
    pub tx_request_sha256: String,
    pub transition_spec_sha256: String,
    pub contract_name: String,
    pub entrypoint: String,
    pub contract_instance_id: String,
    pub network_id: String,
    pub rpc_url: String,
    pub transaction_version: u16,
    pub unsigned_transaction_id: String,
    pub covenant_id: String,
    pub state_outpoint: OutpointSpec,
    pub sponsor_outpoint: OutpointSpec,
    pub state_value: u64,
    pub state_value_preserved: bool,
    pub sponsor_input_value: u64,
    pub sponsor_change_value: u64,
    pub fee_sompi: u64,
    pub minimum_fee_sompi: u64,
    pub maximum_fee_sompi: u64,
    pub oracle_compute_budget: u16,
    pub sponsor_compute_budget: u16,
    pub compute_mass: u64,
    pub transient_mass: u64,
    pub storage_mass: u64,
    pub normalized_non_contextual_mass: u64,
    pub normalized_overall_mass: u64,
    pub pinned_fee_rate_sompi_per_kg: u64,
    pub minimum_relay_fee_sompi: u64,
    pub minimum_operator_fee_sompi: u64,
    pub source_sha256: String,
    pub predecessor_script_sha256: String,
    pub successor_script_sha256: String,
    pub predecessor_script_public_key: ScriptSpec,
    pub successor_script_public_key: ScriptSpec,
    pub report: MetricsReport,
    pub oracle_signing: SigningInput,
    pub sponsor_signing: SigningInput,
    pub safety: BTreeMap<String, bool>,
    pub signing_request_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OracleSignatureVerification {
    pub schema_version: u32,
    pub kind: String,
    pub status: String,
    pub tx_request_sha256: String,
    pub transition_spec_sha256: String,
    pub signing_request_sha256: String,
    pub transaction_id: String,
    pub covenant_id: String,
    pub oracle_signature_sha256: String,
    pub sponsor_signature_sha256: String,
    pub state_value_preserved: bool,
    pub signature_validation: String,
    pub transaction_validation: String,
    pub safety: BTreeMap<String, bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OracleTransitionPreflight {
    pub schema_version: u32,
    pub evidence_type: String,
    pub status: String,
    pub tx_request_sha256: String,
    pub transition_spec_sha256: String,
    pub contract_instance_id: String,
    pub state_outpoint: OutpointSpec,
    pub state_amount: u64,
    pub state_covenant_id: String,
    pub state_utxo_unspent: bool,
    pub sponsor_outpoint: OutpointSpec,
    pub sponsor_amount: u64,
    pub sponsor_utxo_unspent: bool,
    pub node: NodePreflight,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OracleBroadcastResult {
    pub schema_version: u32,
    pub result_type: String,
    pub status: String,
    pub tx_request_sha256: String,
    pub transition_spec_sha256: String,
    pub signing_request_sha256: String,
    pub predecessor_instance_id: String,
    pub successor_instance_id: String,
    pub transaction_id: String,
    pub covenant_id: String,
    pub submitted_at_unix_seconds: u64,
    pub record_source: String,
    pub confirmation_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OracleBroadcastJournal {
    pub schema_version: u32,
    pub journal_type: String,
    pub status: String,
    pub tx_request_sha256: String,
    pub transition_spec_sha256: String,
    pub signing_request_sha256: String,
    pub predecessor_instance_id: String,
    pub expected_successor_instance_id: String,
    pub expected_transaction_id: String,
    pub covenant_id: String,
    pub acknowledged_signing_request_sha256: String,
    pub created_at_unix_seconds: u64,
    pub updated_at_unix_seconds: u64,
    pub submission_started_at_unix_seconds: Option<u64>,
    pub result: Option<OracleBroadcastResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OracleNodeObservation {
    pub schema_version: u32,
    pub evidence_type: String,
    pub status: String,
    pub tx_request_sha256: String,
    pub transition_spec_sha256: String,
    pub signing_request_sha256: String,
    pub predecessor_instance_id: String,
    pub successor_instance_id: String,
    pub transaction_id: String,
    pub output_index: u32,
    pub covenant_id: String,
    pub amount: u64,
    pub successor_script_public_key: ScriptSpec,
    pub block_daa_score: u64,
    pub observed_virtual_daa_score: u64,
    pub daa_depth: u64,
    pub observed_at_unix_seconds: u64,
    pub explorer_block_hash_required: bool,
}

#[derive(Debug)]
pub struct PreparedOracleTransition {
    pub transaction: SignableTransaction,
    pub signing_request: OracleSigningRequest,
    source: String,
    predecessor_state: GovernanceState,
}

#[derive(Debug)]
pub struct VerifiedOracleTransition {
    pub transaction: SignableTransaction,
    pub verification: OracleSignatureVerification,
}

fn oracle_safety_map() -> BTreeMap<String, bool> {
    BTreeMap::from([
        ("accepts_private_keys".to_string(), false),
        ("accepts_seed_phrases".to_string(), false),
        ("accepts_wallet_secrets".to_string(), false),
        ("accepts_raw_transactions".to_string(), false),
        ("signs_transactions".to_string(), false),
    ])
}

fn transition_spec_hash(spec: &OracleTransitionSpec) -> Result<String> {
    let mut value = serde_json::to_value(spec)?;
    value
        .as_object_mut()
        .expect("transition spec serializes as object")
        .remove("transition_spec_sha256");
    Ok(sha256_hex(&canonical_json(&value)?))
}

fn signing_request_hash(request: &OracleSigningRequest) -> Result<String> {
    let mut value = serde_json::to_value(request)?;
    value
        .as_object_mut()
        .expect("oracle signing request serializes as object")
        .remove("signing_request_sha256");
    Ok(sha256_hex(&canonical_json(&value)?))
}

pub fn finalize_transition_spec_hash(spec: &mut OracleTransitionSpec) -> Result<()> {
    spec.transition_spec_sha256 = transition_spec_hash(spec)?;
    Ok(())
}

fn validate_nonnegative_state(state: &GovernanceState) -> Result<()> {
    let values = [
        ("min_stake_kas", state.min_stake_kas),
        ("min_guardian_rep", state.min_guardian_rep),
        ("min_confidence_ki", state.min_confidence_ki),
        ("validator_consensus", state.validator_consensus),
        ("reward_base", state.reward_base),
        ("last_tuning_block", state.last_tuning_block),
        ("active_validators", state.active_validators),
        ("active_guardians", state.active_guardians),
        ("proposals_per_day", state.proposals_per_day),
        ("fp_rate", state.fp_rate),
        ("last_metrics_block", state.last_metrics_block),
    ];
    if let Some((name, _)) = values.into_iter().find(|(_, value)| *value < 0) {
        bail!("state_input.state.{name} must be nonnegative");
    }
    if state.fp_rate > MAX_FP_RATE {
        bail!("state_input.state.fp_rate exceeds contract MAX_FP_RATE");
    }
    validate_lower_hex(&state.metrics_oracle_pk, 32, "state metrics_oracle_pk")?;
    Ok(())
}

fn validate_report(report: &MetricsReport, state: &GovernanceState) -> Result<()> {
    let values = [
        ("new_active_validators", report.new_active_validators),
        ("new_active_guardians", report.new_active_guardians),
        ("new_proposals_per_day", report.new_proposals_per_day),
        ("new_fp_rate", report.new_fp_rate),
        ("block_height", report.block_height),
    ];
    if let Some((name, _)) = values.into_iter().find(|(_, value)| *value < 0) {
        bail!("report.{name} must be nonnegative");
    }
    if report.new_fp_rate > MAX_FP_RATE {
        bail!("report.new_fp_rate exceeds contract MAX_FP_RATE");
    }
    if report.block_height < state.last_metrics_block {
        bail!("report.block_height is below predecessor last_metrics_block");
    }
    Ok(())
}

pub fn validate_transition_spec(spec: &OracleTransitionSpec) -> Result<()> {
    if spec.schema_version != 1 || spec.kind != ORACLE_TRANSITION_SPEC_KIND {
        bail!("unsupported oracle transition spec schema/type");
    }
    if spec.safety != oracle_safety_map() {
        bail!("oracle transition safety profile mismatch");
    }
    if spec.transition_spec_sha256 != transition_spec_hash(spec)? {
        bail!("transition_spec_sha256 mismatch");
    }
    validate_lower_hex(&spec.tx_request_sha256, 32, "tx_request_sha256")?;
    validate_lower_hex(&spec.source_sha256, 32, "source_sha256")?;
    if spec.silverscript_commit != PINNED_SILVERSCRIPT_COMMIT {
        bail!("oracle transition must use the pinned Silverscript commit");
    }
    let network_id = NetworkId::from_str(&spec.network_id).context("invalid network_id")?;
    validate_rpc_url(&spec.rpc_url)?;
    if spec.rpc_url == PUBLIC_TESTNET_RESOLVER {
        validate_resolver_network(network_id)?;
    }
    validate_nonnegative_state(&spec.state_input.state)?;
    validate_report(&spec.report, &spec.state_input.state)?;
    if spec.state_input.utxo.is_coinbase || spec.fee_sponsor.utxo.is_coinbase {
        bail!("coinbase UTXOs are not accepted by the oracle operator");
    }
    if spec.state_input.outpoint == spec.fee_sponsor.outpoint {
        bail!("state and sponsor inputs must use distinct outpoints");
    }
    let expected_instance_id = format!(
        "{}:{}",
        spec.state_input.outpoint.transaction_id, spec.state_input.outpoint.index
    );
    if spec.contract_instance_id != expected_instance_id {
        bail!("contract_instance_id must equal the exact state outpoint");
    }
    validate_lower_hex(&spec.state_input.utxo.covenant_id, 32, "state covenant_id")?;
    let sponsor_key = validate_lower_hex(
        &spec.fee_sponsor.xonly_public_key_hex,
        32,
        "fee sponsor x-only public key",
    )?;
    let (sponsor_address, sponsor_script) = deployer_address_and_funding_script(
        &spec.fee_sponsor.address,
        network_id,
        &spec.fee_sponsor.utxo.script_public_key,
    )?;
    if sponsor_address.payload.as_slice() != sponsor_key.as_slice() {
        bail!("fee sponsor address does not match x-only public key");
    }
    let change_script = spec
        .fee_sponsor
        .change_output
        .script_public_key
        .to_script_public_key()?;
    if change_script != sponsor_script {
        bail!("fee sponsor change must return to the sponsor P2PK script");
    }
    if spec.fee_sponsor.change_output.value == 0 {
        bail!("fee sponsor change output must be nonzero");
    }
    if spec.fee_sponsor.maximum_fee_sompi < spec.fee_sponsor.minimum_fee_sompi {
        bail!("maximum_fee_sompi must not be below minimum_fee_sompi");
    }
    Ok(())
}

pub fn load_transition_spec(path: &Path) -> Result<OracleTransitionSpec> {
    let (spec, _): (OracleTransitionSpec, Value) = read_public_json(path)?;
    validate_transition_spec(&spec)?;
    Ok(spec)
}

pub fn load_oracle_signing_request(path: &Path) -> Result<OracleSigningRequest> {
    let (request, _): (OracleSigningRequest, Value) = read_public_json(path)?;
    if request.schema_version != 1
        || request.kind != ORACLE_SIGNING_REQUEST_KIND
        || request.status != "READY_FOR_EXTERNAL_ORACLE_AND_SPONSOR_SIGNATURES"
        || request.safety != oracle_safety_map()
        || request.signing_request_sha256 != signing_request_hash(&request)?
    {
        bail!("invalid oracle signing request binding/status/safety");
    }
    Ok(request)
}

pub fn validate_metrics_tx_request(path: &Path, spec: &OracleTransitionSpec) -> Result<()> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid JSON in {}", path.display()))?;
    reject_secret_fields(&value, "$")?;
    let provided_hash = value
        .as_object_mut()
        .and_then(|object| object.remove("request_sha256"))
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| anyhow!("metrics tx request is missing request_sha256"))?;
    if provided_hash != sha256_hex(&canonical_json(&value)?)
        || provided_hash != spec.tx_request_sha256
    {
        bail!("metrics tx request hash does not match transition spec");
    }
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("metrics tx request must be an object"))?;
    if object.get("kind").and_then(Value::as_str)
        != Some("prometheus.metrics_oracle.report_metrics.tx_request")
        || object.get("status").and_then(Value::as_str)
            != Some("READY_FOR_KEYLESS_REPORT_METRICS_OPERATOR")
    {
        bail!("metrics tx request is not signer-ready");
    }
    if object.get("safety_scope").and_then(Value::as_str) != Some("metrics_tx_request_builder_only")
        || object.get("safety")
            != Some(&serde_json::json!({
                "accepts_private_keys": false,
                "signs_transactions": false,
                "assembles_chain_transaction": false,
                "broadcasts_transactions": false,
            }))
        || object.get("repository_operator")
            != Some(&serde_json::json!({
                "assembles_transaction_in_memory": true,
                "accepts_private_keys": false,
                "signs_transactions": false,
                "requires_external_oracle_signature": true,
                "requires_external_fee_sponsor_signature": true,
                "broadcast_requires_exact_signing_request_hash_acknowledgement": true,
            }))
    {
        bail!("metrics tx request safety/capability profile mismatch");
    }
    let contract = object
        .get("contract")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("metrics tx request contract is missing"))?;
    if contract.get("name").and_then(Value::as_str) != Some(ORACLE_CONTRACT_NAME)
        || contract.get("entrypoint").and_then(Value::as_str) != Some(ORACLE_ENTRYPOINT)
        || contract.get("instance_id").and_then(Value::as_str)
            != Some(spec.contract_instance_id.as_str())
    {
        bail!("metrics tx request contract binding mismatch");
    }
    let release = object
        .get("release_bundle")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("metrics tx request release bundle is missing"))?;
    if release.get("silverscript_commit").and_then(Value::as_str)
        != Some(spec.silverscript_commit.as_str())
        || release.get("source_sha256").and_then(Value::as_str) != Some(spec.source_sha256.as_str())
    {
        bail!("metrics tx request release binding mismatch");
    }
    let metrics_report = object
        .get("metrics_report")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("metrics tx request metrics_report is missing"))?;
    if metrics_report
        .get("metrics_oracle_pubkey")
        .and_then(Value::as_str)
        != Some(spec.state_input.state.metrics_oracle_pk.as_str())
        || metrics_report
            .get("previous_state")
            .and_then(Value::as_object)
            .and_then(|state| state.get("last_metrics_block"))
            .and_then(Value::as_i64)
            != Some(spec.state_input.state.last_metrics_block)
    {
        bail!("metrics tx request oracle/predecessor binding mismatch");
    }
    let signature = object
        .get("signature")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("metrics tx request signature contract is missing"))?;
    if signature.get("required").and_then(Value::as_bool) != Some(true)
        || signature.get("signer_pubkey").and_then(Value::as_str)
            != Some(spec.state_input.state.metrics_oracle_pk.as_str())
        || signature
            .get("repository_must_not_hold_signing_material")
            .and_then(Value::as_bool)
            != Some(true)
    {
        bail!("metrics tx request signature contract mismatch");
    }
    let args = object
        .get("entrypoint_args")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("metrics tx request entrypoint_args are missing"))?;
    let expected = [
        ("new_active_validators", spec.report.new_active_validators),
        ("new_active_guardians", spec.report.new_active_guardians),
        ("new_proposals_per_day", spec.report.new_proposals_per_day),
        ("new_fp_rate", spec.report.new_fp_rate),
        ("block_height", spec.report.block_height),
    ];
    for (name, expected_value) in expected {
        if args.get(name).and_then(Value::as_i64) != Some(expected_value) {
            bail!("metrics tx request {name} mismatch");
        }
    }
    Ok(())
}

fn state_args(state: &GovernanceState) -> Result<Vec<Expr<'static>>> {
    Ok(vec![
        Expr::bytes(validate_lower_hex(
            &state.metrics_oracle_pk,
            32,
            "state metrics_oracle_pk",
        )?),
        Expr::int(state.min_stake_kas),
        Expr::int(state.min_guardian_rep),
        Expr::int(state.min_confidence_ki),
        Expr::int(state.validator_consensus),
        Expr::int(state.reward_base),
        Expr::int(state.last_tuning_block),
        Expr::int(state.active_validators),
        Expr::int(state.active_guardians),
        Expr::int(state.proposals_per_day),
        Expr::int(state.fp_rate),
        Expr::int(state.last_metrics_block),
    ])
}

fn successor_state(state: &GovernanceState, report: &MetricsReport) -> GovernanceState {
    GovernanceState {
        metrics_oracle_pk: state.metrics_oracle_pk.clone(),
        min_stake_kas: state.min_stake_kas,
        min_guardian_rep: state.min_guardian_rep,
        min_confidence_ki: state.min_confidence_ki,
        validator_consensus: state.validator_consensus,
        reward_base: state.reward_base,
        last_tuning_block: state.last_tuning_block,
        active_validators: report.new_active_validators,
        active_guardians: report.new_active_guardians,
        proposals_per_day: report.new_proposals_per_day,
        fp_rate: report.new_fp_rate,
        last_metrics_block: report.block_height,
    }
}

fn compile_state<'a>(source: &'a str, state: &GovernanceState) -> Result<CompiledContract<'a>> {
    let args = state_args(state)?;
    let compiled = compile_contract(source, &args, CompileOptions::default())
        .map_err(|error| anyhow!("failed to compile GovernanceAutoTuningState: {error}"))?;
    if compiled.contract_name != ORACLE_CONTRACT_NAME {
        bail!("oracle source compiled to an unexpected contract name");
    }
    Ok(compiled)
}

fn report_metrics_sigscript(
    compiled: &CompiledContract<'_>,
    report: &MetricsReport,
    signature_with_hash_type: Vec<u8>,
) -> Result<Vec<u8>> {
    if signature_with_hash_type.len() != ORACLE_SIGNATURE_WITH_HASH_TYPE_LEN {
        bail!("oracle signature argument must contain 64 signature bytes plus sighash type");
    }
    let args = vec![
        Expr::int(report.new_active_validators),
        Expr::int(report.new_active_guardians),
        Expr::int(report.new_proposals_per_day),
        Expr::int(report.new_fp_rate),
        Expr::int(report.block_height),
        Expr::bytes(signature_with_hash_type),
    ];
    let mut sigscript = compiled
        .build_sig_script_for_covenant_decl(
            ORACLE_ENTRYPOINT,
            args,
            CovenantDeclCallOptions { is_leader: false },
        )
        .map_err(|error| anyhow!("failed to build reportMetrics covenant sigscript: {error}"))?;
    let mut builder = ScriptBuilder::with_flags(EngineFlags {
        covenants_enabled: true,
        ..Default::default()
    });
    builder
        .add_data(&compiled.script)
        .context("failed to append predecessor redeem script")?;
    sigscript.extend_from_slice(&builder.drain());
    Ok(sigscript)
}

fn p2pk_signature_script(signature_bytes: &[u8]) -> Result<Vec<u8>> {
    if signature_bytes.len() != 64 {
        bail!("P2PK signature must contain exactly 64 bytes");
    }
    let mut script = Vec::with_capacity(P2PK_SIGNATURE_SCRIPT_LEN);
    script.push(65);
    script.extend_from_slice(signature_bytes);
    script.push(SIG_HASH_ALL.to_u8());
    Ok(script)
}

fn signing_input(role: &str, index: usize, sighash: String, public_key: String) -> SigningInput {
    SigningInput {
        role: role.to_string(),
        input_index: index as u16,
        sighash_type: "SIG_HASH_ALL".to_string(),
        sighash_hex: sighash,
        expected_xonly_public_key_hex: public_key,
        external_signer_contract: external_signer_contract_map(),
    }
}

pub fn prepare_oracle_transition(
    spec: &OracleTransitionSpec,
    metrics_tx_request_path: &Path,
    source: &str,
) -> Result<PreparedOracleTransition> {
    validate_transition_spec(spec)?;
    validate_metrics_tx_request(metrics_tx_request_path, spec)?;
    if sha256_hex(source.as_bytes()) != spec.source_sha256 {
        bail!("GovernanceAutoTuningState source_sha256 mismatch");
    }

    let network_id = NetworkId::from_str(&spec.network_id)?;
    let params = consensus_params(network_id)?;
    let predecessor = compile_state(source, &spec.state_input.state)?;
    let successor_state = successor_state(&spec.state_input.state, &spec.report);
    let successor = compile_state(source, &successor_state)?;
    let predecessor_script_public_key = pay_to_script_hash_script(&predecessor.script);
    let supplied_predecessor_script_public_key = spec
        .state_input
        .utxo
        .script_public_key
        .to_script_public_key()?;
    if predecessor_script_public_key != supplied_predecessor_script_public_key {
        bail!("compiled predecessor state does not match the approved state UTXO script");
    }
    let successor_script_public_key = pay_to_script_hash_script(&successor.script);
    let covenant_id =
        Hash::from_str(&spec.state_input.utxo.covenant_id).context("invalid state covenant_id")?;
    let state_outpoint = spec.state_input.outpoint.to_outpoint()?;
    let sponsor_outpoint = spec.fee_sponsor.outpoint.to_outpoint()?;
    let (_, sponsor_script_public_key) = deployer_address_and_funding_script(
        &spec.fee_sponsor.address,
        network_id,
        &spec.fee_sponsor.utxo.script_public_key,
    )?;
    let sponsor_change_script = spec
        .fee_sponsor
        .change_output
        .script_public_key
        .to_script_public_key()?;

    let fee_sompi = spec
        .fee_sponsor
        .utxo
        .amount
        .checked_sub(spec.fee_sponsor.change_output.value)
        .ok_or_else(|| anyhow!("fee sponsor amount is below sponsor change value"))?;
    if fee_sompi < spec.fee_sponsor.minimum_fee_sompi
        || fee_sompi > spec.fee_sponsor.maximum_fee_sompi
    {
        bail!("implicit sponsor fee is outside the approved fee range");
    }

    let oracle_placeholder = vec![0; ORACLE_SIGNATURE_WITH_HASH_TYPE_LEN];
    let oracle_sigscript =
        report_metrics_sigscript(&predecessor, &spec.report, oracle_placeholder)?;
    let sigop_script_units = ScriptUnits::from(Gram(params.mass_per_sig_op)).0;
    let oracle_script_units =
        estimate_script_units_upper_bound::<PopulatedTransaction<'_>, SigHashReusedValuesUnsync>(
            &oracle_sigscript,
            &predecessor_script_public_key,
            sigop_script_units,
        );
    let oracle_compute_budget =
        ComputeBudget::checked_covering_script_units(oracle_script_units)
            .ok_or_else(|| anyhow!("oracle covenant compute budget exceeds u16"))?;

    let state_input = TransactionInput::new_with_compute_budget(
        state_outpoint,
        oracle_sigscript,
        0,
        oracle_compute_budget.value(),
    );
    let sponsor_input = TransactionInput::new_with_compute_budget(
        sponsor_outpoint,
        vec![0; P2PK_SIGNATURE_SCRIPT_LEN],
        0,
        SPONSOR_COMPUTE_BUDGET,
    );
    let outputs = vec![
        TransactionOutput {
            value: spec.state_input.utxo.amount,
            script_public_key: successor_script_public_key.clone(),
            covenant: Some(CovenantBinding {
                authorizing_input: STATE_INPUT_INDEX as u16,
                covenant_id,
            }),
        },
        TransactionOutput {
            value: spec.fee_sponsor.change_output.value,
            script_public_key: sponsor_change_script,
            covenant: None,
        },
    ];
    let tx = Transaction::new(
        TRANSACTION_VERSION,
        vec![state_input, sponsor_input],
        outputs,
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        Vec::new(),
    );
    let state_utxo = UtxoEntry::new(
        spec.state_input.utxo.amount,
        predecessor_script_public_key.clone(),
        spec.state_input.utxo.block_daa_score,
        false,
        Some(covenant_id),
    );
    let sponsor_utxo = UtxoEntry::new(
        spec.fee_sponsor.utxo.amount,
        sponsor_script_public_key,
        spec.fee_sponsor.utxo.block_daa_score,
        false,
        None,
    );
    let transaction = SignableTransaction::with_entries(tx, vec![state_utxo, sponsor_utxo]);
    let storage_mass = expected_storage_mass(&transaction, &params)?;
    transaction.tx.set_storage_mass(storage_mass);
    let masses = MassCalculator::new_with_consensus_params(&params)
        .calc_non_contextual_masses(&transaction.tx);
    let fee_mass = fee_mass_profile(
        masses.compute_mass,
        masses.transient_mass,
        storage_mass,
        &params,
    )?;
    if fee_sompi < fee_mass.minimum_operator_fee_sompi {
        bail!(
            "implicit sponsor fee is below pinned operator fee/mass floor: {} < {}",
            fee_sompi,
            fee_mass.minimum_operator_fee_sompi
        );
    }

    let (oracle_sighash, sponsor_sighash) = {
        let reused = SigHashReusedValuesUnsync::new();
        let verifiable = transaction.as_verifiable();
        (
            calc_schnorr_signature_hash(&verifiable, STATE_INPUT_INDEX, SIG_HASH_ALL, &reused),
            calc_schnorr_signature_hash(&verifiable, SPONSOR_INPUT_INDEX, SIG_HASH_ALL, &reused),
        )
    };
    let unsigned_transaction_id = transaction.tx.id().to_string();
    let mut signing_request = OracleSigningRequest {
        schema_version: 1,
        kind: ORACLE_SIGNING_REQUEST_KIND.to_string(),
        status: "READY_FOR_EXTERNAL_ORACLE_AND_SPONSOR_SIGNATURES".to_string(),
        tx_request_sha256: spec.tx_request_sha256.clone(),
        transition_spec_sha256: spec.transition_spec_sha256.clone(),
        contract_name: ORACLE_CONTRACT_NAME.to_string(),
        entrypoint: ORACLE_ENTRYPOINT.to_string(),
        contract_instance_id: spec.contract_instance_id.clone(),
        network_id: spec.network_id.clone(),
        rpc_url: spec.rpc_url.clone(),
        transaction_version: TRANSACTION_VERSION,
        unsigned_transaction_id,
        covenant_id: spec.state_input.utxo.covenant_id.clone(),
        state_outpoint: spec.state_input.outpoint.clone(),
        sponsor_outpoint: spec.fee_sponsor.outpoint.clone(),
        state_value: spec.state_input.utxo.amount,
        state_value_preserved: true,
        sponsor_input_value: spec.fee_sponsor.utxo.amount,
        sponsor_change_value: spec.fee_sponsor.change_output.value,
        fee_sompi,
        minimum_fee_sompi: spec.fee_sponsor.minimum_fee_sompi,
        maximum_fee_sompi: spec.fee_sponsor.maximum_fee_sompi,
        oracle_compute_budget: oracle_compute_budget.value(),
        sponsor_compute_budget: SPONSOR_COMPUTE_BUDGET,
        compute_mass: fee_mass.compute_mass,
        transient_mass: fee_mass.transient_mass,
        storage_mass,
        normalized_non_contextual_mass: fee_mass.normalized_non_contextual_mass,
        normalized_overall_mass: fee_mass.normalized_overall_mass,
        pinned_fee_rate_sompi_per_kg: PINNED_FEE_RATE_SOMPI_PER_KG,
        minimum_relay_fee_sompi: fee_mass.minimum_relay_fee_sompi,
        minimum_operator_fee_sompi: fee_mass.minimum_operator_fee_sompi,
        source_sha256: spec.source_sha256.clone(),
        predecessor_script_sha256: sha256_hex(&predecessor.script),
        successor_script_sha256: sha256_hex(&successor.script),
        predecessor_script_public_key: ScriptSpec::from_script_public_key(
            &predecessor_script_public_key,
        ),
        successor_script_public_key: ScriptSpec::from_script_public_key(
            &successor_script_public_key,
        ),
        report: spec.report.clone(),
        oracle_signing: signing_input(
            "metrics_oracle",
            STATE_INPUT_INDEX,
            oracle_sighash.to_string(),
            spec.state_input.state.metrics_oracle_pk.clone(),
        ),
        sponsor_signing: signing_input(
            "fee_sponsor",
            SPONSOR_INPUT_INDEX,
            sponsor_sighash.to_string(),
            spec.fee_sponsor.xonly_public_key_hex.clone(),
        ),
        safety: oracle_safety_map(),
        signing_request_sha256: String::new(),
    };
    signing_request.signing_request_sha256 = signing_request_hash(&signing_request)?;
    Ok(PreparedOracleTransition {
        transaction,
        signing_request,
        source: source.to_string(),
        predecessor_state: spec.state_input.state.clone(),
    })
}

pub async fn preflight_oracle_transition(
    spec: &OracleTransitionSpec,
    metrics_tx_request_path: &Path,
    source: &str,
    encoding: WrpcEncoding,
) -> Result<OracleTransitionPreflight> {
    let _prepared = prepare_oracle_transition(spec, metrics_tx_request_path, source)?;
    let network_id = NetworkId::from_str(&spec.network_id)?;
    let params = consensus_params(network_id)?;
    let state_script = spec
        .state_input
        .utxo
        .script_public_key
        .to_script_public_key()?;
    let state_address = extract_script_pub_key_address(&state_script, Prefix::from(network_id))
        .context("state script_public_key is not an address-bearing P2SH script")?;
    let (sponsor_address, sponsor_script) = deployer_address_and_funding_script(
        &spec.fee_sponsor.address,
        network_id,
        &spec.fee_sponsor.utxo.script_public_key,
    )?;
    let state_outpoint = spec.state_input.outpoint.to_outpoint()?;
    let sponsor_outpoint = spec.fee_sponsor.outpoint.to_outpoint()?;
    let expected_covenant_id = Hash::from_str(&spec.state_input.utxo.covenant_id)?;

    let client = connect_rpc(&spec.rpc_url, network_id, encoding).await?;
    let node = match inspect_node(&client, &spec.rpc_url, network_id, &params, true).await {
        Ok(node) => node,
        Err(error) => {
            let _ = client.disconnect().await;
            return Err(error);
        }
    };
    let entries_result = timeout(
        RPC_REQUEST_TIMEOUT,
        client.get_utxos_by_addresses(vec![state_address.clone(), sponsor_address.clone()]),
    )
    .await
    .map_err(|_| rpc_timeout("get_utxos_by_addresses for oracle transition preflight"))?;
    let _ = client.disconnect().await;
    let entries = entries_result.context("failed to query oracle transition UTXOs")?;
    let state_entry = entries
        .iter()
        .find(|entry| {
            entry.outpoint.transaction_id == state_outpoint.transaction_id
                && entry.outpoint.index == state_outpoint.index
        })
        .ok_or_else(|| anyhow!("state outpoint is absent or already spent"))?;
    if state_entry.address.as_ref() != Some(&state_address)
        || state_entry.utxo_entry.amount != spec.state_input.utxo.amount
        || state_entry.utxo_entry.script_public_key != state_script
        || state_entry.utxo_entry.block_daa_score != spec.state_input.utxo.block_daa_score
        || state_entry.utxo_entry.is_coinbase
        || state_entry.utxo_entry.covenant_id != Some(expected_covenant_id)
    {
        bail!("live state UTXO does not match the approved transition specification");
    }
    let sponsor_entry = entries
        .iter()
        .find(|entry| {
            entry.outpoint.transaction_id == sponsor_outpoint.transaction_id
                && entry.outpoint.index == sponsor_outpoint.index
        })
        .ok_or_else(|| anyhow!("fee sponsor outpoint is absent or already spent"))?;
    if sponsor_entry.address.as_ref() != Some(&sponsor_address)
        || sponsor_entry.utxo_entry.amount != spec.fee_sponsor.utxo.amount
        || sponsor_entry.utxo_entry.script_public_key != sponsor_script
        || sponsor_entry.utxo_entry.block_daa_score != spec.fee_sponsor.utxo.block_daa_score
        || sponsor_entry.utxo_entry.is_coinbase
        || sponsor_entry.utxo_entry.covenant_id.is_some()
    {
        bail!("live fee sponsor UTXO does not match the approved transition specification");
    }
    Ok(OracleTransitionPreflight {
        schema_version: 1,
        evidence_type: "prometheus.metrics_oracle.report_metrics.transition_preflight".to_string(),
        status: "TOCCATA_ORACLE_STATE_AND_SPONSOR_UTXOS_READY".to_string(),
        tx_request_sha256: spec.tx_request_sha256.clone(),
        transition_spec_sha256: spec.transition_spec_sha256.clone(),
        contract_instance_id: spec.contract_instance_id.clone(),
        state_outpoint: spec.state_input.outpoint.clone(),
        state_amount: spec.state_input.utxo.amount,
        state_covenant_id: spec.state_input.utxo.covenant_id.clone(),
        state_utxo_unspent: true,
        sponsor_outpoint: spec.fee_sponsor.outpoint.clone(),
        sponsor_amount: spec.fee_sponsor.utxo.amount,
        sponsor_utxo_unspent: true,
        node,
    })
}

fn verify_bip340(signature_hex: &str, signing: &SigningInput) -> Result<Vec<u8>> {
    let signature_bytes =
        validate_lower_hex(signature_hex, 64, &format!("{} signature", signing.role))?;
    let public_key_bytes = validate_lower_hex(
        &signing.expected_xonly_public_key_hex,
        32,
        &format!("{} x-only public key", signing.role),
    )?;
    let sighash_bytes = validate_lower_hex(
        &signing.sighash_hex,
        32,
        &format!("{} sighash", signing.role),
    )?;
    let signature = Signature::from_slice(&signature_bytes)?;
    let public_key = XOnlyPublicKey::from_slice(&public_key_bytes)?;
    let message = Message::from_digest_slice(&sighash_bytes)?;
    SECP256K1
        .verify_schnorr(&signature, &message, &public_key)
        .with_context(|| format!("{} BIP340 signature verification failed", signing.role))?;
    Ok(signature_bytes)
}

fn execute_all_inputs(transaction: &SignableTransaction, network_id: NetworkId) -> Result<()> {
    let entries = transaction
        .entries
        .iter()
        .cloned()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| anyhow!("oracle transaction is missing UTXO entries"))?;
    let populated = PopulatedTransaction::new(&transaction.tx, entries);
    let covenants = CovenantsContext::from_tx(&populated)
        .context("failed to construct covenant execution context")?;
    let reused = SigHashReusedValuesUnsync::new();
    let cache = Cache::new(10_000);
    let params = consensus_params(network_id)?;
    let flags = EngineFlags {
        covenants_enabled: true,
        sigop_script_units: Gram(params.mass_per_sig_op).into(),
    };
    for (input_index, input) in transaction.tx.inputs.iter().enumerate() {
        let utxo = populated
            .utxo(input_index)
            .ok_or_else(|| anyhow!("missing UTXO for input {input_index}"))?;
        let mut engine = TxScriptEngine::from_transaction_input_with_script_units_limit(
            &populated,
            input,
            input_index,
            utxo,
            EngineCtx::new(&cache)
                .with_reused(&reused)
                .with_covenants_ctx(&covenants),
            flags,
            input.compute_commit.allowed_script_units(),
        );
        engine.execute().with_context(|| {
            format!("complete transaction verification failed for input {input_index}")
        })?;
    }
    Ok(())
}

pub fn import_oracle_signatures(
    prepared: PreparedOracleTransition,
    signing_request: &OracleSigningRequest,
    oracle_signature_hex: &str,
    sponsor_signature_hex: &str,
) -> Result<VerifiedOracleTransition> {
    if prepared.signing_request != *signing_request
        || signing_request.signing_request_sha256 != signing_request_hash(signing_request)?
    {
        bail!("rebuilt oracle transition does not match signing request");
    }
    let oracle_signature = verify_bip340(oracle_signature_hex, &signing_request.oracle_signing)?;
    let sponsor_signature = verify_bip340(sponsor_signature_hex, &signing_request.sponsor_signing)?;
    let mut transaction = prepared.transaction;
    let compiled_predecessor = compile_state(&prepared.source, &prepared.predecessor_state)?;
    let mut oracle_with_hash_type = oracle_signature.clone();
    oracle_with_hash_type.push(SIG_HASH_ALL.to_u8());
    transaction.tx.inputs[STATE_INPUT_INDEX].signature_script = report_metrics_sigscript(
        &compiled_predecessor,
        &signing_request.report,
        oracle_with_hash_type,
    )?;
    transaction.tx.inputs[SPONSOR_INPUT_INDEX].signature_script =
        p2pk_signature_script(&sponsor_signature)?;
    if transaction.tx.id().to_string() != signing_request.unsigned_transaction_id {
        bail!("signed oracle transaction ID differs from prepared transaction ID");
    }
    let network_id = NetworkId::from_str(&signing_request.network_id)?;
    let params = consensus_params(network_id)?;
    if transaction.tx.storage_mass() != expected_storage_mass(&transaction, &params)? {
        bail!("signed oracle transaction mass does not match prepared commitment");
    }
    execute_all_inputs(&transaction, network_id)?;
    Ok(VerifiedOracleTransition {
        transaction,
        verification: OracleSignatureVerification {
            schema_version: 1,
            kind: ORACLE_SIGNATURE_VERIFICATION_KIND.to_string(),
            status: "EXTERNAL_ORACLE_AND_SPONSOR_SIGNATURES_VERIFIED".to_string(),
            tx_request_sha256: signing_request.tx_request_sha256.clone(),
            transition_spec_sha256: signing_request.transition_spec_sha256.clone(),
            signing_request_sha256: signing_request.signing_request_sha256.clone(),
            transaction_id: signing_request.unsigned_transaction_id.clone(),
            covenant_id: signing_request.covenant_id.clone(),
            oracle_signature_sha256: sha256_hex(&oracle_signature),
            sponsor_signature_sha256: sha256_hex(&sponsor_signature),
            state_value_preserved: true,
            signature_validation: "both_bip340_schnorr_signatures_passed".to_string(),
            transaction_validation: "all_covenant_and_p2pk_inputs_passed".to_string(),
            safety: oracle_safety_map(),
        },
    })
}

pub fn load_oracle_signature_hex(path: &Path, role: &str) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {role} signature file"))?;
    let text = std::str::from_utf8(&bytes)
        .with_context(|| format!("{role} signature file must be UTF-8 text"))?;
    let signature = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    if signature.contains(['\r', '\n']) {
        bail!("{role} signature file must contain one canonical hex value");
    }
    validate_lower_hex(signature, 64, &format!("{role} signature"))?;
    Ok(signature.to_string())
}

pub fn reject_oracle_output_collisions(
    inputs: &[(&str, &Path)],
    outputs: &[(&str, &Path)],
) -> Result<()> {
    reject_import_output_collisions(inputs, outputs)
}

#[allow(clippy::too_many_arguments)]
pub fn import_oracle_signature_files(
    transition_spec_path: &Path,
    metrics_tx_request_path: &Path,
    source_path: &Path,
    signing_request_path: &Path,
    oracle_signature_path: &Path,
    sponsor_signature_path: &Path,
    verification_out: &Path,
) -> Result<OracleSignatureVerification> {
    reject_import_output_collisions(
        &[
            ("transition-spec input", transition_spec_path),
            ("metrics-tx-request input", metrics_tx_request_path),
            ("contract-source input", source_path),
            ("signing-request input", signing_request_path),
            ("oracle-signature input", oracle_signature_path),
            ("sponsor-signature input", sponsor_signature_path),
        ],
        &[("verification output", verification_out)],
    )?;
    let spec = load_transition_spec(transition_spec_path)?;
    let source = fs::read_to_string(source_path)
        .with_context(|| format!("failed to read {}", source_path.display()))?;
    let prepared = prepare_oracle_transition(&spec, metrics_tx_request_path, &source)?;
    let signing_request = load_oracle_signing_request(signing_request_path)?;
    let oracle_signature = load_oracle_signature_hex(oracle_signature_path, "metrics-oracle")?;
    let sponsor_signature = load_oracle_signature_hex(sponsor_signature_path, "fee-sponsor")?;
    let verified = import_oracle_signatures(
        prepared,
        &signing_request,
        &oracle_signature,
        &sponsor_signature,
    )?;
    write_public_json(verification_out, &verified.verification)?;
    Ok(verified.verification)
}

#[allow(clippy::too_many_arguments)]
pub fn rebuild_verified_oracle_transition(
    transition_spec_path: &Path,
    metrics_tx_request_path: &Path,
    source_path: &Path,
    signing_request_path: &Path,
    oracle_signature_path: &Path,
    sponsor_signature_path: &Path,
) -> Result<(
    OracleTransitionSpec,
    OracleSigningRequest,
    VerifiedOracleTransition,
)> {
    let spec = load_transition_spec(transition_spec_path)?;
    let source = fs::read_to_string(source_path)
        .with_context(|| format!("failed to read {}", source_path.display()))?;
    let prepared = prepare_oracle_transition(&spec, metrics_tx_request_path, &source)?;
    let signing_request = load_oracle_signing_request(signing_request_path)?;
    let oracle_signature = load_oracle_signature_hex(oracle_signature_path, "metrics-oracle")?;
    let sponsor_signature = load_oracle_signature_hex(sponsor_signature_path, "fee-sponsor")?;
    let verified = import_oracle_signatures(
        prepared,
        &signing_request,
        &oracle_signature,
        &sponsor_signature,
    )?;
    Ok((spec, signing_request, verified))
}

fn validate_verified_oracle_binding(
    verified: &VerifiedOracleTransition,
    signing_request: &OracleSigningRequest,
) -> Result<()> {
    if signing_request.signing_request_sha256 != signing_request_hash(signing_request)?
        || verified.verification.schema_version != 1
        || verified.verification.kind != ORACLE_SIGNATURE_VERIFICATION_KIND
        || verified.verification.status != "EXTERNAL_ORACLE_AND_SPONSOR_SIGNATURES_VERIFIED"
        || verified.verification.tx_request_sha256 != signing_request.tx_request_sha256
        || verified.verification.transition_spec_sha256 != signing_request.transition_spec_sha256
        || verified.verification.signing_request_sha256 != signing_request.signing_request_sha256
        || verified.verification.transaction_id != signing_request.unsigned_transaction_id
        || verified.verification.covenant_id != signing_request.covenant_id
        || !verified.verification.state_value_preserved
        || verified.verification.signature_validation != "both_bip340_schnorr_signatures_passed"
        || verified.verification.transaction_validation != "all_covenant_and_p2pk_inputs_passed"
        || verified.verification.safety != oracle_safety_map()
        || verified.transaction.tx.id().to_string() != signing_request.unsigned_transaction_id
        || verified.transaction.tx.inputs.len() != 2
        || verified.transaction.tx.outputs.len() != 2
        || verified.transaction.tx.outputs[STATE_INPUT_INDEX].value != signing_request.state_value
        || verified.transaction.tx.outputs[SPONSOR_INPUT_INDEX].value
            != signing_request.sponsor_change_value
    {
        bail!("verified oracle transaction is not bound to signing request");
    }
    let successor = &verified.transaction.tx.outputs[SUCCESSOR_OUTPUT_INDEX as usize];
    let expected_covenant_id = Hash::from_str(&signing_request.covenant_id)?;
    if successor.script_public_key
        != signing_request
            .successor_script_public_key
            .to_script_public_key()?
        || successor.covenant
            != Some(CovenantBinding {
                authorizing_input: STATE_INPUT_INDEX as u16,
                covenant_id: expected_covenant_id,
            })
    {
        bail!("verified oracle successor output binding mismatch");
    }
    let network_id = NetworkId::from_str(&signing_request.network_id)?;
    execute_all_inputs(&verified.transaction, network_id)
}

fn successor_instance_id(signing_request: &OracleSigningRequest) -> String {
    format!(
        "{}:{}",
        signing_request.unsigned_transaction_id, SUCCESSOR_OUTPUT_INDEX
    )
}

pub fn prepare_oracle_broadcast_journal(
    verified: &VerifiedOracleTransition,
    signing_request: &OracleSigningRequest,
    acknowledgement: &str,
) -> Result<OracleBroadcastJournal> {
    validate_verified_oracle_binding(verified, signing_request)?;
    if acknowledgement != signing_request.signing_request_sha256 {
        bail!("oracle broadcast acknowledgement must equal signing_request_sha256");
    }
    let now = unix_seconds()?;
    Ok(OracleBroadcastJournal {
        schema_version: 1,
        journal_type: "prometheus.metrics_oracle.report_metrics.broadcast_journal".to_string(),
        status: "verified_pending_submission".to_string(),
        tx_request_sha256: signing_request.tx_request_sha256.clone(),
        transition_spec_sha256: signing_request.transition_spec_sha256.clone(),
        signing_request_sha256: signing_request.signing_request_sha256.clone(),
        predecessor_instance_id: signing_request.contract_instance_id.clone(),
        expected_successor_instance_id: successor_instance_id(signing_request),
        expected_transaction_id: signing_request.unsigned_transaction_id.clone(),
        covenant_id: signing_request.covenant_id.clone(),
        acknowledged_signing_request_sha256: acknowledgement.to_string(),
        created_at_unix_seconds: now,
        updated_at_unix_seconds: now,
        submission_started_at_unix_seconds: None,
        result: None,
    })
}

fn validate_oracle_journal_binding(
    journal: &OracleBroadcastJournal,
    expected: &OracleBroadcastJournal,
) -> Result<()> {
    if journal.schema_version != expected.schema_version
        || journal.journal_type != expected.journal_type
        || journal.tx_request_sha256 != expected.tx_request_sha256
        || journal.transition_spec_sha256 != expected.transition_spec_sha256
        || journal.signing_request_sha256 != expected.signing_request_sha256
        || journal.predecessor_instance_id != expected.predecessor_instance_id
        || journal.expected_successor_instance_id != expected.expected_successor_instance_id
        || journal.expected_transaction_id != expected.expected_transaction_id
        || journal.covenant_id != expected.covenant_id
        || journal.acknowledged_signing_request_sha256
            != expected.acknowledged_signing_request_sha256
        || journal.created_at_unix_seconds == 0
        || journal.updated_at_unix_seconds < journal.created_at_unix_seconds
        || !matches!(
            journal.status.as_str(),
            "verified_pending_submission" | "submission_in_progress" | "submission_recorded"
        )
    {
        bail!("oracle broadcast journal binding/status mismatch");
    }
    match journal.status.as_str() {
        "verified_pending_submission" => {
            if journal.submission_started_at_unix_seconds.is_some() || journal.result.is_some() {
                bail!("pending oracle journal contains submission state");
            }
        }
        "submission_in_progress" => {
            if journal.submission_started_at_unix_seconds.is_none() || journal.result.is_some() {
                bail!("in-progress oracle journal state is inconsistent");
            }
        }
        "submission_recorded" => {
            let result = journal
                .result
                .as_ref()
                .ok_or_else(|| anyhow!("recorded oracle journal is missing result"))?;
            validate_oracle_result_binding(result, journal)?;
        }
        _ => unreachable!("status checked above"),
    }
    Ok(())
}

fn validate_oracle_result_binding(
    result: &OracleBroadcastResult,
    journal: &OracleBroadcastJournal,
) -> Result<()> {
    if result.schema_version != 1
        || result.result_type != "prometheus.metrics_oracle.report_metrics.submission"
        || result.tx_request_sha256 != journal.tx_request_sha256
        || result.transition_spec_sha256 != journal.transition_spec_sha256
        || result.signing_request_sha256 != journal.signing_request_sha256
        || result.predecessor_instance_id != journal.predecessor_instance_id
        || result.successor_instance_id != journal.expected_successor_instance_id
        || result.transaction_id != journal.expected_transaction_id
        || result.covenant_id != journal.covenant_id
        || result.submitted_at_unix_seconds == 0
        || !matches!(
            result.status.as_str(),
            "submitted_unconfirmed" | "reconciled_mempool" | "reconciled_confirmed"
        )
    {
        bail!("oracle broadcast result binding/status mismatch");
    }
    Ok(())
}

pub fn load_oracle_broadcast_journal(
    path: &Path,
    expected: &OracleBroadcastJournal,
) -> Result<OracleBroadcastJournal> {
    let (journal, _): (OracleBroadcastJournal, Value) = read_public_json(path)?;
    validate_oracle_journal_binding(&journal, expected)?;
    Ok(journal)
}

pub fn load_oracle_broadcast_result(
    path: &Path,
    journal: &OracleBroadcastJournal,
) -> Result<OracleBroadcastResult> {
    let (result, _): (OracleBroadcastResult, Value) = read_public_json(path)?;
    validate_oracle_result_binding(&result, journal)?;
    Ok(result)
}

pub fn finalize_oracle_broadcast_journal(
    mut journal: OracleBroadcastJournal,
    result: OracleBroadcastResult,
) -> Result<OracleBroadcastJournal> {
    validate_oracle_result_binding(&result, &journal)?;
    journal.status = "submission_recorded".to_string();
    journal.updated_at_unix_seconds = unix_seconds()?;
    journal.result = Some(result);
    Ok(journal)
}

fn mark_oracle_submission_in_progress(
    journal: &mut OracleBroadcastJournal,
    path: &Path,
) -> Result<u64> {
    if journal.status != "verified_pending_submission"
        || journal.submission_started_at_unix_seconds.is_some()
        || journal.result.is_some()
    {
        bail!("oracle broadcast journal is not eligible for a first submission attempt");
    }
    let started_at = unix_seconds()?;
    journal.status = "submission_in_progress".to_string();
    journal.updated_at_unix_seconds = started_at;
    journal.submission_started_at_unix_seconds = Some(started_at);
    write_public_json(path, journal)?;
    Ok(started_at)
}

fn oracle_broadcast_result(
    signing_request: &OracleSigningRequest,
    status: &str,
    record_source: &str,
    confirmation_required: bool,
    submitted_at_unix_seconds: u64,
) -> OracleBroadcastResult {
    OracleBroadcastResult {
        schema_version: 1,
        result_type: "prometheus.metrics_oracle.report_metrics.submission".to_string(),
        status: status.to_string(),
        tx_request_sha256: signing_request.tx_request_sha256.clone(),
        transition_spec_sha256: signing_request.transition_spec_sha256.clone(),
        signing_request_sha256: signing_request.signing_request_sha256.clone(),
        predecessor_instance_id: signing_request.contract_instance_id.clone(),
        successor_instance_id: successor_instance_id(signing_request),
        transaction_id: signing_request.unsigned_transaction_id.clone(),
        covenant_id: signing_request.covenant_id.clone(),
        submitted_at_unix_seconds,
        record_source: record_source.to_string(),
        confirmation_required,
    }
}

fn successor_entry(
    entries: Vec<RpcUtxosByAddressesEntry>,
    signing_request: &OracleSigningRequest,
) -> Result<Option<RpcUtxosByAddressesEntry>> {
    let expected_tx_id = TransactionId::from_str(&signing_request.unsigned_transaction_id)?;
    let Some(entry) = entries.into_iter().find(|entry| {
        entry.outpoint.transaction_id == expected_tx_id
            && entry.outpoint.index == SUCCESSOR_OUTPUT_INDEX
    }) else {
        return Ok(None);
    };
    if entry.utxo_entry.amount != signing_request.state_value
        || entry.utxo_entry.covenant_id.map(|value| value.to_string())
            != Some(signing_request.covenant_id.clone())
        || ScriptSpec::from_script_public_key(&entry.utxo_entry.script_public_key)
            != signing_request.successor_script_public_key
    {
        bail!("node successor UTXO does not match verified amount, covenant ID, or script");
    }
    Ok(Some(entry))
}

fn validate_live_transition_inputs(
    entries: &[RpcUtxosByAddressesEntry],
    spec: &OracleTransitionSpec,
    network_id: NetworkId,
) -> Result<()> {
    let state_script = spec
        .state_input
        .utxo
        .script_public_key
        .to_script_public_key()?;
    let state_address = extract_script_pub_key_address(&state_script, Prefix::from(network_id))?;
    let (sponsor_address, sponsor_script) = deployer_address_and_funding_script(
        &spec.fee_sponsor.address,
        network_id,
        &spec.fee_sponsor.utxo.script_public_key,
    )?;
    let state_outpoint = spec.state_input.outpoint.to_outpoint()?;
    let sponsor_outpoint = spec.fee_sponsor.outpoint.to_outpoint()?;
    let covenant_id = Hash::from_str(&spec.state_input.utxo.covenant_id)?;
    let state = entries
        .iter()
        .find(|entry| {
            entry.outpoint.transaction_id == state_outpoint.transaction_id
                && entry.outpoint.index == state_outpoint.index
        })
        .ok_or_else(|| anyhow!("state outpoint is absent or already spent"))?;
    if state.address.as_ref() != Some(&state_address)
        || state.utxo_entry.amount != spec.state_input.utxo.amount
        || state.utxo_entry.script_public_key != state_script
        || state.utxo_entry.block_daa_score != spec.state_input.utxo.block_daa_score
        || state.utxo_entry.is_coinbase
        || state.utxo_entry.covenant_id != Some(covenant_id)
    {
        bail!("live state UTXO does not match the approved transition specification");
    }
    let sponsor = entries
        .iter()
        .find(|entry| {
            entry.outpoint.transaction_id == sponsor_outpoint.transaction_id
                && entry.outpoint.index == sponsor_outpoint.index
        })
        .ok_or_else(|| anyhow!("fee sponsor outpoint is absent or already spent"))?;
    if sponsor.address.as_ref() != Some(&sponsor_address)
        || sponsor.utxo_entry.amount != spec.fee_sponsor.utxo.amount
        || sponsor.utxo_entry.script_public_key != sponsor_script
        || sponsor.utxo_entry.block_daa_score != spec.fee_sponsor.utxo.block_daa_score
        || sponsor.utxo_entry.is_coinbase
        || sponsor.utxo_entry.covenant_id.is_some()
    {
        bail!("live fee sponsor UTXO does not match the approved transition specification");
    }
    Ok(())
}

pub async fn broadcast_verified_oracle_transition(
    verified: VerifiedOracleTransition,
    signing_request: &OracleSigningRequest,
    spec: &OracleTransitionSpec,
    acknowledgement: &str,
    encoding: WrpcEncoding,
    journal: &mut OracleBroadcastJournal,
    journal_path: &Path,
) -> Result<OracleBroadcastResult> {
    validate_verified_oracle_binding(&verified, signing_request)?;
    validate_transition_spec(spec)?;
    if spec.transition_spec_sha256 != signing_request.transition_spec_sha256
        || spec.tx_request_sha256 != signing_request.tx_request_sha256
        || spec.network_id != signing_request.network_id
        || spec.rpc_url != signing_request.rpc_url
    {
        bail!("oracle transition spec does not match signing request");
    }
    if acknowledgement != signing_request.signing_request_sha256 {
        bail!("oracle broadcast acknowledgement must equal signing_request_sha256");
    }
    let expected_journal =
        prepare_oracle_broadcast_journal(&verified, signing_request, acknowledgement)?;
    validate_oracle_journal_binding(journal, &expected_journal)?;
    let network_id = NetworkId::from_str(&signing_request.network_id)?;
    let params = consensus_params(network_id)?;
    let successor_script = signing_request
        .successor_script_public_key
        .to_script_public_key()?;
    let successor_address =
        extract_script_pub_key_address(&successor_script, Prefix::from(network_id))?;
    let state_script = spec
        .state_input
        .utxo
        .script_public_key
        .to_script_public_key()?;
    let state_address = extract_script_pub_key_address(&state_script, Prefix::from(network_id))?;
    let (sponsor_address, _) = deployer_address_and_funding_script(
        &spec.fee_sponsor.address,
        network_id,
        &spec.fee_sponsor.utxo.script_public_key,
    )?;
    let expected_tx_id = TransactionId::from_str(&signing_request.unsigned_transaction_id)?;
    let client = connect_rpc(&signing_request.rpc_url, network_id, encoding).await?;
    if let Err(error) =
        inspect_node(&client, &signing_request.rpc_url, network_id, &params, true).await
    {
        let _ = client.disconnect().await;
        return Err(error);
    }

    let successor_entries = timeout(
        RPC_REQUEST_TIMEOUT,
        client.get_utxos_by_addresses(vec![successor_address]),
    )
    .await
    .map_err(|_| rpc_timeout("get_utxos_by_addresses for oracle reconciliation"))?;
    match successor_entries
        .context("failed to reconcile oracle successor UTXO")
        .and_then(|entries| successor_entry(entries, signing_request))
    {
        Ok(Some(_)) => {
            let _ = client.disconnect().await;
            return Ok(oracle_broadcast_result(
                signing_request,
                "reconciled_confirmed",
                "known_transaction_successor_utxo",
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
    .map_err(|_| rpc_timeout("get_mempool_entry for oracle reconciliation"))?;
    match mempool_result {
        Ok(_) => {
            let _ = client.disconnect().await;
            return Ok(oracle_broadcast_result(
                signing_request,
                "reconciled_mempool",
                "known_transaction_mempool",
                true,
                journal
                    .submission_started_at_unix_seconds
                    .unwrap_or(journal.created_at_unix_seconds),
            ));
        }
        Err(error) if is_expected_transaction_not_found(&error, expected_tx_id) => {}
        Err(error) => {
            let _ = client.disconnect().await;
            return Err(error)
                .context("failed to reconcile expected oracle transaction in mempool");
        }
    }
    if journal.status == "submission_in_progress" {
        let _ = client.disconnect().await;
        bail!("prior oracle submission is ambiguous; automatic resubmission is forbidden");
    }
    if journal.status != "verified_pending_submission" {
        let _ = client.disconnect().await;
        bail!("oracle broadcast journal is not eligible for transaction submission");
    }

    let live_entries = timeout(
        RPC_REQUEST_TIMEOUT,
        client.get_utxos_by_addresses(vec![state_address, sponsor_address]),
    )
    .await
    .map_err(|_| rpc_timeout("get_utxos_by_addresses before oracle broadcast"))?;
    if let Err(error) = live_entries
        .context("failed to query oracle inputs before broadcast")
        .and_then(|entries| validate_live_transition_inputs(&entries, spec, network_id))
    {
        let _ = client.disconnect().await;
        return Err(error);
    }
    let submission_started_at = mark_oracle_submission_in_progress(journal, journal_path)?;
    let result = timeout(
        RPC_REQUEST_TIMEOUT,
        client.submit_transaction((&verified.transaction.tx).into(), false),
    )
    .await
    .map_err(|_| rpc_timeout("submit oracle transaction"))?
    .context("Kaspa oracle transaction submission failed");
    let _ = client.disconnect().await;
    let submitted_id = result?.to_string();
    if submitted_id != signing_request.unsigned_transaction_id {
        bail!("RPC returned a transaction ID different from the verified oracle transaction");
    }
    Ok(oracle_broadcast_result(
        signing_request,
        "submitted_unconfirmed",
        "local_rpc_submission",
        true,
        submission_started_at,
    ))
}

pub async fn observe_oracle_successor(
    verified: &VerifiedOracleTransition,
    signing_request: &OracleSigningRequest,
    encoding: WrpcEncoding,
) -> Result<OracleNodeObservation> {
    validate_verified_oracle_binding(verified, signing_request)?;
    let network_id = NetworkId::from_str(&signing_request.network_id)?;
    let params = consensus_params(network_id)?;
    let successor_script = signing_request
        .successor_script_public_key
        .to_script_public_key()?;
    let address = extract_script_pub_key_address(&successor_script, Prefix::from(network_id))?;
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
    .map_err(|_| rpc_timeout("get_utxos_by_addresses for oracle observation"))?;
    let dag_result = timeout(RPC_REQUEST_TIMEOUT, client.get_block_dag_info())
        .await
        .map_err(|_| rpc_timeout("get_block_dag_info for oracle observation"))?;
    let _ = client.disconnect().await;
    let entry = successor_entry(
        entries_result.context("failed to query oracle successor UTXO")?,
        signing_request,
    )?
    .ok_or_else(|| anyhow!("oracle successor UTXO is not visible on the configured node"))?;
    let dag = dag_result.context("failed to query virtual DAA score")?;
    Ok(OracleNodeObservation {
        schema_version: 1,
        evidence_type: "prometheus.metrics_oracle.report_metrics.node_observation".to_string(),
        status: "confirmed_successor_utxo_observed".to_string(),
        tx_request_sha256: signing_request.tx_request_sha256.clone(),
        transition_spec_sha256: signing_request.transition_spec_sha256.clone(),
        signing_request_sha256: signing_request.signing_request_sha256.clone(),
        predecessor_instance_id: signing_request.contract_instance_id.clone(),
        successor_instance_id: successor_instance_id(signing_request),
        transaction_id: signing_request.unsigned_transaction_id.clone(),
        output_index: SUCCESSOR_OUTPUT_INDEX,
        covenant_id: signing_request.covenant_id.clone(),
        amount: entry.utxo_entry.amount,
        successor_script_public_key: signing_request.successor_script_public_key.clone(),
        block_daa_score: entry.utxo_entry.block_daa_score,
        observed_virtual_daa_score: dag.virtual_daa_score,
        daa_depth: dag
            .virtual_daa_score
            .saturating_sub(entry.utxo_entry.block_daa_score),
        observed_at_unix_seconds: unix_seconds()?,
        explorer_block_hash_required: true,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use kaspa_addresses::{Address, Prefix, Version as AddressVersion};
    use kaspa_bip32::secp256k1::{rand::thread_rng, Keypair};
    use kaspa_txscript::pay_to_address_script;
    use serde_json::json;

    use super::*;

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);
    const SOURCE: &str = include_str!("../../contracts/silverc/GovernanceAutoTuningState.sil");

    struct Fixture {
        spec: OracleTransitionSpec,
        tx_request_path: std::path::PathBuf,
        oracle_keypair: Keypair,
        sponsor_keypair: Keypair,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.tx_request_path);
        }
    }

    fn temp_path(label: &str) -> std::path::PathBuf {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "prometheus-oracle-{label}-{}-{id}.json",
            std::process::id()
        ))
    }

    fn key_hex(keypair: &Keypair) -> String {
        hex::encode(keypair.x_only_public_key().0.serialize())
    }

    fn sign_hex(keypair: &Keypair, sighash_hex: &str) -> String {
        let message = Message::from_digest_slice(&hex::decode(sighash_hex).unwrap()).unwrap();
        hex::encode(keypair.sign_schnorr(message).serialize())
    }

    fn fixture() -> Fixture {
        let oracle_keypair = Keypair::new(SECP256K1, &mut thread_rng());
        let sponsor_keypair = Keypair::new(SECP256K1, &mut thread_rng());
        let state = GovernanceState {
            metrics_oracle_pk: key_hex(&oracle_keypair),
            min_stake_kas: 10_000,
            min_guardian_rep: 1_000,
            min_confidence_ki: 8_500,
            validator_consensus: 6_700,
            reward_base: 100,
            last_tuning_block: 0,
            active_validators: 100,
            active_guardians: 500,
            proposals_per_day: 150,
            fp_rate: 0,
            last_metrics_block: 0,
        };
        let report = MetricsReport {
            new_active_validators: 30,
            new_active_guardians: 500,
            new_proposals_per_day: 50,
            new_fp_rate: 100,
            block_height: 1_000,
        };
        let predecessor = compile_state(SOURCE, &state).unwrap();
        let predecessor_spk = pay_to_script_hash_script(&predecessor.script);
        let sponsor_address = Address::new(
            Prefix::Testnet,
            AddressVersion::PubKey,
            &sponsor_keypair.x_only_public_key().0.serialize(),
        );
        let sponsor_spk = pay_to_address_script(&sponsor_address);
        let source_sha256 = sha256_hex(SOURCE.as_bytes());
        let contract_instance_id = format!("{}:0", "11".repeat(32));
        let mut request = json!({
            "schema_version": 1,
            "kind": "prometheus.metrics_oracle.report_metrics.tx_request",
            "status": "READY_FOR_KEYLESS_REPORT_METRICS_OPERATOR",
            "network": "testnet",
            "contract": {
                "name": ORACLE_CONTRACT_NAME,
                "entrypoint": ORACLE_ENTRYPOINT,
                "abi_entrypoint": "__covenant_entrypoint_auth_reportMetrics",
                "instance_id": contract_instance_id,
            },
            "release_bundle": {
                "silverscript_ref": PINNED_SILVERSCRIPT_COMMIT,
                "silverscript_commit": PINNED_SILVERSCRIPT_COMMIT,
                "source_sha256": source_sha256,
            },
            "metrics_report": {
                "payload_sha256": "22".repeat(32),
                "metrics_oracle_pubkey": state.metrics_oracle_pk,
                "previous_state": {"last_metrics_block": state.last_metrics_block},
                "metrics": {
                    "active_validators": report.new_active_validators,
                    "active_guardians": report.new_active_guardians,
                    "proposals_per_day": report.new_proposals_per_day,
                    "fp_rate": report.new_fp_rate,
                    "block_height": report.block_height,
                },
                "sources_count": 1,
            },
            "entrypoint_args": {
                "new_active_validators": report.new_active_validators,
                "new_active_guardians": report.new_active_guardians,
                "new_proposals_per_day": report.new_proposals_per_day,
                "new_fp_rate": report.new_fp_rate,
                "block_height": report.block_height,
                "oracle_sig": "external_wallet_signature_required",
            },
            "safety": {
                "accepts_private_keys": false,
                "signs_transactions": false,
                "assembles_chain_transaction": false,
                "broadcasts_transactions": false,
            },
            "safety_scope": "metrics_tx_request_builder_only",
            "repository_operator": {
                "assembles_transaction_in_memory": true,
                "accepts_private_keys": false,
                "signs_transactions": false,
                "requires_external_oracle_signature": true,
                "requires_external_fee_sponsor_signature": true,
                "broadcast_requires_exact_signing_request_hash_acknowledgement": true,
            },
            "signature": {
                "required": true,
                "signer": "metrics_oracle_wallet",
                "signer_pubkey": state.metrics_oracle_pk,
                "signature_field": "oracle_sig",
                "signature_placeholder": "external_wallet_signature_required",
                "repository_must_not_hold_signing_material": true,
            },
        });
        let request_sha256 = sha256_hex(&canonical_json(&request).unwrap());
        request.as_object_mut().unwrap().insert(
            "request_sha256".to_string(),
            Value::String(request_sha256.clone()),
        );
        let tx_request_path = temp_path("request");
        fs::write(
            &tx_request_path,
            serde_json::to_vec_pretty(&request).unwrap(),
        )
        .unwrap();
        let mut spec = OracleTransitionSpec {
            schema_version: 1,
            kind: ORACLE_TRANSITION_SPEC_KIND.to_string(),
            network_id: "testnet-10".to_string(),
            rpc_url: "wss://tn10.example.invalid".to_string(),
            tx_request_sha256: request_sha256,
            contract_instance_id,
            silverscript_commit: PINNED_SILVERSCRIPT_COMMIT.to_string(),
            source_sha256,
            state_input: StateInputSpec {
                outpoint: OutpointSpec {
                    transaction_id: "11".repeat(32),
                    index: 0,
                },
                utxo: CovenantUtxoSpec {
                    amount: 1_000_000_000,
                    script_public_key: ScriptSpec::from_script_public_key(&predecessor_spk),
                    covenant_id: "aa".repeat(32),
                    block_daa_score: 500_000_000,
                    is_coinbase: false,
                },
                state,
            },
            fee_sponsor: FeeSponsorSpec {
                address: sponsor_address.to_string(),
                xonly_public_key_hex: key_hex(&sponsor_keypair),
                outpoint: OutpointSpec {
                    transaction_id: "22".repeat(32),
                    index: 1,
                },
                utxo: SponsorUtxoSpec {
                    amount: 10_000_000_000,
                    script_public_key: ScriptSpec::from_script_public_key(&sponsor_spk),
                    block_daa_score: 500_000_001,
                    is_coinbase: false,
                },
                change_output: SponsorChangeSpec {
                    value: 9_000_000_000,
                    script_public_key: ScriptSpec::from_script_public_key(&sponsor_spk),
                },
                minimum_fee_sompi: 1,
                maximum_fee_sompi: 2_000_000_000,
            },
            report,
            safety: oracle_safety_map(),
            transition_spec_sha256: String::new(),
        };
        finalize_transition_spec_hash(&mut spec).unwrap();
        Fixture {
            spec,
            tx_request_path,
            oracle_keypair,
            sponsor_keypair,
        }
    }

    #[test]
    fn prepares_value_preserving_dual_signature_transition() {
        let fixture = fixture();
        let prepared = prepare_oracle_transition(&fixture.spec, &fixture.tx_request_path, SOURCE)
            .expect("oracle transition prepares");
        let request = &prepared.signing_request;
        assert!(request.state_value_preserved);
        assert_eq!(request.state_value, 1_000_000_000);
        assert_eq!(request.fee_sompi, 1_000_000_000);
        assert_eq!(request.oracle_signing.input_index, 0);
        assert_eq!(request.sponsor_signing.input_index, 1);
        assert_eq!(
            request.oracle_signing.expected_xonly_public_key_hex,
            key_hex(&fixture.oracle_keypair)
        );
        assert_eq!(
            request.sponsor_signing.expected_xonly_public_key_hex,
            key_hex(&fixture.sponsor_keypair)
        );
        assert_ne!(
            request.predecessor_script_sha256,
            request.successor_script_sha256
        );
        assert!(request.oracle_compute_budget > 0);
        assert_eq!(
            prepared.transaction.tx.outputs[0].value,
            fixture.spec.state_input.utxo.amount
        );
        assert_eq!(
            prepared.transaction.tx.outputs[1].value,
            fixture.spec.fee_sponsor.change_output.value
        );
    }

    #[test]
    fn imports_both_signatures_and_executes_every_input() {
        let fixture = fixture();
        let prepared = prepare_oracle_transition(&fixture.spec, &fixture.tx_request_path, SOURCE)
            .expect("oracle transition prepares");
        let signing_request = prepared.signing_request.clone();
        let oracle_signature = sign_hex(
            &fixture.oracle_keypair,
            &signing_request.oracle_signing.sighash_hex,
        );
        let sponsor_signature = sign_hex(
            &fixture.sponsor_keypair,
            &signing_request.sponsor_signing.sighash_hex,
        );
        let verified = import_oracle_signatures(
            prepared,
            &signing_request,
            &oracle_signature,
            &sponsor_signature,
        )
        .expect("dual signatures and complete transaction verify");
        assert_eq!(
            verified.verification.status,
            "EXTERNAL_ORACLE_AND_SPONSOR_SIGNATURES_VERIFIED"
        );
        assert_eq!(
            verified.verification.transaction_validation,
            "all_covenant_and_p2pk_inputs_passed"
        );
        assert!(verified.verification.state_value_preserved);
    }

    #[test]
    fn rejects_wrong_oracle_signature() {
        let fixture = fixture();
        let prepared = prepare_oracle_transition(&fixture.spec, &fixture.tx_request_path, SOURCE)
            .expect("oracle transition prepares");
        let signing_request = prepared.signing_request.clone();
        let wrong_keypair = Keypair::new(SECP256K1, &mut thread_rng());
        let oracle_signature =
            sign_hex(&wrong_keypair, &signing_request.oracle_signing.sighash_hex);
        let sponsor_signature = sign_hex(
            &fixture.sponsor_keypair,
            &signing_request.sponsor_signing.sighash_hex,
        );
        let error = import_oracle_signatures(
            prepared,
            &signing_request,
            &oracle_signature,
            &sponsor_signature,
        )
        .expect_err("wrong oracle signature must fail");
        assert!(error
            .to_string()
            .contains("metrics_oracle BIP340 signature verification failed"));
    }

    #[test]
    fn rejects_wrong_fee_sponsor_signature() {
        let fixture = fixture();
        let prepared = prepare_oracle_transition(&fixture.spec, &fixture.tx_request_path, SOURCE)
            .expect("oracle transition prepares");
        let signing_request = prepared.signing_request.clone();
        let oracle_signature = sign_hex(
            &fixture.oracle_keypair,
            &signing_request.oracle_signing.sighash_hex,
        );
        let wrong_keypair = Keypair::new(SECP256K1, &mut thread_rng());
        let sponsor_signature =
            sign_hex(&wrong_keypair, &signing_request.sponsor_signing.sighash_hex);
        let error = import_oracle_signatures(
            prepared,
            &signing_request,
            &oracle_signature,
            &sponsor_signature,
        )
        .expect_err("wrong fee sponsor signature must fail");
        assert!(error
            .to_string()
            .contains("fee_sponsor BIP340 signature verification failed"));
    }

    #[test]
    fn rejects_rehashed_tampered_signing_request() {
        let fixture = fixture();
        let prepared = prepare_oracle_transition(&fixture.spec, &fixture.tx_request_path, SOURCE)
            .expect("oracle transition prepares");
        let mut signing_request = prepared.signing_request.clone();
        let oracle_signature = sign_hex(
            &fixture.oracle_keypair,
            &signing_request.oracle_signing.sighash_hex,
        );
        let sponsor_signature = sign_hex(
            &fixture.sponsor_keypair,
            &signing_request.sponsor_signing.sighash_hex,
        );
        signing_request.compute_mass += 1;
        signing_request.signing_request_sha256 = signing_request_hash(&signing_request).unwrap();
        let error = import_oracle_signatures(
            prepared,
            &signing_request,
            &oracle_signature,
            &sponsor_signature,
        )
        .expect_err("rehashed tampered signing request must fail");
        assert!(error
            .to_string()
            .contains("rebuilt oracle transition does not match signing request"));
    }

    #[test]
    fn rejects_oracle_output_collision_with_input() {
        let input = temp_path("collision-input");
        fs::write(&input, b"public fixture").unwrap();
        let error = reject_oracle_output_collisions(
            &[("transition-spec input", input.as_path())],
            &[("signing-request output", input.as_path())],
        )
        .expect_err("output collision must fail");
        assert!(error
            .to_string()
            .contains("signing-request output collides with transition-spec input"));
        fs::remove_file(input).unwrap();
    }

    #[test]
    fn rejects_predecessor_state_script_mismatch() {
        let mut fixture = fixture();
        fixture.spec.state_input.state.reward_base += 1;
        finalize_transition_spec_hash(&mut fixture.spec).unwrap();
        let error = prepare_oracle_transition(&fixture.spec, &fixture.tx_request_path, SOURCE)
            .expect_err("tampered predecessor state must fail");
        assert!(error
            .to_string()
            .contains("compiled predecessor state does not match"));
    }

    #[test]
    fn rejects_state_value_paid_as_fee_by_schema_shape() {
        let mut fixture = fixture();
        fixture.spec.fee_sponsor.change_output.value = fixture.spec.fee_sponsor.utxo.amount + 1;
        finalize_transition_spec_hash(&mut fixture.spec).unwrap();
        let error = prepare_oracle_transition(&fixture.spec, &fixture.tx_request_path, SOURCE)
            .expect_err("sponsor underflow must fail");
        assert!(error.to_string().contains("fee sponsor amount is below"));
    }

    #[test]
    fn oracle_broadcast_journal_requires_exact_acknowledgement() {
        let fixture = fixture();
        let prepared = prepare_oracle_transition(&fixture.spec, &fixture.tx_request_path, SOURCE)
            .expect("oracle transition prepares");
        let signing_request = prepared.signing_request.clone();
        let oracle_signature = sign_hex(
            &fixture.oracle_keypair,
            &signing_request.oracle_signing.sighash_hex,
        );
        let sponsor_signature = sign_hex(
            &fixture.sponsor_keypair,
            &signing_request.sponsor_signing.sighash_hex,
        );
        let verified = import_oracle_signatures(
            prepared,
            &signing_request,
            &oracle_signature,
            &sponsor_signature,
        )
        .unwrap();
        let error = prepare_oracle_broadcast_journal(&verified, &signing_request, "wrong")
            .expect_err("wrong acknowledgement must fail");
        assert!(error
            .to_string()
            .contains("acknowledgement must equal signing_request_sha256"));
        let journal = prepare_oracle_broadcast_journal(
            &verified,
            &signing_request,
            &signing_request.signing_request_sha256,
        )
        .unwrap();
        assert_eq!(journal.status, "verified_pending_submission");
        assert_eq!(
            journal.expected_successor_instance_id,
            format!("{}:0", signing_request.unsigned_transaction_id)
        );
    }

    #[test]
    fn oracle_broadcast_journal_finalizes_and_reloads_recorded_result() {
        let fixture = fixture();
        let prepared = prepare_oracle_transition(&fixture.spec, &fixture.tx_request_path, SOURCE)
            .expect("oracle transition prepares");
        let signing_request = prepared.signing_request.clone();
        let oracle_signature = sign_hex(
            &fixture.oracle_keypair,
            &signing_request.oracle_signing.sighash_hex,
        );
        let sponsor_signature = sign_hex(
            &fixture.sponsor_keypair,
            &signing_request.sponsor_signing.sighash_hex,
        );
        let verified = import_oracle_signatures(
            prepared,
            &signing_request,
            &oracle_signature,
            &sponsor_signature,
        )
        .unwrap();
        let expected = prepare_oracle_broadcast_journal(
            &verified,
            &signing_request,
            &signing_request.signing_request_sha256,
        )
        .unwrap();
        let result = oracle_broadcast_result(
            &signing_request,
            "reconciled_confirmed",
            "node_reconciliation",
            false,
            1,
        );
        let finalized =
            finalize_oracle_broadcast_journal(expected.clone(), result.clone()).unwrap();
        let journal_path = temp_path("recorded-journal");
        let result_path = temp_path("recorded-result");
        write_public_json(&journal_path, &finalized).unwrap();
        write_public_json(&result_path, &result).unwrap();
        let reloaded = load_oracle_broadcast_journal(&journal_path, &expected).unwrap();
        let reloaded_result = load_oracle_broadcast_result(&result_path, &reloaded).unwrap();
        assert_eq!(reloaded.status, "submission_recorded");
        assert_eq!(reloaded.result, Some(result.clone()));
        assert_eq!(reloaded_result, result);
        fs::remove_file(journal_path).unwrap();
        fs::remove_file(result_path).unwrap();
    }

    #[tokio::test]
    async fn oracle_broadcast_rejects_tamper_before_network_access() {
        let fixture = fixture();
        let prepared = prepare_oracle_transition(&fixture.spec, &fixture.tx_request_path, SOURCE)
            .expect("oracle transition prepares");
        let signing_request = prepared.signing_request.clone();
        let oracle_signature = sign_hex(
            &fixture.oracle_keypair,
            &signing_request.oracle_signing.sighash_hex,
        );
        let sponsor_signature = sign_hex(
            &fixture.sponsor_keypair,
            &signing_request.sponsor_signing.sighash_hex,
        );
        let mut verified = import_oracle_signatures(
            prepared,
            &signing_request,
            &oracle_signature,
            &sponsor_signature,
        )
        .unwrap();
        let mut journal = prepare_oracle_broadcast_journal(
            &verified,
            &signing_request,
            &signing_request.signing_request_sha256,
        )
        .unwrap();
        verified.verification.transaction_validation = "tampered".to_string();
        let journal_path = temp_path("tampered-journal");
        let error = broadcast_verified_oracle_transition(
            verified,
            &signing_request,
            &fixture.spec,
            &signing_request.signing_request_sha256,
            WrpcEncoding::Borsh,
            &mut journal,
            &journal_path,
        )
        .await
        .expect_err("tampered verification must fail before RPC");
        assert!(error
            .to_string()
            .contains("verified oracle transaction is not bound"));
        assert!(!journal_path.exists());
    }
}
