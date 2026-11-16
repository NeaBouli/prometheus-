#!/usr/bin/env python3
"""Verify Prometheus current-silverc contract fixtures against upstream silverc."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_CARGO_TOML = ROOT / "Cargo.toml"
H001_CONTRACT = ROOT / "modules" / "contracts" / "silverc" / "ValidatorStakingH001.sil"
VALIDATOR_STATE_CONTRACT = (
    ROOT / "modules" / "contracts" / "silverc" / "ValidatorStakingState.sil"
)
GUARDIAN_STATE_CONTRACT = (
    ROOT / "modules" / "contracts" / "silverc" / "GuardianReputationState.sil"
)
RULE_STORAGE_STATE_CONTRACT = (
    ROOT / "modules" / "contracts" / "silverc" / "RuleStorageState.sil"
)
COMMUNITY_DONATIONS_STATE_CONTRACT = (
    ROOT / "modules" / "contracts" / "silverc" / "CommunityDonationsState.sil"
)
DEV_INCENTIVE_POOL_STATE_CONTRACT = (
    ROOT / "modules" / "contracts" / "silverc" / "DevIncentivePoolState.sil"
)
GOVERNANCE_AUTO_TUNING_STATE_CONTRACT = (
    ROOT / "modules" / "contracts" / "silverc" / "GovernanceAutoTuningState.sil"
)
DEFAULT_SILVERSCRIPT_REPO = Path("/tmp/prom-silverscript")
SILVERSCRIPT_GIT = "https://github.com/kaspanet/silverscript.git"
DEFAULT_SILVERSCRIPT_REF = "d25bd3427a093c17327ca3d6b9e1aa5f7688c863"
SILVERSCRIPT_REF_RE = re.compile(r"[0-9a-f]{40}")
PROBE_TEST_NAME = "prometheus_h001_probe"
# Neutralise repository-local hooks and fsmonitor commands of a pre-existing checkout.
GIT_SAFE_CONFIG = (
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "advice.detachedHead=false",
)

RUST_TEST = r"""
use kaspa_consensus_core::hashing::sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::mass::units::SigopCount;
use kaspa_consensus_core::tx::{
    PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine};
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{CompileOptions, CompiledContract, CovenantDeclCallOptions, compile_contract};

mod common;

use common::{covenant_output, covenant_utxo, execute_input_with_covenants};

const COV_A: Hash = Hash::from_bytes(*b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

const SOMPI_PER_KAS: u64 = 100_000_000;

fn kas(amount: u64) -> u64 {
    amount * SOMPI_PER_KAS
}

fn valued_covenant_utxo(compiled: &CompiledContract<'_>, value: u64) -> UtxoEntry {
    let mut entry = covenant_utxo(compiled, COV_A);
    entry.amount = value;
    entry
}

fn valued_covenant_output(compiled: &CompiledContract<'_>, value: u64) -> TransactionOutput {
    let mut output = covenant_output(compiled, 0, COV_A);
    output.value = value;
    output
}

fn burn_output(value: u64) -> TransactionOutput {
    // P2SH of the always-failing script OP_RETURN (0x6a): standard and provably unspendable.
    TransactionOutput { value, script_public_key: kaspa_txscript::pay_to_script_hash_script(&[0x6a]), covenant: None }
}

const COV_B: Hash = Hash::from_bytes(*b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
// DAA score of the block that accepted the spent covenant UTXO (the previous transition).
const PROPOSAL_DAA: u64 = 1_000;
// rusty-kaspa marks UTXOs of unaccepted mempool parents with u64::MAX; OpTxInputDaaScore then pushes -1.
const UNACCEPTED_DAA: u64 = u64::MAX;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tamper {
    None,
    Instance,
    Nonce,
    Content,
    Session,
    Attestor,
}

fn sha256_parts(parts: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn attested_cov(tamper: Tamper) -> Hash {
    if tamper == Tamper::Instance { COV_B } else { COV_A }
}

fn attested_nonce(tamper: Tamper, nonce: i64) -> i64 {
    // Replay: an attestation issued for the previous proposal slot.
    if tamper == Tamper::Nonce { nonce - 1 } else { nonce }
}

fn attestor_keypair(tamper: Tamper) -> Keypair {
    if tamper == Tamper::Attestor { keypair_from_seed(99) } else { keypair_from_seed(8) }
}

fn state_output(compiled: &CompiledContract<'_>, covenant_id: Hash, value: u64) -> TransactionOutput {
    let mut output = covenant_output(compiled, 0, covenant_id);
    output.value = value;
    output
}

#[allow(clippy::too_many_arguments)]
fn spend_transition(
    entry_state: &CompiledContract<'_>,
    function_name: &str,
    args: &dyn Fn(Vec<u8>) -> Vec<Expr<'static>>,
    covenant_id: Hash,
    spent_daa_score: u64,
    entry_value: u64,
    outputs: Vec<TransactionOutput>,
    lock_time: u64,
    signer: Option<&Keypair>,
) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let build = |call_args: Vec<Expr<'static>>| -> Vec<u8> {
        let mut sigscript = entry_state
            .build_sig_script_for_covenant_decl(function_name, call_args, CovenantDeclCallOptions { is_leader: false })
            .unwrap_or_else(|err| panic!("{function_name} sigscript builds: {err}"));
        sigscript.extend_from_slice(&common::push_redeem_script(&entry_state.script));
        sigscript
    };
    let mut entry = covenant_utxo(entry_state, covenant_id);
    entry.amount = entry_value;
    entry.block_daa_score = spent_daa_score;
    let entries = vec![entry];
    let mut tx = Transaction::new(1, vec![tx_input_with_sigops(0, build(args(dummy_signature())), 2)], outputs, lock_time, Default::default(), 0, vec![]);
    if let Some(keypair) = signer {
        let sig = sign_tx_input(&tx, &entries, 0, keypair);
        tx.inputs[0].signature_script = build(args(sig));
    }
    execute_input_with_covenants(tx, entries, 0)
}

fn assert_lock_time_error(err: kaspa_txscript_errors::TxScriptError) {
    assert!(matches!(err, kaspa_txscript_errors::TxScriptError::UnsatisfiedLockTime(_)), "expected lock-time failure, got {err:?}");
}

fn run_script(script: Vec<u8>, sigscript: Vec<u8>) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(10_000);

    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_bytes([1u8; 32]), index: 0 },
        signature_script: sigscript,
        sequence: 0,
        compute_commit: SigopCount(0).into(),
    };
    let output = TransactionOutput { value: 1000, script_public_key: ScriptPublicKey::new(0, script.clone().into()), covenant: None };
    let tx = Transaction::new(1, vec![input.clone()], vec![output.clone()], 0, Default::default(), 0, vec![]);
    let utxo_entry = UtxoEntry::new(output.value, output.script_public_key.clone(), 0, tx.is_coinbase(), None);
    let populated_tx = PopulatedTransaction::new(&tx, vec![utxo_entry.clone()]);

    let mut vm = TxScriptEngine::from_transaction_input(
        &populated_tx,
        &input,
        0,
        &utxo_entry,
        EngineCtx::new(&sig_cache).with_reused(&reused_values),
        EngineFlags { covenants_enabled: true, ..Default::default() },
    );
    vm.execute()
}

fn hex32(input: &str) -> Vec<u8> {
    assert_eq!(input.len(), 64);
    (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16).expect("valid hex byte"))
        .collect()
}

fn zero32() -> Vec<u8> {
    vec![0u8; 32]
}

fn zero36() -> Vec<u8> {
    vec![0u8; 36]
}

fn cid36(seed: u8) -> Vec<u8> {
    vec![seed; 36]
}

fn dummy_signature() -> Vec<u8> {
    vec![0u8; 65]
}

fn keypair_from_seed(seed: u8) -> Keypair {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[seed; 32]).expect("valid deterministic secret key");
    Keypair::from_secret_key(&secp, &secret)
}

fn tx_input_with_sigops(index: u32, signature_script: Vec<u8>, sigops: u8) -> TransactionInput {
    TransactionInput::new(
        TransactionOutpoint { transaction_id: TransactionId::from_bytes([index as u8 + 1; 32]), index },
        signature_script,
        0,
        SigopCount(sigops).into(),
    )
}

fn sign_tx_input(tx: &Transaction, entries: &[UtxoEntry], input_idx: usize, keypair: &Keypair) -> Vec<u8> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let sig_hash = calc_schnorr_signature_hash(&populated, input_idx, SIG_HASH_ALL, &reused_values);
    let msg = Message::from_digest_slice(sig_hash.as_bytes().as_slice()).expect("valid sighash message");
    let sig = keypair.sign_schnorr(msg);
    let mut signature = Vec::new();
    signature.extend_from_slice(sig.as_ref());
    signature.push(SIG_HASH_ALL.to_u8());
    signature
}

fn validator_state_args(
    validator_pk: Vec<u8>,
    stake_kas: i64,
    active: bool,
    joined_at: i64,
    reputation: i64,
    slashing_count: i64,
    last_vote_block: i64,
    commitment: Vec<u8>,
    bond_kas: i64,
    committed_at_block: i64,
    withdraw_request_block: i64,
) -> Vec<Expr<'static>> {
    vec![
        Expr::bytes(validator_pk),
        Expr::int(stake_kas),
        Expr::bool(active),
        Expr::int(joined_at),
        Expr::int(reputation),
        Expr::int(slashing_count),
        Expr::int(last_vote_block),
        Expr::bytes(commitment),
        Expr::int(bond_kas),
        Expr::int(committed_at_block),
        Expr::int(withdraw_request_block),
    ]
}

fn guardian_state_args(
    guardian_pk: Vec<u8>,
    governance_pk: Vec<u8>,
    compute_power_gflops: i64,
    reputation: i64,
    proposals_submitted: i64,
    proposals_accepted: i64,
    registered_at: i64,
    model_type: i64,
) -> Vec<Expr<'static>> {
    vec![
        Expr::bytes(guardian_pk),
        Expr::bytes(governance_pk),
        Expr::int(compute_power_gflops),
        Expr::int(reputation),
        Expr::int(proposals_submitted),
        Expr::int(proposals_accepted),
        Expr::int(registered_at),
        Expr::int(model_type),
    ]
}

fn rule_storage_state_args(
    governance_pk: Vec<u8>,
    next_proposal_id: i64,
    proposal_id: i64,
    guardian_pk: Vec<u8>,
    threat_hash: Vec<u8>,
    rule_type: i64,
    rule_content_ipfs: Vec<u8>,
    confidence: i64,
    submitted_at_block: i64,
    votes_for: i64,
    votes_against: i64,
    voting_end_block: i64,
    status: i64,
    rule_count: i64,
    count_in_window: i64,
    last_count_reset_block: i64,
    consensus_score: i64,
    stored_at_block: i64,
    active: bool,
    guardian_reputation_event: i64,
) -> Vec<Expr<'static>> {
    vec![
        Expr::bytes(governance_pk),
        Expr::int(next_proposal_id),
        Expr::int(proposal_id),
        Expr::bytes(guardian_pk),
        Expr::bytes(threat_hash),
        Expr::int(rule_type),
        Expr::bytes(rule_content_ipfs),
        Expr::int(confidence),
        Expr::int(submitted_at_block),
        Expr::int(votes_for),
        Expr::int(votes_against),
        Expr::int(voting_end_block),
        Expr::int(status),
        Expr::int(rule_count),
        Expr::int(count_in_window),
        Expr::int(last_count_reset_block),
        Expr::int(consensus_score),
        Expr::int(stored_at_block),
        Expr::bool(active),
        Expr::int(guardian_reputation_event),
    ]
}

fn community_donations_state_args(
    governance_pk: Vec<u8>,
    donation_count: i64,
    total_donated_kas: i64,
    pool_balance_kas: i64,
    next_disbursement_id: i64,
    disbursement_id: i64,
    recipient_pk: Vec<u8>,
    amount_kas: i64,
    purpose_hash: Vec<u8>,
    votes_for: i64,
    votes_against: i64,
    voting_end_block: i64,
    status: i64,
    executed: bool,
    last_donor_pk: Vec<u8>,
    last_message_hash: Vec<u8>,
    last_donation_block: i64,
) -> Vec<Expr<'static>> {
    vec![
        Expr::bytes(governance_pk),
        Expr::int(donation_count),
        Expr::int(total_donated_kas),
        Expr::int(pool_balance_kas),
        Expr::int(next_disbursement_id),
        Expr::int(disbursement_id),
        Expr::bytes(recipient_pk),
        Expr::int(amount_kas),
        Expr::bytes(purpose_hash),
        Expr::int(votes_for),
        Expr::int(votes_against),
        Expr::int(voting_end_block),
        Expr::int(status),
        Expr::bool(executed),
        Expr::bytes(last_donor_pk),
        Expr::bytes(last_message_hash),
        Expr::int(last_donation_block),
    ]
}

fn dev_incentive_pool_state_args(
    next_grant_id: i64,
    pool_balance_prom: i64,
    grant_id: i64,
    developer_pk: Vec<u8>,
    contribution_hash: Vec<u8>,
    description_hash: Vec<u8>,
    lines_of_code: i64,
    complexity: i64,
    requested_amount_prom: i64,
    votes_for: i64,
    votes_against: i64,
    voting_end_block: i64,
    executed: bool,
    paid: bool,
    status: i64,
    last_proposer_pk: Vec<u8>,
) -> Vec<Expr<'static>> {
    vec![
        Expr::bytes(keypair_from_seed(8).x_only_public_key().0.serialize().to_vec()),
        Expr::int(next_grant_id),
        Expr::int(pool_balance_prom),
        Expr::int(grant_id),
        Expr::bytes(developer_pk),
        Expr::bytes(contribution_hash),
        Expr::bytes(description_hash),
        Expr::int(lines_of_code),
        Expr::int(complexity),
        Expr::int(requested_amount_prom),
        Expr::int(votes_for),
        Expr::int(votes_against),
        Expr::int(voting_end_block),
        Expr::bool(executed),
        Expr::bool(paid),
        Expr::int(status),
        Expr::bytes(last_proposer_pk),
    ]
}

fn governance_auto_tuning_state_args(
    metrics_oracle_pk: Vec<u8>,
    min_stake_kas: i64,
    min_guardian_rep: i64,
    min_confidence_ki: i64,
    validator_consensus: i64,
    reward_base: i64,
    last_tuning_block: i64,
    active_validators: i64,
    active_guardians: i64,
    proposals_per_day: i64,
    fp_rate: i64,
    last_metrics_block: i64,
) -> Vec<Expr<'static>> {
    vec![
        Expr::bytes(metrics_oracle_pk),
        Expr::int(min_stake_kas),
        Expr::int(min_guardian_rep),
        Expr::int(min_confidence_ki),
        Expr::int(validator_consensus),
        Expr::int(reward_base),
        Expr::int(last_tuning_block),
        Expr::int(active_validators),
        Expr::int(active_guardians),
        Expr::int(proposals_per_day),
        Expr::int(fp_rate),
        Expr::int(last_metrics_block),
    ]
}

fn build_covenant_sigscript(compiled: &silverscript_lang::compiler::CompiledContract<'_>, function_name: &str, args: Vec<Expr<'_>>) {
    compiled
        .build_sig_script_for_covenant_decl(function_name, args, CovenantDeclCallOptions { is_leader: false })
        .unwrap_or_else(|err| panic!("ValidatorStakingState {function_name} sigscript builds: {err}"));
}

fn compile_rule_storage_state<'a>(source: &'a str, args: Vec<Expr<'static>>) -> CompiledContract<'a> {
    compile_contract(source, &args, CompileOptions::default()).expect("RuleStorageState fixture compiles")
}

fn validator_state_entry_sigscript(compiled: &CompiledContract<'_>, function_name: &str, args: Vec<Expr<'_>>) -> Vec<u8> {
    let mut sigscript = compiled
        .build_sig_script_for_covenant_decl(function_name, args, CovenantDeclCallOptions { is_leader: false })
        .unwrap_or_else(|err| panic!("ValidatorStakingState {function_name} sigscript builds: {err}"));
    sigscript.extend_from_slice(&common::push_redeem_script(&compiled.script));
    sigscript
}

fn guardian_state_entry_sigscript(compiled: &CompiledContract<'_>, function_name: &str, args: Vec<Expr<'_>>) -> Vec<u8> {
    let mut sigscript = compiled
        .build_sig_script_for_covenant_decl(function_name, args, CovenantDeclCallOptions { is_leader: false })
        .unwrap_or_else(|err| panic!("GuardianReputationState {function_name} sigscript builds: {err}"));
    sigscript.extend_from_slice(&common::push_redeem_script(&compiled.script));
    sigscript
}

fn rule_storage_state_entry_sigscript(compiled: &CompiledContract<'_>, function_name: &str, args: Vec<Expr<'_>>) -> Vec<u8> {
    let mut sigscript = compiled
        .build_sig_script_for_covenant_decl(function_name, args, CovenantDeclCallOptions { is_leader: false })
        .unwrap_or_else(|err| panic!("RuleStorageState {function_name} sigscript builds: {err}"));
    sigscript.extend_from_slice(&common::push_redeem_script(&compiled.script));
    sigscript
}

fn governance_auto_tuning_state_entry_sigscript(compiled: &CompiledContract<'_>, function_name: &str, args: Vec<Expr<'_>>) -> Vec<u8> {
    let mut sigscript = compiled
        .build_sig_script_for_covenant_decl(function_name, args, CovenantDeclCallOptions { is_leader: false })
        .unwrap_or_else(|err| panic!("GovernanceAutoTuningState {function_name} sigscript builds: {err}"));
    sigscript.extend_from_slice(&common::push_redeem_script(&compiled.script));
    sigscript
}

fn compile_validator_state<'a>(source: &'a str, args: Vec<Expr<'static>>) -> CompiledContract<'a> {
    compile_contract(source, &args, CompileOptions::default()).expect("ValidatorStakingState fixture compiles")
}

fn compile_guardian_state<'a>(source: &'a str, args: Vec<Expr<'static>>) -> CompiledContract<'a> {
    compile_contract(source, &args, CompileOptions::default()).expect("GuardianReputationState fixture compiles")
}

fn compile_community_donations_state<'a>(source: &'a str, args: Vec<Expr<'static>>) -> CompiledContract<'a> {
    compile_contract(source, &args, CompileOptions::default()).expect("CommunityDonationsState fixture compiles")
}

fn compile_dev_incentive_pool_state<'a>(source: &'a str, args: Vec<Expr<'static>>) -> CompiledContract<'a> {
    compile_contract(source, &args, CompileOptions::default()).expect("DevIncentivePoolState fixture compiles")
}

fn compile_governance_auto_tuning_state<'a>(source: &'a str, args: Vec<Expr<'static>>) -> CompiledContract<'a> {
    compile_contract(source, &args, CompileOptions::default()).expect("GovernanceAutoTuningState fixture compiles")
}

#[test]
fn prometheus_h001_vectors_match_current_silverc_runtime() {
    let contract_path = std::env::var("PROMETHEUS_H001_CONTRACT").expect("PROMETHEUS_H001_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus H-001 contract fixture");

    let vectors = [
        (true, 42, 1000, "cda9cc6bb51d36be5db27eb6e86bfc6b6173d5918f24f81939af5411bff90ffb"),
        (false, 0, 0, "0a88111852095cae045340ea1f0b279944b2a756a213d9b50107d7489771e159"),
        (
            true,
            0x0102030405060708,
            0x1112131415161718,
            "66fb23b92e68c968da255e16a553db24a2dff80e2a9bfe6af494b3480a4af651",
        ),
    ];

    for (vote, salt, block_height, expected_hash) in vectors {
        let compiled =
            compile_contract(&source, &[Expr::bytes(hex32(expected_hash))], CompileOptions::default()).expect("H-001 fixture compiles");
        let sigscript = compiled
            .build_sig_script("verify", vec![Expr::bool(vote), Expr::int(salt), Expr::int(block_height)])
            .expect("H-001 fixture sigscript builds");
        let result = run_script(compiled.script, sigscript);
        assert!(
            result.is_ok(),
            "H-001 vector failed for vote={vote}, salt={salt}, block_height={block_height}: {:?}",
            result.err()
        );
    }
}

#[test]
fn prometheus_validator_state_fixture_compiles_against_current_silverc() {
    let contract_path = std::env::var("PROMETHEUS_VALIDATOR_STATE_CONTRACT")
        .expect("PROMETHEUS_VALIDATOR_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus validator state contract fixture");
    let validator_pk = vec![7u8; 32];
    let commitment = hex32("cda9cc6bb51d36be5db27eb6e86bfc6b6173d5918f24f81939af5411bff90ffb");
    let sig = dummy_signature();

    let active_args = validator_state_args(
        validator_pk.clone(),
        20_000,
        true,
        1_000,
        10_000,
        0,
        0,
        zero32(),
        0,
        0,
        0,
    );
    let active = compile_contract(&source, &active_args, CompileOptions::default())
        .expect("ValidatorStakingState active fixture compiles");
    build_covenant_sigscript(
        &active,
        "commitVote",
        vec![Expr::bytes(commitment.clone()), Expr::int(2_000), Expr::int(42), Expr::bytes(sig.clone())],
    );
    build_covenant_sigscript(&active, "requestWithdraw", vec![Expr::int(500), Expr::bytes(sig.clone())]);

    let committed_args = validator_state_args(
        validator_pk.clone(),
        20_000,
        true,
        1_000,
        10_000,
        0,
        0,
        commitment,
        2_000,
        42,
        0,
    );
    let committed = compile_contract(&source, &committed_args, CompileOptions::default())
        .expect("ValidatorStakingState committed fixture compiles");
    build_covenant_sigscript(
        &committed,
        "revealVote",
        vec![Expr::bool(true), Expr::int(42), Expr::int(600), Expr::bytes(sig.clone())],
    );
    build_covenant_sigscript(
        &committed,
        "slashInvalidReveal",
        vec![Expr::bool(false), Expr::int(42), Expr::bytes(sig.clone())],
    );

    let withdraw_args = validator_state_args(
        validator_pk,
        20_000,
        false,
        1_000,
        10_000,
        0,
        0,
        zero32(),
        0,
        0,
        500,
    );
    let withdraw = compile_contract(&source, &withdraw_args, CompileOptions::default())
        .expect("ValidatorStakingState withdrawal fixture compiles");
    build_covenant_sigscript(
        &withdraw,
        "completeWithdraw",
        vec![Vec::<Expr>::new().into(), Expr::bytes(sig)],
    );
}

#[test]
fn prometheus_guardian_reputation_state_fixture_compiles_against_current_silverc() {
    let contract_path = std::env::var("PROMETHEUS_GUARDIAN_STATE_CONTRACT")
        .expect("PROMETHEUS_GUARDIAN_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus guardian reputation contract fixture");
    let guardian_pk = vec![9u8; 32];
    let governance_pk = vec![8u8; 32];
    let sig = dummy_signature();

    let unregistered = compile_guardian_state(
        &source,
        guardian_state_args(
            guardian_pk.clone(),
            governance_pk.clone(),
            0,
            0,
            0,
            0,
            0,
            1,
        ),
    );
    build_covenant_sigscript(
        &unregistered,
        "register",
        vec![Expr::int(500), Expr::int(1_000), Expr::bytes(sig.clone())],
    );

    let registered = compile_guardian_state(
        &source,
        guardian_state_args(
            guardian_pk,
            governance_pk,
            500,
            1_000,
            0,
            0,
            1_000,
            0,
        ),
    );
    build_covenant_sigscript(
        &registered,
        "proposalAccepted",
        vec![Expr::bytes(sig.clone())],
    );
    build_covenant_sigscript(
        &registered,
        "proposalRejected",
        vec![Expr::bytes(sig)],
    );
}

#[test]
fn prometheus_rule_storage_state_fixture_compiles_against_current_silverc() {
    let contract_path = std::env::var("PROMETHEUS_RULE_STORAGE_STATE_CONTRACT")
        .expect("PROMETHEUS_RULE_STORAGE_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus rule storage contract fixture");
    let governance_pk = vec![8u8; 32];
    let guardian_pk = vec![9u8; 32];
    let validator_pk = vec![7u8; 32];
    let threat_hash = vec![3u8; 32];
    let rule_cid = cid36(4);
    let sig = dummy_signature();

    let empty = compile_rule_storage_state(
        &source,
        rule_storage_state_args(
            governance_pk.clone(),
            1,
            0,
            guardian_pk.clone(),
            zero32(),
            0,
            zero36(),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            false,
            0,
        ),
    );
    build_covenant_sigscript(
        &empty,
        "submitProposal",
        vec![
            Expr::bytes(guardian_pk.clone()),
            Expr::bytes(threat_hash.clone()),
            Expr::int(0),
            Expr::bytes(rule_cid.clone()),
            Expr::int(9_000),
            Expr::bytes(vec![0u8; 64]),
            Expr::bytes(sig.clone()),
        ],
    );

    let pending = compile_rule_storage_state(
        &source,
        rule_storage_state_args(
            governance_pk.clone(),
            2,
            1,
            guardian_pk.clone(),
            threat_hash.clone(),
            0,
            rule_cid.clone(),
            9_000,
            1_000,
            2,
            0,
            865_000,
            1,
            0,
            1,
            1_000,
            0,
            0,
            false,
            0,
        ),
    );
    let _ = &validator_pk;
    build_covenant_sigscript(
        &pending,
        "finalizeProposal",
        vec![
            Expr::int(8),
            Expr::int(2),
            Expr::int(10),
            Expr::bytes(vec![5u8; 32]),
            Expr::bytes(vec![0u8; 64]),
            Expr::bytes(sig.clone()),
        ],
    );

    let accepted = compile_rule_storage_state(
        &source,
        rule_storage_state_args(
            governance_pk,
            2,
            1,
            guardian_pk,
            threat_hash,
            0,
            rule_cid,
            9_000,
            1_000,
            2,
            0,
            865_000,
            2,
            1,
            1,
            1_000,
            10_000,
            865_000,
            true,
            1,
        ),
    );
    build_covenant_sigscript(&accepted, "deactivateRule", vec![Expr::bytes(sig)]);
}

#[test]
fn prometheus_community_donations_state_fixture_compiles_against_current_silverc() {
    let contract_path = std::env::var("PROMETHEUS_COMMUNITY_DONATIONS_STATE_CONTRACT")
        .expect("PROMETHEUS_COMMUNITY_DONATIONS_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus community donations contract fixture");
    let governance_pk = vec![8u8; 32];
    let donor_pk = vec![6u8; 32];
    let proposer_pk = vec![5u8; 32];
    let validator_pk = vec![7u8; 32];
    let recipient_pk = vec![4u8; 32];
    let message_hash = vec![2u8; 32];
    let purpose_hash = vec![3u8; 32];
    let sig = dummy_signature();

    let empty = compile_community_donations_state(
        &source,
        community_donations_state_args(
            governance_pk.clone(),
            0,
            0,
            0,
            1,
            0,
            recipient_pk.clone(),
            0,
            zero32(),
            0,
            0,
            0,
            0,
            false,
            donor_pk.clone(),
            zero32(),
            0,
        ),
    );
    build_covenant_sigscript(
        &empty,
        "donateKas",
        vec![Expr::bytes(donor_pk.clone()), Expr::int(100), Expr::bytes(message_hash), Expr::int(1_000), Expr::bytes(sig.clone())],
    );
    build_covenant_sigscript(
        &empty,
        "proposeDisbursement",
        vec![Expr::bytes(recipient_pk.clone()), Expr::int(50), Expr::bytes(purpose_hash.clone()), Expr::bytes(vec![0u8; 64]), Expr::bytes(sig.clone()), Expr::bytes(proposer_pk)],
    );

    let pending = compile_community_donations_state(
        &source,
        community_donations_state_args(
            governance_pk.clone(),
            1,
            100,
            100,
            2,
            1,
            recipient_pk,
            50,
            purpose_hash,
            10,
            0,
            606_000,
            1,
            false,
            donor_pk,
            zero32(),
            1_000,
        ),
    );
    let _ = &validator_pk;
    build_covenant_sigscript(
        &pending,
        "finalizeDisbursement",
        vec![
            Expr::int(8),
            Expr::int(2),
            Expr::int(10),
            Expr::bytes(vec![5u8; 32]),
            Expr::bytes(vec![0u8; 64]),
            Expr::bytes(sig),
        ],
    );
}

fn cd_source() -> String {
    let contract_path = std::env::var("PROMETHEUS_COMMUNITY_DONATIONS_STATE_CONTRACT")
        .expect("PROMETHEUS_COMMUNITY_DONATIONS_STATE_CONTRACT is set");
    std::fs::read_to_string(contract_path).expect("read Prometheus community donations contract fixture")
}

fn p2pk_output(pk: &[u8], value: u64) -> TransactionOutput {
    let mut script = vec![0x20u8];
    script.extend_from_slice(pk);
    script.push(0xac);
    TransactionOutput { value, script_public_key: ScriptPublicKey::new(0, script.into()), covenant: None }
}

fn cd_donate_case(amount: i64, output_kas: u64, label_height: i64, lock_time: u64, pending: bool) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let source = cd_source();
    let governance_pk = keypair_from_seed(8).x_only_public_key().0.serialize().to_vec();
    let donor_keypair = keypair_from_seed(6);
    let donor_pk = donor_keypair.x_only_public_key().0.serialize().to_vec();
    let recipient_pk = keypair_from_seed(4).x_only_public_key().0.serialize().to_vec();
    let message_hash = vec![2u8; 32];
    let (status, disbursement_amount, purpose) = if pending { (1, 50, vec![3u8; 32]) } else { (0, 0, zero32()) };
    // A donation that is the first spend of a pending proposal records its exact consensus voting end.
    let voting_end = if pending { PROPOSAL_DAA as i64 + 604_800 } else { 0 };
    let before = compile_community_donations_state(
        &source,
        community_donations_state_args(governance_pk.clone(), 3, 500, 500, 2, 1, recipient_pk.clone(), disbursement_amount, purpose.clone(), 0, 0, 0, status, false, donor_pk.clone(), zero32(), 0),
    );
    let after = compile_community_donations_state(
        &source,
        community_donations_state_args(governance_pk, 4, 500 + amount, 500 + amount, 2, 1, recipient_pk, disbursement_amount, purpose, 0, 0, voting_end, status, false, donor_pk.clone(), message_hash.clone(), label_height),
    );
    let args = move |sig: Vec<u8>| -> Vec<Expr<'static>> {
        vec![Expr::bytes(donor_pk.clone()), Expr::int(amount), Expr::bytes(message_hash.clone()), Expr::int(label_height), Expr::bytes(sig)]
    };
    spend_transition(&before, "donateKas", &args, COV_A, PROPOSAL_DAA, kas(500), vec![state_output(&after, COV_A, kas(output_kas))], lock_time, Some(&donor_keypair))
}

#[test]
fn prometheus_community_donations_donate_runtime_accepts_value_backed_donation() {
    let result = cd_donate_case(100, 600, 1_000, 1_000, false);
    assert!(result.is_ok(), "donation that adds exactly its value must be accepted: {:?}", result.err());
}

#[test]
fn prometheus_community_donations_donate_runtime_rejects_zero_amount() {
    let err = cd_donate_case(0, 500, 1_000, 1_000, false).expect_err("zero donation must fail");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_community_donations_donate_runtime_rejects_unbacked_donation() {
    // PRM-19: the recorded donation must be matched by covenant value.
    let err = cd_donate_case(100, 500, 1_000, 1_000, false).expect_err("donation without added value must fail");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_community_donations_donate_runtime_rejects_future_block_height() {
    let err = cd_donate_case(100, 600, 1_000, 999, false).expect_err("future donation height must fail");
    assert_lock_time_error(err);
}

#[test]
fn prometheus_community_donations_donate_runtime_rejects_label_before_previous_transition() {
    let err = cd_donate_case(100, 600, 999, 1_000, false).expect_err("donation label older than the spent state must fail");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_community_donations_donate_runtime_records_pending_voting_end() {
    let result = cd_donate_case(100, 600, 1_000, 1_000, true);
    assert!(result.is_ok(), "donation during a pending proposal must record the consensus voting end: {:?}", result.err());
}

// Arithmetic boundaries (K1 follow-up): the pinned engine evaluates OpAdd/OpSub/OpMul with checked
// i64 arithmetic, so an overflow aborts the transition instead of wrapping. The after-state uses
// wrapping values only so the test itself never panics; the script must fail before comparing it.
fn cd_donate_boundary_case(before_total_kas: i64, amount: i64, output_sompi: u64) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let source = cd_source();
    let governance_pk = keypair_from_seed(8).x_only_public_key().0.serialize().to_vec();
    let donor_keypair = keypair_from_seed(6);
    let donor_pk = donor_keypair.x_only_public_key().0.serialize().to_vec();
    let recipient_pk = keypair_from_seed(4).x_only_public_key().0.serialize().to_vec();
    let message_hash = vec![2u8; 32];
    let before = compile_community_donations_state(
        &source,
        community_donations_state_args(governance_pk.clone(), 3, before_total_kas, 500, 2, 1, recipient_pk.clone(), 0, zero32(), 0, 0, 0, 0, false, donor_pk.clone(), zero32(), 0),
    );
    let after = compile_community_donations_state(
        &source,
        community_donations_state_args(governance_pk, 4, before_total_kas.wrapping_add(amount), 500i64.wrapping_add(amount), 2, 1, recipient_pk, 0, zero32(), 0, 0, 0, 0, false, donor_pk.clone(), message_hash.clone(), 1_000),
    );
    let args = move |sig: Vec<u8>| -> Vec<Expr<'static>> {
        vec![Expr::bytes(donor_pk.clone()), Expr::int(amount), Expr::bytes(message_hash.clone()), Expr::int(1_000), Expr::bytes(sig)]
    };
    spend_transition(&before, "donateKas", &args, COV_A, PROPOSAL_DAA, kas(500), vec![state_output(&after, COV_A, output_sompi)], 1_000, Some(&donor_keypair))
}

fn assert_number_too_big(err: kaspa_txscript_errors::TxScriptError) {
    assert!(matches!(err, kaspa_txscript_errors::TxScriptError::NumberTooBig(_)), "expected checked-arithmetic overflow, got {err:?}");
}

#[test]
fn prometheus_community_donations_donate_runtime_rejects_value_multiplication_overflow() {
    let amount = i64::MAX / 100_000_000 + 1;
    let err = cd_donate_boundary_case(500, amount, kas(600)).expect_err("amount * SOMPI_PER_KAS overflow must abort");
    assert_number_too_big(err);
}

#[test]
fn prometheus_community_donations_donate_runtime_rejects_value_addition_overflow() {
    // amount * SOMPI_PER_KAS still fits i64, adding the covenant value does not.
    let amount = i64::MAX / 100_000_000;
    let err = cd_donate_boundary_case(500, amount, kas(600)).expect_err("covenant value + donation overflow must abort");
    assert_number_too_big(err);
}

#[test]
fn prometheus_community_donations_donate_runtime_rejects_cumulative_total_overflow() {
    // Cumulative counters are not value-backed; overflow aborts the donation (liveness only, no wrap).
    let err = cd_donate_boundary_case(i64::MAX - 50, 100, kas(600)).expect_err("total_donated_kas overflow must abort");
    assert_number_too_big(err);
}

#[test]
fn prometheus_community_donations_donate_runtime_accepts_large_in_range_donation() {
    let amount: i64 = 1_000_000_000;
    let output = kas(500) + (amount as u64) * 100_000_000;
    let result = cd_donate_boundary_case(500, amount, output);
    assert!(result.is_ok(), "a large value-backed donation inside i64 range must be accepted: {:?}", result.err());
}

fn disbursement_proposal_digest(covenant_id: Hash, nonce: i64, recipient_pk: &[u8], amount: i64, purpose_hash: &[u8], proposer_pk: &[u8]) -> [u8; 32] {
    sha256_parts(&[
        &b"prometheus-disbursement-proposal-v2"[..],
        &covenant_id.as_bytes()[..],
        &nonce.to_le_bytes()[..],
        recipient_pk,
        &amount.to_le_bytes()[..],
        purpose_hash,
        proposer_pk,
    ])
}

fn cd_propose_case(amount: i64, tamper: Tamper) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let source = cd_source();
    let governance_pk = keypair_from_seed(8).x_only_public_key().0.serialize().to_vec();
    let proposer_keypair = keypair_from_seed(5);
    let proposer_pk = proposer_keypair.x_only_public_key().0.serialize().to_vec();
    let recipient_pk = keypair_from_seed(4).x_only_public_key().0.serialize().to_vec();
    let donor_pk = keypair_from_seed(6).x_only_public_key().0.serialize().to_vec();
    let purpose_hash = vec![3u8; 32];
    let before = compile_community_donations_state(
        &source,
        community_donations_state_args(governance_pk.clone(), 3, 500, 500, 1, 0, recipient_pk.clone(), 0, zero32(), 0, 0, 0, 0, false, donor_pk.clone(), zero32(), 0),
    );
    let after = compile_community_donations_state(
        &source,
        community_donations_state_args(governance_pk, 3, 500, 500, 2, 1, recipient_pk.clone(), amount, purpose_hash.clone(), 0, 0, 0, 1, false, donor_pk, zero32(), 0),
    );
    let attested_amount = if tamper == Tamper::Content { amount - 10 } else { amount };
    let digest = disbursement_proposal_digest(attested_cov(tamper), attested_nonce(tamper, 1), &recipient_pk, attested_amount, &purpose_hash, &proposer_pk);
    let attestation = attest(&attestor_keypair(tamper), digest);
    let args = move |sig: Vec<u8>| -> Vec<Expr<'static>> {
        vec![
            Expr::bytes(recipient_pk.clone()),
            Expr::int(amount),
            Expr::bytes(purpose_hash.clone()),
            Expr::bytes(attestation.clone()),
            Expr::bytes(sig),
            Expr::bytes(proposer_pk.clone()),
        ]
    };
    spend_transition(&before, "proposeDisbursement", &args, COV_A, PROPOSAL_DAA, kas(500), vec![state_output(&after, COV_A, kas(500))], 0, Some(&proposer_keypair))
}

#[test]
fn prometheus_community_donations_propose_runtime_accepts_valid_transition() {
    let result = cd_propose_case(50, Tamper::None);
    assert!(result.is_ok(), "attested proposal within the pool must be accepted: {:?}", result.err());
}

#[test]
fn prometheus_community_donations_propose_runtime_rejects_amount_above_pool() {
    let err = cd_propose_case(501, Tamper::None).expect_err("proposal above the pool must fail");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_community_donations_propose_runtime_rejects_unattested_proposal() {
    let err = cd_propose_case(50, Tamper::Attestor).expect_err("proposal without governance attestation must fail");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_community_donations_propose_runtime_rejects_cross_instance_attestation() {
    let err = cd_propose_case(50, Tamper::Instance).expect_err("attestation of another deployment must fail");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_community_donations_propose_runtime_rejects_replayed_attestation() {
    let err = cd_propose_case(50, Tamper::Nonce).expect_err("attestation for another disbursement id must fail");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_community_donations_propose_runtime_rejects_substituted_amount() {
    let err = cd_propose_case(50, Tamper::Content).expect_err("attestation for another amount must fail");
    common::assert_verify_like_error(err);
}

#[allow(clippy::too_many_arguments)]
fn disbursement_tally_digest(
    covenant_id: Hash,
    disbursement_id: i64,
    recipient_pk: &[u8],
    amount: i64,
    purpose_hash: &[u8],
    voting_end: i64,
    tally_for: i64,
    tally_against: i64,
    active_set_size: i64,
    set_root: &[u8],
) -> [u8; 32] {
    sha256_parts(&[
        &b"prometheus-disbursement-tally-v2"[..],
        &covenant_id.as_bytes()[..],
        &disbursement_id.to_le_bytes()[..],
        recipient_pk,
        &amount.to_le_bytes()[..],
        purpose_hash,
        &voting_end.to_le_bytes()[..],
        &tally_for.to_le_bytes()[..],
        &tally_against.to_le_bytes()[..],
        &active_set_size.to_le_bytes()[..],
        set_root,
    ])
}

struct CdFinalize {
    tally_for: i64,
    tally_against: i64,
    signed_set_size: i64,
    claimed_set_size: i64,
    approved: bool,
    covenant_out_kas: u64,
    payout: Option<(u8, u64)>,
    lock_time: u64,
    tamper: Tamper,
    spent_daa_score: u64,
    stored_voting_end: i64,
}

impl CdFinalize {
    fn new(tally_for: i64, tally_against: i64, approved: bool, covenant_out_kas: u64, payout: Option<(u8, u64)>, lock_time: u64) -> Self {
        Self {
            tally_for,
            tally_against,
            signed_set_size: 10,
            claimed_set_size: 10,
            approved,
            covenant_out_kas,
            payout,
            lock_time,
            tamper: Tamper::None,
            spent_daa_score: PROPOSAL_DAA,
            stored_voting_end: 0,
        }
    }
}

fn cd_finalize_case(case: CdFinalize) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let source = cd_source();
    let governance_keypair = keypair_from_seed(8);
    let governance_pk = governance_keypair.x_only_public_key().0.serialize().to_vec();
    let recipient_pk = keypair_from_seed(4).x_only_public_key().0.serialize().to_vec();
    let donor_pk = keypair_from_seed(6).x_only_public_key().0.serialize().to_vec();
    let purpose_hash = vec![3u8; 32];
    let set_root = vec![5u8; 32];
    let pending = compile_community_donations_state(
        &source,
        community_donations_state_args(governance_pk.clone(), 3, 500, 500, 2, 1, recipient_pk.clone(), 50, purpose_hash.clone(), 0, 0, case.stored_voting_end, 1, false, donor_pk.clone(), zero32(), 0),
    );
    let voting_end = if case.stored_voting_end == 0 { case.spent_daa_score as i64 + 604_800 } else { case.stored_voting_end };
    let (tally_for, tally_against) = (case.tally_for, case.tally_against);
    let next = if case.approved {
        community_donations_state_args(governance_pk, 3, 500, 450, 2, 1, recipient_pk.clone(), 50, purpose_hash.clone(), tally_for, tally_against, voting_end, 2, true, donor_pk, zero32(), 0)
    } else {
        community_donations_state_args(governance_pk, 3, 500, 500, 2, 1, recipient_pk.clone(), 50, purpose_hash.clone(), tally_for, tally_against, voting_end, 3, false, donor_pk, zero32(), 0)
    };
    let next_state = compile_community_donations_state(&source, next);
    let mut outputs = vec![state_output(&next_state, COV_A, kas(case.covenant_out_kas))];
    if let Some((recipient_seed, payout_kas)) = case.payout {
        let pk = keypair_from_seed(recipient_seed).x_only_public_key().0.serialize().to_vec();
        outputs.push(p2pk_output(&pk, kas(payout_kas)));
    }
    let attested_amount = if case.tamper == Tamper::Content { 40 } else { 50 };
    let attested_end = if case.tamper == Tamper::Session { voting_end - 1 } else { voting_end };
    let digest = disbursement_tally_digest(
        attested_cov(case.tamper),
        attested_nonce(case.tamper, 1),
        &recipient_pk,
        attested_amount,
        &purpose_hash,
        attested_end,
        tally_for,
        tally_against,
        case.signed_set_size,
        &set_root,
    );
    let attestation = attest(&attestor_keypair(case.tamper), digest);
    let claimed_set_size = case.claimed_set_size;
    let args = move |sig: Vec<u8>| -> Vec<Expr<'static>> {
        vec![
            Expr::int(tally_for),
            Expr::int(tally_against),
            Expr::int(claimed_set_size),
            Expr::bytes(set_root.clone()),
            Expr::bytes(attestation.clone()),
            Expr::bytes(sig),
        ]
    };
    spend_transition(&pending, "finalizeDisbursement", &args, COV_A, case.spent_daa_score, kas(500), outputs, case.lock_time, Some(&governance_keypair))
}

#[test]
fn prometheus_community_donations_finalize_runtime_pays_recipient_on_approval() {
    let result = cd_finalize_case(CdFinalize::new(8, 2, true, 450, Some((4, 50)), 605_800));
    assert!(result.is_ok(), "approved disbursement must pay exactly the recipient: {:?}", result.err());
}

#[test]
fn prometheus_community_donations_finalize_runtime_rejects_payout_to_other_key() {
    let err = cd_finalize_case(CdFinalize::new(8, 2, true, 450, Some((7, 50)), 605_800)).expect_err("payout to another key must fail");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_community_donations_finalize_runtime_rejects_keeping_payout_value() {
    let err = cd_finalize_case(CdFinalize::new(8, 2, true, 500, Some((4, 50)), 605_800)).expect_err("covenant must release the payout value");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_community_donations_finalize_runtime_records_rejected_tally() {
    // A failed vote ends in REJECTED instead of leaving the proposal slot PENDING forever.
    let result = cd_finalize_case(CdFinalize::new(3, 7, false, 500, None, 605_800));
    assert!(result.is_ok(), "rejected tally must finalize as REJECTED: {:?}", result.err());
}

#[test]
fn prometheus_community_donations_finalize_runtime_zero_vote_tally_is_terminal_rejection() {
    let result = cd_finalize_case(CdFinalize::new(0, 0, false, 500, None, 605_800));
    assert!(result.is_ok(), "attested zero-vote tally must finalize as REJECTED: {:?}", result.err());
    let err = cd_finalize_case(CdFinalize::new(0, 0, true, 450, Some((4, 50)), 605_800)).expect_err("zero votes must not pay");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_community_donations_finalize_runtime_rejects_low_participation_as_rejected() {
    // PRM-18: one vote out of ten is not a quorum, so the disbursement is rejected, not paid.
    let result = cd_finalize_case(CdFinalize::new(1, 0, false, 500, None, 605_800));
    assert!(result.is_ok(), "low participation must finalize as REJECTED: {:?}", result.err());
    let err = cd_finalize_case(CdFinalize::new(1, 0, true, 450, Some((4, 50)), 605_800)).expect_err("low participation must not pay");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_community_donations_finalize_runtime_rejects_tampered_set_size() {
    let case = CdFinalize { tally_for: 2, tally_against: 0, claimed_set_size: 4, ..CdFinalize::new(2, 0, true, 450, Some((4, 50)), 605_800) };
    let err = cd_finalize_case(case).expect_err("tampered set size must fail");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_community_donations_finalize_runtime_rejects_mismatched_attestation_context() {
    for tamper in [Tamper::Instance, Tamper::Nonce, Tamper::Content, Tamper::Session, Tamper::Attestor] {
        let case = CdFinalize { tamper, ..CdFinalize::new(0, 0, false, 500, None, 605_800) };
        let err = cd_finalize_case(case).expect_err("tally with mismatched attestation context must fail");
        common::assert_verify_like_error(err);
    }
}

#[test]
fn prometheus_community_donations_finalize_runtime_rejects_before_voting_end() {
    let err = cd_finalize_case(CdFinalize::new(8, 2, true, 450, Some((4, 50)), 605_799)).expect_err("early finalize must fail");
    assert_lock_time_error(err);
}

#[test]
fn prometheus_community_donations_finalize_runtime_rejects_old_start_height() {
    // Proposal accepted at DAA 300,000: a lock time that fits an old start (1,000) cannot finalize.
    let case = CdFinalize { spent_daa_score: 300_000, ..CdFinalize::new(8, 2, true, 450, Some((4, 50)), 605_800) };
    let err = cd_finalize_case(case).expect_err("old start height must fail");
    assert_lock_time_error(err);
}

#[test]
fn prometheus_community_donations_finalize_runtime_keeps_window_recorded_by_donation() {
    // A donation recorded the exact voting end (605,800); later spends cannot move it.
    let case = CdFinalize { spent_daa_score: 400_000, stored_voting_end: 605_800, ..CdFinalize::new(8, 2, true, 450, Some((4, 50)), 605_800) };
    let result = cd_finalize_case(case);
    assert!(result.is_ok(), "stored consensus voting end must be used: {:?}", result.err());
    let early = CdFinalize { spent_daa_score: 400_000, stored_voting_end: 605_800, ..CdFinalize::new(8, 2, true, 450, Some((4, 50)), 605_799) };
    assert_lock_time_error(cd_finalize_case(early).expect_err("stored voting end is binding"));
}

#[test]
fn prometheus_dev_incentive_pool_state_fixture_compiles_against_current_silverc() {
    let contract_path = std::env::var("PROMETHEUS_DEV_INCENTIVE_POOL_STATE_CONTRACT")
        .expect("PROMETHEUS_DEV_INCENTIVE_POOL_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus dev incentive pool contract fixture");
    let developer_pk = vec![4u8; 32];
    let proposer_pk = vec![5u8; 32];
    let validator_pk = vec![7u8; 32];
    let contribution_hash = vec![2u8; 32];
    let description_hash = vec![3u8; 32];
    let sig = dummy_signature();

    let funded = compile_dev_incentive_pool_state(
        &source,
        dev_incentive_pool_state_args(1, 500_000, 0, developer_pk.clone(), zero32(), zero32(), 0, 1, 0, 0, 0, 0, false, false, 0, proposer_pk.clone()),
    );
    build_covenant_sigscript(
        &funded,
        "proposeGrant",
        vec![
            Expr::bytes(developer_pk.clone()),
            Expr::bytes(contribution_hash.clone()),
            Expr::bytes(description_hash.clone()),
            Expr::int(100),
            Expr::int(5),
            Expr::int(10_000),
            Expr::bytes(vec![0u8; 64]),
            Expr::bytes(sig.clone()),
            Expr::bytes(proposer_pk.clone()),
        ],
    );

    let pending = compile_dev_incentive_pool_state(
        &source,
        dev_incentive_pool_state_args(2, 500_000, 1, developer_pk, contribution_hash, description_hash, 100, 5, 10_000, 10, 0, 605_800, false, false, 1, proposer_pk),
    );
    let _ = &validator_pk;
    build_covenant_sigscript(
        &pending,
        "finalizeGrant",
        vec![
            Expr::int(8),
            Expr::int(2),
            Expr::int(10),
            Expr::bytes(vec![5u8; 32]),
            Expr::bytes(vec![0u8; 64]),
            Expr::bytes(sig),
        ],
    );
}

#[test]
fn prometheus_governance_auto_tuning_state_fixture_compiles_against_current_silverc() {
    let contract_path = std::env::var("PROMETHEUS_GOVERNANCE_AUTO_TUNING_STATE_CONTRACT")
        .expect("PROMETHEUS_GOVERNANCE_AUTO_TUNING_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus governance auto tuning contract fixture");
    let oracle_pk = vec![8u8; 32];
    let sig = dummy_signature();

    let current = compile_governance_auto_tuning_state(
        &source,
        governance_auto_tuning_state_args(oracle_pk.clone(), 10_000, 1_000, 8_500, 6_700, 100, 0, 100, 500, 150, 0, 0),
    );
    build_covenant_sigscript(
        &current,
        "reportMetrics",
        vec![
            Expr::int(30),
            Expr::int(500),
            Expr::int(50),
            Expr::int(100),
            Expr::int(1_000),
            Expr::bytes(sig),
        ],
    );
    build_covenant_sigscript(&current, "autoTune", vec![]);
    build_covenant_sigscript(&current, "settleTuning", vec![]);
}

#[test]
fn prometheus_governance_auto_tuning_report_metrics_runtime_accepts_valid_transition() {
    let contract_path = std::env::var("PROMETHEUS_GOVERNANCE_AUTO_TUNING_STATE_CONTRACT")
        .expect("PROMETHEUS_GOVERNANCE_AUTO_TUNING_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus governance auto tuning contract fixture");
    let oracle_keypair = keypair_from_seed(8);
    let oracle_pk = oracle_keypair.x_only_public_key().0.serialize().to_vec();

    let current = compile_governance_auto_tuning_state(
        &source,
        governance_auto_tuning_state_args(oracle_pk.clone(), 10_000, 1_000, 8_500, 6_700, 100, 0, 100, 500, 150, 0, 0),
    );
    let reported = compile_governance_auto_tuning_state(
        &source,
        governance_auto_tuning_state_args(oracle_pk.clone(), 10_000, 1_000, 8_500, 6_700, 100, 0, 30, 500, 50, 100, 1_000),
    );

    let placeholder_sigscript = governance_auto_tuning_state_entry_sigscript(
        &current,
        "reportMetrics",
        vec![Expr::int(30), Expr::int(500), Expr::int(50), Expr::int(100), Expr::int(1_000), Expr::bytes(dummy_signature())],
    );
    let outputs = vec![covenant_output(&reported, 0, COV_A)];
    let entries = vec![covenant_utxo(&current, COV_A)];
    let mut tx = Transaction::new(
        1,
        vec![tx_input_with_sigops(0, placeholder_sigscript, 1)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    let sig = sign_tx_input(&tx, &entries, 0, &oracle_keypair);
    tx.inputs[0].signature_script = governance_auto_tuning_state_entry_sigscript(
        &current,
        "reportMetrics",
        vec![Expr::int(30), Expr::int(500), Expr::int(50), Expr::int(100), Expr::int(1_000), Expr::bytes(sig)],
    );

    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(
        result.is_ok(),
        "GovernanceAutoTuning reportMetrics runtime should accept valid oracle signature/state transition: {:?}",
        result.err()
    );
}

#[test]
fn prometheus_governance_auto_tuning_report_metrics_runtime_rejects_fp_rate_above_max() {
    let contract_path = std::env::var("PROMETHEUS_GOVERNANCE_AUTO_TUNING_STATE_CONTRACT")
        .expect("PROMETHEUS_GOVERNANCE_AUTO_TUNING_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus governance auto tuning contract fixture");
    let oracle_keypair = keypair_from_seed(8);
    let oracle_pk = oracle_keypair.x_only_public_key().0.serialize().to_vec();

    let current = compile_governance_auto_tuning_state(
        &source,
        governance_auto_tuning_state_args(oracle_pk.clone(), 10_000, 1_000, 8_500, 6_700, 100, 0, 100, 500, 150, 0, 0),
    );
    let invalid_next = compile_governance_auto_tuning_state(
        &source,
        governance_auto_tuning_state_args(oracle_pk.clone(), 10_000, 1_000, 8_500, 6_700, 100, 0, 30, 500, 50, 10_001, 1_000),
    );

    let placeholder_sigscript = governance_auto_tuning_state_entry_sigscript(
        &current,
        "reportMetrics",
        vec![Expr::int(30), Expr::int(500), Expr::int(50), Expr::int(10_001), Expr::int(1_000), Expr::bytes(dummy_signature())],
    );
    let outputs = vec![covenant_output(&invalid_next, 0, COV_A)];
    let entries = vec![covenant_utxo(&current, COV_A)];
    let mut tx = Transaction::new(
        1,
        vec![tx_input_with_sigops(0, placeholder_sigscript, 1)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    let sig = sign_tx_input(&tx, &entries, 0, &oracle_keypair);
    tx.inputs[0].signature_script = governance_auto_tuning_state_entry_sigscript(
        &current,
        "reportMetrics",
        vec![Expr::int(30), Expr::int(500), Expr::int(50), Expr::int(10_001), Expr::int(1_000), Expr::bytes(sig)],
    );

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("reportMetrics must reject fp_rate above MAX_FP_RATE");
    common::assert_verify_like_error(err);
}

fn gat_source() -> String {
    let contract_path = std::env::var("PROMETHEUS_GOVERNANCE_AUTO_TUNING_STATE_CONTRACT")
        .expect("PROMETHEUS_GOVERNANCE_AUTO_TUNING_STATE_CONTRACT is set");
    std::fs::read_to_string(contract_path).expect("read Prometheus governance auto tuning contract fixture")
}

// High-FP metrics: 30 validators, 500 guardians, 50 proposals/day, fp_rate 100.
fn auto_tune_case(prev_last_tuning: i64, next_last_tuning: i64, spent_daa_score: u64, lock_time: u64) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let source = gat_source();
    let oracle_pk = keypair_from_seed(8).x_only_public_key().0.serialize().to_vec();
    let current = compile_governance_auto_tuning_state(
        &source,
        governance_auto_tuning_state_args(oracle_pk.clone(), 10_000, 1_000, 8_500, 6_700, 100, prev_last_tuning, 30, 500, 50, 100, 1_000),
    );
    let tuned = compile_governance_auto_tuning_state(
        &source,
        governance_auto_tuning_state_args(oracle_pk, 9_500, 1_000, 8_600, 6_700, 110, next_last_tuning, 30, 500, 50, 100, 1_000),
    );
    let args = |_sig: Vec<u8>| -> Vec<Expr<'static>> { vec![] };
    spend_transition(&current, "autoTune", &args, COV_A, spent_daa_score, 1_500, vec![state_output(&tuned, COV_A, 1_500)], lock_time, None)
}

fn settle_tuning_case(prev_last_tuning: i64, next_last_tuning: i64, spent_daa_score: u64) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let source = gat_source();
    let oracle_pk = keypair_from_seed(8).x_only_public_key().0.serialize().to_vec();
    let current = compile_governance_auto_tuning_state(
        &source,
        governance_auto_tuning_state_args(oracle_pk.clone(), 9_500, 1_000, 8_600, 6_700, 110, prev_last_tuning, 30, 500, 50, 100, 1_000),
    );
    let settled = compile_governance_auto_tuning_state(
        &source,
        governance_auto_tuning_state_args(oracle_pk, 9_500, 1_000, 8_600, 6_700, 110, next_last_tuning, 30, 500, 50, 100, 1_000),
    );
    let args = |_sig: Vec<u8>| -> Vec<Expr<'static>> { vec![] };
    spend_transition(&current, "settleTuning", &args, COV_A, spent_daa_score, 1_500, vec![state_output(&settled, COV_A, 1_500)], 0, None)
}

#[test]
fn prometheus_governance_auto_tuning_auto_tune_runtime_accepts_high_fp_adjustment() {
    // Pending anchor resolved from the spent UTXO (DAA 1,000); one interval later tuning is allowed.
    let result = auto_tune_case(0, 0, PROPOSAL_DAA, 605_800);
    assert!(result.is_ok(), "autoTune must accept the deterministic high-FP adjustment after one interval: {:?}", result.err());
}

#[test]
fn prometheus_governance_auto_tuning_auto_tune_runtime_rejects_early_execution() {
    let err = auto_tune_case(0, 0, PROPOSAL_DAA, 605_799).expect_err("autoTune before one interval must fail");
    assert_lock_time_error(err);
}

#[test]
fn prometheus_governance_auto_tuning_auto_tune_runtime_uses_settled_anchor() {
    // A settled anchor (1,000) survives later metrics reports (spent UTXO at DAA 500,000).
    let result = auto_tune_case(1_000, 0, 500_000, 605_800);
    assert!(result.is_ok(), "settled anchor must be binding: {:?}", result.err());
    assert_lock_time_error(auto_tune_case(1_000, 0, 500_000, 605_799).expect_err("settled anchor must not be undercut"));
}

#[test]
fn prometheus_governance_auto_tuning_auto_tune_runtime_rejects_historical_catch_up() {
    // Review finding 2: tuning twice in a row. The second autoTune spends the first one's output
    // (accepted at DAA 605,800); a lock time that fits an old caller height cannot tune again.
    let err = auto_tune_case(0, 0, 605_800, 605_800).expect_err("second tuning in the same interval must fail");
    assert_lock_time_error(err);
    let err = auto_tune_case(0, 0, 605_800, 1_210_599).expect_err("second tuning one block early must fail");
    assert_lock_time_error(err);
    let result = auto_tune_case(0, 0, 605_800, 1_210_600);
    assert!(result.is_ok(), "next tuning after a full interval must pass: {:?}", result.err());
}

#[test]
fn prometheus_governance_auto_tuning_auto_tune_runtime_unsettled_anchor_is_conservative() {
    // Unsettled anchor followed by a metrics report at DAA 700,000: the report time is the bound.
    let err = auto_tune_case(0, 0, 700_000, 1_210_600).expect_err("unsettled anchor must not allow earlier tuning");
    assert_lock_time_error(err);
}

#[test]
fn prometheus_governance_auto_tuning_auto_tune_runtime_rejects_caller_chosen_anchor() {
    let err = auto_tune_case(0, 605_800, PROPOSAL_DAA, 605_800).expect_err("autoTune must not record a caller-chosen anchor");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_governance_auto_tuning_auto_tune_runtime_rejects_unaccepted_input() {
    let err = auto_tune_case(0, 0, UNACCEPTED_DAA, 605_800).expect_err("unaccepted covenant input must fail");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_governance_auto_tuning_settle_tuning_runtime_records_exact_anchor() {
    let result = settle_tuning_case(0, 605_800, 605_800);
    assert!(result.is_ok(), "settleTuning must record the spent UTXO DAA score: {:?}", result.err());
    let err = settle_tuning_case(0, 605_000, 605_800).expect_err("settleTuning must not record another value");
    common::assert_verify_like_error(err);
    let err = settle_tuning_case(1_000, 605_800, 605_800).expect_err("settled anchor must not be moved");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_governance_auto_tuning_auto_tune_runtime_lowers_confidence_on_zero_fp() {
    let source = gat_source();
    let oracle_pk = keypair_from_seed(8).x_only_public_key().0.serialize().to_vec();
    let current = compile_governance_auto_tuning_state(
        &source,
        governance_auto_tuning_state_args(oracle_pk.clone(), 10_000, 1_000, 8_500, 6_700, 100, 0, 100, 500, 150, 0, 1_000),
    );
    let tuned = compile_governance_auto_tuning_state(
        &source,
        governance_auto_tuning_state_args(oracle_pk, 10_000, 1_000, 8_400, 6_700, 100, 0, 100, 500, 150, 0, 1_000),
    );
    let args = |_sig: Vec<u8>| -> Vec<Expr<'static>> { vec![] };
    let result = spend_transition(&current, "autoTune", &args, COV_A, PROPOSAL_DAA, 1_500, vec![state_output(&tuned, COV_A, 1_500)], 605_800, None);
    assert!(result.is_ok(), "autoTune must lower confidence when fp_rate is zero: {:?}", result.err());
}

fn dev_source() -> String {
    let contract_path = std::env::var("PROMETHEUS_DEV_INCENTIVE_POOL_STATE_CONTRACT")
        .expect("PROMETHEUS_DEV_INCENTIVE_POOL_STATE_CONTRACT is set");
    std::fs::read_to_string(contract_path).expect("read Prometheus dev incentive pool contract fixture")
}

#[allow(clippy::too_many_arguments)]
fn grant_proposal_digest(
    covenant_id: Hash,
    nonce: i64,
    developer_pk: &[u8],
    contribution_hash: &[u8],
    description_hash: &[u8],
    lines: i64,
    complexity: i64,
    amount: i64,
    proposer_pk: &[u8],
) -> [u8; 32] {
    sha256_parts(&[
        &b"prometheus-grant-proposal-v2"[..],
        &covenant_id.as_bytes()[..],
        &nonce.to_le_bytes()[..],
        developer_pk,
        contribution_hash,
        description_hash,
        &lines.to_le_bytes()[..],
        &complexity.to_le_bytes()[..],
        &amount.to_le_bytes()[..],
        proposer_pk,
    ])
}

fn dev_propose_case(amount: i64, tamper: Tamper) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let source = dev_source();
    let developer_pk = keypair_from_seed(4).x_only_public_key().0.serialize().to_vec();
    let proposer_keypair = keypair_from_seed(5);
    let proposer_pk = proposer_keypair.x_only_public_key().0.serialize().to_vec();
    let contribution_hash = vec![2u8; 32];
    let description_hash = vec![3u8; 32];
    let funded = compile_dev_incentive_pool_state(
        &source,
        dev_incentive_pool_state_args(1, 500_000, 0, developer_pk.clone(), zero32(), zero32(), 0, 1, 0, 0, 0, 0, false, false, 0, proposer_pk.clone()),
    );
    let pending = compile_dev_incentive_pool_state(
        &source,
        dev_incentive_pool_state_args(2, 500_000, 1, developer_pk.clone(), contribution_hash.clone(), description_hash.clone(), 100, 5, amount, 0, 0, 0, false, false, 1, proposer_pk.clone()),
    );
    let attested_lines = if tamper == Tamper::Content { 1_000 } else { 100 };
    let digest = grant_proposal_digest(
        attested_cov(tamper),
        attested_nonce(tamper, 1),
        &developer_pk,
        &contribution_hash,
        &description_hash,
        attested_lines,
        5,
        amount,
        &proposer_pk,
    );
    let attestation = attest(&attestor_keypair(tamper), digest);
    let args = move |sig: Vec<u8>| -> Vec<Expr<'static>> {
        vec![
            Expr::bytes(developer_pk.clone()),
            Expr::bytes(contribution_hash.clone()),
            Expr::bytes(description_hash.clone()),
            Expr::int(100),
            Expr::int(5),
            Expr::int(amount),
            Expr::bytes(attestation.clone()),
            Expr::bytes(sig),
            Expr::bytes(proposer_pk.clone()),
        ]
    };
    spend_transition(&funded, "proposeGrant", &args, COV_A, PROPOSAL_DAA, 1_500, vec![state_output(&pending, COV_A, 1_500)], 0, Some(&proposer_keypair))
}

#[test]
fn prometheus_dev_incentive_pool_propose_runtime_accepts_valid_transition() {
    let result = dev_propose_case(10_000, Tamper::None);
    assert!(result.is_ok(), "DevIncentivePool proposeGrant must accept an attested proposal: {:?}", result.err());
}

#[test]
fn prometheus_dev_incentive_pool_propose_runtime_rejects_amount_above_max_grant() {
    let err = dev_propose_case(100_001, Tamper::None).expect_err("proposeGrant must reject amounts above MAX_GRANT_PROM");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_dev_incentive_pool_propose_runtime_rejects_mismatched_attestation_context() {
    for tamper in [Tamper::Instance, Tamper::Nonce, Tamper::Content, Tamper::Attestor] {
        let err = dev_propose_case(10_000, tamper).expect_err("proposal with mismatched attestation context must fail");
        common::assert_verify_like_error(err);
    }
}

#[allow(clippy::too_many_arguments)]
fn grant_tally_digest(
    covenant_id: Hash,
    grant_id: i64,
    content_hash: &[u8; 32],
    voting_end: i64,
    tally_for: i64,
    tally_against: i64,
    active_set_size: i64,
    set_root: &[u8],
) -> [u8; 32] {
    sha256_parts(&[
        &b"prometheus-grant-tally-v2"[..],
        &covenant_id.as_bytes()[..],
        &grant_id.to_le_bytes()[..],
        &content_hash[..],
        &voting_end.to_le_bytes()[..],
        &tally_for.to_le_bytes()[..],
        &tally_against.to_le_bytes()[..],
        &active_set_size.to_le_bytes()[..],
        set_root,
    ])
}

#[allow(clippy::too_many_arguments)]
fn dev_finalize_case(
    tally_for: i64,
    tally_against: i64,
    signed_set_size: i64,
    claimed_set_size: i64,
    approved: bool,
    lock_time: u64,
    tamper: Tamper,
    spent_daa_score: u64,
) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let source = dev_source();
    let governance_keypair = keypair_from_seed(8);
    let developer_pk = keypair_from_seed(10).x_only_public_key().0.serialize().to_vec();
    let proposer_pk = keypair_from_seed(12).x_only_public_key().0.serialize().to_vec();
    let set_root = vec![5u8; 32];
    let pending = compile_dev_incentive_pool_state(
        &source,
        dev_incentive_pool_state_args(2, 50_000, 1, developer_pk.clone(), vec![1u8; 32], vec![2u8; 32], 100, 5, 1_500, 0, 0, 0, false, false, 1, proposer_pk.clone()),
    );
    let voting_end = spent_daa_score as i64 + 604_800;
    let next = if approved {
        dev_incentive_pool_state_args(2, 48_500, 1, developer_pk.clone(), vec![1u8; 32], vec![2u8; 32], 100, 5, 1_500, tally_for, tally_against, voting_end, true, true, 2, proposer_pk.clone())
    } else {
        dev_incentive_pool_state_args(2, 50_000, 1, developer_pk.clone(), vec![1u8; 32], vec![2u8; 32], 100, 5, 1_500, tally_for, tally_against, voting_end, false, false, 3, proposer_pk.clone())
    };
    let next_state = compile_dev_incentive_pool_state(&source, next);
    let attested_amount: i64 = if tamper == Tamper::Content { 100_000 } else { 1_500 };
    let content = sha256_parts(&[
        &developer_pk[..],
        &[1u8; 32][..],
        &[2u8; 32][..],
        &100i64.to_le_bytes()[..],
        &5i64.to_le_bytes()[..],
        &attested_amount.to_le_bytes()[..],
        &proposer_pk[..],
    ]);
    let attested_end = if tamper == Tamper::Session { voting_end - 1 } else { voting_end };
    let digest = grant_tally_digest(attested_cov(tamper), attested_nonce(tamper, 1), &content, attested_end, tally_for, tally_against, signed_set_size, &set_root);
    let attestation = attest(&attestor_keypair(tamper), digest);
    let args = move |sig: Vec<u8>| -> Vec<Expr<'static>> {
        vec![
            Expr::int(tally_for),
            Expr::int(tally_against),
            Expr::int(claimed_set_size),
            Expr::bytes(set_root.clone()),
            Expr::bytes(attestation.clone()),
            Expr::bytes(sig),
        ]
    };
    spend_transition(
        &pending,
        "finalizeGrant",
        &args,
        COV_A,
        spent_daa_score,
        1_500,
        vec![state_output(&next_state, COV_A, 1_500)],
        lock_time,
        Some(&governance_keypair),
    )
}

#[test]
fn prometheus_dev_incentive_pool_finalize_runtime_executes_approved_grant() {
    let result = dev_finalize_case(8, 2, 10, 10, true, 605_800, Tamper::None, PROPOSAL_DAA);
    assert!(result.is_ok(), "attested approving tally must execute the grant: {:?}", result.err());
}

#[test]
fn prometheus_dev_incentive_pool_finalize_runtime_records_rejected_grant() {
    let result = dev_finalize_case(3, 7, 10, 10, false, 605_800, Tamper::None, PROPOSAL_DAA);
    assert!(result.is_ok(), "rejecting tally must end REJECTED: {:?}", result.err());
}

#[test]
fn prometheus_dev_incentive_pool_finalize_runtime_zero_vote_tally_is_terminal_rejection() {
    let result = dev_finalize_case(0, 0, 10, 10, false, 605_800, Tamper::None, PROPOSAL_DAA);
    assert!(result.is_ok(), "attested zero-vote tally must end REJECTED: {:?}", result.err());
    let err = dev_finalize_case(0, 0, 10, 10, true, 605_800, Tamper::None, PROPOSAL_DAA).expect_err("zero votes must not execute");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_dev_incentive_pool_finalize_runtime_low_participation_cannot_execute() {
    let result = dev_finalize_case(1, 0, 10, 10, false, 605_800, Tamper::None, PROPOSAL_DAA);
    assert!(result.is_ok(), "low participation must end REJECTED: {:?}", result.err());
    let err = dev_finalize_case(1, 0, 10, 10, true, 605_800, Tamper::None, PROPOSAL_DAA).expect_err("low participation must not execute");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_dev_incentive_pool_finalize_runtime_rejects_tampered_set_size() {
    let err = dev_finalize_case(2, 0, 10, 4, true, 605_800, Tamper::None, PROPOSAL_DAA).expect_err("tampered set size must fail");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_dev_incentive_pool_finalize_runtime_rejects_mismatched_attestation_context() {
    for tamper in [Tamper::Instance, Tamper::Nonce, Tamper::Content, Tamper::Session, Tamper::Attestor] {
        let err = dev_finalize_case(0, 0, 10, 10, false, 605_800, tamper, PROPOSAL_DAA).expect_err("tally with mismatched attestation context must fail");
        common::assert_verify_like_error(err);
    }
}

#[test]
fn prometheus_dev_incentive_pool_finalize_runtime_rejects_before_voting_end() {
    let err = dev_finalize_case(8, 2, 10, 10, true, 605_799, Tamper::None, PROPOSAL_DAA).expect_err("early finalize must fail");
    assert_lock_time_error(err);
}

#[test]
fn prometheus_dev_incentive_pool_finalize_runtime_rejects_old_start_height() {
    let err = dev_finalize_case(8, 2, 10, 10, true, 605_800, Tamper::None, 300_000).expect_err("old start height must fail");
    assert_lock_time_error(err);
}

fn rule_source() -> String {
    let contract_path = std::env::var("PROMETHEUS_RULE_STORAGE_STATE_CONTRACT")
        .expect("PROMETHEUS_RULE_STORAGE_STATE_CONTRACT is set");
    std::fs::read_to_string(contract_path).expect("read Prometheus rule storage contract fixture")
}

fn rule_content_hash(guardian_pk: &[u8], threat_hash: &[u8], rule_type: i64, rule_cid: &[u8], confidence: i64) -> [u8; 32] {
    sha256_parts(&[guardian_pk, threat_hash, &rule_type.to_le_bytes()[..], rule_cid, &confidence.to_le_bytes()[..]])
}

fn rule_submission_digest(covenant_id: Hash, nonce: i64, content_hash: &[u8; 32]) -> [u8; 32] {
    sha256_parts(&[&b"prometheus-rule-submission-v2"[..], &covenant_id.as_bytes()[..], &nonce.to_le_bytes()[..], &content_hash[..]])
}

#[allow(clippy::too_many_arguments)]
fn rule_tally_digest(
    covenant_id: Hash,
    proposal_id: i64,
    content_hash: &[u8; 32],
    session_start: i64,
    tally_for: i64,
    tally_against: i64,
    active_set_size: i64,
    set_root: &[u8],
) -> [u8; 32] {
    sha256_parts(&[
        &b"prometheus-rule-tally-v2"[..],
        &covenant_id.as_bytes()[..],
        &proposal_id.to_le_bytes()[..],
        &content_hash[..],
        &session_start.to_le_bytes()[..],
        &tally_for.to_le_bytes()[..],
        &tally_against.to_le_bytes()[..],
        &active_set_size.to_le_bytes()[..],
        set_root,
    ])
}

fn attest(keypair: &Keypair, digest: [u8; 32]) -> Vec<u8> {
    let msg = Message::from_digest_slice(&digest).expect("valid attestation digest");
    keypair.sign_schnorr(msg).as_ref().to_vec()
}

fn rule_storage_submit_case(prev_status: i64, confidence: i64, tamper: Tamper, spent_daa_score: u64) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let source = rule_source();
    let governance_pk = keypair_from_seed(8).x_only_public_key().0.serialize().to_vec();
    let guardian_keypair = keypair_from_seed(9);
    let guardian_pk = guardian_keypair.x_only_public_key().0.serialize().to_vec();
    let threat_hash = vec![3u8; 32];
    let rule_cid = cid36(4);
    let prev = compile_rule_storage_state(
        &source,
        rule_storage_state_args(governance_pk.clone(), 1, 0, guardian_pk.clone(), zero32(), 0, zero36(), 0, 0, 0, 0, 0, prev_status, 0, 0, 0, 0, 0, false, 0),
    );
    // Submission time and voting end stay 0 until the next spend records the consensus submission time.
    let pending = compile_rule_storage_state(
        &source,
        rule_storage_state_args(governance_pk, 2, 1, guardian_pk.clone(), threat_hash.clone(), 0, rule_cid.clone(), confidence, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, false, 0),
    );
    let attested_cid = if tamper == Tamper::Content { cid36(5) } else { rule_cid.clone() };
    let content = rule_content_hash(&guardian_pk, &threat_hash, 0, &attested_cid, confidence);
    let attestation = attest(&attestor_keypair(tamper), rule_submission_digest(COV_A, attested_nonce(tamper, 1), &content));
    // Cross-instance: the attestation for deployment A is replayed on deployment B.
    let spend_cov = if tamper == Tamper::Instance { COV_B } else { COV_A };
    let args = move |sig: Vec<u8>| -> Vec<Expr<'static>> {
        vec![
            Expr::bytes(guardian_pk.clone()),
            Expr::bytes(threat_hash.clone()),
            Expr::int(0),
            Expr::bytes(rule_cid.clone()),
            Expr::int(confidence),
            Expr::bytes(attestation.clone()),
            Expr::bytes(sig),
        ]
    };
    spend_transition(&prev, "submitProposal", &args, spend_cov, spent_daa_score, 1_500, vec![state_output(&pending, spend_cov, 1_500)], 0, Some(&guardian_keypair))
}

#[test]
fn prometheus_rule_storage_submit_proposal_runtime_accepts_attested_guardian() {
    let result = rule_storage_submit_case(0, 9_000, Tamper::None, PROPOSAL_DAA);
    assert!(result.is_ok(), "attested submission must be accepted: {:?}", result.err());
}

#[test]
fn prometheus_rule_storage_submit_proposal_runtime_accepts_after_terminal_rejection() {
    // A terminal REJECTED tally frees the single proposal slot.
    let result = rule_storage_submit_case(3, 9_000, Tamper::None, PROPOSAL_DAA);
    assert!(result.is_ok(), "submission after a rejected proposal must be accepted: {:?}", result.err());
}

#[test]
fn prometheus_rule_storage_submit_proposal_runtime_rejects_while_pending() {
    let err = rule_storage_submit_case(1, 9_000, Tamper::None, PROPOSAL_DAA).expect_err("pending slot must not be overwritten");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_rule_storage_submit_proposal_runtime_rejects_unattested_guardian() {
    // PRM-17: a guardian key without a membership attestation from the governance key is rejected.
    let err = rule_storage_submit_case(0, 9_000, Tamper::Attestor, PROPOSAL_DAA).expect_err("forged attestation must fail");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_rule_storage_submit_proposal_runtime_rejects_cross_instance_attestation() {
    let err = rule_storage_submit_case(0, 9_000, Tamper::Instance, PROPOSAL_DAA).expect_err("attestation of another deployment must fail");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_rule_storage_submit_proposal_runtime_rejects_replayed_attestation() {
    let err = rule_storage_submit_case(0, 9_000, Tamper::Nonce, PROPOSAL_DAA).expect_err("attestation for another proposal id must fail");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_rule_storage_submit_proposal_runtime_rejects_substituted_rule_content() {
    // The attestation binds the rule CID, type, and confidence, not only the guardian and threat hash.
    let err = rule_storage_submit_case(0, 9_000, Tamper::Content, PROPOSAL_DAA).expect_err("substituted rule CID must fail");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_rule_storage_submit_proposal_runtime_rejects_low_confidence() {
    let err = rule_storage_submit_case(0, 8_499, Tamper::None, PROPOSAL_DAA).expect_err("submitProposal must reject low confidence");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_rule_storage_submit_proposal_runtime_rejects_unaccepted_input() {
    let err = rule_storage_submit_case(0, 9_000, Tamper::None, UNACCEPTED_DAA).expect_err("unaccepted covenant input must fail");
    common::assert_verify_like_error(err);
}

#[allow(clippy::too_many_arguments)]
fn rule_storage_finalize_case(
    tally_for: i64,
    tally_against: i64,
    signed_set_size: i64,
    claimed_set_size: i64,
    expect_accepted: bool,
    tamper: Tamper,
    spent_daa_score: u64,
    lock_time: u64,
) -> Result<(), kaspa_txscript_errors::TxScriptError> {
    let source = rule_source();
    let governance_keypair = keypair_from_seed(8);
    let governance_pk = governance_keypair.x_only_public_key().0.serialize().to_vec();
    let guardian_pk = keypair_from_seed(9).x_only_public_key().0.serialize().to_vec();
    let threat_hash = vec![3u8; 32];
    let rule_cid = cid36(4);
    let set_root = vec![5u8; 32];
    let pending = compile_rule_storage_state(
        &source,
        rule_storage_state_args(governance_pk.clone(), 2, 1, guardian_pk.clone(), threat_hash.clone(), 0, rule_cid.clone(), 9_000, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, false, 0),
    );
    let session_start = spent_daa_score as i64;
    let session_end = session_start + 864_000;
    let total = tally_for + tally_against;
    let approval = if total > 0 { tally_for * 10_000 / total } else { 0 };
    let next = if expect_accepted {
        rule_storage_state_args(governance_pk, 2, 1, guardian_pk.clone(), threat_hash.clone(), 0, rule_cid.clone(), 9_000, session_start, tally_for, tally_against, session_end, 2, 1, 1, 0, approval, session_end, true, 1)
    } else {
        rule_storage_state_args(governance_pk, 2, 1, guardian_pk.clone(), threat_hash.clone(), 0, rule_cid.clone(), 9_000, session_start, tally_for, tally_against, session_end, 3, 0, 1, 0, approval, 0, false, 2)
    };
    let next_state = compile_rule_storage_state(&source, next);
    let attested_cid = if tamper == Tamper::Content { cid36(5) } else { rule_cid };
    let content = rule_content_hash(&guardian_pk, &threat_hash, 0, &attested_cid, 9_000);
    let attested_session = if tamper == Tamper::Session { session_start - 1 } else { session_start };
    let digest = rule_tally_digest(
        attested_cov(tamper),
        attested_nonce(tamper, 1),
        &content,
        attested_session,
        tally_for,
        tally_against,
        signed_set_size,
        &set_root,
    );
    let attestation = attest(&attestor_keypair(tamper), digest);
    let args = move |sig: Vec<u8>| -> Vec<Expr<'static>> {
        vec![
            Expr::int(tally_for),
            Expr::int(tally_against),
            Expr::int(claimed_set_size),
            Expr::bytes(set_root.clone()),
            Expr::bytes(attestation.clone()),
            Expr::bytes(sig),
        ]
    };
    spend_transition(
        &pending,
        "finalizeProposal",
        &args,
        COV_A,
        spent_daa_score,
        1_500,
        vec![state_output(&next_state, COV_A, 1_500)],
        lock_time,
        Some(&governance_keypair),
    )
}

#[test]
fn prometheus_rule_storage_finalize_proposal_runtime_accepts_accepted_tally() {
    let result = rule_storage_finalize_case(8, 2, 10, 10, true, Tamper::None, PROPOSAL_DAA, 865_000);
    assert!(result.is_ok(), "attested accepting tally must finalize: {:?}", result.err());
}

#[test]
fn prometheus_rule_storage_finalize_proposal_runtime_accepts_rejected_tally() {
    let result = rule_storage_finalize_case(3, 7, 10, 10, false, Tamper::None, PROPOSAL_DAA, 865_000);
    assert!(result.is_ok(), "attested rejecting tally must finalize as rejected: {:?}", result.err());
}

#[test]
fn prometheus_rule_storage_finalize_proposal_runtime_accepts_exact_threshold_tie() {
    // 67 of 100 = 6700 bps: ties at the threshold are accepted (documented in PRM-26).
    let result = rule_storage_finalize_case(67, 33, 100, 100, true, Tamper::None, PROPOSAL_DAA, 865_000);
    assert!(result.is_ok(), "approval exactly at 6700 bps must accept: {:?}", result.err());
}

#[test]
fn prometheus_rule_storage_finalize_proposal_runtime_zero_vote_tally_is_terminal_rejection() {
    // Review finding 3: an attested zero-participation tally ends REJECTED instead of leaving the slot PENDING.
    let result = rule_storage_finalize_case(0, 0, 10, 10, false, Tamper::None, PROPOSAL_DAA, 865_000);
    assert!(result.is_ok(), "attested zero-vote tally must finalize as REJECTED: {:?}", result.err());
    let err = rule_storage_finalize_case(0, 0, 10, 10, true, Tamper::None, PROPOSAL_DAA, 865_000).expect_err("zero votes must not accept");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_rule_storage_finalize_proposal_runtime_low_participation_is_terminal_rejection() {
    // PRM-18: one approving vote out of ten active validators is not a quorum; the tally is terminal.
    let result = rule_storage_finalize_case(1, 0, 10, 10, false, Tamper::None, PROPOSAL_DAA, 865_000);
    assert!(result.is_ok(), "low participation must finalize as REJECTED: {:?}", result.err());
    let err = rule_storage_finalize_case(1, 0, 10, 10, true, Tamper::None, PROPOSAL_DAA, 865_000).expect_err("participation below 50% must not accept");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_rule_storage_finalize_proposal_runtime_rejects_unattested_rejection() {
    // The rejection path is authenticated: a zero tally without the governance attestation fails.
    let err = rule_storage_finalize_case(0, 0, 10, 10, false, Tamper::Attestor, PROPOSAL_DAA, 865_000).expect_err("forged rejection must fail");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_rule_storage_finalize_proposal_runtime_rejects_early_rejection() {
    let err = rule_storage_finalize_case(0, 0, 10, 10, false, Tamper::None, PROPOSAL_DAA, 864_999).expect_err("early rejection must fail");
    assert_lock_time_error(err);
}

#[test]
fn prometheus_rule_storage_finalize_proposal_runtime_rejects_tampered_set_size() {
    // The set size is not part of the transaction outputs; the attestation must bind it.
    let err = rule_storage_finalize_case(2, 0, 10, 4, true, Tamper::None, PROPOSAL_DAA, 865_000).expect_err("tampered set size must fail");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_rule_storage_finalize_proposal_runtime_rejects_cross_instance_tally() {
    let err = rule_storage_finalize_case(8, 2, 10, 10, true, Tamper::Instance, PROPOSAL_DAA, 865_000).expect_err("tally of another deployment must fail");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_rule_storage_finalize_proposal_runtime_rejects_replayed_tally() {
    let err = rule_storage_finalize_case(8, 2, 10, 10, true, Tamper::Nonce, PROPOSAL_DAA, 865_000).expect_err("tally of the previous proposal must fail");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_rule_storage_finalize_proposal_runtime_rejects_tally_for_other_content() {
    let err = rule_storage_finalize_case(8, 2, 10, 10, true, Tamper::Content, PROPOSAL_DAA, 865_000).expect_err("tally for other rule content must fail");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_rule_storage_finalize_proposal_runtime_rejects_tally_for_other_session() {
    let err = rule_storage_finalize_case(8, 2, 10, 10, true, Tamper::Session, PROPOSAL_DAA, 865_000).expect_err("tally for another voting session must fail");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_rule_storage_finalize_proposal_runtime_rejects_before_voting_end() {
    let err = rule_storage_finalize_case(8, 2, 10, 10, true, Tamper::None, PROPOSAL_DAA, 864_999).expect_err("early finalize must fail");
    assert_lock_time_error(err);
}

#[test]
fn prometheus_rule_storage_finalize_proposal_runtime_rejects_old_start_height() {
    // Review finding 2: the proposal was accepted at DAA 500,000. A lock time that would satisfy an old
    // caller-selected start (1,000) no longer finalizes; the window runs from the consensus submission time.
    let err = rule_storage_finalize_case(8, 2, 10, 10, true, Tamper::None, 500_000, 865_000).expect_err("old start height must fail");
    assert_lock_time_error(err);
    let result = rule_storage_finalize_case(8, 2, 10, 10, true, Tamper::None, 500_000, 1_364_000);
    assert!(result.is_ok(), "finalize after the consensus window must pass: {:?}", result.err());
}

#[test]
fn prometheus_rule_storage_finalize_proposal_runtime_rejects_unaccepted_input() {
    let err = rule_storage_finalize_case(8, 2, 10, 10, true, Tamper::None, UNACCEPTED_DAA, 865_000).expect_err("unaccepted covenant input must fail");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_rule_storage_deactivate_rule_runtime_accepts_active_accepted_rule() {
    let contract_path = std::env::var("PROMETHEUS_RULE_STORAGE_STATE_CONTRACT")
        .expect("PROMETHEUS_RULE_STORAGE_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus rule storage contract fixture");
    let governance_keypair = keypair_from_seed(8);
    let governance_pk = governance_keypair.x_only_public_key().0.serialize().to_vec();
    let guardian_pk = keypair_from_seed(9).x_only_public_key().0.serialize().to_vec();
    let threat_hash = vec![3u8; 32];
    let rule_cid = cid36(4);

    let accepted = compile_rule_storage_state(
        &source,
        rule_storage_state_args(governance_pk.clone(), 2, 1, guardian_pk.clone(), threat_hash.clone(), 0, rule_cid.clone(), 9_000, 1_000, 2, 0, 865_000, 2, 1, 1, 0, 10_000, 865_000, true, 1),
    );
    let inactive = compile_rule_storage_state(
        &source,
        rule_storage_state_args(governance_pk, 2, 1, guardian_pk, threat_hash, 0, rule_cid, 9_000, 1_000, 2, 0, 865_000, 2, 1, 1, 0, 10_000, 865_000, false, 1),
    );

    let placeholder_sigscript = rule_storage_state_entry_sigscript(
        &accepted,
        "deactivateRule",
        vec![Expr::bytes(dummy_signature())],
    );
    let outputs = vec![covenant_output(&inactive, 0, COV_A)];
    let entries = vec![covenant_utxo(&accepted, COV_A)];
    let mut tx = Transaction::new(
        1,
        vec![tx_input_with_sigops(0, placeholder_sigscript, 1)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    let sig = sign_tx_input(&tx, &entries, 0, &governance_keypair);
    tx.inputs[0].signature_script = rule_storage_state_entry_sigscript(
        &accepted,
        "deactivateRule",
        vec![Expr::bytes(sig)],
    );

    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(
        result.is_ok(),
        "RuleStorage deactivateRule runtime should accept active accepted rule transition: {:?}",
        result.err()
    );
}

#[test]
fn prometheus_rule_storage_deactivate_rule_runtime_rejects_pending_rule() {
    let contract_path = std::env::var("PROMETHEUS_RULE_STORAGE_STATE_CONTRACT")
        .expect("PROMETHEUS_RULE_STORAGE_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus rule storage contract fixture");
    let governance_keypair = keypair_from_seed(8);
    let governance_pk = governance_keypair.x_only_public_key().0.serialize().to_vec();
    let guardian_pk = keypair_from_seed(9).x_only_public_key().0.serialize().to_vec();
    let threat_hash = vec![3u8; 32];
    let rule_cid = cid36(4);

    let pending = compile_rule_storage_state(
        &source,
        rule_storage_state_args(governance_pk.clone(), 2, 1, guardian_pk.clone(), threat_hash.clone(), 0, rule_cid.clone(), 9_000, 1_000, 2, 0, 865_000, 1, 0, 1, 0, 0, 0, false, 0),
    );
    let invalid_next = compile_rule_storage_state(
        &source,
        rule_storage_state_args(governance_pk, 2, 1, guardian_pk, threat_hash, 0, rule_cid, 9_000, 1_000, 2, 0, 865_000, 1, 0, 1, 0, 0, 0, false, 0),
    );

    let placeholder_sigscript = rule_storage_state_entry_sigscript(
        &pending,
        "deactivateRule",
        vec![Expr::bytes(dummy_signature())],
    );
    let outputs = vec![covenant_output(&invalid_next, 0, COV_A)];
    let entries = vec![covenant_utxo(&pending, COV_A)];
    let mut tx = Transaction::new(
        1,
        vec![tx_input_with_sigops(0, placeholder_sigscript, 1)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    let sig = sign_tx_input(&tx, &entries, 0, &governance_keypair);
    tx.inputs[0].signature_script = rule_storage_state_entry_sigscript(
        &pending,
        "deactivateRule",
        vec![Expr::bytes(sig)],
    );

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("deactivateRule must reject pending/non-accepted rule state");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_guardian_reputation_register_runtime_accepts_valid_transition() {
    let contract_path = std::env::var("PROMETHEUS_GUARDIAN_STATE_CONTRACT")
        .expect("PROMETHEUS_GUARDIAN_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus guardian reputation contract fixture");
    let guardian_keypair = keypair_from_seed(9);
    let guardian_pk = guardian_keypair.x_only_public_key().0.serialize().to_vec();
    let governance_pk = keypair_from_seed(8).x_only_public_key().0.serialize().to_vec();

    let unregistered = compile_guardian_state(
        &source,
        guardian_state_args(guardian_pk.clone(), governance_pk.clone(), 0, 0, 0, 0, 0, 1),
    );
    let registered = compile_guardian_state(
        &source,
        guardian_state_args(guardian_pk, governance_pk, 500, 1_000, 0, 0, 1_000, 0),
    );

    let placeholder_sigscript = guardian_state_entry_sigscript(
        &unregistered,
        "register",
        vec![Expr::int(500), Expr::int(1_000), Expr::bytes(dummy_signature())],
    );
    let outputs = vec![covenant_output(&registered, 0, COV_A)];
    let entries = vec![covenant_utxo(&unregistered, COV_A)];
    let mut tx = Transaction::new(
        1,
        vec![tx_input_with_sigops(0, placeholder_sigscript, 1)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    let sig = sign_tx_input(&tx, &entries, 0, &guardian_keypair);
    tx.inputs[0].signature_script = guardian_state_entry_sigscript(
        &unregistered,
        "register",
        vec![Expr::int(500), Expr::int(1_000), Expr::bytes(sig)],
    );

    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(
        result.is_ok(),
        "Guardian register runtime should accept valid guardian signature/state transition: {:?}",
        result.err()
    );
}

#[test]
fn prometheus_guardian_reputation_register_runtime_rejects_low_compute_power() {
    let contract_path = std::env::var("PROMETHEUS_GUARDIAN_STATE_CONTRACT")
        .expect("PROMETHEUS_GUARDIAN_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus guardian reputation contract fixture");
    let guardian_keypair = keypair_from_seed(9);
    let guardian_pk = guardian_keypair.x_only_public_key().0.serialize().to_vec();
    let governance_pk = keypair_from_seed(8).x_only_public_key().0.serialize().to_vec();

    let unregistered = compile_guardian_state(
        &source,
        guardian_state_args(guardian_pk.clone(), governance_pk.clone(), 0, 0, 0, 0, 0, 1),
    );
    let low_compute_state = compile_guardian_state(
        &source,
        guardian_state_args(guardian_pk, governance_pk, 99, 1_000, 0, 0, 1_000, 1),
    );

    let placeholder_sigscript = guardian_state_entry_sigscript(
        &unregistered,
        "register",
        vec![Expr::int(99), Expr::int(1_000), Expr::bytes(dummy_signature())],
    );
    let outputs = vec![covenant_output(&low_compute_state, 0, COV_A)];
    let entries = vec![covenant_utxo(&unregistered, COV_A)];
    let mut tx = Transaction::new(
        1,
        vec![tx_input_with_sigops(0, placeholder_sigscript, 1)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    let sig = sign_tx_input(&tx, &entries, 0, &guardian_keypair);
    tx.inputs[0].signature_script = guardian_state_entry_sigscript(
        &unregistered,
        "register",
        vec![Expr::int(99), Expr::int(1_000), Expr::bytes(sig)],
    );

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("Guardian register must reject compute below minimum");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_guardian_reputation_proposal_accepted_runtime_accepts_valid_transition() {
    let contract_path = std::env::var("PROMETHEUS_GUARDIAN_STATE_CONTRACT")
        .expect("PROMETHEUS_GUARDIAN_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus guardian reputation contract fixture");
    let guardian_pk = keypair_from_seed(9).x_only_public_key().0.serialize().to_vec();
    let governance_keypair = keypair_from_seed(8);
    let governance_pk = governance_keypair.x_only_public_key().0.serialize().to_vec();

    let registered = compile_guardian_state(
        &source,
        guardian_state_args(guardian_pk.clone(), governance_pk.clone(), 500, 1_000, 0, 0, 1_000, 0),
    );
    let accepted = compile_guardian_state(
        &source,
        guardian_state_args(guardian_pk, governance_pk, 500, 3_200, 0, 1, 1_000, 0),
    );

    let placeholder_sigscript = guardian_state_entry_sigscript(
        &registered,
        "proposalAccepted",
        vec![Expr::bytes(dummy_signature())],
    );
    let outputs = vec![covenant_output(&accepted, 0, COV_A)];
    let entries = vec![covenant_utxo(&registered, COV_A)];
    let mut tx = Transaction::new(
        1,
        vec![tx_input_with_sigops(0, placeholder_sigscript, 1)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    let sig = sign_tx_input(&tx, &entries, 0, &governance_keypair);
    tx.inputs[0].signature_script = guardian_state_entry_sigscript(
        &registered,
        "proposalAccepted",
        vec![Expr::bytes(sig)],
    );

    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(
        result.is_ok(),
        "Guardian proposalAccepted runtime should accept valid governance signature/state transition: {:?}",
        result.err()
    );
}

#[test]
fn prometheus_guardian_reputation_proposal_accepted_runtime_caps_reputation() {
    let contract_path = std::env::var("PROMETHEUS_GUARDIAN_STATE_CONTRACT")
        .expect("PROMETHEUS_GUARDIAN_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus guardian reputation contract fixture");
    let guardian_pk = keypair_from_seed(9).x_only_public_key().0.serialize().to_vec();
    let governance_keypair = keypair_from_seed(8);
    let governance_pk = governance_keypair.x_only_public_key().0.serialize().to_vec();

    let registered = compile_guardian_state(
        &source,
        guardian_state_args(guardian_pk.clone(), governance_pk.clone(), 500, 99_000, 0, 0, 1_000, 0),
    );
    let capped = compile_guardian_state(
        &source,
        guardian_state_args(guardian_pk, governance_pk, 500, 100_000, 0, 1, 1_000, 0),
    );

    let placeholder_sigscript = guardian_state_entry_sigscript(
        &registered,
        "proposalAccepted",
        vec![Expr::bytes(dummy_signature())],
    );
    let outputs = vec![covenant_output(&capped, 0, COV_A)];
    let entries = vec![covenant_utxo(&registered, COV_A)];
    let mut tx = Transaction::new(
        1,
        vec![tx_input_with_sigops(0, placeholder_sigscript, 1)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    let sig = sign_tx_input(&tx, &entries, 0, &governance_keypair);
    tx.inputs[0].signature_script = guardian_state_entry_sigscript(
        &registered,
        "proposalAccepted",
        vec![Expr::bytes(sig)],
    );

    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(
        result.is_ok(),
        "Guardian proposalAccepted runtime should cap reputation at REPUTATION_MAX: {:?}",
        result.err()
    );
}

#[test]
fn prometheus_guardian_reputation_proposal_rejected_runtime_accepts_valid_transition() {
    let contract_path = std::env::var("PROMETHEUS_GUARDIAN_STATE_CONTRACT")
        .expect("PROMETHEUS_GUARDIAN_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus guardian reputation contract fixture");
    let guardian_pk = keypair_from_seed(9).x_only_public_key().0.serialize().to_vec();
    let governance_keypair = keypair_from_seed(8);
    let governance_pk = governance_keypair.x_only_public_key().0.serialize().to_vec();

    let registered = compile_guardian_state(
        &source,
        guardian_state_args(guardian_pk.clone(), governance_pk.clone(), 500, 3_000, 0, 1, 1_000, 0),
    );
    let rejected = compile_guardian_state(
        &source,
        guardian_state_args(guardian_pk, governance_pk, 500, 1_500, 0, 1, 1_000, 0),
    );

    let placeholder_sigscript = guardian_state_entry_sigscript(
        &registered,
        "proposalRejected",
        vec![Expr::bytes(dummy_signature())],
    );
    let outputs = vec![covenant_output(&rejected, 0, COV_A)];
    let entries = vec![covenant_utxo(&registered, COV_A)];
    let mut tx = Transaction::new(
        1,
        vec![tx_input_with_sigops(0, placeholder_sigscript, 1)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    let sig = sign_tx_input(&tx, &entries, 0, &governance_keypair);
    tx.inputs[0].signature_script = guardian_state_entry_sigscript(
        &registered,
        "proposalRejected",
        vec![Expr::bytes(sig)],
    );

    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(
        result.is_ok(),
        "Guardian proposalRejected runtime should accept valid governance signature/state transition: {:?}",
        result.err()
    );
}

#[test]
fn prometheus_guardian_reputation_proposal_rejected_runtime_rejects_unregistered_state() {
    let contract_path = std::env::var("PROMETHEUS_GUARDIAN_STATE_CONTRACT")
        .expect("PROMETHEUS_GUARDIAN_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus guardian reputation contract fixture");
    let guardian_pk = keypair_from_seed(9).x_only_public_key().0.serialize().to_vec();
    let governance_keypair = keypair_from_seed(8);
    let governance_pk = governance_keypair.x_only_public_key().0.serialize().to_vec();

    let unregistered = compile_guardian_state(
        &source,
        guardian_state_args(guardian_pk.clone(), governance_pk.clone(), 0, 0, 0, 0, 0, 1),
    );
    let invalid_next = compile_guardian_state(
        &source,
        guardian_state_args(guardian_pk, governance_pk, 0, 0, 0, 0, 0, 1),
    );

    let placeholder_sigscript = guardian_state_entry_sigscript(
        &unregistered,
        "proposalRejected",
        vec![Expr::bytes(dummy_signature())],
    );
    let outputs = vec![covenant_output(&invalid_next, 0, COV_A)];
    let entries = vec![covenant_utxo(&unregistered, COV_A)];
    let mut tx = Transaction::new(
        1,
        vec![tx_input_with_sigops(0, placeholder_sigscript, 1)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    let sig = sign_tx_input(&tx, &entries, 0, &governance_keypair);
    tx.inputs[0].signature_script = guardian_state_entry_sigscript(
        &unregistered,
        "proposalRejected",
        vec![Expr::bytes(sig)],
    );

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("proposalRejected must reject unregistered guardian state");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_validator_state_commit_vote_runtime_accepts_valid_transition() {
    let contract_path = std::env::var("PROMETHEUS_VALIDATOR_STATE_CONTRACT")
        .expect("PROMETHEUS_VALIDATOR_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus validator state contract fixture");
    let keypair = keypair_from_seed(7);
    let validator_pk = keypair.x_only_public_key().0.serialize().to_vec();
    let commitment = hex32("cda9cc6bb51d36be5db27eb6e86bfc6b6173d5918f24f81939af5411bff90ffb");

    let active = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk.clone(),
            20_000,
            true,
            1_000,
            10_000,
            0,
            0,
            zero32(),
            0,
            0,
            0,
        ),
    );
    let committed = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk,
            20_000,
            true,
            1_000,
            10_000,
            0,
            0,
            commitment.clone(),
            2_000,
            42,
            0,
        ),
    );

    let placeholder_sigscript = validator_state_entry_sigscript(
        &active,
        "commitVote",
        vec![Expr::bytes(commitment.clone()), Expr::int(2_000), Expr::int(42), Expr::bytes(dummy_signature())],
    );
    let outputs = vec![valued_covenant_output(&committed, kas(20_000))];
    let entries = vec![valued_covenant_utxo(&active, kas(20_000))];
    let mut tx = Transaction::new(
        1,
        vec![tx_input_with_sigops(0, placeholder_sigscript, 1)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    let sig = sign_tx_input(&tx, &entries, 0, &keypair);
    tx.inputs[0].signature_script = validator_state_entry_sigscript(
        &active,
        "commitVote",
        vec![Expr::bytes(commitment), Expr::int(2_000), Expr::int(42), Expr::bytes(sig)],
    );

    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(
        result.is_ok(),
        "commitVote runtime should accept valid bond/signature/state transition: {:?}",
        result.err()
    );
}

#[test]
fn prometheus_validator_state_commit_vote_runtime_rejects_low_bond() {
    let contract_path = std::env::var("PROMETHEUS_VALIDATOR_STATE_CONTRACT")
        .expect("PROMETHEUS_VALIDATOR_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus validator state contract fixture");
    let keypair = keypair_from_seed(7);
    let validator_pk = keypair.x_only_public_key().0.serialize().to_vec();
    let commitment = hex32("cda9cc6bb51d36be5db27eb6e86bfc6b6173d5918f24f81939af5411bff90ffb");

    let active = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk.clone(),
            20_000,
            true,
            1_000,
            10_000,
            0,
            0,
            zero32(),
            0,
            0,
            0,
        ),
    );
    let low_bond_state = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk,
            20_000,
            true,
            1_000,
            10_000,
            0,
            0,
            commitment.clone(),
            1_999,
            42,
            0,
        ),
    );

    let placeholder_sigscript = validator_state_entry_sigscript(
        &active,
        "commitVote",
        vec![Expr::bytes(commitment.clone()), Expr::int(1_999), Expr::int(42), Expr::bytes(dummy_signature())],
    );
    let outputs = vec![valued_covenant_output(&low_bond_state, kas(20_000))];
    let entries = vec![valued_covenant_utxo(&active, kas(20_000))];
    let mut tx = Transaction::new(
        1,
        vec![tx_input_with_sigops(0, placeholder_sigscript, 1)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    let sig = sign_tx_input(&tx, &entries, 0, &keypair);
    tx.inputs[0].signature_script = validator_state_entry_sigscript(
        &active,
        "commitVote",
        vec![Expr::bytes(commitment), Expr::int(1_999), Expr::int(42), Expr::bytes(sig)],
    );

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("commitVote must reject bond below 10% of stake");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_validator_state_commit_vote_runtime_rejects_negative_block_height() {
    let contract_path = std::env::var("PROMETHEUS_VALIDATOR_STATE_CONTRACT")
        .expect("PROMETHEUS_VALIDATOR_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus validator state contract fixture");
    let keypair = keypair_from_seed(7);
    let validator_pk = keypair.x_only_public_key().0.serialize().to_vec();
    let commitment = hex32("cda9cc6bb51d36be5db27eb6e86bfc6b6173d5918f24f81939af5411bff90ffb");

    let active = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk.clone(),
            20_000,
            true,
            1_000,
            10_000,
            0,
            0,
            zero32(),
            0,
            0,
            0,
        ),
    );
    let committed = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk,
            20_000,
            true,
            1_000,
            10_000,
            0,
            0,
            commitment.clone(),
            2_000,
            -1,
            0,
        ),
    );

    let placeholder_sigscript = validator_state_entry_sigscript(
        &active,
        "commitVote",
        vec![Expr::bytes(commitment.clone()), Expr::int(2_000), Expr::int(-1), Expr::bytes(dummy_signature())],
    );
    let outputs = vec![valued_covenant_output(&committed, kas(20_000))];
    let entries = vec![valued_covenant_utxo(&active, kas(20_000))];
    let mut tx = Transaction::new(
        1,
        vec![tx_input_with_sigops(0, placeholder_sigscript, 1)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    let sig = sign_tx_input(&tx, &entries, 0, &keypair);
    tx.inputs[0].signature_script = validator_state_entry_sigscript(
        &active,
        "commitVote",
        vec![Expr::bytes(commitment), Expr::int(2_000), Expr::int(-1), Expr::bytes(sig)],
    );

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("commitVote must reject negative block height");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_validator_state_reveal_vote_runtime_accepts_valid_transition() {
    let contract_path = std::env::var("PROMETHEUS_VALIDATOR_STATE_CONTRACT")
        .expect("PROMETHEUS_VALIDATOR_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus validator state contract fixture");
    let keypair = keypair_from_seed(7);
    let validator_pk = keypair.x_only_public_key().0.serialize().to_vec();
    let commitment = hex32("cda9cc6bb51d36be5db27eb6e86bfc6b6173d5918f24f81939af5411bff90ffb");

    let committed = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk.clone(),
            20_000,
            true,
            1_000,
            10_000,
            0,
            0,
            commitment.clone(),
            2_000,
            1_000,
            0,
        ),
    );
    let revealed = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk,
            20_000,
            true,
            1_000,
            10_000,
            0,
            1_200,
            zero32(),
            0,
            0,
            0,
        ),
    );

    let placeholder_sigscript = validator_state_entry_sigscript(
        &committed,
        "revealVote",
        vec![Expr::bool(true), Expr::int(42), Expr::int(1_200), Expr::bytes(dummy_signature())],
    );
    let outputs = vec![valued_covenant_output(&revealed, kas(20_000))];
    let entries = vec![valued_covenant_utxo(&committed, kas(20_000))];
    let mut tx = Transaction::new(
        1,
        vec![tx_input_with_sigops(0, placeholder_sigscript, 1)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    let sig = sign_tx_input(&tx, &entries, 0, &keypair);
    tx.inputs[0].signature_script = validator_state_entry_sigscript(
        &committed,
        "revealVote",
        vec![Expr::bool(true), Expr::int(42), Expr::int(1_200), Expr::bytes(sig)],
    );

    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(
        result.is_ok(),
        "revealVote runtime should accept valid commitment/signature/state transition: {:?}",
        result.err()
    );
}

#[test]
fn prometheus_h001_signed_negative_values_do_not_match_u64_max_vector() {
    let contract_path = std::env::var("PROMETHEUS_H001_CONTRACT").expect("PROMETHEUS_H001_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus H-001 contract fixture");
    let compiled = compile_contract(
        &source,
        &[Expr::bytes(hex32("1d037f75eb96d1ab0615732e2aacdd2a701ecf59fb048987a47cb50a2b483a86"))],
        CompileOptions::default(),
    )
    .expect("H-001 fixture compiles");
    let sigscript = compiled
        .build_sig_script("verify", vec![Expr::bool(false), Expr::int(-1), Expr::int(-1)])
        .expect("H-001 fixture signed negative sigscript builds");

    let err = run_script(compiled.script, sigscript).expect_err("signed negative int values must not be treated as Rust u64::MAX");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_validator_state_reveal_vote_runtime_rejects_negative_salt() {
    let contract_path = std::env::var("PROMETHEUS_VALIDATOR_STATE_CONTRACT")
        .expect("PROMETHEUS_VALIDATOR_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus validator state contract fixture");
    let keypair = keypair_from_seed(7);
    let validator_pk = keypair.x_only_public_key().0.serialize().to_vec();
    let commitment = hex32("bd29bc18736e3c8b3e46ab62781dc96de07ab222102ea8881309dee54cac47ec");

    let committed = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk.clone(),
            20_000,
            true,
            1_000,
            10_000,
            0,
            0,
            commitment,
            2_000,
            1_000,
            0,
        ),
    );
    let revealed = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk,
            20_000,
            true,
            1_000,
            10_000,
            0,
            1_200,
            zero32(),
            0,
            0,
            0,
        ),
    );

    let placeholder_sigscript = validator_state_entry_sigscript(
        &committed,
        "revealVote",
        vec![Expr::bool(true), Expr::int(-1), Expr::int(1_200), Expr::bytes(dummy_signature())],
    );
    let outputs = vec![valued_covenant_output(&revealed, kas(20_000))];
    let entries = vec![valued_covenant_utxo(&committed, kas(20_000))];
    let mut tx = Transaction::new(
        1,
        vec![tx_input_with_sigops(0, placeholder_sigscript, 1)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    let sig = sign_tx_input(&tx, &entries, 0, &keypair);
    tx.inputs[0].signature_script = validator_state_entry_sigscript(
        &committed,
        "revealVote",
        vec![Expr::bool(true), Expr::int(-1), Expr::int(1_200), Expr::bytes(sig)],
    );

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("revealVote must reject negative salt values");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_validator_state_reveal_vote_runtime_rejects_wrong_salt() {
    let contract_path = std::env::var("PROMETHEUS_VALIDATOR_STATE_CONTRACT")
        .expect("PROMETHEUS_VALIDATOR_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus validator state contract fixture");
    let keypair = keypair_from_seed(7);
    let validator_pk = keypair.x_only_public_key().0.serialize().to_vec();
    let commitment = hex32("cda9cc6bb51d36be5db27eb6e86bfc6b6173d5918f24f81939af5411bff90ffb");

    let committed = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk.clone(),
            20_000,
            true,
            1_000,
            10_000,
            0,
            0,
            commitment,
            2_000,
            1_000,
            0,
        ),
    );
    let revealed = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk,
            20_000,
            true,
            1_000,
            10_000,
            0,
            1_200,
            zero32(),
            0,
            0,
            0,
        ),
    );

    let placeholder_sigscript = validator_state_entry_sigscript(
        &committed,
        "revealVote",
        vec![Expr::bool(true), Expr::int(43), Expr::int(1_200), Expr::bytes(dummy_signature())],
    );
    let outputs = vec![valued_covenant_output(&revealed, kas(20_000))];
    let entries = vec![valued_covenant_utxo(&committed, kas(20_000))];
    let mut tx = Transaction::new(
        1,
        vec![tx_input_with_sigops(0, placeholder_sigscript, 1)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    let sig = sign_tx_input(&tx, &entries, 0, &keypair);
    tx.inputs[0].signature_script = validator_state_entry_sigscript(
        &committed,
        "revealVote",
        vec![Expr::bool(true), Expr::int(43), Expr::int(1_200), Expr::bytes(sig)],
    );

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("revealVote must reject a salt that does not match the commitment");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_validator_state_slash_invalid_reveal_runtime_accepts_invalid_reveal() {
    let contract_path = std::env::var("PROMETHEUS_VALIDATOR_STATE_CONTRACT")
        .expect("PROMETHEUS_VALIDATOR_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus validator state contract fixture");
    let keypair = keypair_from_seed(7);
    let validator_pk = keypair.x_only_public_key().0.serialize().to_vec();
    let commitment = hex32("cda9cc6bb51d36be5db27eb6e86bfc6b6173d5918f24f81939af5411bff90ffb");

    let committed = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk.clone(),
            20_000,
            true,
            1_000,
            10_000,
            0,
            0,
            commitment,
            2_000,
            1_000,
            0,
        ),
    );
    let slashed = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk,
            18_000,
            true,
            1_000,
            10_000,
            1,
            0,
            zero32(),
            0,
            0,
            0,
        ),
    );

    let placeholder_sigscript = validator_state_entry_sigscript(
        &committed,
        "slashInvalidReveal",
        vec![Expr::bool(true), Expr::int(43), Expr::bytes(dummy_signature())],
    );
    let outputs = vec![valued_covenant_output(&slashed, kas(18_000)), burn_output(kas(2000))];
    let entries = vec![valued_covenant_utxo(&committed, kas(20_000))];
    let mut tx = Transaction::new(
        1,
        vec![tx_input_with_sigops(0, placeholder_sigscript, 1)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    let sig = sign_tx_input(&tx, &entries, 0, &keypair);
    tx.inputs[0].signature_script = validator_state_entry_sigscript(
        &committed,
        "slashInvalidReveal",
        vec![Expr::bool(true), Expr::int(43), Expr::bytes(sig)],
    );

    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(
        result.is_ok(),
        "slashInvalidReveal runtime should accept invalid reveal slash transition: {:?}",
        result.err()
    );
}

#[test]
fn prometheus_validator_state_slash_invalid_reveal_runtime_rejects_valid_reveal() {
    let contract_path = std::env::var("PROMETHEUS_VALIDATOR_STATE_CONTRACT")
        .expect("PROMETHEUS_VALIDATOR_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus validator state contract fixture");
    let keypair = keypair_from_seed(7);
    let validator_pk = keypair.x_only_public_key().0.serialize().to_vec();
    let commitment = hex32("cda9cc6bb51d36be5db27eb6e86bfc6b6173d5918f24f81939af5411bff90ffb");

    let committed = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk.clone(),
            20_000,
            true,
            1_000,
            10_000,
            0,
            0,
            commitment,
            2_000,
            1_000,
            0,
        ),
    );
    let slashed = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk,
            18_000,
            true,
            1_000,
            10_000,
            1,
            0,
            zero32(),
            0,
            0,
            0,
        ),
    );

    let placeholder_sigscript = validator_state_entry_sigscript(
        &committed,
        "slashInvalidReveal",
        vec![Expr::bool(true), Expr::int(42), Expr::bytes(dummy_signature())],
    );
    let outputs = vec![valued_covenant_output(&slashed, kas(18_000)), burn_output(kas(2000))];
    let entries = vec![valued_covenant_utxo(&committed, kas(20_000))];
    let mut tx = Transaction::new(
        1,
        vec![tx_input_with_sigops(0, placeholder_sigscript, 1)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    let sig = sign_tx_input(&tx, &entries, 0, &keypair);
    tx.inputs[0].signature_script = validator_state_entry_sigscript(
        &committed,
        "slashInvalidReveal",
        vec![Expr::bool(true), Expr::int(42), Expr::bytes(sig)],
    );

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("slashInvalidReveal must reject a reveal that matches the commitment");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_validator_state_request_withdraw_runtime_accepts_active_uncommitted_validator() {
    let contract_path = std::env::var("PROMETHEUS_VALIDATOR_STATE_CONTRACT")
        .expect("PROMETHEUS_VALIDATOR_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus validator state contract fixture");
    let keypair = keypair_from_seed(7);
    let validator_pk = keypair.x_only_public_key().0.serialize().to_vec();

    let active = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk.clone(),
            20_000,
            true,
            1_000,
            10_000,
            0,
            1_200,
            zero32(),
            0,
            0,
            0,
        ),
    );
    let withdrawal_requested = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk,
            20_000,
            false,
            1_000,
            10_000,
            0,
            1_200,
            zero32(),
            0,
            0,
            2_000,
        ),
    );

    let placeholder_sigscript = validator_state_entry_sigscript(
        &active,
        "requestWithdraw",
        vec![Expr::int(2_000), Expr::bytes(dummy_signature())],
    );
    let outputs = vec![valued_covenant_output(&withdrawal_requested, kas(20_000))];
    let entries = vec![valued_covenant_utxo(&active, kas(20_000))];
    let mut tx = Transaction::new(
        1,
        vec![tx_input_with_sigops(0, placeholder_sigscript, 1)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    let sig = sign_tx_input(&tx, &entries, 0, &keypair);
    tx.inputs[0].signature_script = validator_state_entry_sigscript(
        &active,
        "requestWithdraw",
        vec![Expr::int(2_000), Expr::bytes(sig)],
    );

    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(
        result.is_ok(),
        "requestWithdraw runtime should accept active uncommitted validator transition: {:?}",
        result.err()
    );
}

#[test]
fn prometheus_validator_state_request_withdraw_runtime_rejects_open_commitment() {
    let contract_path = std::env::var("PROMETHEUS_VALIDATOR_STATE_CONTRACT")
        .expect("PROMETHEUS_VALIDATOR_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus validator state contract fixture");
    let keypair = keypair_from_seed(7);
    let validator_pk = keypair.x_only_public_key().0.serialize().to_vec();
    let commitment = hex32("cda9cc6bb51d36be5db27eb6e86bfc6b6173d5918f24f81939af5411bff90ffb");

    let committed = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk.clone(),
            20_000,
            true,
            1_000,
            10_000,
            0,
            1_200,
            commitment.clone(),
            2_000,
            1_000,
            0,
        ),
    );
    let withdrawal_requested = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk,
            20_000,
            false,
            1_000,
            10_000,
            0,
            1_200,
            commitment,
            2_000,
            1_000,
            2_000,
        ),
    );

    let placeholder_sigscript = validator_state_entry_sigscript(
        &committed,
        "requestWithdraw",
        vec![Expr::int(2_000), Expr::bytes(dummy_signature())],
    );
    let outputs = vec![valued_covenant_output(&withdrawal_requested, kas(20_000))];
    let entries = vec![valued_covenant_utxo(&committed, kas(20_000))];
    let mut tx = Transaction::new(
        1,
        vec![tx_input_with_sigops(0, placeholder_sigscript, 1)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    let sig = sign_tx_input(&tx, &entries, 0, &keypair);
    tx.inputs[0].signature_script = validator_state_entry_sigscript(
        &committed,
        "requestWithdraw",
        vec![Expr::int(2_000), Expr::bytes(sig)],
    );

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("requestWithdraw must reject while a vote commitment is open");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_validator_state_complete_withdraw_runtime_accepts_after_cooldown() {
    let contract_path = std::env::var("PROMETHEUS_VALIDATOR_STATE_CONTRACT")
        .expect("PROMETHEUS_VALIDATOR_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus validator state contract fixture");
    let keypair = keypair_from_seed(7);
    let validator_pk = keypair.x_only_public_key().0.serialize().to_vec();

    let withdrawal_requested = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk,
            20_000,
            false,
            1_000,
            10_000,
            0,
            1_200,
            zero32(),
            0,
            0,
            2_000,
        ),
    );

    let placeholder_sigscript = validator_state_entry_sigscript(
        &withdrawal_requested,
        "completeWithdraw",
        vec![Vec::<Expr>::new().into(), Expr::bytes(dummy_signature())],
    );
    let outputs = vec![];
    let entries = vec![valued_covenant_utxo(&withdrawal_requested, kas(20_000))];
    let mut tx = Transaction::new(
        1,
        vec![tx_input_with_sigops(0, placeholder_sigscript, 1)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    tx.inputs[0].sequence = 6_048_000;
    let sig = sign_tx_input(&tx, &entries, 0, &keypair);
    tx.inputs[0].signature_script = validator_state_entry_sigscript(
        &withdrawal_requested,
        "completeWithdraw",
        vec![Vec::<Expr>::new().into(), Expr::bytes(sig)],
    );

    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(
        result.is_ok(),
        "completeWithdraw runtime should accept zero-output termination after cooldown: {:?}",
        result.err()
    );
}

#[test]
fn prometheus_validator_state_complete_withdraw_runtime_rejects_before_cooldown() {
    let contract_path = std::env::var("PROMETHEUS_VALIDATOR_STATE_CONTRACT")
        .expect("PROMETHEUS_VALIDATOR_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus validator state contract fixture");
    let keypair = keypair_from_seed(7);
    let validator_pk = keypair.x_only_public_key().0.serialize().to_vec();

    let withdrawal_requested = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk,
            20_000,
            false,
            1_000,
            10_000,
            0,
            1_200,
            zero32(),
            0,
            0,
            2_000,
        ),
    );

    let placeholder_sigscript = validator_state_entry_sigscript(
        &withdrawal_requested,
        "completeWithdraw",
        vec![Vec::<Expr>::new().into(), Expr::bytes(dummy_signature())],
    );
    let outputs = vec![];
    let entries = vec![valued_covenant_utxo(&withdrawal_requested, kas(20_000))];
    let mut tx = Transaction::new(
        1,
        vec![tx_input_with_sigops(0, placeholder_sigscript, 1)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    tx.inputs[0].sequence = 6_047_999;
    let sig = sign_tx_input(&tx, &entries, 0, &keypair);
    tx.inputs[0].signature_script = validator_state_entry_sigscript(
        &withdrawal_requested,
        "completeWithdraw",
        vec![Vec::<Expr>::new().into(), Expr::bytes(sig)],
    );

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("completeWithdraw must reject before cooldown expires");
    assert!(matches!(err, kaspa_txscript_errors::TxScriptError::UnsatisfiedLockTime(_)), "expected relative-lock failure, got {err:?}");
}

#[test]
fn prometheus_validator_state_complete_withdraw_runtime_rejects_disabled_sequence_lock() {
    let contract_path = std::env::var("PROMETHEUS_VALIDATOR_STATE_CONTRACT")
        .expect("PROMETHEUS_VALIDATOR_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus validator state contract fixture");
    let keypair = keypair_from_seed(7);
    let validator_pk = keypair.x_only_public_key().0.serialize().to_vec();
    let withdrawal_requested = compile_validator_state(
        &source,
        validator_state_args(validator_pk, 20_000, false, 1_000, 10_000, 0, 1_200, zero32(), 0, 0, 2_000),
    );
    let placeholder_sigscript = validator_state_entry_sigscript(
        &withdrawal_requested,
        "completeWithdraw",
        vec![Vec::<Expr>::new().into(), Expr::bytes(dummy_signature())],
    );
    let entries = vec![valued_covenant_utxo(&withdrawal_requested, kas(20_000))];
    let mut tx = Transaction::new(
        1,
        vec![tx_input_with_sigops(0, placeholder_sigscript, 1)],
        vec![],
        0,
        Default::default(),
        0,
        vec![],
    );
    // Relative lock disabled (bit 63) even though the masked value is large enough.
    tx.inputs[0].sequence = (1u64 << 63) | 6_048_000;
    let sig = sign_tx_input(&tx, &entries, 0, &keypair);
    tx.inputs[0].signature_script = validator_state_entry_sigscript(
        &withdrawal_requested,
        "completeWithdraw",
        vec![Vec::<Expr>::new().into(), Expr::bytes(sig)],
    );
    let err = execute_input_with_covenants(tx, entries, 0)
        .expect_err("completeWithdraw must reject a disabled relative lock");
    assert!(matches!(err, kaspa_txscript_errors::TxScriptError::UnsatisfiedLockTime(_)), "expected relative-lock failure, got {err:?}");
}

#[test]
fn prometheus_validator_state_request_withdraw_runtime_accepts_inactive_slashed_validator() {
    // PRM-13: a validator slashed below MIN_STAKE (active = false, no withdrawal
    // requested) must still be able to start the cooldown instead of being locked.
    let contract_path = std::env::var("PROMETHEUS_VALIDATOR_STATE_CONTRACT")
        .expect("PROMETHEUS_VALIDATOR_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus validator state contract fixture");
    let keypair = keypair_from_seed(7);
    let validator_pk = keypair.x_only_public_key().0.serialize().to_vec();
    let slashed_inactive = compile_validator_state(
        &source,
        validator_state_args(validator_pk.clone(), 8_000, false, 1_000, 10_000, 1, 1_200, zero32(), 0, 0, 0),
    );
    let withdrawal_requested = compile_validator_state(
        &source,
        validator_state_args(validator_pk, 8_000, false, 1_000, 10_000, 1, 1_200, zero32(), 0, 0, 3_000),
    );
    let placeholder_sigscript = validator_state_entry_sigscript(
        &slashed_inactive,
        "requestWithdraw",
        vec![Expr::int(3_000), Expr::bytes(dummy_signature())],
    );
    let outputs = vec![valued_covenant_output(&withdrawal_requested, kas(8_000))];
    let entries = vec![valued_covenant_utxo(&slashed_inactive, kas(8_000))];
    let mut tx = Transaction::new(
        1,
        vec![tx_input_with_sigops(0, placeholder_sigscript, 1)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    let sig = sign_tx_input(&tx, &entries, 0, &keypair);
    tx.inputs[0].signature_script = validator_state_entry_sigscript(
        &slashed_inactive,
        "requestWithdraw",
        vec![Expr::int(3_000), Expr::bytes(sig)],
    );
    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(result.is_ok(), "requestWithdraw must open an exit for an inactive slashed validator: {:?}", result.err());
}

#[test]
fn prometheus_validator_state_request_withdraw_runtime_rejects_zero_marker() {
    let contract_path = std::env::var("PROMETHEUS_VALIDATOR_STATE_CONTRACT")
        .expect("PROMETHEUS_VALIDATOR_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus validator state contract fixture");
    let keypair = keypair_from_seed(7);
    let validator_pk = keypair.x_only_public_key().0.serialize().to_vec();
    let active = compile_validator_state(
        &source,
        validator_state_args(validator_pk.clone(), 20_000, true, 1_000, 10_000, 0, 1_200, zero32(), 0, 0, 0),
    );
    // A zero marker would create an unreachable state (inactive without a request).
    let bricked = compile_validator_state(
        &source,
        validator_state_args(validator_pk, 20_000, false, 1_000, 10_000, 0, 1_200, zero32(), 0, 0, 0),
    );
    let placeholder_sigscript =
        validator_state_entry_sigscript(&active, "requestWithdraw", vec![Expr::int(0), Expr::bytes(dummy_signature())]);
    let outputs = vec![valued_covenant_output(&bricked, kas(20_000))];
    let entries = vec![valued_covenant_utxo(&active, kas(20_000))];
    let mut tx = Transaction::new(
        1,
        vec![tx_input_with_sigops(0, placeholder_sigscript, 1)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    let sig = sign_tx_input(&tx, &entries, 0, &keypair);
    tx.inputs[0].signature_script =
        validator_state_entry_sigscript(&active, "requestWithdraw", vec![Expr::int(0), Expr::bytes(sig)]);
    let err = execute_input_with_covenants(tx, entries, 0).expect_err("requestWithdraw must reject a zero marker");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_validator_state_slash_invalid_reveal_runtime_rejects_missing_burn() {
    let contract_path = std::env::var("PROMETHEUS_VALIDATOR_STATE_CONTRACT")
        .expect("PROMETHEUS_VALIDATOR_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus validator state contract fixture");
    let keypair = keypair_from_seed(7);
    let validator_pk = keypair.x_only_public_key().0.serialize().to_vec();
    let commitment = hex32("cda9cc6bb51d36be5db27eb6e86bfc6b6173d5918f24f81939af5411bff90ffb");

    let committed = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk.clone(),
            20_000,
            true,
            1_000,
            10_000,
            0,
            0,
            commitment,
            2_000,
            1_000,
            0,
        ),
    );
    let slashed = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk,
            18_000,
            true,
            1_000,
            10_000,
            1,
            0,
            zero32(),
            0,
            0,
            0,
        ),
    );

    let placeholder_sigscript = validator_state_entry_sigscript(
        &committed,
        "slashInvalidReveal",
        vec![Expr::bool(true), Expr::int(43), Expr::bytes(dummy_signature())],
    );
    let outputs = vec![valued_covenant_output(&slashed, kas(18_000))];
    let entries = vec![valued_covenant_utxo(&committed, kas(20_000))];
    let mut tx = Transaction::new(
        1,
        vec![tx_input_with_sigops(0, placeholder_sigscript, 1)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    let sig = sign_tx_input(&tx, &entries, 0, &keypair);
    tx.inputs[0].signature_script = validator_state_entry_sigscript(
        &committed,
        "slashInvalidReveal",
        vec![Expr::bool(true), Expr::int(43), Expr::bytes(sig)],
    );

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("slashing without a burn output must fail");
    assert!(matches!(err, kaspa_txscript_errors::TxScriptError::InvalidOutputIndex(..)), "expected missing burn output, got {err:?}");
}

#[test]
fn prometheus_validator_state_slash_invalid_reveal_runtime_rejects_burn_to_spendable_script() {
    let contract_path = std::env::var("PROMETHEUS_VALIDATOR_STATE_CONTRACT")
        .expect("PROMETHEUS_VALIDATOR_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus validator state contract fixture");
    let keypair = keypair_from_seed(7);
    let validator_pk = keypair.x_only_public_key().0.serialize().to_vec();
    let commitment = hex32("cda9cc6bb51d36be5db27eb6e86bfc6b6173d5918f24f81939af5411bff90ffb");

    let committed = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk.clone(),
            20_000,
            true,
            1_000,
            10_000,
            0,
            0,
            commitment,
            2_000,
            1_000,
            0,
        ),
    );
    let slashed = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk,
            18_000,
            true,
            1_000,
            10_000,
            1,
            0,
            zero32(),
            0,
            0,
            0,
        ),
    );

    let placeholder_sigscript = validator_state_entry_sigscript(
        &committed,
        "slashInvalidReveal",
        vec![Expr::bool(true), Expr::int(43), Expr::bytes(dummy_signature())],
    );
    let outputs = vec![valued_covenant_output(&slashed, kas(18_000)), TransactionOutput { value: kas(2000), script_public_key: kaspa_txscript::pay_to_script_hash_script(&[0x51]), covenant: None }];
    let entries = vec![valued_covenant_utxo(&committed, kas(20_000))];
    let mut tx = Transaction::new(
        1,
        vec![tx_input_with_sigops(0, placeholder_sigscript, 1)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    let sig = sign_tx_input(&tx, &entries, 0, &keypair);
    tx.inputs[0].signature_script = validator_state_entry_sigscript(
        &committed,
        "slashInvalidReveal",
        vec![Expr::bool(true), Expr::int(43), Expr::bytes(sig)],
    );

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("slashed KAS must not go to a spendable script");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_validator_state_slash_invalid_reveal_runtime_rejects_keeping_slashed_value() {
    let contract_path = std::env::var("PROMETHEUS_VALIDATOR_STATE_CONTRACT")
        .expect("PROMETHEUS_VALIDATOR_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus validator state contract fixture");
    let keypair = keypair_from_seed(7);
    let validator_pk = keypair.x_only_public_key().0.serialize().to_vec();
    let commitment = hex32("cda9cc6bb51d36be5db27eb6e86bfc6b6173d5918f24f81939af5411bff90ffb");

    let committed = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk.clone(),
            20_000,
            true,
            1_000,
            10_000,
            0,
            0,
            commitment,
            2_000,
            1_000,
            0,
        ),
    );
    let slashed = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk,
            18_000,
            true,
            1_000,
            10_000,
            1,
            0,
            zero32(),
            0,
            0,
            0,
        ),
    );

    let placeholder_sigscript = validator_state_entry_sigscript(
        &committed,
        "slashInvalidReveal",
        vec![Expr::bool(true), Expr::int(43), Expr::bytes(dummy_signature())],
    );
    let outputs = vec![valued_covenant_output(&slashed, kas(20_000)), burn_output(0)];
    let entries = vec![valued_covenant_utxo(&committed, kas(20_000))];
    let mut tx = Transaction::new(
        1,
        vec![tx_input_with_sigops(0, placeholder_sigscript, 1)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    let sig = sign_tx_input(&tx, &entries, 0, &keypair);
    tx.inputs[0].signature_script = validator_state_entry_sigscript(
        &committed,
        "slashInvalidReveal",
        vec![Expr::bool(true), Expr::int(43), Expr::bytes(sig)],
    );

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("slashing must remove the bond value from the covenant");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_validator_state_commit_vote_runtime_rejects_value_leak() {
    let contract_path = std::env::var("PROMETHEUS_VALIDATOR_STATE_CONTRACT")
        .expect("PROMETHEUS_VALIDATOR_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus validator state contract fixture");
    let keypair = keypair_from_seed(7);
    let validator_pk = keypair.x_only_public_key().0.serialize().to_vec();
    let commitment = hex32("cda9cc6bb51d36be5db27eb6e86bfc6b6173d5918f24f81939af5411bff90ffb");

    let active = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk.clone(),
            20_000,
            true,
            1_000,
            10_000,
            0,
            0,
            zero32(),
            0,
            0,
            0,
        ),
    );
    let committed = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk,
            20_000,
            true,
            1_000,
            10_000,
            0,
            0,
            commitment.clone(),
            2_000,
            42,
            0,
        ),
    );

    let placeholder_sigscript = validator_state_entry_sigscript(
        &active,
        "commitVote",
        vec![Expr::bytes(commitment.clone()), Expr::int(2_000), Expr::int(42), Expr::bytes(dummy_signature())],
    );
    let outputs = vec![valued_covenant_output(&committed, kas(19_999))];
    let entries = vec![valued_covenant_utxo(&active, kas(20_000))];
    let mut tx = Transaction::new(
        1,
        vec![tx_input_with_sigops(0, placeholder_sigscript, 1)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    let sig = sign_tx_input(&tx, &entries, 0, &keypair);
    tx.inputs[0].signature_script = validator_state_entry_sigscript(
        &active,
        "commitVote",
        vec![Expr::bytes(commitment), Expr::int(2_000), Expr::int(42), Expr::bytes(sig)],
    );

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("a transition must not leak covenant value");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_validator_state_commit_vote_runtime_rejects_unbacked_stake() {
    let contract_path = std::env::var("PROMETHEUS_VALIDATOR_STATE_CONTRACT")
        .expect("PROMETHEUS_VALIDATOR_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus validator state contract fixture");
    let keypair = keypair_from_seed(7);
    let validator_pk = keypair.x_only_public_key().0.serialize().to_vec();
    let commitment = hex32("cda9cc6bb51d36be5db27eb6e86bfc6b6173d5918f24f81939af5411bff90ffb");

    let active = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk.clone(),
            20_000,
            true,
            1_000,
            10_000,
            0,
            0,
            zero32(),
            0,
            0,
            0,
        ),
    );
    let committed = compile_validator_state(
        &source,
        validator_state_args(
            validator_pk,
            20_000,
            true,
            1_000,
            10_000,
            0,
            0,
            commitment.clone(),
            2_000,
            42,
            0,
        ),
    );

    let placeholder_sigscript = validator_state_entry_sigscript(
        &active,
        "commitVote",
        vec![Expr::bytes(commitment.clone()), Expr::int(2_000), Expr::int(42), Expr::bytes(dummy_signature())],
    );
    let outputs = vec![valued_covenant_output(&committed, kas(10_000))];
    let entries = vec![valued_covenant_utxo(&active, kas(10_000))];
    let mut tx = Transaction::new(
        1,
        vec![tx_input_with_sigops(0, placeholder_sigscript, 1)],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    let sig = sign_tx_input(&tx, &entries, 0, &keypair);
    tx.inputs[0].signature_script = validator_state_entry_sigscript(
        &active,
        "commitVote",
        vec![Expr::bytes(commitment), Expr::int(2_000), Expr::int(42), Expr::bytes(sig)],
    );

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("state stake must be backed by the covenant value");
    common::assert_verify_like_error(err);
}
"""


def run(cmd: list[str], cwd: Path, env: dict[str, str] | None = None) -> None:
    print(f"+ {' '.join(cmd)}", flush=True)
    subprocess.run(cmd, cwd=cwd, env=env, check=True)


class SilverscriptCheckoutError(RuntimeError):
    """Fail-closed error for the silverscript checkout trust boundary.

    Messages never include local paths, git output, or file content.
    """


def workspace_silverscript_rev(cargo_toml: Path | None = None) -> str:
    try:
        with (cargo_toml or WORKSPACE_CARGO_TOML).open("rb") as handle:
            manifest = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        raise SilverscriptCheckoutError("cannot parse workspace Cargo.toml") from None
    workspace = manifest.get("workspace")
    dependencies = workspace.get("dependencies") if isinstance(workspace, dict) else None
    entry = dependencies.get("silverscript-lang") if isinstance(dependencies, dict) else None
    if not isinstance(entry, dict):
        raise SilverscriptCheckoutError("workspace silverscript-lang dependency is missing")
    if entry.get("git") != SILVERSCRIPT_GIT or "branch" in entry or "tag" in entry:
        raise SilverscriptCheckoutError("workspace silverscript-lang must be a canonical git rev pin")
    rev = entry.get("rev")
    if not isinstance(rev, str) or not SILVERSCRIPT_REF_RE.fullmatch(rev):
        raise SilverscriptCheckoutError("workspace silverscript-lang rev must be a lowercase 40-hex commit id")
    return rev


def require_pinned_silverscript_ref(ref: str, cargo_toml: Path | None = None) -> None:
    if not isinstance(ref, str) or not SILVERSCRIPT_REF_RE.fullmatch(ref):
        raise SilverscriptCheckoutError("requested silverscript ref must be a lowercase 40-hex commit id")
    if ref != workspace_silverscript_rev(cargo_toml):
        raise SilverscriptCheckoutError("requested silverscript ref does not match the workspace silverscript-lang rev")


def git_output(args: list[str], cwd: Path) -> str:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    try:
        proc = subprocess.run(
            ["git", *GIT_SAFE_CONFIG, *args],
            cwd=cwd,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError:
        raise SilverscriptCheckoutError("git is not available") from None
    if proc.returncode != 0:
        raise SilverscriptCheckoutError(f"silverscript checkout: git {args[0]} failed")
    return proc.stdout


def require_canonical_origin(path: Path) -> None:
    urls = git_output(["config", "--get-all", "remote.origin.url"], path).splitlines()
    if urls != [SILVERSCRIPT_GIT]:
        raise SilverscriptCheckoutError("silverscript checkout origin is not the canonical upstream")
    if git_output(["remote", "get-url", "origin"], path).strip() != SILVERSCRIPT_GIT:
        raise SilverscriptCheckoutError("silverscript checkout origin is rewritten away from the canonical upstream")


def require_clean_tree(path: Path) -> None:
    status = git_output(["status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"], path)
    if status.strip():
        raise SilverscriptCheckoutError("silverscript checkout has local modifications")


def require_checkout_root(path: Path) -> None:
    if path.is_symlink():
        raise SilverscriptCheckoutError("silverscript checkout path must not be a symlink")
    if not path.is_dir():
        raise SilverscriptCheckoutError("silverscript checkout path is not a directory")
    toplevel = git_output(["rev-parse", "--show-toplevel"], path).strip()
    if Path(toplevel).resolve() != path.resolve():
        raise SilverscriptCheckoutError("silverscript checkout path is not a repository root")


def ensure_silverscript_repo(path: Path, ref: str) -> None:
    require_pinned_silverscript_ref(ref)
    if path.exists() or path.is_symlink():
        require_checkout_root(path)
        require_canonical_origin(path)
        require_clean_tree(path)
        print("+ git fetch --quiet --tags origin", flush=True)
        git_output(["fetch", "--quiet", "--tags", "origin"], path)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        print(f"+ git clone --quiet {SILVERSCRIPT_GIT} <checkout>", flush=True)
        git_output(["clone", "--quiet", "--", SILVERSCRIPT_GIT, str(path)], path.parent)
        require_checkout_root(path)
        require_canonical_origin(path)
    print(f"+ git checkout --quiet --detach {ref}", flush=True)
    git_output(["checkout", "--quiet", "--detach", ref], path)
    head = git_output(["rev-parse", "--verify", "HEAD^{commit}"], path).strip()
    if head != ref:
        raise SilverscriptCheckoutError("silverscript checkout HEAD does not equal the pinned rev")
    require_clean_tree(path)


def remove_probe_and_require_clean_tree(repo: Path, probe: Path) -> None:
    try:
        probe.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        raise SilverscriptCheckoutError("cannot remove temporary silverscript probe") from None
    require_clean_tree(repo)


def main() -> int:
    for contract in (
        H001_CONTRACT,
        VALIDATOR_STATE_CONTRACT,
        GUARDIAN_STATE_CONTRACT,
        RULE_STORAGE_STATE_CONTRACT,
        COMMUNITY_DONATIONS_STATE_CONTRACT,
        DEV_INCENTIVE_POOL_STATE_CONTRACT,
        GOVERNANCE_AUTO_TUNING_STATE_CONTRACT,
    ):
        if not contract.exists():
            print(f"missing contract fixture: {contract}", file=sys.stderr)
            return 1

    silver_repo = (
        Path(os.environ.get("SILVERSCRIPT_REPO", str(DEFAULT_SILVERSCRIPT_REPO)))
        .expanduser()
        .resolve()
    )
    silver_ref = os.environ.get("SILVERSCRIPT_REF", DEFAULT_SILVERSCRIPT_REF)
    try:
        ensure_silverscript_repo(silver_repo, silver_ref)
    except SilverscriptCheckoutError as err:
        print(f"silverscript checkout rejected: {err}", file=sys.stderr)
        return 1

    test_dir = silver_repo / "silverscript-lang" / "tests"
    if not test_dir.is_dir():
        print("not a silverscript repo: missing silverscript-lang/tests", file=sys.stderr)
        return 1

    test_file = test_dir / f"{PROBE_TEST_NAME}.rs"

    env = os.environ.copy()
    env["PROMETHEUS_H001_CONTRACT"] = str(H001_CONTRACT)
    env["PROMETHEUS_VALIDATOR_STATE_CONTRACT"] = str(VALIDATOR_STATE_CONTRACT)
    env["PROMETHEUS_GUARDIAN_STATE_CONTRACT"] = str(GUARDIAN_STATE_CONTRACT)
    env["PROMETHEUS_RULE_STORAGE_STATE_CONTRACT"] = str(RULE_STORAGE_STATE_CONTRACT)
    env["PROMETHEUS_COMMUNITY_DONATIONS_STATE_CONTRACT"] = str(COMMUNITY_DONATIONS_STATE_CONTRACT)
    env["PROMETHEUS_DEV_INCENTIVE_POOL_STATE_CONTRACT"] = str(DEV_INCENTIVE_POOL_STATE_CONTRACT)
    env["PROMETHEUS_GOVERNANCE_AUTO_TUNING_STATE_CONTRACT"] = str(GOVERNANCE_AUTO_TUNING_STATE_CONTRACT)
    try:
        try:
            test_file.write_text(RUST_TEST, encoding="utf-8")
            run(
                [
                    "cargo",
                    "test",
                    "--locked",
                    "-p",
                    "silverscript-lang",
                    "--test",
                    PROBE_TEST_NAME,
                    "--",
                    "--nocapture",
                ],
                silver_repo,
                env,
            )
        finally:
            remove_probe_and_require_clean_tree(silver_repo, test_file)
    except SilverscriptCheckoutError as err:
        print(f"silverscript checkout rejected: {err}", file=sys.stderr)
        return 1

    print("H-001, ValidatorStakingState, GuardianReputationState, RuleStorageState, CommunityDonationsState, DevIncentivePoolState, and GovernanceAutoTuningState silverc fixture verification passed.")
    print(f"Silverscript ref: {silver_ref}")
    print(
        "Note: current silverc uses signed int entrypoint arguments; deployment salt and block-height values are scoped to 0..=i64::MAX."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
