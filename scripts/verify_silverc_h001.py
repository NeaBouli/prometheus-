#!/usr/bin/env python3
"""Verify Prometheus current-silverc contract fixtures against upstream silverc."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
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
DEFAULT_SILVERSCRIPT_REPO = Path("/tmp/prom-silverscript")
SILVERSCRIPT_GIT = "https://github.com/kaspanet/silverscript.git"
DEFAULT_SILVERSCRIPT_REF = "d25bd3427a093c17327ca3d6b9e1aa5f7688c863"

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

fn compile_validator_state<'a>(source: &'a str, args: Vec<Expr<'static>>) -> CompiledContract<'a> {
    compile_contract(source, &args, CompileOptions::default()).expect("ValidatorStakingState fixture compiles")
}

fn compile_guardian_state<'a>(source: &'a str, args: Vec<Expr<'static>>) -> CompiledContract<'a> {
    compile_contract(source, &args, CompileOptions::default()).expect("GuardianReputationState fixture compiles")
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
        vec![Vec::<Expr>::new().into(), Expr::int(101_300), Expr::bytes(sig)],
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
            Expr::int(1_000),
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
    build_covenant_sigscript(
        &pending,
        "voteOnProposal",
        vec![
            Expr::bool(true),
            Expr::int(1_100),
            Expr::bytes(sig.clone()),
            Expr::bytes(validator_pk),
        ],
    );
    build_covenant_sigscript(
        &pending,
        "finalizeProposal",
        vec![Expr::int(865_000), Expr::bytes(sig.clone())],
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
fn prometheus_rule_storage_submit_proposal_runtime_accepts_valid_transition() {
    let contract_path = std::env::var("PROMETHEUS_RULE_STORAGE_STATE_CONTRACT")
        .expect("PROMETHEUS_RULE_STORAGE_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus rule storage contract fixture");
    let governance_pk = keypair_from_seed(8).x_only_public_key().0.serialize().to_vec();
    let guardian_keypair = keypair_from_seed(9);
    let guardian_pk = guardian_keypair.x_only_public_key().0.serialize().to_vec();
    let threat_hash = vec![3u8; 32];
    let rule_cid = cid36(4);

    let empty = compile_rule_storage_state(
        &source,
        rule_storage_state_args(governance_pk.clone(), 1, 0, guardian_pk.clone(), zero32(), 0, zero36(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, false, 0),
    );
    let pending = compile_rule_storage_state(
        &source,
        rule_storage_state_args(
            governance_pk,
            2,
            1,
            guardian_pk.clone(),
            threat_hash.clone(),
            0,
            rule_cid.clone(),
            9_000,
            1_000,
            0,
            0,
            865_000,
            1,
            0,
            1,
            0,
            0,
            0,
            false,
            0,
        ),
    );

    let placeholder_sigscript = rule_storage_state_entry_sigscript(
        &empty,
        "submitProposal",
        vec![
            Expr::bytes(guardian_pk.clone()),
            Expr::bytes(threat_hash.clone()),
            Expr::int(0),
            Expr::bytes(rule_cid.clone()),
            Expr::int(9_000),
            Expr::int(1_000),
            Expr::bytes(dummy_signature()),
        ],
    );
    let outputs = vec![covenant_output(&pending, 0, COV_A)];
    let entries = vec![covenant_utxo(&empty, COV_A)];
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
    tx.inputs[0].signature_script = rule_storage_state_entry_sigscript(
        &empty,
        "submitProposal",
        vec![
            Expr::bytes(guardian_pk),
            Expr::bytes(threat_hash),
            Expr::int(0),
            Expr::bytes(rule_cid),
            Expr::int(9_000),
            Expr::int(1_000),
            Expr::bytes(sig),
        ],
    );

    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(
        result.is_ok(),
        "RuleStorage submitProposal runtime should accept valid guardian signature/state transition: {:?}",
        result.err()
    );
}

#[test]
fn prometheus_rule_storage_submit_proposal_runtime_rejects_low_confidence() {
    let contract_path = std::env::var("PROMETHEUS_RULE_STORAGE_STATE_CONTRACT")
        .expect("PROMETHEUS_RULE_STORAGE_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus rule storage contract fixture");
    let governance_pk = keypair_from_seed(8).x_only_public_key().0.serialize().to_vec();
    let guardian_keypair = keypair_from_seed(9);
    let guardian_pk = guardian_keypair.x_only_public_key().0.serialize().to_vec();
    let threat_hash = vec![3u8; 32];
    let rule_cid = cid36(4);

    let empty = compile_rule_storage_state(
        &source,
        rule_storage_state_args(governance_pk.clone(), 1, 0, guardian_pk.clone(), zero32(), 0, zero36(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, false, 0),
    );
    let low_confidence_next = compile_rule_storage_state(
        &source,
        rule_storage_state_args(
            governance_pk,
            2,
            1,
            guardian_pk.clone(),
            threat_hash.clone(),
            0,
            rule_cid.clone(),
            8_499,
            1_000,
            0,
            0,
            865_000,
            1,
            0,
            1,
            0,
            0,
            0,
            false,
            0,
        ),
    );

    let placeholder_sigscript = rule_storage_state_entry_sigscript(
        &empty,
        "submitProposal",
        vec![
            Expr::bytes(guardian_pk.clone()),
            Expr::bytes(threat_hash.clone()),
            Expr::int(0),
            Expr::bytes(rule_cid.clone()),
            Expr::int(8_499),
            Expr::int(1_000),
            Expr::bytes(dummy_signature()),
        ],
    );
    let outputs = vec![covenant_output(&low_confidence_next, 0, COV_A)];
    let entries = vec![covenant_utxo(&empty, COV_A)];
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
    tx.inputs[0].signature_script = rule_storage_state_entry_sigscript(
        &empty,
        "submitProposal",
        vec![
            Expr::bytes(guardian_pk),
            Expr::bytes(threat_hash),
            Expr::int(0),
            Expr::bytes(rule_cid),
            Expr::int(8_499),
            Expr::int(1_000),
            Expr::bytes(sig),
        ],
    );

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("submitProposal must reject confidence below MIN_CONFIDENCE");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_rule_storage_vote_on_proposal_runtime_accepts_support_vote() {
    let contract_path = std::env::var("PROMETHEUS_RULE_STORAGE_STATE_CONTRACT")
        .expect("PROMETHEUS_RULE_STORAGE_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus rule storage contract fixture");
    let governance_pk = keypair_from_seed(8).x_only_public_key().0.serialize().to_vec();
    let guardian_pk = keypair_from_seed(9).x_only_public_key().0.serialize().to_vec();
    let validator_keypair = keypair_from_seed(7);
    let validator_pk = validator_keypair.x_only_public_key().0.serialize().to_vec();
    let threat_hash = vec![3u8; 32];
    let rule_cid = cid36(4);

    let pending = compile_rule_storage_state(
        &source,
        rule_storage_state_args(governance_pk.clone(), 2, 1, guardian_pk.clone(), threat_hash.clone(), 0, rule_cid.clone(), 9_000, 1_000, 0, 0, 865_000, 1, 0, 1, 0, 0, 0, false, 0),
    );
    let voted = compile_rule_storage_state(
        &source,
        rule_storage_state_args(governance_pk, 2, 1, guardian_pk, threat_hash, 0, rule_cid, 9_000, 1_000, 1, 0, 865_000, 1, 0, 1, 0, 0, 0, false, 0),
    );

    let placeholder_sigscript = rule_storage_state_entry_sigscript(
        &pending,
        "voteOnProposal",
        vec![Expr::bool(true), Expr::int(1_100), Expr::bytes(dummy_signature()), Expr::bytes(validator_pk.clone())],
    );
    let outputs = vec![covenant_output(&voted, 0, COV_A)];
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
    let sig = sign_tx_input(&tx, &entries, 0, &validator_keypair);
    tx.inputs[0].signature_script = rule_storage_state_entry_sigscript(
        &pending,
        "voteOnProposal",
        vec![Expr::bool(true), Expr::int(1_100), Expr::bytes(sig), Expr::bytes(validator_pk)],
    );

    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(
        result.is_ok(),
        "RuleStorage voteOnProposal runtime should accept valid validator signature/state transition: {:?}",
        result.err()
    );
}

#[test]
fn prometheus_rule_storage_vote_on_proposal_runtime_rejects_late_vote() {
    let contract_path = std::env::var("PROMETHEUS_RULE_STORAGE_STATE_CONTRACT")
        .expect("PROMETHEUS_RULE_STORAGE_STATE_CONTRACT is set");
    let source = std::fs::read_to_string(contract_path).expect("read Prometheus rule storage contract fixture");
    let governance_pk = keypair_from_seed(8).x_only_public_key().0.serialize().to_vec();
    let guardian_pk = keypair_from_seed(9).x_only_public_key().0.serialize().to_vec();
    let validator_keypair = keypair_from_seed(7);
    let validator_pk = validator_keypair.x_only_public_key().0.serialize().to_vec();
    let threat_hash = vec![3u8; 32];
    let rule_cid = cid36(4);

    let pending = compile_rule_storage_state(
        &source,
        rule_storage_state_args(governance_pk.clone(), 2, 1, guardian_pk.clone(), threat_hash.clone(), 0, rule_cid.clone(), 9_000, 1_000, 0, 0, 865_000, 1, 0, 1, 0, 0, 0, false, 0),
    );
    let invalid_next = compile_rule_storage_state(
        &source,
        rule_storage_state_args(governance_pk, 2, 1, guardian_pk, threat_hash, 0, rule_cid, 9_000, 1_000, 1, 0, 865_000, 1, 0, 1, 0, 0, 0, false, 0),
    );

    let placeholder_sigscript = rule_storage_state_entry_sigscript(
        &pending,
        "voteOnProposal",
        vec![Expr::bool(true), Expr::int(865_000), Expr::bytes(dummy_signature()), Expr::bytes(validator_pk.clone())],
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
    let sig = sign_tx_input(&tx, &entries, 0, &validator_keypair);
    tx.inputs[0].signature_script = rule_storage_state_entry_sigscript(
        &pending,
        "voteOnProposal",
        vec![Expr::bool(true), Expr::int(865_000), Expr::bytes(sig), Expr::bytes(validator_pk)],
    );

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("voteOnProposal must reject votes at or after voting_end_block");
    common::assert_verify_like_error(err);
}

#[test]
fn prometheus_rule_storage_finalize_proposal_runtime_accepts_accepted_transition() {
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
    let accepted = compile_rule_storage_state(
        &source,
        rule_storage_state_args(governance_pk, 2, 1, guardian_pk, threat_hash, 0, rule_cid, 9_000, 1_000, 2, 0, 865_000, 2, 1, 1, 0, 10_000, 865_000, true, 1),
    );

    let placeholder_sigscript = rule_storage_state_entry_sigscript(
        &pending,
        "finalizeProposal",
        vec![Expr::int(865_000), Expr::bytes(dummy_signature())],
    );
    let outputs = vec![covenant_output(&accepted, 0, COV_A)];
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
        "finalizeProposal",
        vec![Expr::int(865_000), Expr::bytes(sig)],
    );

    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(
        result.is_ok(),
        "RuleStorage finalizeProposal runtime should accept accepted proposal transition: {:?}",
        result.err()
    );
}

#[test]
fn prometheus_rule_storage_finalize_proposal_runtime_accepts_rejected_transition() {
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
        rule_storage_state_args(governance_pk.clone(), 2, 1, guardian_pk.clone(), threat_hash.clone(), 0, rule_cid.clone(), 9_000, 1_000, 1, 2, 865_000, 1, 0, 1, 0, 0, 0, false, 0),
    );
    let rejected = compile_rule_storage_state(
        &source,
        rule_storage_state_args(governance_pk, 2, 1, guardian_pk, threat_hash, 0, rule_cid, 9_000, 1_000, 1, 2, 865_000, 3, 0, 1, 0, 3_333, 0, false, 2),
    );

    let placeholder_sigscript = rule_storage_state_entry_sigscript(
        &pending,
        "finalizeProposal",
        vec![Expr::int(865_000), Expr::bytes(dummy_signature())],
    );
    let outputs = vec![covenant_output(&rejected, 0, COV_A)];
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
        "finalizeProposal",
        vec![Expr::int(865_000), Expr::bytes(sig)],
    );

    let result = execute_input_with_covenants(tx, entries, 0);
    assert!(
        result.is_ok(),
        "RuleStorage finalizeProposal runtime should accept rejected proposal transition: {:?}",
        result.err()
    );
}

#[test]
fn prometheus_rule_storage_finalize_proposal_runtime_rejects_no_votes() {
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
        rule_storage_state_args(governance_pk.clone(), 2, 1, guardian_pk.clone(), threat_hash.clone(), 0, rule_cid.clone(), 9_000, 1_000, 0, 0, 865_000, 1, 0, 1, 0, 0, 0, false, 0),
    );
    let invalid_next = compile_rule_storage_state(
        &source,
        rule_storage_state_args(governance_pk, 2, 1, guardian_pk, threat_hash, 0, rule_cid, 9_000, 1_000, 0, 0, 865_000, 3, 0, 1, 0, 0, 0, false, 2),
    );

    let placeholder_sigscript = rule_storage_state_entry_sigscript(
        &pending,
        "finalizeProposal",
        vec![Expr::int(865_000), Expr::bytes(dummy_signature())],
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
        "finalizeProposal",
        vec![Expr::int(865_000), Expr::bytes(sig)],
    );

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("finalizeProposal must reject zero total votes");
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
    let outputs = vec![covenant_output(&committed, 0, COV_A)];
    let entries = vec![covenant_utxo(&active, COV_A)];
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
    let outputs = vec![covenant_output(&low_bond_state, 0, COV_A)];
    let entries = vec![covenant_utxo(&active, COV_A)];
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
    let outputs = vec![covenant_output(&committed, 0, COV_A)];
    let entries = vec![covenant_utxo(&active, COV_A)];
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
    let outputs = vec![covenant_output(&revealed, 0, COV_A)];
    let entries = vec![covenant_utxo(&committed, COV_A)];
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
    let outputs = vec![covenant_output(&revealed, 0, COV_A)];
    let entries = vec![covenant_utxo(&committed, COV_A)];
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
    let outputs = vec![covenant_output(&revealed, 0, COV_A)];
    let entries = vec![covenant_utxo(&committed, COV_A)];
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
    let outputs = vec![covenant_output(&slashed, 0, COV_A)];
    let entries = vec![covenant_utxo(&committed, COV_A)];
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
    let outputs = vec![covenant_output(&slashed, 0, COV_A)];
    let entries = vec![covenant_utxo(&committed, COV_A)];
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
    let outputs = vec![covenant_output(&withdrawal_requested, 0, COV_A)];
    let entries = vec![covenant_utxo(&active, COV_A)];
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
    let outputs = vec![covenant_output(&withdrawal_requested, 0, COV_A)];
    let entries = vec![covenant_utxo(&committed, COV_A)];
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
        vec![Vec::<Expr>::new().into(), Expr::int(102_800), Expr::bytes(dummy_signature())],
    );
    let outputs = vec![];
    let entries = vec![covenant_utxo(&withdrawal_requested, COV_A)];
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
        &withdrawal_requested,
        "completeWithdraw",
        vec![Vec::<Expr>::new().into(), Expr::int(102_800), Expr::bytes(sig)],
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
        vec![Vec::<Expr>::new().into(), Expr::int(102_799), Expr::bytes(dummy_signature())],
    );
    let outputs = vec![];
    let entries = vec![covenant_utxo(&withdrawal_requested, COV_A)];
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
        &withdrawal_requested,
        "completeWithdraw",
        vec![Vec::<Expr>::new().into(), Expr::int(102_799), Expr::bytes(sig)],
    );

    let err = execute_input_with_covenants(tx, entries, 0).expect_err("completeWithdraw must reject before cooldown expires");
    common::assert_verify_like_error(err);
}
"""


def run(cmd: list[str], cwd: Path, env: dict[str, str] | None = None) -> None:
    print(f"+ {' '.join(cmd)}", flush=True)
    subprocess.run(cmd, cwd=cwd, env=env, check=True)


def ensure_silverscript_repo(path: Path, ref: str) -> None:
    if path.exists():
        run(["git", "fetch", "--quiet", "--tags", "origin"], path)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        run(["git", "clone", SILVERSCRIPT_GIT, str(path)], ROOT)
    run(["git", "-c", "advice.detachedHead=false", "checkout", "--quiet", ref], path)


def main() -> int:
    for contract in (
        H001_CONTRACT,
        VALIDATOR_STATE_CONTRACT,
        GUARDIAN_STATE_CONTRACT,
        RULE_STORAGE_STATE_CONTRACT,
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
    ensure_silverscript_repo(silver_repo, silver_ref)

    test_dir = silver_repo / "silverscript-lang" / "tests"
    if not test_dir.is_dir():
        print(f"not a silverscript repo: {silver_repo}", file=sys.stderr)
        return 1

    test_file = test_dir / "prometheus_h001_probe.rs"
    test_file.write_text(RUST_TEST, encoding="utf-8")

    env = os.environ.copy()
    env["PROMETHEUS_H001_CONTRACT"] = str(H001_CONTRACT)
    env["PROMETHEUS_VALIDATOR_STATE_CONTRACT"] = str(VALIDATOR_STATE_CONTRACT)
    env["PROMETHEUS_GUARDIAN_STATE_CONTRACT"] = str(GUARDIAN_STATE_CONTRACT)
    env["PROMETHEUS_RULE_STORAGE_STATE_CONTRACT"] = str(RULE_STORAGE_STATE_CONTRACT)
    try:
        run(
            [
                "cargo",
                "test",
                "-p",
                "silverscript-lang",
                "--test",
                "prometheus_h001_probe",
                "--",
                "--nocapture",
            ],
            silver_repo,
            env,
        )
    finally:
        try:
            test_file.unlink()
        except FileNotFoundError:
            pass

    print("H-001, ValidatorStakingState, GuardianReputationState, and RuleStorageState silverc fixture verification passed.")
    print(f"Silverscript ref: {silver_ref}")
    print(
        "Note: current silverc uses signed int entrypoint arguments; deployment salt and block-height values are scoped to 0..=i64::MAX."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
