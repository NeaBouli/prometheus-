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

fn build_covenant_sigscript(compiled: &silverscript_lang::compiler::CompiledContract<'_>, function_name: &str, args: Vec<Expr<'_>>) {
    compiled
        .build_sig_script_for_covenant_decl(function_name, args, CovenantDeclCallOptions { is_leader: false })
        .unwrap_or_else(|err| panic!("ValidatorStakingState {function_name} sigscript builds: {err}"));
}

fn validator_state_entry_sigscript(compiled: &CompiledContract<'_>, function_name: &str, args: Vec<Expr<'_>>) -> Vec<u8> {
    let mut sigscript = compiled
        .build_sig_script_for_covenant_decl(function_name, args, CovenantDeclCallOptions { is_leader: false })
        .unwrap_or_else(|err| panic!("ValidatorStakingState {function_name} sigscript builds: {err}"));
    sigscript.extend_from_slice(&common::push_redeem_script(&compiled.script));
    sigscript
}

fn compile_validator_state<'a>(source: &'a str, args: Vec<Expr<'static>>) -> CompiledContract<'a> {
    compile_contract(source, &args, CompileOptions::default()).expect("ValidatorStakingState fixture compiles")
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
    for contract in (H001_CONTRACT, VALIDATOR_STATE_CONTRACT):
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

    print("H-001 and ValidatorStakingState silverc fixture verification passed.")
    print(f"Silverscript ref: {silver_ref}")
    print(
        "Note: current silverc uses signed int entrypoint arguments; the u64::MAX Rust vector remains a full-contract port item."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
