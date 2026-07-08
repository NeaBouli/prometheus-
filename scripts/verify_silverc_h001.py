#!/usr/bin/env python3
"""Verify Prometheus H-001 vectors against current upstream silverc runtime."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "modules" / "contracts" / "silverc" / "ValidatorStakingH001.sil"
DEFAULT_SILVERSCRIPT_REPO = Path("/tmp/prom-silverscript")
SILVERSCRIPT_GIT = "https://github.com/kaspanet/silverscript.git"
DEFAULT_SILVERSCRIPT_REF = "d25bd3427a093c17327ca3d6b9e1aa5f7688c863"

RUST_TEST = r"""
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::mass::units::SigopCount;
use kaspa_consensus_core::tx::{
    PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine};
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{CompileOptions, compile_contract};

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
    if not CONTRACT.exists():
        print(f"missing contract fixture: {CONTRACT}", file=sys.stderr)
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
    env["PROMETHEUS_H001_CONTRACT"] = str(CONTRACT)
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

    print("H-001 silverc fixture verification passed.")
    print(f"Silverscript ref: {silver_ref}")
    print(
        "Note: current silverc uses signed int entrypoint arguments; the u64::MAX Rust vector remains a full-contract port item."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
