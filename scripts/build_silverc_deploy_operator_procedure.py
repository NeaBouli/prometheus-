#!/usr/bin/env python3
"""Build a public Silverc deploy-operator procedure from verified requests."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from preflight_silverc_deploy import bundle_root_from_args, load_json, validate_manifest
from verify_silverc_deploy_requests import validate_request_set
from verify_silverc_h001 import DEFAULT_SILVERSCRIPT_REF

PROCEDURE_KIND = "prometheus.silverc.deploy.operator_procedure"
PROCEDURE_STATUS = "READY_FOR_EXTERNAL_DEPLOY_OPERATOR"
GENESIS_PROFILE = {
    "transaction_version": 1,
    "script_public_key_builder": "kaspa_txscript::pay_to_script_hash_script",
    "script_public_key_source": "compiled_contract_script",
    "covenant_id_builder": "kaspa_consensus_core::hashing::covenant_id",
    "covenant_id_preimage": "funding_outpoint_and_unbound_genesis_outputs",
    "authorizing_input_source": "funding_input_index",
    "binding_order": "derive_id_before_setting_covenant_binding",
    "runtime_ref": "rusty-kaspa-v2.0.1",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build a public operator procedure for a verified Silverc deploy request set. "
            "This validates public artifacts only; it does not accept keys, assemble raw "
            "transactions, sign, broadcast, deploy, or update status files."
        )
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--bundle-dir", type=Path, help="Directory containing manifest.json and artifacts")
    source.add_argument("--archive", type=Path, help="Release .tar.gz archive to validate")
    parser.add_argument("--request-set", type=Path, required=True, help="Deploy request-set summary JSON")
    parser.add_argument("--requests-dir", type=Path, required=True, help="Directory containing deploy-request JSON files")
    parser.add_argument(
        "--silverscript-ref",
        default=DEFAULT_SILVERSCRIPT_REF,
        help="Expected Silverscript commit, tag, or branch in the release manifest",
    )
    parser.add_argument("--summary-out", type=Path, help="Optional JSON procedure summary path")
    parser.add_argument("--runbook-out", type=Path, help="Optional Markdown operator procedure path")
    return parser.parse_args()


def build_procedure(request_summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": PROCEDURE_KIND,
        "status": PROCEDURE_STATUS,
        "network": request_summary["network"],
        "request_set_sha256": request_summary["request_set_sha256"],
        "silverscript_commit": request_summary["silverscript_commit"],
        "request_count": request_summary["request_count"],
        "required_genesis_profile": GENESIS_PROFILE,
        "contracts": [
            {
                "order": request["order"],
                "contract_name": request["contract_name"],
                "file": request["file"],
                "request_sha256": request["request_sha256"],
                "artifact_sha256": request["artifact_sha256"],
                "script_sha256": request["script_sha256"],
            }
            for request in request_summary["requests"]
        ],
        "repository_boundary": {
            "role": "prepare_and_verify_public_artifacts_only",
            "forbidden_material": [
                "private keys",
                "seed phrases",
                "wallet files",
                "keystore material",
                "raw transactions",
                "serialized transactions",
            ],
        },
        "external_operator_sequence": [
            "Verify request_set_sha256 against the handoff package.",
            "Import each deploy-request JSON into the approved external deploy orchestrator.",
            "Validate every per-contract request_sha256 before assembly.",
            "Assemble, sign, and broadcast outside this repository through the approved wallet/vault process.",
            "Wait for network confirmation for every deployed contract instance.",
            "Record only public operator_record deploy results.",
            "Convert public deploy results with scripts/build_silverc_operator_receipts.py.",
            "Verify operator receipts with scripts/verify_silverc_deploy_receipts.py before any status update.",
        ],
        "required_public_result_fields": {
            "schema_version": 1,
            "result_type": "prometheus_silverc_external_deploy_results",
            "network": request_summary["network"],
            "provenance.type": "operator_record",
            "request_set_sha256": request_summary["request_set_sha256"],
            "release_bundle.silverscript_commit": request_summary["silverscript_commit"],
            "release_bundle.fixture_count": request_summary["request_count"],
            "results[].status": "confirmed",
            "results[].contract_name": "contract name from deploy request set",
            "results[].request_sha256": "request hash from deploy request set",
            "results[].deployed_instance_id": "public deployed contract instance/outpoint",
            "results[].deploy_tx_id": "32-byte public tx id hex",
            "results[].block_hash": "32-byte public block hash hex",
            "results[].deployer_address": "public deployer address",
            "results[].confirmations": "integer >= 1",
            "results[].block_daa_score": "integer network DAA score",
            "results[].deployed_at": "public ISO-8601 deployment timestamp",
        },
        "safety": {
            "accepts_private_keys": False,
            "accepts_raw_transactions": False,
            "signs_transactions": False,
            "assembles_chain_transaction": False,
            "broadcasts_transactions": False,
            "deploys_contracts": False,
            "updates_status_files": False,
        },
        "blockers": [],
    }


def write_json(path: Path | None, value: dict[str, Any]) -> None:
    if not path:
        return
    target = path.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_runbook(path: Path | None, procedure: dict[str, Any]) -> None:
    if not path:
        return
    lines = [
        "# Prometheus Silverc Public Deploy Operator Procedure",
        "",
        f"Status: {procedure['status']}",
        f"Network: {procedure['network']}",
        f"Request set SHA-256: `{procedure['request_set_sha256']}`",
        "",
        "## Boundary",
        "",
        "- This procedure is a public deploy operator checklist, not a chain transaction.",
        "- This repository prepares and verifies public artifacts only.",
        "- Private keys, seed phrases, wallet files, keystore material, raw transactions, and serialized transactions must remain outside this repository.",
        "- The repository does not sign, assemble, broadcast, deploy, or update status files.",
        "",
        "## Contracts",
        "",
        "| Order | Contract | Request SHA-256 | Script SHA-256 |",
        "|------:|----------|-----------------|----------------|",
    ]
    for contract in procedure["contracts"]:
        lines.append(
            "| {order} | `{contract}` | `{request_hash}` | `{script_hash}` |".format(
                order=contract["order"],
                contract=contract["contract_name"],
                request_hash=contract["request_sha256"],
                script_hash=contract["script_sha256"],
            )
        )
    lines.extend(["", "## Required Covenant Genesis Profile", ""])
    for key, value in procedure["required_genesis_profile"].items():
        lines.append(f"- `{key}`: `{value}`")
    lines.extend(["", "## External Operator Sequence", ""])
    lines.extend(f"{index}. {step}" for index, step in enumerate(procedure["external_operator_sequence"], start=1))
    lines.extend(["", "## Required Public Result Evidence", ""])
    for key, value in procedure["required_public_result_fields"].items():
        lines.append(f"- `{key}`: `{value}`")

    target = path.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    bundle_dir, tmp = bundle_root_from_args(args)
    try:
        manifest = validate_manifest(bundle_dir, args.silverscript_ref)
        request_set = load_json(args.request_set.expanduser().resolve())
        requests_dir = args.requests_dir.expanduser().resolve()
        if not requests_dir.is_dir():
            raise FileNotFoundError(f"requests directory not found: {requests_dir}")
        request_summary = validate_request_set(request_set=request_set, requests_dir=requests_dir, manifest=manifest)
        procedure = build_procedure(request_summary)
        write_json(args.summary_out, procedure)
        write_runbook(args.runbook_out, procedure)
        print(json.dumps(procedure, indent=2, sort_keys=True))
        return 0
    finally:
        if tmp is not None:
            tmp.cleanup()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
