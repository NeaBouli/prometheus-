#!/usr/bin/env python3
"""Build a public Silverc deploy-operator procedure from verified requests."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from preflight_silverc_deploy import bundle_root_from_args, load_json, validate_manifest
from silverc_deployment_profiles import CANARY_SCOPE_NOTICE, is_canary, procedure_status
from verify_silverc_deploy_requests import validate_request_set
from verify_silverc_h001 import DEFAULT_SILVERSCRIPT_REF

PROCEDURE_KIND = "prometheus.silverc.deploy.operator_procedure"
GENESIS_PROFILE = {
    "transaction_version": 1,
    "funding_input_compute_budget": 10,
    "storage_mass_commitment": "contextual_storage_mass",
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
    deployment_profile = request_summary["deployment_profile"]
    procedure = {
        "schema_version": 1,
        "kind": PROCEDURE_KIND,
        "status": procedure_status(deployment_profile),
        "network": request_summary["network"],
        "deployment_profile": deployment_profile,
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
        "execution_boundary": {
            "repository_operator": [
                "assemble transaction v1 in memory",
                "export the canonical public sighash",
                "verify the external signature and complete transaction",
                "broadcast only after exact hash acknowledgement",
                "observe the confirmed covenant UTXO",
            ],
            "external_signer": [
                "hold all private signing material outside the repository",
                "sign only the canonical 32-byte sighash",
                "return only the public BIP340 signature response",
            ],
            "public_evidence_path": [
                "record confirmed public operator results",
                "verify receipts and independent node/explorer evidence",
                "update status manually only after readiness gates pass",
            ],
            "forbidden_material": [
                "private keys",
                "seed phrases",
                "wallet files",
                "keystore material",
                "raw transactions",
                "serialized transactions",
            ],
        },
        "execution_sequence": [
            "Verify request_set_sha256 against the handoff package.",
            "Import each deploy-request JSON into the repository Toccata-v1 genesis operator.",
            "Run live node and exact funding-UTXO preflight for every contract.",
            "Prepare each transaction and send only its canonical sighash to the approved external vault/HSM.",
            "Return each public signature response to the repository operator for full verification and acknowledged broadcast.",
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
            "release_bundle.fixture_count": deployment_profile["full_bundle_fixture_count"],
            "deployment_profile": deployment_profile,
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
        "safety_scope": "procedure_builder_only",
        "blockers": [],
    }
    if is_canary(deployment_profile):
        procedure["blockers"].append(CANARY_SCOPE_NOTICE)
        procedure["execution_sequence"].append(
            "Treat the confirmed result only as H-001 canary evidence; do not promote full release or metrics-oracle status."
        )
    return procedure


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
        f"Deployment profile: `{procedure['deployment_profile']['name']}`",
        f"Request set SHA-256: `{procedure['request_set_sha256']}`",
        "",
        "## Boundary",
        "",
        "- This procedure is a public deploy operator checklist, not a chain transaction.",
        "- This procedure builder only prepares and verifies public procedure artifacts.",
        "- The Rust repository operator assembles and broadcasts keyless transactions in memory; the external vault/HSM alone signs the digest.",
        "- Private keys, seed phrases, wallet files, keystore material, raw transactions, and serialized transactions must remain outside this repository.",
        "- This procedure builder does not sign, assemble, broadcast, deploy, or update status files.",
        "",
        "## Contracts",
        "",
        "| Order | Contract | Request SHA-256 | Script SHA-256 |",
        "|------:|----------|-----------------|----------------|",
    ]
    if is_canary(procedure["deployment_profile"]):
        lines.insert(
            lines.index("## Contracts") - 1,
            "- This canary procedure cannot authorize full release or metrics-oracle readiness.",
        )
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
    lines.extend(f"{index}. {step}" for index, step in enumerate(procedure["execution_sequence"], start=1))
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
