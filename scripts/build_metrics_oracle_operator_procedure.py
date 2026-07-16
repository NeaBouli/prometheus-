#!/usr/bin/env python3
"""Build a public metrics-oracle operator procedure from a signer-ready request."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from preflight_silverc_deploy import bundle_root_from_args, validate_manifest
from verify_metrics_oracle_tx_result import load_json, validate_request
from verify_silverc_h001 import DEFAULT_SILVERSCRIPT_REF

PROCEDURE_KIND = "prometheus.metrics_oracle.report_metrics.operator_procedure"
PROCEDURE_STATUS = "READY_FOR_KEYLESS_REPORT_METRICS_OPERATION"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build a public operator procedure for a signer-ready GovernanceAutoTuning "
            "metrics-oracle transaction request. This procedure builder validates public "
            "artifacts only and documents the repository-owned keyless Rust workflow."
        )
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--bundle-dir", type=Path, help="Directory containing manifest.json and artifacts")
    source.add_argument("--archive", type=Path, help="Release .tar.gz archive to validate")
    parser.add_argument("--tx-request", type=Path, required=True, help="Signer-ready metrics-oracle tx request JSON")
    parser.add_argument(
        "--silverscript-ref",
        default=DEFAULT_SILVERSCRIPT_REF,
        help="Expected Silverscript commit, tag, or branch in the release manifest",
    )
    parser.add_argument("--summary-out", type=Path, help="Optional JSON procedure summary path")
    parser.add_argument("--runbook-out", type=Path, help="Optional Markdown operator procedure path")
    return parser.parse_args()


def build_procedure(request_summary: dict[str, Any]) -> dict[str, Any]:
    procedure = {
        "schema_version": 1,
        "kind": PROCEDURE_KIND,
        "status": PROCEDURE_STATUS,
        "network": request_summary["network"],
        "tx_request_sha256": request_summary["request_sha256"],
        "silverscript_commit": request_summary["silverscript_commit"],
        "contract": {
            "name": "GovernanceAutoTuningState",
            "entrypoint": "reportMetrics",
            "instance_id": request_summary["contract_instance_id"],
            "artifact_sha256": request_summary["artifact_sha256"],
            "script_sha256": request_summary["script_sha256"],
        },
        "metrics_report": {
            "payload_sha256": request_summary["metrics_payload_sha256"],
            "entrypoint_args_sha256": request_summary["entrypoint_args_sha256"],
        },
        "repository_boundary": {
            "role": "keyless_transaction_assembly_verification_and_guarded_broadcast",
            "forbidden_material": [
                "private keys",
                "seed phrases",
                "wallet files",
                "keystore material",
                "raw transactions",
                "serialized transactions",
            ],
        },
        "operator_sequence": [
            "Verify the tx_request_sha256 against the handoff package.",
            "Load the public contract instance id from verified operator_record deployment receipts.",
            "Create a closed transition spec with exact predecessor state and a separate public P2PK fee-sponsor UTXO.",
            "Run report-metrics-preflight, then report-metrics-prepare to build the transaction and both sighashes in memory.",
            "Produce the oracle and fee-sponsor BIP340 signatures outside this repository.",
            "Run report-metrics-import-signatures and require both BIP340 checks plus complete covenant and P2PK execution.",
            "Acknowledge the exact signing_request_sha256 and run report-metrics-broadcast once.",
            "Run report-metrics-observe and record only public successor-UTXO evidence.",
            "Verify the public result with scripts/verify_metrics_oracle_tx_result.py before any status update.",
        ],
        "repository_operator": {
            "assembles_transaction_in_memory": True,
            "accepts_private_keys": False,
            "signs_transactions": False,
            "requires_external_oracle_signature": True,
            "requires_external_fee_sponsor_signature": True,
            "broadcast_requires_exact_signing_request_hash_acknowledgement": True,
            "preserves_covenant_state_value": True,
            "fee_paid_by_separate_p2pk_sponsor": True,
        },
        "required_public_result_fields": {
            "schema_version": 1,
            "result_type": "prometheus.metrics_oracle.report_metrics.tx_result",
            "status": "confirmed",
            "provenance.type": "operator_record",
            "tx_request_sha256": request_summary["request_sha256"],
            "contract.instance_id": request_summary["contract_instance_id"],
            "metrics_report.payload_sha256": request_summary["metrics_payload_sha256"],
            "entrypoint_args_sha256": request_summary["entrypoint_args_sha256"],
            "transaction.tx_id": "32-byte public tx id hex",
            "transaction.block_hash": "32-byte public block hash hex",
            "transaction.confirmations": "integer >= 1",
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
        "safety_scope": "operator_procedure_builder_only",
        "blockers": [],
    }
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
    contract = procedure["contract"]
    lines = [
        "# Prometheus Metrics-Oracle Operator Procedure",
        "",
        f"Status: {procedure['status']}",
        f"Network: {procedure['network']}",
        f"Tx request SHA-256: `{procedure['tx_request_sha256']}`",
        "",
        "## Boundary",
        "",
        "- This procedure is a public operator checklist, not a chain transaction.",
        "- The safety flags below describe this procedure builder, not the Rust execution operator.",
        "- Private keys, seed phrases, wallet files, keystore material, raw transactions, and serialized transactions must remain outside this repository.",
        "- The Rust operator assembles in memory, verifies both external signatures and all inputs, and broadcasts only after exact hash acknowledgement.",
        "- The repository never signs, accepts private keys, deploys from this procedure builder, or updates status files automatically.",
        "",
        "## Contract Binding",
        "",
        f"- Contract: `{contract['name']}`",
        f"- Entrypoint: `{contract['entrypoint']}`",
        f"- Instance ID: `{contract['instance_id']}`",
        f"- Script SHA-256: `{contract['script_sha256']}`",
        "",
        "## Operator Sequence",
        "",
    ]
    lines.extend(f"{index}. {step}" for index, step in enumerate(procedure["operator_sequence"], start=1))
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
        request_summary = validate_request(load_json(args.tx_request.expanduser().resolve()), manifest)
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
