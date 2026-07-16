#!/usr/bin/env python3
"""Build a deterministic, unsigned metrics-oracle transaction request."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from hashlib import sha256
from pathlib import Path
from typing import Any

from preflight_metrics_oracle_report import (
    CONTRACT_NAME,
    ENTRYPOINT,
    build_plan as build_report_plan,
    canonical_json_bytes,
    load_json as load_report_json,
    validate_report,
)
from preflight_silverc_deploy import bundle_root_from_args, validate_manifest
from verify_silverc_h001 import DEFAULT_SILVERSCRIPT_REF

ABI_ENTRYPOINT = "__covenant_entrypoint_auth_reportMetrics"
CONTRACT_OUTPOINT_RE = re.compile(r"^[0-9a-f]{64}:(?:0|[1-9][0-9]*)$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build a deterministic unsigned operator request for "
            "GovernanceAutoTuningState.reportMetrics. This validates the public "
            "report and release bundle for the repository-owned keyless Rust operator. "
            "This request builder does not assemble, sign, or broadcast a Kaspa transaction."
        )
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--bundle-dir", type=Path, help="Directory containing manifest.json and artifacts")
    source.add_argument("--archive", type=Path, help="Release .tar.gz archive to validate")
    parser.add_argument("--report", type=Path, required=True, help="Public metrics report JSON")
    parser.add_argument(
        "--contract-instance-id",
        help=(
            "Exact deployed GovernanceAutoTuningState outpoint as lowercase txid:index. "
            "Do not pass wallet secrets."
        ),
    )
    parser.add_argument(
        "--silverscript-ref",
        default=os.environ.get("SILVERSCRIPT_REF", DEFAULT_SILVERSCRIPT_REF),
        help="Expected Silverscript commit, tag, or branch in the release manifest",
    )
    parser.add_argument(
        "--require-contract-instance-id",
        action="store_true",
        help="Fail unless --contract-instance-id is supplied and valid",
    )
    parser.add_argument("--tx-request-out", type=Path, help="Optional JSON unsigned request output path")
    parser.add_argument("--runbook-out", type=Path, help="Optional Markdown operator handoff path")
    return parser.parse_args()


def sha256_hex(value: Any) -> str:
    return sha256(canonical_json_bytes(value)).hexdigest()


def validate_contract_instance_id(value: str | None, required: bool) -> str | None:
    if not value:
        if required:
            raise ValueError("--contract-instance-id is required for signer-ready requests")
        return None
    if not CONTRACT_OUTPOINT_RE.fullmatch(value):
        raise ValueError("--contract-instance-id must be an exact lowercase Kaspa outpoint txid:index")
    output_index = int(value.rsplit(":", 1)[1])
    if output_index > 0xFFFFFFFF:
        raise ValueError("--contract-instance-id output index exceeds uint32")
    return value


def governance_manifest_entry(manifest: dict[str, Any]) -> dict[str, Any]:
    for entry in manifest["fixtures"]:
        if entry["contract_name"] == CONTRACT_NAME:
            if ABI_ENTRYPOINT not in entry.get("abi", []):
                raise ValueError(f"{CONTRACT_NAME}: missing ABI entrypoint {ABI_ENTRYPOINT}")
            return entry
    raise ValueError(f"release bundle does not contain {CONTRACT_NAME}")


def build_request(
    payload: dict[str, Any],
    report_plan: dict[str, Any],
    manifest: dict[str, Any],
    contract_entry: dict[str, Any],
    contract_instance_id: str | None,
) -> dict[str, Any]:
    blockers = []
    if not contract_instance_id:
        blockers.append("missing deployed GovernanceAutoTuningState contract instance id")

    request: dict[str, Any] = {
        "schema_version": 1,
        "kind": "prometheus.metrics_oracle.report_metrics.tx_request",
        "status": "READY_FOR_KEYLESS_REPORT_METRICS_OPERATOR" if not blockers else "BLOCKED_UNTIL_CONTRACT_INSTANCE_ID",
        "network": payload["network"],
        "contract": {
            "name": CONTRACT_NAME,
            "entrypoint": ENTRYPOINT,
            "abi_entrypoint": ABI_ENTRYPOINT,
            "instance_id": contract_instance_id or "deployment_receipt_required",
        },
        "release_bundle": {
            "silverscript_ref": manifest["silverscript_ref"],
            "silverscript_commit": manifest["silverscript_commit"],
            "artifact_file": contract_entry["artifact_file"],
            "source_file": contract_entry["source_file"],
            "source_sha256": contract_entry["source_sha256"],
            "constructor_args_sha256": contract_entry["constructor_args_sha256"],
            "artifact_sha256": contract_entry["artifact_sha256"],
            "script_sha256": contract_entry["script_sha256"],
            "script_len": contract_entry["script_len"],
        },
        "metrics_report": {
            "payload_sha256": report_plan["payload_sha256"],
            "metrics_oracle_pubkey": payload["metrics_oracle_pubkey"],
            "previous_state": payload["previous_state"],
            "metrics": payload["metrics"],
            "sources_count": len(payload["sources"]),
        },
        "entrypoint_args": report_plan["entrypoint_args"],
        "signature": {
            "required": True,
            "signer": "metrics_oracle_wallet",
            "signer_pubkey": payload["metrics_oracle_pubkey"],
            "signature_field": "oracle_sig",
            "signature_placeholder": "external_wallet_signature_required",
            "repository_must_not_hold_signing_material": True,
        },
        "safety": {
            "accepts_private_keys": False,
            "signs_transactions": False,
            "assembles_chain_transaction": False,
            "broadcasts_transactions": False,
        },
        "safety_scope": "metrics_tx_request_builder_only",
        "repository_operator": {
            "assembles_transaction_in_memory": True,
            "accepts_private_keys": False,
            "signs_transactions": False,
            "requires_external_oracle_signature": True,
            "requires_external_fee_sponsor_signature": True,
            "broadcast_requires_exact_signing_request_hash_acknowledgement": True,
        },
        "blockers": blockers,
        "operator_next_steps": [
            "Verify the contract instance id from a real deployment receipt before signing.",
            "Create a closed transition spec with the exact covenant state UTXO and a separate public P2PK fee-sponsor UTXO.",
            "Run report-metrics-preflight and report-metrics-prepare with the repository Rust operator.",
            "Produce the oracle and fee-sponsor BIP340 signatures outside this repository.",
            "Import both signatures and require complete covenant plus P2PK input verification.",
            "Acknowledge the exact signing_request_sha256 before the guarded one-shot broadcast.",
            "Observe the successor covenant UTXO and verify public evidence before updating status files.",
        ],
    }
    request["request_sha256"] = sha256_hex(request)
    return request


def write_json(path: Path | None, value: dict[str, Any]) -> None:
    if not path:
        return
    target = path.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_runbook(path: Path | None, request: dict[str, Any]) -> None:
    if not path:
        return

    contract = request["contract"]
    bundle = request["release_bundle"]
    metrics = request["metrics_report"]["metrics"]
    lines = [
        "# Prometheus Metrics-Oracle Unsigned Transaction Request",
        "",
        f"Status: {request['status']}",
        f"Network: {request['network']}",
        f"Request SHA-256: `{request['request_sha256']}`",
        "",
        "## Safety Rules",
        "",
        "- This artifact is an unsigned operator request, not a serialized Kaspa transaction.",
        "- The safety flags describe this request builder, not the Rust execution operator.",
        "- This artifact does not accept private keys, sign transactions, assemble chain transactions, or broadcast transactions.",
        "- The Rust operator assembles only in memory and requires external oracle and fee-sponsor signatures.",
        "- Both signatures must be produced outside this repository.",
        "- Signing material must remain in an external wallet/keychain or deployment vault.",
        "",
        "## Contract Binding",
        "",
        f"- Contract: `{contract['name']}`",
        f"- Entrypoint: `{contract['entrypoint']}`",
        f"- ABI entrypoint: `{contract['abi_entrypoint']}`",
        f"- Contract instance id: `{contract['instance_id']}`",
        f"- Artifact: `{bundle['artifact_file']}`",
        f"- Script SHA-256: `{bundle['script_sha256']}`",
        "",
        "## reportMetrics Arguments",
        "",
        f"- `new_active_validators`: {metrics['active_validators']}",
        f"- `new_active_guardians`: {metrics['active_guardians']}",
        f"- `new_proposals_per_day`: {metrics['proposals_per_day']}",
        f"- `new_fp_rate`: {metrics['fp_rate']}",
        f"- `block_height`: {metrics['block_height']}",
        "- `oracle_sig`: external wallet signature required",
        "",
        "## Blockers",
        "",
    ]
    blockers = request["blockers"]
    lines.extend(f"- {blocker}" for blocker in blockers) if blockers else lines.append("- none")
    lines.extend(["", "## Operator Sequence", ""])
    lines.extend(f"{index}. {step}" for index, step in enumerate(request["operator_next_steps"], start=1))

    target = path.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    contract_instance_id = validate_contract_instance_id(
        args.contract_instance_id,
        args.require_contract_instance_id,
    )
    payload = validate_report(load_report_json(args.report.expanduser().resolve()))
    report_plan = build_report_plan(payload)

    bundle_dir, tmp = bundle_root_from_args(args)
    try:
        manifest = validate_manifest(bundle_dir, args.silverscript_ref)
        contract_entry = governance_manifest_entry(manifest)
        request = build_request(payload, report_plan, manifest, contract_entry, contract_instance_id)
        write_json(args.tx_request_out, request)
        write_runbook(args.runbook_out, request)
        print(json.dumps(request, indent=2, sort_keys=True))
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
