#!/usr/bin/env python3
"""Verify public metrics-oracle transaction results against an unsigned request."""

from __future__ import annotations

import argparse
import json
import re
import sys
from hashlib import sha256
from pathlib import Path
from typing import Any

from build_metrics_oracle_tx_request import ABI_ENTRYPOINT
from preflight_metrics_oracle_report import CONTRACT_NAME, ENTRYPOINT, canonical_json_bytes
from preflight_silverc_deploy import NETWORKS, bundle_root_from_args, validate_manifest
from verify_silverc_h001 import DEFAULT_SILVERSCRIPT_REF

RESULT_TYPE = "prometheus.metrics_oracle.report_metrics.tx_result"
RESULT_STATUS = "METRICS_ORACLE_TX_RESULT_VERIFIED"
CONFIRMED_STATUS = "confirmed"
HEX_32_BYTES_RE = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")
CONTRACT_OUTPOINT_RE = re.compile(r"^[0-9a-f]{64}:(?:0|[1-9][0-9]*)$")
UTC_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SECRET_KEY_RE = re.compile(
    r"(private|secret|seed|mnemonic|password|passwd|wallet|keystore|token)",
    re.IGNORECASE,
)
ALLOWED_SECRET_WORD_KEYS = {"accepts_private_keys"}
RAW_TX_KEY_RE = re.compile(r"(raw|signed|serialized).*transaction|transaction_(hex|bytes)", re.IGNORECASE)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify a public GovernanceAutoTuning metrics-oracle transaction result "
            "against a signer-ready unsigned request and release bundle. This "
            "checks public records only; it does not accept keys, signatures, raw "
            "transactions, sign, broadcast, deploy, or update status files."
        )
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--bundle-dir", type=Path, help="Directory containing manifest.json and artifacts")
    source.add_argument("--archive", type=Path, help="Release .tar.gz archive to validate")
    parser.add_argument("--tx-request", type=Path, required=True, help="Signer-ready metrics-oracle tx request JSON")
    parser.add_argument("--tx-result", type=Path, required=True, help="Public metrics-oracle tx result JSON")
    parser.add_argument(
        "--silverscript-ref",
        default=DEFAULT_SILVERSCRIPT_REF,
        help="Expected Silverscript commit, tag, or branch in the release manifest",
    )
    parser.add_argument("--summary-out", type=Path, help="Optional JSON verification summary path")
    parser.add_argument("--runbook-out", type=Path, help="Optional Markdown runbook path")
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected JSON object")
    return data


def reject_forbidden_fields(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            if key_text not in ALLOWED_SECRET_WORD_KEYS and SECRET_KEY_RE.search(key_text):
                raise ValueError(f"{path}.{key}: secret-like fields are not allowed in public transaction artifacts")
            if RAW_TX_KEY_RE.search(key_text):
                raise ValueError(f"{path}.{key}: raw or serialized transaction fields are not allowed")
            reject_forbidden_fields(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_forbidden_fields(item, f"{path}[{index}]")


def require_dict(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected object")
    return value


def require_str(data: dict[str, Any], key: str, path: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{path}.{key}: expected non-empty string")
    return value


def require_int(data: dict[str, Any], key: str, path: str, *, minimum: int) -> int:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{path}.{key}: expected integer")
    if value < minimum:
        raise ValueError(f"{path}.{key}: expected >= {minimum}")
    return value


def normalize_hex(value: str) -> str:
    return value.lower().removeprefix("0x")


def hash_without_key(data: dict[str, Any], key: str) -> str:
    clone = dict(data)
    clone.pop(key, None)
    return sha256(canonical_json_bytes(clone)).hexdigest()


def sha256_hex(value: Any) -> str:
    return sha256(canonical_json_bytes(value)).hexdigest()


def validate_request_hash(tx_request: dict[str, Any]) -> None:
    expected = require_str(tx_request, "request_sha256", "tx_request")
    actual = hash_without_key(tx_request, "request_sha256")
    if expected != actual:
        raise ValueError("tx_request.request_sha256 mismatch")


def governance_manifest_entry(manifest: dict[str, Any]) -> dict[str, Any]:
    for entry in manifest["fixtures"]:
        if entry["contract_name"] == CONTRACT_NAME:
            if ABI_ENTRYPOINT not in entry.get("abi", []):
                raise ValueError(f"{CONTRACT_NAME}: missing ABI entrypoint {ABI_ENTRYPOINT}")
            return entry
    raise ValueError(f"release bundle does not contain {CONTRACT_NAME}")


def validate_request(tx_request: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    reject_forbidden_fields(tx_request)
    validate_request_hash(tx_request)

    if tx_request.get("schema_version") != 1:
        raise ValueError("tx_request.schema_version: expected 1")
    if tx_request.get("kind") != "prometheus.metrics_oracle.report_metrics.tx_request":
        raise ValueError("tx_request.kind mismatch")
    if tx_request.get("status") != "READY_FOR_KEYLESS_REPORT_METRICS_OPERATOR":
        raise ValueError("tx_request.status: expected READY_FOR_KEYLESS_REPORT_METRICS_OPERATOR")
    if tx_request.get("network") not in NETWORKS:
        raise ValueError(f"tx_request.network: expected one of {', '.join(NETWORKS)}")
    if tx_request.get("blockers") != []:
        raise ValueError("tx_request.blockers: expected empty list")

    contract = require_dict(tx_request.get("contract"), "tx_request.contract")
    if contract.get("name") != CONTRACT_NAME:
        raise ValueError(f"tx_request.contract.name: expected {CONTRACT_NAME}")
    if contract.get("entrypoint") != ENTRYPOINT:
        raise ValueError(f"tx_request.contract.entrypoint: expected {ENTRYPOINT}")
    if contract.get("abi_entrypoint") != ABI_ENTRYPOINT:
        raise ValueError(f"tx_request.contract.abi_entrypoint: expected {ABI_ENTRYPOINT}")
    instance_id = require_str(contract, "instance_id", "tx_request.contract")
    if instance_id == "deployment_receipt_required" or not CONTRACT_OUTPOINT_RE.fullmatch(instance_id):
        raise ValueError("tx_request.contract.instance_id: expected exact lowercase Kaspa outpoint txid:index")
    if int(instance_id.rsplit(":", 1)[1]) > 0xFFFFFFFF:
        raise ValueError("tx_request.contract.instance_id: output index exceeds uint32")

    bundle = require_dict(tx_request.get("release_bundle"), "tx_request.release_bundle")
    manifest_entry = governance_manifest_entry(manifest)
    if bundle.get("silverscript_ref") != manifest["silverscript_ref"]:
        raise ValueError("tx_request.release_bundle.silverscript_ref mismatch")
    if bundle.get("silverscript_commit") != manifest["silverscript_commit"]:
        raise ValueError("tx_request.release_bundle.silverscript_commit mismatch")
    for key in (
        "artifact_file",
        "source_file",
        "source_sha256",
        "constructor_args_sha256",
        "artifact_sha256",
        "script_sha256",
        "script_len",
    ):
        if bundle.get(key) != manifest_entry[key]:
            raise ValueError(f"tx_request.release_bundle.{key}: manifest mismatch")

    metrics_report = require_dict(tx_request.get("metrics_report"), "tx_request.metrics_report")
    require_str(metrics_report, "payload_sha256", "tx_request.metrics_report")
    entrypoint_args = require_dict(tx_request.get("entrypoint_args"), "tx_request.entrypoint_args")
    signature = require_dict(tx_request.get("signature"), "tx_request.signature")
    if signature.get("required") is not True:
        raise ValueError("tx_request.signature.required: expected true")
    if signature.get("repository_must_not_hold_signing_material") is not True:
        raise ValueError("tx_request.signature.repository_must_not_hold_signing_material: expected true")

    safety = require_dict(tx_request.get("safety"), "tx_request.safety")
    expected_flags = {
        "accepts_private_keys",
        "signs_transactions",
        "assembles_chain_transaction",
        "broadcasts_transactions",
    }
    if set(safety) != expected_flags:
        raise ValueError("tx_request.safety: unexpected safety flags")
    for key in expected_flags:
        if safety[key] is not False:
            raise ValueError(f"tx_request.safety.{key}: expected false")
    if tx_request.get("safety_scope") != "metrics_tx_request_builder_only":
        raise ValueError("tx_request.safety_scope: expected metrics_tx_request_builder_only")

    repository_operator = require_dict(tx_request.get("repository_operator"), "tx_request.repository_operator")
    expected_operator = {
        "assembles_transaction_in_memory": True,
        "accepts_private_keys": False,
        "signs_transactions": False,
        "requires_external_oracle_signature": True,
        "requires_external_fee_sponsor_signature": True,
        "broadcast_requires_exact_signing_request_hash_acknowledgement": True,
    }
    if repository_operator != expected_operator:
        raise ValueError("tx_request.repository_operator: capability profile mismatch")

    return {
        "network": tx_request["network"],
        "request_sha256": tx_request["request_sha256"],
        "contract_instance_id": instance_id,
        "metrics_payload_sha256": metrics_report["payload_sha256"],
        "entrypoint_args_sha256": sha256_hex(entrypoint_args),
        "silverscript_commit": manifest["silverscript_commit"],
        "artifact_sha256": manifest_entry["artifact_sha256"],
        "script_sha256": manifest_entry["script_sha256"],
    }


def validate_result(tx_result: dict[str, Any], request_summary: dict[str, Any]) -> dict[str, Any]:
    reject_forbidden_fields(tx_result)

    if tx_result.get("schema_version") != 1:
        raise ValueError("tx_result.schema_version: expected 1")
    if tx_result.get("result_type") != RESULT_TYPE:
        raise ValueError(f"tx_result.result_type: expected {RESULT_TYPE}")
    if tx_result.get("network") != request_summary["network"]:
        raise ValueError("tx_result.network mismatch")
    if tx_result.get("tx_request_sha256") != request_summary["request_sha256"]:
        raise ValueError("tx_result.tx_request_sha256 mismatch")
    if tx_result.get("status") != CONFIRMED_STATUS:
        raise ValueError("tx_result.status: expected confirmed")

    provenance = require_dict(tx_result.get("provenance"), "tx_result.provenance")
    if provenance.get("type") != "operator_record":
        raise ValueError("tx_result.provenance.type: expected operator_record")
    assembler = require_str(provenance, "assembler", "tx_result.provenance")
    recorded_at = require_str(provenance, "recorded_at", "tx_result.provenance")
    if not UTC_TIMESTAMP_RE.match(recorded_at):
        raise ValueError("tx_result.provenance.recorded_at: expected UTC timestamp")

    contract = require_dict(tx_result.get("contract"), "tx_result.contract")
    if contract.get("name") != CONTRACT_NAME:
        raise ValueError(f"tx_result.contract.name: expected {CONTRACT_NAME}")
    if contract.get("entrypoint") != ENTRYPOINT:
        raise ValueError(f"tx_result.contract.entrypoint: expected {ENTRYPOINT}")
    if contract.get("instance_id") != request_summary["contract_instance_id"]:
        raise ValueError("tx_result.contract.instance_id mismatch")

    metrics_report = require_dict(tx_result.get("metrics_report"), "tx_result.metrics_report")
    if metrics_report.get("payload_sha256") != request_summary["metrics_payload_sha256"]:
        raise ValueError("tx_result.metrics_report.payload_sha256 mismatch")
    if tx_result.get("entrypoint_args_sha256") != request_summary["entrypoint_args_sha256"]:
        raise ValueError("tx_result.entrypoint_args_sha256 mismatch")

    transaction = require_dict(tx_result.get("transaction"), "tx_result.transaction")
    tx_id = require_str(transaction, "tx_id", "tx_result.transaction")
    if not HEX_32_BYTES_RE.match(tx_id):
        raise ValueError("tx_result.transaction.tx_id: expected 32-byte tx id hex")
    block_hash = require_str(transaction, "block_hash", "tx_result.transaction")
    if not HEX_32_BYTES_RE.match(block_hash):
        raise ValueError("tx_result.transaction.block_hash: expected 32-byte block hash hex")
    confirmations = require_int(transaction, "confirmations", "tx_result.transaction", minimum=1)
    block_daa_score = require_int(transaction, "block_daa_score", "tx_result.transaction", minimum=1)
    broadcast_at = require_str(transaction, "broadcast_at", "tx_result.transaction")
    confirmed_at = require_str(transaction, "confirmed_at", "tx_result.transaction")
    if not UTC_TIMESTAMP_RE.match(broadcast_at):
        raise ValueError("tx_result.transaction.broadcast_at: expected UTC timestamp")
    if not UTC_TIMESTAMP_RE.match(confirmed_at):
        raise ValueError("tx_result.transaction.confirmed_at: expected UTC timestamp")

    return {
        "schema_version": 1,
        "status": RESULT_STATUS,
        "network": request_summary["network"],
        "provenance_type": "operator_record",
        "assembler": assembler,
        "recorded_at": recorded_at,
        "silverscript_commit": request_summary["silverscript_commit"],
        "tx_request_sha256": request_summary["request_sha256"],
        "tx_result_sha256": sha256_hex(tx_result),
        "contract": {
            "name": CONTRACT_NAME,
            "entrypoint": ENTRYPOINT,
            "instance_id": request_summary["contract_instance_id"],
            "artifact_sha256": request_summary["artifact_sha256"],
            "script_sha256": request_summary["script_sha256"],
        },
        "metrics_report": {
            "payload_sha256": request_summary["metrics_payload_sha256"],
            "entrypoint_args_sha256": request_summary["entrypoint_args_sha256"],
        },
        "transaction": {
            "tx_id": normalize_hex(tx_id),
            "block_hash": normalize_hex(block_hash),
            "block_daa_score": block_daa_score,
            "confirmations": confirmations,
            "broadcast_at": broadcast_at,
            "confirmed_at": confirmed_at,
        },
        "safety": {
            "accepts_private_keys": False,
            "accepts_raw_transactions": False,
            "signs_transactions": False,
            "assembles_chain_transaction": False,
            "broadcasts_transactions": False,
            "updates_status_files": False,
        },
        "operator_next_steps": [
            "Verify the transaction ID and block hash against a trusted node or explorer.",
            "Verify the transaction invokes GovernanceAutoTuningState.reportMetrics for the expected instance ID.",
            "Use this result together with verified deployment receipts before updating release status.",
            "Keep wallet keys, raw transactions, and signing material outside this repository.",
        ],
    }


def write_json(path: Path | None, value: dict[str, Any]) -> None:
    if not path:
        return
    target = path.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_runbook(path: Path | None, summary: dict[str, Any]) -> None:
    if not path:
        return
    tx = summary["transaction"]
    contract = summary["contract"]
    lines = [
        "# Prometheus Metrics-Oracle Transaction Result Verification",
        "",
        f"Status: {summary['status']}",
        f"Network: {summary['network']}",
        f"Tx request SHA-256: `{summary['tx_request_sha256']}`",
        f"Tx result SHA-256: `{summary['tx_result_sha256']}`",
        "",
        "## Safety Rules",
        "",
        "- This verifier accepts public transaction results only.",
        "- This verifier rejects private keys, secret-like fields, raw transactions, and serialized transactions.",
        "- This verifier does not sign, assemble chain transactions, broadcast, deploy, or update status files.",
        "",
        "## Contract Binding",
        "",
        f"- Contract: `{contract['name']}`",
        f"- Entrypoint: `{contract['entrypoint']}`",
        f"- Instance ID: `{contract['instance_id']}`",
        f"- Script SHA-256: `{contract['script_sha256']}`",
        "",
        "## Transaction",
        "",
        f"- TX ID: `{tx['tx_id']}`",
        f"- Block hash: `{tx['block_hash']}`",
        f"- DAA score: {tx['block_daa_score']}",
        f"- Confirmations: {tx['confirmations']}",
        f"- Confirmed at: `{tx['confirmed_at']}`",
        "",
        "## Operator Sequence",
        "",
    ]
    lines.extend(f"{index}. {step}" for index, step in enumerate(summary["operator_next_steps"], start=1))

    target = path.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    bundle_dir, tmp = bundle_root_from_args(args)
    try:
        manifest = validate_manifest(bundle_dir, args.silverscript_ref)
        request_summary = validate_request(load_json(args.tx_request.expanduser().resolve()), manifest)
        result_summary = validate_result(load_json(args.tx_result.expanduser().resolve()), request_summary)
        write_json(args.summary_out, result_summary)
        write_runbook(args.runbook_out, result_summary)
        print(json.dumps(result_summary, indent=2, sort_keys=True))
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
