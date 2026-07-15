#!/usr/bin/env python3
"""Verify public Prometheus Silverc deployment receipts against a release bundle."""

from __future__ import annotations

import argparse
import json
import re
import sys
from hashlib import sha256
from pathlib import Path
from typing import Any

from preflight_silverc_deploy import (
    KASPA_ADDRESS_RE,
    NETWORKS,
    bundle_root_from_args,
    load_json,
    validate_manifest,
)
from silverc_deployment_profiles import (
    FULL_PROFILE,
    CANARY_SCOPE_NOTICE,
    expected_profile,
    is_canary,
    receipt_verification_status,
    validate_profile_document,
)
from smoke_silverc_artifacts import canonical_json_bytes
from verify_silverc_h001 import DEFAULT_SILVERSCRIPT_REF

RECEIPT_SOURCES = ("ci_fixture", "operator_record")
STATUSES = ("confirmed",)
HEX_32_BYTES_RE = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")
PUBLIC_ID_RE = re.compile(r"^[A-Za-z0-9:._/-]{4,200}$")
SECRET_KEY_RE = re.compile(
    r"(private|secret|seed|mnemonic|password|passwd|wallet|keystore|token)",
    re.IGNORECASE,
)
RAW_TX_KEY_RE = re.compile(
    r"(raw|signed|serialized).*transaction|transaction_(hex|bytes)",
    re.IGNORECASE,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify public deployment receipts against a Prometheus current-Silverc "
            "release bundle. This validates records only; it does not deploy, sign, "
            "or broadcast."
        )
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--bundle-dir", type=Path, help="Directory containing manifest.json and artifacts")
    source.add_argument("--archive", type=Path, help="Release .tar.gz archive to validate")
    parser.add_argument("--receipts", type=Path, required=True, help="Public deployment receipts JSON")
    parser.add_argument(
        "--silverscript-ref",
        default=DEFAULT_SILVERSCRIPT_REF,
        help="Expected Silverscript commit, tag, or branch in the release manifest",
    )
    parser.add_argument(
        "--require-operator-record",
        action="store_true",
        help="Fail unless receipts.provenance.type is operator_record",
    )
    parser.add_argument("--summary-out", type=Path, help="Optional JSON verification summary path")
    parser.add_argument("--runbook-out", type=Path, help="Optional Markdown receipt runbook path")
    return parser.parse_args()


def reject_forbidden_fields(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            if SECRET_KEY_RE.search(key_text):
                raise ValueError(f"{path}.{key}: secret-like fields are not allowed in deployment receipts")
            if RAW_TX_KEY_RE.search(key_text):
                raise ValueError(f"{path}.{key}: raw or serialized transaction fields are not allowed")
            reject_forbidden_fields(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_forbidden_fields(item, f"{path}[{index}]")


def require_int(data: dict[str, Any], key: str, *, minimum: int = 0) -> int:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{key}: expected integer")
    if value < minimum:
        raise ValueError(f"{key}: expected >= {minimum}")
    return value


def require_str(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key}: expected non-empty string")
    return value


def normalize_hex(value: str) -> str:
    return value.lower().removeprefix("0x")


def validate_public_id(value: str, key: str) -> None:
    if not PUBLIC_ID_RE.match(value):
        raise ValueError(f"{key}: expected public identifier/outpoint/address-like value")


def validate_receipts_document(
    receipts_doc: dict[str, Any],
    manifest: dict[str, Any],
    require_operator_record: bool,
) -> dict[str, Any]:
    reject_forbidden_fields(receipts_doc)

    if receipts_doc.get("schema_version") != 1:
        raise ValueError("schema_version: expected 1")
    network = receipts_doc.get("network")
    if network not in NETWORKS:
        raise ValueError(f"network: expected one of {', '.join(NETWORKS)}")

    provenance = receipts_doc.get("provenance")
    if not isinstance(provenance, dict):
        raise ValueError("provenance: expected object")
    provenance_type = provenance.get("type")
    if provenance_type not in RECEIPT_SOURCES:
        raise ValueError(f"provenance.type: expected one of {', '.join(RECEIPT_SOURCES)}")
    if require_operator_record and provenance_type != "operator_record":
        raise ValueError("provenance.type: expected operator_record")

    bundle = receipts_doc.get("release_bundle")
    if not isinstance(bundle, dict):
        raise ValueError("release_bundle: expected object")
    if bundle.get("silverscript_ref") != manifest["silverscript_ref"]:
        raise ValueError("release_bundle.silverscript_ref mismatch")
    if bundle.get("silverscript_commit") != manifest["silverscript_commit"]:
        raise ValueError("release_bundle.silverscript_commit mismatch")
    if bundle.get("fixture_count") != manifest["fixture_count"]:
        raise ValueError("release_bundle.fixture_count mismatch")

    profile_document = receipts_doc.get("deployment_profile")
    if profile_document is None:
        deployment_profile = expected_profile(FULL_PROFILE, manifest)
        manifest_entries = manifest["fixtures"]
    else:
        deployment_profile, manifest_entries = validate_profile_document(profile_document, manifest)

    receipts = receipts_doc.get("receipts")
    if not isinstance(receipts, list):
        raise ValueError("receipts: expected list")

    manifest_by_name = {entry["contract_name"]: entry for entry in manifest["fixtures"]}
    expected_names = [entry["contract_name"] for entry in manifest_entries]
    if len(receipts) != len(expected_names):
        raise ValueError("receipts: expected one receipt per manifest contract")

    seen = set()
    normalized_receipts = []
    for index, receipt in enumerate(receipts):
        if not isinstance(receipt, dict):
            raise ValueError(f"receipts[{index}]: expected object")
        normalized_receipts.append(validate_receipt(index, receipt, manifest_by_name, seen))

    actual_names = [receipt["contract_name"] for receipt in normalized_receipts]
    if actual_names != expected_names:
        raise ValueError("receipts: contract order/name mismatch")

    status = receipt_verification_status(deployment_profile, provenance_type)
    summary = {
        "schema_version": 1,
        "status": status,
        "network": network,
        "provenance_type": provenance_type,
        "deployment_profile": deployment_profile,
        "silverscript_commit": manifest["silverscript_commit"],
        "receipt_count": len(normalized_receipts),
        "contracts": normalized_receipts,
        "safety": {
            "accepts_private_keys": False,
            "signs_transactions": False,
            "broadcasts_transactions": False,
            "updates_status_files": False,
        },
        "operator_next_steps": [
            "Use only operator_record receipts from a real network deploy when updating status files.",
            "Verify every deploy transaction in an external explorer or node before recording contract IDs.",
            "Update memory/STATUS.md only after receipt verification succeeds for all contracts.",
            "Keep ci_fixture receipts out of release status claims.",
        ],
    }
    if is_canary(deployment_profile):
        summary["operator_next_steps"] = [
            "Verify the H-001 deploy transaction against a trusted node or explorer.",
            "Use the canary evidence verifier before recording any canary result.",
            "Do not use canary receipts for full release or metrics-oracle status.",
            CANARY_SCOPE_NOTICE,
        ]
    summary["receipts_sha256"] = sha256(canonical_json_bytes(receipts_doc)).hexdigest()
    return summary


def validate_receipt(
    index: int,
    receipt: dict[str, Any],
    manifest_by_name: dict[str, dict[str, Any]],
    seen: set[str],
) -> dict[str, Any]:
    prefix = f"receipts[{index}]"
    contract_name = require_str(receipt, "contract_name")
    if contract_name in seen:
        raise ValueError(f"{prefix}.contract_name: duplicate {contract_name}")
    seen.add(contract_name)
    manifest_entry = manifest_by_name.get(contract_name)
    if not manifest_entry:
        raise ValueError(f"{prefix}.contract_name: not present in manifest")

    if receipt.get("status") not in STATUSES:
        raise ValueError(f"{prefix}.status: expected confirmed")
    deployed_instance_id = require_str(receipt, "deployed_instance_id")
    validate_public_id(deployed_instance_id, f"{prefix}.deployed_instance_id")
    deploy_tx_id = require_str(receipt, "deploy_tx_id")
    if not HEX_32_BYTES_RE.match(deploy_tx_id):
        raise ValueError(f"{prefix}.deploy_tx_id: expected 32-byte tx id hex")
    block_hash = require_str(receipt, "block_hash")
    if not HEX_32_BYTES_RE.match(block_hash):
        raise ValueError(f"{prefix}.block_hash: expected 32-byte block hash hex")
    deployer_address = require_str(receipt, "deployer_address")
    if not KASPA_ADDRESS_RE.match(deployer_address):
        raise ValueError(f"{prefix}.deployer_address: expected public Kaspa address")
    confirmations = require_int(receipt, "confirmations", minimum=1)
    block_daa_score = require_int(receipt, "block_daa_score", minimum=1)

    for key in (
        "source_sha256",
        "constructor_args_sha256",
        "artifact_sha256",
        "script_sha256",
    ):
        if receipt.get(key) != manifest_entry[key]:
            raise ValueError(f"{prefix}.{key}: manifest hash mismatch")
    if receipt.get("script_len") != manifest_entry["script_len"]:
        raise ValueError(f"{prefix}.script_len: manifest script length mismatch")

    deployed_at = require_str(receipt, "deployed_at")
    if not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", deployed_at):
        raise ValueError(f"{prefix}.deployed_at: expected UTC timestamp like 2026-07-11T00:00:00Z")

    return {
        "contract_name": contract_name,
        "deployed_instance_id": deployed_instance_id,
        "deploy_tx_id": normalize_hex(deploy_tx_id),
        "block_hash": normalize_hex(block_hash),
        "block_daa_score": block_daa_score,
        "confirmations": confirmations,
        "artifact_sha256": manifest_entry["artifact_sha256"],
        "script_sha256": manifest_entry["script_sha256"],
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
    lines = [
        "# Prometheus Silverc Deployment Receipt Verification",
        "",
        f"Status: {summary['status']}",
        f"Network: {summary['network']}",
        f"Deployment profile: `{summary['deployment_profile']['name']}`",
        f"Provenance: {summary['provenance_type']}",
        f"Silverscript commit: `{summary['silverscript_commit']}`",
        f"Receipts SHA-256: `{summary['receipts_sha256']}`",
        "",
        "## Safety Rules",
        "",
        "- This verifier accepts public deployment receipts only.",
        "- This verifier rejects secret-like and raw/serialized transaction fields.",
        "- This verifier does not accept private keys, sign transactions, broadcast transactions, or update status files.",
        "- ci_fixture receipts are test fixtures and must not be used as release status claims.",
        "- Only operator_record receipts verified against a real node/explorer may be copied into deployment status.",
        "",
        "## Contracts",
        "",
        "| Contract | Instance ID | Deploy TX | DAA score | Confirmations | Script SHA-256 |",
        "|----------|-------------|-----------|----------:|--------------:|----------------|",
    ]
    for contract in summary["contracts"]:
        lines.append(
            "| `{contract_name}` | `{instance}` | `{tx}` | {daa} | {confirmations} | `{script}` |".format(
                contract_name=contract["contract_name"],
                instance=contract["deployed_instance_id"],
                tx=contract["deploy_tx_id"],
                daa=contract["block_daa_score"],
                confirmations=contract["confirmations"],
                script=contract["script_sha256"],
            )
        )
    lines.extend(["", "## Operator Sequence", ""])
    lines.extend(f"{index}. {step}" for index, step in enumerate(summary["operator_next_steps"], start=1))

    target = path.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    bundle_dir, tmp = bundle_root_from_args(args)
    try:
        manifest = validate_manifest(bundle_dir, args.silverscript_ref)
        receipts_doc = load_json(args.receipts.expanduser().resolve())
        summary = validate_receipts_document(receipts_doc, manifest, args.require_operator_record)
        write_json(args.summary_out, summary)
        write_runbook(args.runbook_out, summary)
        print(json.dumps(summary, indent=2, sort_keys=True))
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
