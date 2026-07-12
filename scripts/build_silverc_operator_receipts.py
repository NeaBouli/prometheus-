#!/usr/bin/env python3
"""Build verified operator_record receipts from public external deploy results."""

from __future__ import annotations

import argparse
import json
import re
import sys
from hashlib import sha256
from pathlib import Path
from typing import Any

from preflight_silverc_deploy import NETWORKS, bundle_root_from_args, load_json, validate_manifest
from smoke_silverc_artifacts import canonical_json_bytes
from verify_silverc_deploy_receipts import validate_receipts_document
from verify_silverc_deploy_requests import validate_request_set
from verify_silverc_h001 import DEFAULT_SILVERSCRIPT_REF

RESULT_TYPE = "prometheus_silverc_external_deploy_results"
RESULT_STATUS = "OPERATOR_RECEIPTS_READY_FOR_STATUS_STAGING"
SECRET_LIKE_RE = re.compile(
    r"(private|secret|seed|mnemonic|password|passwd|wallet|keystore|token)",
    re.IGNORECASE,
)
RAW_TX_KEY_RE = re.compile(
    r"(raw|signed|serialized).*transaction|transaction_(hex|bytes)",
    re.IGNORECASE,
)
UTC_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Convert public external Silverc deploy-orchestrator results into "
            "Prometheus operator_record receipts. This validates request hashes "
            "and release-bundle binding, then re-validates the generated receipts. "
            "It does not accept keys, sign, assemble transactions, broadcast, "
            "deploy, or update status files."
        )
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--bundle-dir", type=Path, help="Directory containing manifest.json and artifacts")
    source.add_argument("--archive", type=Path, help="Release .tar.gz archive to validate")
    parser.add_argument("--request-set", type=Path, required=True, help="Verified deploy request-set JSON")
    parser.add_argument("--requests-dir", type=Path, required=True, help="Directory containing deploy-request JSON files")
    parser.add_argument(
        "--orchestrator-results",
        type=Path,
        required=True,
        help="Public external deploy-orchestrator result JSON",
    )
    parser.add_argument(
        "--silverscript-ref",
        default=DEFAULT_SILVERSCRIPT_REF,
        help="Expected Silverscript commit, tag, or branch in the release manifest",
    )
    parser.add_argument("--operator-receipts-out", type=Path, help="Optional generated operator_record receipts JSON")
    parser.add_argument("--summary-out", type=Path, help="Optional JSON summary path")
    parser.add_argument("--runbook-out", type=Path, help="Optional Markdown runbook path")
    return parser.parse_args()


def reject_forbidden_fields(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            if SECRET_LIKE_RE.search(key_text):
                raise ValueError(f"{path}.{key}: secret-like fields are not allowed in orchestrator results")
            if RAW_TX_KEY_RE.search(key_text):
                raise ValueError(f"{path}.{key}: raw or serialized transaction fields are not allowed")
            reject_forbidden_fields(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_forbidden_fields(item, f"{path}[{index}]")


def require_dict(value: Any, key: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{key}: expected object")
    return value


def require_list(value: Any, key: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"{key}: expected list")
    return value


def require_str(data: dict[str, Any], key: str, path: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{path}.{key}: expected non-empty string")
    return value


def source_hash(doc: dict[str, Any]) -> str:
    return sha256(canonical_json_bytes(doc)).hexdigest()


def validate_results_header(
    *,
    results_doc: dict[str, Any],
    manifest: dict[str, Any],
    request_summary: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    reject_forbidden_fields(results_doc)

    if results_doc.get("schema_version") != 1:
        raise ValueError("schema_version: expected 1")
    if results_doc.get("result_type") != RESULT_TYPE:
        raise ValueError(f"result_type: expected {RESULT_TYPE}")
    network = results_doc.get("network")
    if network not in NETWORKS:
        raise ValueError(f"network: expected one of {', '.join(NETWORKS)}")
    if network != request_summary["network"]:
        raise ValueError("network: request-set/result mismatch")

    provenance = require_dict(results_doc.get("provenance"), "provenance")
    if provenance.get("type") != "operator_record":
        raise ValueError("provenance.type: expected operator_record")
    require_str(provenance, "orchestrator", "provenance")
    recorded_at = require_str(provenance, "recorded_at", "provenance")
    if not UTC_TIMESTAMP_RE.match(recorded_at):
        raise ValueError("provenance.recorded_at: expected UTC timestamp like 2026-07-11T00:00:00Z")

    bundle = require_dict(results_doc.get("release_bundle"), "release_bundle")
    if bundle.get("silverscript_ref") != manifest["silverscript_ref"]:
        raise ValueError("release_bundle.silverscript_ref mismatch")
    if bundle.get("silverscript_commit") != manifest["silverscript_commit"]:
        raise ValueError("release_bundle.silverscript_commit mismatch")
    if bundle.get("fixture_count") != manifest["fixture_count"]:
        raise ValueError("release_bundle.fixture_count mismatch")

    if results_doc.get("request_set_sha256") != request_summary["request_set_sha256"]:
        raise ValueError("request_set_sha256 mismatch")

    return provenance, bundle


def build_receipts(
    *,
    results_doc: dict[str, Any],
    manifest: dict[str, Any],
    request_summary: dict[str, Any],
) -> dict[str, Any]:
    provenance, bundle = validate_results_header(
        results_doc=results_doc,
        manifest=manifest,
        request_summary=request_summary,
    )
    results = require_list(results_doc.get("results"), "results")
    if len(results) != manifest["fixture_count"]:
        raise ValueError("results: expected one result per manifest contract")

    receipts = []
    for index, (result, manifest_entry, request_entry) in enumerate(
        zip(results, manifest["fixtures"], request_summary["requests"]),
        start=1,
    ):
        if not isinstance(result, dict):
            raise ValueError(f"results[{index - 1}]: expected object")
        path = f"results[{index - 1}]"
        if result.get("contract_name") != manifest_entry["contract_name"]:
            raise ValueError(f"{path}.contract_name mismatch")
        if result.get("contract_name") != request_entry["contract_name"]:
            raise ValueError(f"{path}.contract_name request mismatch")
        if result.get("request_sha256") != request_entry["request_sha256"]:
            raise ValueError(f"{path}.request_sha256 mismatch")

        receipt = {
            "contract_name": manifest_entry["contract_name"],
            "status": result.get("status"),
            "deployed_instance_id": result.get("deployed_instance_id"),
            "deploy_tx_id": result.get("deploy_tx_id"),
            "block_hash": result.get("block_hash"),
            "deployer_address": result.get("deployer_address"),
            "confirmations": result.get("confirmations"),
            "block_daa_score": result.get("block_daa_score"),
            "deployed_at": result.get("deployed_at"),
            "source_sha256": manifest_entry["source_sha256"],
            "constructor_args_sha256": manifest_entry["constructor_args_sha256"],
            "artifact_sha256": manifest_entry["artifact_sha256"],
            "script_sha256": manifest_entry["script_sha256"],
            "script_len": manifest_entry["script_len"],
        }
        receipts.append(receipt)

    return {
        "schema_version": 1,
        "network": results_doc["network"],
        "provenance": {
            "type": "operator_record",
            "description": "Generated from public external deploy-orchestrator results after request-set verification.",
            "orchestrator": provenance["orchestrator"],
            "recorded_at": provenance["recorded_at"],
            "source_result_sha256": source_hash(results_doc),
            "request_set_sha256": request_summary["request_set_sha256"],
        },
        "release_bundle": {
            "silverscript_ref": bundle["silverscript_ref"],
            "silverscript_commit": bundle["silverscript_commit"],
            "fixture_count": bundle["fixture_count"],
        },
        "receipts": receipts,
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
        "# Prometheus Silverc Operator Receipt Import",
        "",
        f"Status: {summary['status']}",
        f"Network: {summary['network']}",
        f"Silverscript commit: `{summary['silverscript_commit']}`",
        f"Request set SHA-256: `{summary['request_set_sha256']}`",
        f"Source result SHA-256: `{summary['source_result_sha256']}`",
        f"Receipts SHA-256: `{summary['receipts_sha256']}`",
        "",
        "## Safety Rules",
        "",
        "- This importer accepts public external deploy results only.",
        "- This importer rejects secret-like and raw/serialized transaction fields.",
        "- This importer does not sign, assemble chain transactions, broadcast, deploy, or update status files.",
        "- Generated receipts are re-validated as `operator_record` receipts before status staging.",
        "",
        "## Contracts",
        "",
        "| Order | Contract | Instance ID | Deploy TX | Request SHA-256 |",
        "|------:|----------|-------------|-----------|-----------------|",
    ]
    for contract in summary["contracts"]:
        lines.append(
            "| {order} | `{contract}` | `{instance}` | `{tx}` | `{request_hash}` |".format(
                order=contract["order"],
                contract=contract["contract_name"],
                instance=contract["deployed_instance_id"],
                tx=contract["deploy_tx_id"],
                request_hash=contract["request_sha256"],
            )
        )
    lines.extend(["", "## Operator Sequence", ""])
    lines.extend(f"{index}. {step}" for index, step in enumerate(summary["operator_next_steps"], start=1))

    target = path.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_summary(
    *,
    receipts_doc: dict[str, Any],
    receipt_summary: dict[str, Any],
    request_summary: dict[str, Any],
) -> dict[str, Any]:
    contracts = []
    by_request_name = {entry["contract_name"]: entry for entry in request_summary["requests"]}
    for index, contract in enumerate(receipt_summary["contracts"], start=1):
        request_entry = by_request_name[contract["contract_name"]]
        contracts.append(
            {
                "order": index,
                "contract_name": contract["contract_name"],
                "deployed_instance_id": contract["deployed_instance_id"],
                "deploy_tx_id": contract["deploy_tx_id"],
                "block_hash": contract["block_hash"],
                "block_daa_score": contract["block_daa_score"],
                "confirmations": contract["confirmations"],
                "request_sha256": request_entry["request_sha256"],
                "artifact_sha256": contract["artifact_sha256"],
                "script_sha256": contract["script_sha256"],
            }
        )

    return {
        "schema_version": 1,
        "status": RESULT_STATUS,
        "network": receipt_summary["network"],
        "provenance_type": receipt_summary["provenance_type"],
        "orchestrator": receipts_doc["provenance"]["orchestrator"],
        "silverscript_commit": receipt_summary["silverscript_commit"],
        "request_set_sha256": receipts_doc["provenance"]["request_set_sha256"],
        "source_result_sha256": receipts_doc["provenance"]["source_result_sha256"],
        "receipts_sha256": receipt_summary["receipts_sha256"],
        "receipt_count": receipt_summary["receipt_count"],
        "contracts": contracts,
        "operator_next_steps": [
            "Verify every deploy transaction ID against a trusted node or explorer.",
            "Verify deployed instance IDs/outpoints match the expected contract artifacts.",
            "Run scripts/stage_silverc_deployment_status.py with the generated receipts.",
            "Copy public contract IDs into status files only after manual verification.",
        ],
        "safety": {
            "accepts_private_keys": False,
            "signs_transactions": False,
            "assembles_chain_transaction": False,
            "broadcasts_transactions": False,
            "deploys_contracts": False,
            "updates_status_files": False,
        },
    }


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
        results_doc = load_json(args.orchestrator_results.expanduser().resolve())
        receipts_doc = build_receipts(
            results_doc=results_doc,
            manifest=manifest,
            request_summary=request_summary,
        )
        receipt_summary = validate_receipts_document(receipts_doc, manifest, require_operator_record=True)
        summary = build_summary(
            receipts_doc=receipts_doc,
            receipt_summary=receipt_summary,
            request_summary=request_summary,
        )
        write_json(args.operator_receipts_out, receipts_doc)
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
