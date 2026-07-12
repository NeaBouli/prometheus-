#!/usr/bin/env python3
"""Verify public node/explorer evidence for metrics-oracle transaction results."""

from __future__ import annotations

import argparse
import json
import re
import sys
from hashlib import sha256
from pathlib import Path
from typing import Any

from preflight_metrics_oracle_report import CONTRACT_NAME, ENTRYPOINT, canonical_json_bytes
from preflight_silverc_deploy import NETWORKS, bundle_root_from_args, validate_manifest
from verify_metrics_oracle_tx_result import validate_request, validate_result
from verify_silverc_h001 import DEFAULT_SILVERSCRIPT_REF

EVIDENCE_TYPE = "prometheus.metrics_oracle.report_metrics.tx_public_evidence"
EVIDENCE_STATUS = "PUBLIC_METRICS_ORACLE_TX_EVIDENCE_VERIFIED"
UTC_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SECRET_KEY_RE = re.compile(
    r"(private|secret|seed|mnemonic|password|passwd|wallet|keystore|token)",
    re.IGNORECASE,
)
RAW_TX_KEY_RE = re.compile(r"(raw|signed|serialized).*transaction|transaction_(hex|bytes)", re.IGNORECASE)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify a public node/explorer evidence snapshot against a verified "
            "GovernanceAutoTuning metrics-oracle transaction result. This checks "
            "public records only; it does not query nodes, accept keys, sign, "
            "assemble, broadcast, deploy, or update status files."
        )
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--bundle-dir", type=Path, help="Directory containing manifest.json and artifacts")
    source.add_argument("--archive", type=Path, help="Release .tar.gz archive to validate")
    parser.add_argument("--tx-request", type=Path, required=True, help="Signer-ready metrics-oracle tx request JSON")
    parser.add_argument("--tx-result", type=Path, required=True, help="Verified public metrics-oracle tx result JSON")
    parser.add_argument("--evidence", type=Path, required=True, help="Public node/explorer evidence JSON")
    parser.add_argument(
        "--silverscript-ref",
        default=DEFAULT_SILVERSCRIPT_REF,
        help="Expected Silverscript commit, tag, or branch in the release manifest",
    )
    parser.add_argument("--summary-out", type=Path, help="Optional JSON verification summary path")
    parser.add_argument("--runbook-out", type=Path, help="Optional Markdown evidence runbook path")
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
            if SECRET_KEY_RE.search(key_text):
                raise ValueError(f"{path}.{key}: secret-like fields are not allowed in public transaction evidence")
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


def sha256_json(value: dict[str, Any]) -> str:
    return sha256(canonical_json_bytes(value)).hexdigest()


def validate_evidence_document(
    evidence_doc: dict[str, Any],
    request_summary: dict[str, Any],
    result_summary: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    reject_forbidden_fields(evidence_doc)

    if evidence_doc.get("schema_version") != 1:
        raise ValueError("evidence.schema_version: expected 1")
    if evidence_doc.get("evidence_type") != EVIDENCE_TYPE:
        raise ValueError(f"evidence.evidence_type: expected {EVIDENCE_TYPE}")
    network = evidence_doc.get("network")
    if network not in NETWORKS:
        raise ValueError(f"evidence.network: expected one of {', '.join(NETWORKS)}")
    if network != result_summary["network"]:
        raise ValueError("evidence.network: result/evidence mismatch")

    provenance = require_dict(evidence_doc.get("provenance"), "evidence.provenance")
    if provenance.get("type") not in {"public_explorer_snapshot", "public_node_snapshot"}:
        raise ValueError("evidence.provenance.type: expected public_explorer_snapshot or public_node_snapshot")
    observer = require_str(provenance, "observer", "evidence.provenance")
    observed_at = require_str(provenance, "observed_at", "evidence.provenance")
    if not UTC_TIMESTAMP_RE.match(observed_at):
        raise ValueError("evidence.provenance.observed_at: expected UTC timestamp")

    bundle = require_dict(evidence_doc.get("release_bundle"), "evidence.release_bundle")
    if bundle.get("silverscript_ref") != manifest["silverscript_ref"]:
        raise ValueError("evidence.release_bundle.silverscript_ref mismatch")
    if bundle.get("silverscript_commit") != manifest["silverscript_commit"]:
        raise ValueError("evidence.release_bundle.silverscript_commit mismatch")

    if evidence_doc.get("tx_request_sha256") != request_summary["request_sha256"]:
        raise ValueError("evidence.tx_request_sha256 mismatch")
    if evidence_doc.get("tx_result_sha256") != result_summary["tx_result_sha256"]:
        raise ValueError("evidence.tx_result_sha256 mismatch")

    observation = require_dict(evidence_doc.get("observation"), "evidence.observation")
    if observation.get("status") != "confirmed":
        raise ValueError("evidence.observation.status: expected confirmed")

    contract = require_dict(observation.get("contract"), "evidence.observation.contract")
    expected_contract = result_summary["contract"]
    for key in ("name", "entrypoint", "instance_id"):
        if contract.get(key) != expected_contract.get(key):
            raise ValueError(f"evidence.observation.contract.{key}: result/evidence mismatch")

    metrics_report = require_dict(observation.get("metrics_report"), "evidence.observation.metrics_report")
    expected_metrics = result_summary["metrics_report"]
    for key in ("payload_sha256", "entrypoint_args_sha256"):
        if metrics_report.get(key) != expected_metrics.get(key):
            raise ValueError(f"evidence.observation.metrics_report.{key}: result/evidence mismatch")

    transaction = require_dict(observation.get("transaction"), "evidence.observation.transaction")
    expected_tx = result_summary["transaction"]
    for key in ("tx_id", "block_hash", "block_daa_score"):
        if transaction.get(key) != expected_tx.get(key):
            raise ValueError(f"evidence.observation.transaction.{key}: result/evidence mismatch")
    evidence_confirmations = require_int(transaction, "confirmations", "evidence.observation.transaction", minimum=1)
    if evidence_confirmations < expected_tx["confirmations"]:
        raise ValueError("evidence.observation.transaction.confirmations: expected >= result confirmations")
    explorer_url = observation.get("explorer_url")
    if explorer_url is not None and (not isinstance(explorer_url, str) or not explorer_url.startswith("https://")):
        raise ValueError("evidence.observation.explorer_url: expected https URL when provided")

    return {
        "schema_version": 1,
        "status": EVIDENCE_STATUS,
        "network": network,
        "provenance_type": provenance["type"],
        "observer": observer,
        "observed_at": observed_at,
        "silverscript_commit": manifest["silverscript_commit"],
        "tx_request_sha256": request_summary["request_sha256"],
        "tx_result_sha256": result_summary["tx_result_sha256"],
        "evidence_sha256": sha256_json(evidence_doc),
        "contract": {
            "name": CONTRACT_NAME,
            "entrypoint": ENTRYPOINT,
            "instance_id": expected_contract["instance_id"],
            "artifact_sha256": expected_contract["artifact_sha256"],
            "script_sha256": expected_contract["script_sha256"],
        },
        "metrics_report": {
            "payload_sha256": expected_metrics["payload_sha256"],
            "entrypoint_args_sha256": expected_metrics["entrypoint_args_sha256"],
        },
        "transaction": {
            "tx_id": expected_tx["tx_id"],
            "block_hash": expected_tx["block_hash"],
            "block_daa_score": expected_tx["block_daa_score"],
            "result_confirmations": expected_tx["confirmations"],
            "evidence_confirmations": evidence_confirmations,
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
        "operator_next_steps": [
            "Use this summary only as public evidence binding; it is not a transaction action.",
            "Keep the original public node/explorer evidence with the operator handoff package.",
            "Update status files only after deployment receipts, receipt evidence, oracle tx result, and oracle tx evidence all verify.",
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
        "# Prometheus Metrics-Oracle Transaction Public Evidence",
        "",
        f"Status: {summary['status']}",
        f"Network: {summary['network']}",
        f"Provenance: {summary['provenance_type']}",
        f"Observer: `{summary['observer']}`",
        f"Observed at: `{summary['observed_at']}`",
        f"Tx result SHA-256: `{summary['tx_result_sha256']}`",
        f"Evidence SHA-256: `{summary['evidence_sha256']}`",
        "",
        "## Safety Rules",
        "",
        "- This verifier accepts public metrics-oracle transaction evidence only.",
        "- This verifier rejects secret-like and raw/serialized transaction fields.",
        "- This verifier does not query nodes, accept keys, sign, assemble, broadcast, deploy, or update status files.",
        "",
        "## Contract Binding",
        "",
        f"- Contract: `{contract['name']}`",
        f"- Entrypoint: `{contract['entrypoint']}`",
        f"- Instance ID: `{contract['instance_id']}`",
        "",
        "## Transaction",
        "",
        f"- TX ID: `{tx['tx_id']}`",
        f"- Block hash: `{tx['block_hash']}`",
        f"- DAA score: {tx['block_daa_score']}",
        f"- Result confirmations: {tx['result_confirmations']}",
        f"- Evidence confirmations: {tx['evidence_confirmations']}",
        "",
        "## Operator Next Steps",
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
        tx_request = load_json(args.tx_request.expanduser().resolve())
        tx_result = load_json(args.tx_result.expanduser().resolve())
        request_summary = validate_request(tx_request, manifest)
        result_summary = validate_result(tx_result, request_summary)
        evidence_summary = validate_evidence_document(
            load_json(args.evidence.expanduser().resolve()),
            request_summary,
            result_summary,
            manifest,
        )
        write_json(args.summary_out, evidence_summary)
        write_runbook(args.runbook_out, evidence_summary)
        print(json.dumps(evidence_summary, indent=2, sort_keys=True))
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
