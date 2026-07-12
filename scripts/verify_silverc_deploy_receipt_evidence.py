#!/usr/bin/env python3
"""Verify public node/explorer evidence for Silverc deployment receipts."""

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
from verify_silverc_h001 import DEFAULT_SILVERSCRIPT_REF

EVIDENCE_TYPE = "prometheus_silverc_deploy_receipt_public_evidence"
EVIDENCE_STATUS = "PUBLIC_DEPLOY_RECEIPT_EVIDENCE_VERIFIED"
UTC_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
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
            "Verify a public node/explorer evidence snapshot against verified "
            "Silverc operator_record deployment receipts. This checks public "
            "records only; it does not query nodes, accept keys, sign, assemble, "
            "broadcast, deploy, or update status files."
        )
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--bundle-dir", type=Path, help="Directory containing manifest.json and artifacts")
    source.add_argument("--archive", type=Path, help="Release .tar.gz archive to validate")
    parser.add_argument("--receipts", type=Path, required=True, help="Verified operator_record receipt JSON")
    parser.add_argument("--evidence", type=Path, required=True, help="Public node/explorer evidence JSON")
    parser.add_argument(
        "--silverscript-ref",
        default=DEFAULT_SILVERSCRIPT_REF,
        help="Expected Silverscript commit, tag, or branch in the release manifest",
    )
    parser.add_argument("--summary-out", type=Path, help="Optional JSON verification summary path")
    parser.add_argument("--runbook-out", type=Path, help="Optional Markdown evidence runbook path")
    return parser.parse_args()


def reject_forbidden_fields(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            if SECRET_KEY_RE.search(key_text):
                raise ValueError(f"{path}.{key}: secret-like fields are not allowed in public receipt evidence")
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


def require_list(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"{path}: expected list")
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
    receipts_doc: dict[str, Any],
    receipt_summary: dict[str, Any],
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
    if network != receipt_summary["network"]:
        raise ValueError("evidence.network: receipt/evidence mismatch")

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
    if bundle.get("fixture_count") != manifest["fixture_count"]:
        raise ValueError("evidence.release_bundle.fixture_count mismatch")

    expected_receipts_sha = receipt_summary["receipts_sha256"]
    if evidence_doc.get("receipts_sha256") != expected_receipts_sha:
        raise ValueError("evidence.receipts_sha256 mismatch")
    if evidence_doc.get("receipt_count") != receipt_summary["receipt_count"]:
        raise ValueError("evidence.receipt_count mismatch")

    observations = require_list(evidence_doc.get("observations"), "evidence.observations")
    receipt_records = require_list(receipts_doc.get("receipts"), "receipts.receipts")
    if len(observations) != len(receipt_records):
        raise ValueError("evidence.observations: expected one observation per receipt")

    contracts = []
    for index, (observation, receipt, normalized) in enumerate(
        zip(observations, receipt_records, receipt_summary["contracts"]),
    ):
        path = f"evidence.observations[{index}]"
        observation = require_dict(observation, path)
        if observation.get("status") != "confirmed":
            raise ValueError(f"{path}.status: expected confirmed")
        for key in ("contract_name", "deployed_instance_id", "deploy_tx_id", "block_hash", "block_daa_score"):
            if observation.get(key) != normalized.get(key):
                raise ValueError(f"{path}.{key}: receipt/evidence mismatch")
        evidence_confirmations = require_int(observation, "confirmations", path, minimum=1)
        if evidence_confirmations < normalized["confirmations"]:
            raise ValueError(f"{path}.confirmations: expected >= receipt confirmations")
        explorer_url = observation.get("explorer_url")
        if explorer_url is not None and (not isinstance(explorer_url, str) or not explorer_url.startswith("https://")):
            raise ValueError(f"{path}.explorer_url: expected https URL when provided")
        contracts.append(
            {
                "order": index + 1,
                "contract_name": normalized["contract_name"],
                "deployed_instance_id": normalized["deployed_instance_id"],
                "deploy_tx_id": normalized["deploy_tx_id"],
                "block_hash": normalized["block_hash"],
                "receipt_confirmations": normalized["confirmations"],
                "evidence_confirmations": evidence_confirmations,
                "block_daa_score": normalized["block_daa_score"],
            }
        )

    return {
        "schema_version": 1,
        "status": EVIDENCE_STATUS,
        "network": network,
        "provenance_type": provenance["type"],
        "observer": observer,
        "observed_at": observed_at,
        "silverscript_commit": manifest["silverscript_commit"],
        "receipts_sha256": expected_receipts_sha,
        "evidence_sha256": sha256_json(evidence_doc),
        "receipt_count": receipt_summary["receipt_count"],
        "contracts": contracts,
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
            "Use this summary only as public evidence binding; it is not a deploy action.",
            "Keep the original public node/explorer evidence with the operator handoff package.",
            "Record contract IDs in status files only after receipt, evidence, and readiness audits pass.",
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
    lines = [
        "# Prometheus Silverc Deployment Receipt Public Evidence",
        "",
        f"Status: {summary['status']}",
        f"Network: {summary['network']}",
        f"Provenance: {summary['provenance_type']}",
        f"Observer: `{summary['observer']}`",
        f"Observed at: `{summary['observed_at']}`",
        f"Receipts SHA-256: `{summary['receipts_sha256']}`",
        f"Evidence SHA-256: `{summary['evidence_sha256']}`",
        "",
        "## Safety Rules",
        "",
        "- This verifier accepts public receipt evidence only.",
        "- This verifier rejects secret-like and raw/serialized transaction fields.",
        "- This verifier does not query nodes, accept keys, sign, assemble, broadcast, deploy, or update status files.",
        "",
        "## Contracts",
        "",
        "| Order | Contract | Instance ID | Deploy TX | Receipt Conf. | Evidence Conf. |",
        "|------:|----------|-------------|-----------|--------------:|---------------:|",
    ]
    for contract in summary["contracts"]:
        lines.append(
            "| {order} | `{contract}` | `{instance}` | `{tx}` | {receipt_conf} | {evidence_conf} |".format(
                order=contract["order"],
                contract=contract["contract_name"],
                instance=contract["deployed_instance_id"],
                tx=contract["deploy_tx_id"],
                receipt_conf=contract["receipt_confirmations"],
                evidence_conf=contract["evidence_confirmations"],
            )
        )
    lines.extend(["", "## Operator Next Steps", ""])
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
        receipt_summary = validate_receipts_document(receipts_doc, manifest, require_operator_record=True)
        evidence_doc = load_json(args.evidence.expanduser().resolve())
        summary = validate_evidence_document(evidence_doc, receipts_doc, receipt_summary, manifest)
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
