#!/usr/bin/env python3
"""Stage a manual Silverc deployment status update from verified operator receipts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from preflight_silverc_deploy import bundle_root_from_args, load_json, validate_manifest
from verify_silverc_deploy_receipts import validate_receipts_document
from verify_silverc_h001 import DEFAULT_SILVERSCRIPT_REF


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build a public, manual status-update draft from verified Prometheus "
            "current-Silverc operator_record receipts. This script never writes "
            "memory/STATUS.md and never signs, broadcasts, or deploys."
        )
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--bundle-dir", type=Path, help="Directory containing manifest.json and artifacts")
    source.add_argument("--archive", type=Path, help="Release .tar.gz archive to validate")
    parser.add_argument("--operator-receipts", type=Path, required=True, help="Real public operator_record receipts JSON")
    parser.add_argument(
        "--silverscript-ref",
        default=DEFAULT_SILVERSCRIPT_REF,
        help="Expected Silverscript commit, tag, or branch in the release manifest",
    )
    parser.add_argument("--status-out", type=Path, help="Optional JSON status draft path")
    parser.add_argument("--snippet-out", type=Path, help="Optional Markdown status snippet path")
    return parser.parse_args()


def write_json(path: Path | None, value: dict[str, Any]) -> None:
    if not path:
        return
    target = path.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_snippet(path: Path | None, status: dict[str, Any]) -> None:
    if not path:
        return

    lines = [
        "# Prometheus Silverc Deployment Status Draft",
        "",
        f"Status: {status['status']}",
        f"Network: {status['network']}",
        f"Silverscript commit: `{status['silverscript_commit']}`",
        f"Receipts SHA-256: `{status['receipts_sha256']}`",
        "",
        "## Safety Rules",
        "",
        "- This is a manual status-update draft, not an automatic repository edit.",
        "- Copy contract IDs into `memory/STATUS.md` only after independent node or explorer verification.",
        "- This draft was built from `operator_record` receipts; `ci_fixture` receipts are rejected.",
        "- This script does not accept private keys, sign transactions, broadcast transactions, deploy contracts, or update status files.",
        "",
        "## Contracts",
        "",
        "| Contract | Instance ID | Deploy TX | DAA score | Confirmations |",
        "|----------|-------------|-----------|----------:|--------------:|",
    ]
    for contract in status["contracts"]:
        lines.append(
            "| `{contract_name}` | `{instance}` | `{tx}` | {daa} | {confirmations} |".format(
                contract_name=contract["contract_name"],
                instance=contract["deployed_instance_id"],
                tx=contract["deploy_tx_id"],
                daa=contract["block_daa_score"],
                confirmations=contract["confirmations"],
            )
        )

    lines.extend(
        [
            "",
            "## Required Manual Checks",
            "",
        ]
    )
    lines.extend(f"{index}. {step}" for index, step in enumerate(status["manual_checks"], start=1))

    target = path.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_status(summary: dict[str, Any]) -> dict[str, Any]:
    contracts = []
    for contract in summary["contracts"]:
        contracts.append(
            {
                "contract_name": contract["contract_name"],
                "deployed_instance_id": contract["deployed_instance_id"],
                "deploy_tx_id": contract["deploy_tx_id"],
                "block_hash": contract["block_hash"],
                "block_daa_score": contract["block_daa_score"],
                "confirmations": contract["confirmations"],
                "artifact_sha256": contract["artifact_sha256"],
                "script_sha256": contract["script_sha256"],
            }
        )

    return {
        "schema_version": 1,
        "status": "READY_FOR_MANUAL_STATUS_UPDATE",
        "network": summary["network"],
        "provenance_type": summary["provenance_type"],
        "silverscript_commit": summary["silverscript_commit"],
        "receipts_sha256": summary["receipts_sha256"],
        "contract_count": len(contracts),
        "contracts": contracts,
        "manual_checks": [
            "Verify each deploy transaction ID against a trusted node or explorer.",
            "Verify each deployed instance ID/outpoint belongs to the expected contract artifact.",
            "Verify confirmations and DAA score are current enough for the selected release policy.",
            "Only then copy the public contract IDs into memory/STATUS.md and public release notes.",
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
        receipts_doc = load_json(args.operator_receipts.expanduser().resolve())
        summary = validate_receipts_document(receipts_doc, manifest, require_operator_record=True)
        status = build_status(summary)
        write_json(args.status_out, status)
        write_snippet(args.snippet_out, status)
        print(json.dumps(status, indent=2, sort_keys=True))
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
