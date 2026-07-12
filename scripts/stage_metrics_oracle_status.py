#!/usr/bin/env python3
"""Stage a manual metrics-oracle status update from a verified tx result."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from preflight_silverc_deploy import bundle_root_from_args, load_json, validate_manifest
from verify_metrics_oracle_tx_result import validate_request, validate_result
from verify_silverc_h001 import DEFAULT_SILVERSCRIPT_REF


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build a public, manual status-update draft from a verified "
            "GovernanceAutoTuning metrics-oracle tx result. This script never "
            "writes memory/STATUS.md and never accepts keys, raw transactions, "
            "signs, broadcasts, or deploys."
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
    tx = status["transaction"]
    contract = status["contract"]
    metrics = status["metrics_report"]
    lines = [
        "# Prometheus Metrics-Oracle Status Draft",
        "",
        f"Status: {status['status']}",
        f"Network: {status['network']}",
        f"Silverscript commit: `{status['silverscript_commit']}`",
        f"Tx result SHA-256: `{status['tx_result_sha256']}`",
        "",
        "## Safety Rules",
        "",
        "- This is a manual status-update draft, not an automatic repository edit.",
        "- Copy metrics-oracle transaction evidence into status files only after independent node or explorer verification.",
        "- This draft was built from a verified `operator_record` transaction result.",
        "- This script does not accept private keys, raw transactions, sign, assemble, broadcast, deploy, or update status files.",
        "",
        "## Oracle Transaction",
        "",
        f"- Contract: `{contract['name']}`",
        f"- Entrypoint: `{contract['entrypoint']}`",
        f"- Instance ID: `{contract['instance_id']}`",
        f"- TX ID: `{tx['tx_id']}`",
        f"- Block hash: `{tx['block_hash']}`",
        f"- DAA score: {tx['block_daa_score']}",
        f"- Confirmations: {tx['confirmations']}",
        f"- Confirmed at: `{tx['confirmed_at']}`",
        f"- Metrics payload SHA-256: `{metrics['payload_sha256']}`",
        f"- Entrypoint args SHA-256: `{metrics['entrypoint_args_sha256']}`",
        "",
        "## Required Manual Checks",
        "",
    ]
    lines.extend(f"{index}. {step}" for index, step in enumerate(status["manual_checks"], start=1))

    target = path.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_status(result_summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "status": "READY_FOR_MANUAL_ORACLE_STATUS_UPDATE",
        "network": result_summary["network"],
        "provenance_type": result_summary["provenance_type"],
        "assembler": result_summary["assembler"],
        "recorded_at": result_summary["recorded_at"],
        "silverscript_commit": result_summary["silverscript_commit"],
        "tx_request_sha256": result_summary["tx_request_sha256"],
        "tx_result_sha256": result_summary["tx_result_sha256"],
        "contract": result_summary["contract"],
        "metrics_report": result_summary["metrics_report"],
        "transaction": result_summary["transaction"],
        "manual_checks": [
            "Verify the transaction ID and block hash against a trusted node or explorer.",
            "Verify the transaction invokes GovernanceAutoTuningState.reportMetrics for the expected instance ID.",
            "Verify confirmations and DAA score are current enough for the selected release policy.",
            "Use this evidence together with verified deployment receipts before updating public release status.",
        ],
        "safety": {
            "accepts_private_keys": False,
            "accepts_raw_transactions": False,
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
        request_summary = validate_request(load_json(args.tx_request.expanduser().resolve()), manifest)
        result_summary = validate_result(load_json(args.tx_result.expanduser().resolve()), request_summary)
        status = build_status(result_summary)
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
