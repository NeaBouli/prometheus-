#!/usr/bin/env python3
"""Validate a public GovernanceAutoTuning metrics-oracle report."""

from __future__ import annotations

import argparse
import json
import re
import sys
from hashlib import sha256
from pathlib import Path
from typing import Any

NETWORKS = ("sandbox", "testnet", "mainnet")
CONTRACT_NAME = "GovernanceAutoTuningState"
ENTRYPOINT = "reportMetrics"
MAX_FP_RATE = 10_000
HEX_32_BYTES_RE = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")
SECRET_KEY_RE = re.compile(
    r"(private|secret|seed|mnemonic|password|passwd|wallet|keystore|token)",
    re.IGNORECASE,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Preflight-check a public metrics-oracle report for "
            "GovernanceAutoTuningState.reportMetrics. This does not sign or broadcast."
        )
    )
    parser.add_argument("--report", type=Path, required=True, help="Public metrics report JSON")
    parser.add_argument("--plan-out", type=Path, help="Optional JSON preflight plan path")
    parser.add_argument("--runbook-out", type=Path, help="Optional Markdown operator handoff path")
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected JSON object")
    return data


def reject_secret_fields(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if SECRET_KEY_RE.search(str(key)):
                raise ValueError(f"{path}.{key}: secret-like fields are not allowed in oracle reports")
            reject_secret_fields(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_secret_fields(item, f"{path}[{index}]")


def require_int(data: dict[str, Any], key: str, *, minimum: int | None = None, maximum: int | None = None) -> int:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{key}: expected integer")
    if minimum is not None and value < minimum:
        raise ValueError(f"{key}: expected >= {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{key}: expected <= {maximum}")
    return value


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(value: Any) -> str:
    return sha256(canonical_json_bytes(value)).hexdigest()


def validate_report(report: dict[str, Any]) -> dict[str, Any]:
    reject_secret_fields(report)

    if report.get("schema_version") != 1:
        raise ValueError("schema_version: expected 1")
    network = report.get("network")
    if network not in NETWORKS:
        raise ValueError(f"network: expected one of {', '.join(NETWORKS)}")
    if report.get("contract") != CONTRACT_NAME:
        raise ValueError(f"contract: expected {CONTRACT_NAME}")
    if report.get("entrypoint") != ENTRYPOINT:
        raise ValueError(f"entrypoint: expected {ENTRYPOINT}")

    oracle_pubkey = report.get("metrics_oracle_pubkey")
    if not isinstance(oracle_pubkey, str) or not HEX_32_BYTES_RE.match(oracle_pubkey):
        raise ValueError("metrics_oracle_pubkey: expected 32-byte public key hex")

    previous_state = report.get("previous_state")
    if not isinstance(previous_state, dict):
        raise ValueError("previous_state: expected object")
    last_metrics_block = require_int(previous_state, "last_metrics_block", minimum=0)

    metrics = report.get("metrics")
    if not isinstance(metrics, dict):
        raise ValueError("metrics: expected object")
    active_validators = require_int(metrics, "active_validators", minimum=0)
    active_guardians = require_int(metrics, "active_guardians", minimum=0)
    proposals_per_day = require_int(metrics, "proposals_per_day", minimum=0)
    fp_rate = require_int(metrics, "fp_rate", minimum=0, maximum=MAX_FP_RATE)
    block_height = require_int(metrics, "block_height", minimum=0)
    if block_height < last_metrics_block:
        raise ValueError("metrics.block_height must be >= previous_state.last_metrics_block")

    sources = report.get("sources", [])
    if not isinstance(sources, list):
        raise ValueError("sources: expected list when present")
    for index, source in enumerate(sources):
        if not isinstance(source, dict):
            raise ValueError(f"sources[{index}]: expected object")
        if not source.get("name"):
            raise ValueError(f"sources[{index}].name: required")

    payload = {
        "schema_version": 1,
        "network": network,
        "contract": CONTRACT_NAME,
        "entrypoint": ENTRYPOINT,
        "metrics_oracle_pubkey": oracle_pubkey.lower().removeprefix("0x"),
        "previous_state": {"last_metrics_block": last_metrics_block},
        "metrics": {
            "active_validators": active_validators,
            "active_guardians": active_guardians,
            "proposals_per_day": proposals_per_day,
            "fp_rate": fp_rate,
            "block_height": block_height,
        },
        "sources": sources,
    }
    return payload


def build_plan(payload: dict[str, Any]) -> dict[str, Any]:
    metrics = payload["metrics"]
    entrypoint_args = {
        "new_active_validators": metrics["active_validators"],
        "new_active_guardians": metrics["active_guardians"],
        "new_proposals_per_day": metrics["proposals_per_day"],
        "new_fp_rate": metrics["fp_rate"],
        "block_height": metrics["block_height"],
        "oracle_sig": "external_wallet_signature_required",
    }
    return {
        "schema_version": 1,
        "status": "READY_FOR_TX_BUILDER",
        "network": payload["network"],
        "contract": payload["contract"],
        "entrypoint": payload["entrypoint"],
        "payload_sha256": sha256_hex(payload),
        "entrypoint_args": entrypoint_args,
        "safety": {
            "accepts_private_keys": False,
            "signs_transactions": False,
            "broadcasts_transactions": False,
        },
        "operator_next_steps": [
            "Build the GovernanceAutoTuningState reportMetrics transaction with these public entrypoint arguments.",
            "Sign the transaction input with the metrics-oracle wallet outside this repository.",
            "Broadcast only through the release deploy/orchestration path after network tooling is available.",
            "Record verified transaction receipts before updating deployment status files.",
        ],
    }


def write_plan(path: Path | None, plan: dict[str, Any]) -> None:
    if not path:
        return
    target = path.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_runbook(path: Path | None, plan: dict[str, Any]) -> None:
    if not path:
        return
    args = plan["entrypoint_args"]
    lines = [
        "# Prometheus Metrics-Oracle Report Preflight",
        "",
        f"Status: {plan['status']}",
        f"Network: {plan['network']}",
        f"Contract: `{plan['contract']}`",
        f"Entrypoint: `{plan['entrypoint']}`",
        f"Payload SHA-256: `{plan['payload_sha256']}`",
        "",
        "## Safety Rules",
        "",
        "- This preflight validates public metrics only.",
        "- This preflight does not accept private keys, sign transactions, or broadcast transactions.",
        "- Metrics-oracle signing must happen in an external wallet/keychain or deployment vault.",
        "",
        "## reportMetrics Arguments",
        "",
        f"- `new_active_validators`: {args['new_active_validators']}",
        f"- `new_active_guardians`: {args['new_active_guardians']}",
        f"- `new_proposals_per_day`: {args['new_proposals_per_day']}",
        f"- `new_fp_rate`: {args['new_fp_rate']}",
        f"- `block_height`: {args['block_height']}",
        "- `oracle_sig`: external wallet signature required",
        "",
        "## Operator Sequence",
        "",
    ]
    lines.extend(f"{index}. {step}" for index, step in enumerate(plan["operator_next_steps"], start=1))
    target = path.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    payload = validate_report(load_json(args.report.expanduser().resolve()))
    plan = build_plan(payload)
    write_plan(args.plan_out, plan)
    write_runbook(args.runbook_out, plan)
    print(json.dumps(plan, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
