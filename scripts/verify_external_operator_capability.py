#!/usr/bin/env python3
"""Verify a public external-operator capability record against operator procedures."""

from __future__ import annotations

import argparse
import json
import re
import sys
from hashlib import sha256
from pathlib import Path
from typing import Any

from build_metrics_oracle_operator_procedure import PROCEDURE_KIND as METRICS_PROCEDURE_KIND
from build_metrics_oracle_operator_procedure import PROCEDURE_STATUS as METRICS_PROCEDURE_STATUS
from build_silverc_deploy_operator_procedure import PROCEDURE_KIND as DEPLOY_PROCEDURE_KIND
from build_silverc_deploy_operator_procedure import PROCEDURE_STATUS as DEPLOY_PROCEDURE_STATUS
from build_silverc_deploy_operator_procedure import GENESIS_PROFILE
from smoke_silverc_artifacts import canonical_json_bytes

CAPABILITY_KIND = "prometheus.external_operator.public_capability"
CAPABILITY_STATUS = "PUBLIC_CAPABILITY_ATTESTED"
VERIFIED_STATUS = "EXTERNAL_OPERATOR_CAPABILITY_VERIFIED"
PUBLIC_ID_RE = re.compile(r"^[A-Za-z0-9:._/-]{4,200}$")
UTC_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SECRET_KEY_RE = re.compile(
    r"(private|secret|seed|mnemonic|password|passwd|wallet|keystore|token)",
    re.IGNORECASE,
)
RAW_TX_KEY_RE = re.compile(r"(raw|signed|serialized).*transaction|transaction_(hex|bytes)", re.IGNORECASE)
ALLOWED_SECRET_WORD_KEYS = {"accepts_private_keys"}
ALLOWED_RAW_WORD_KEYS = {"accepts_raw_transactions"}
EXPECTED_FALSE_SAFETY_FLAGS = {
    "accepts_private_keys",
    "accepts_raw_transactions",
    "signs_transactions",
    "assembles_chain_transaction",
    "broadcasts_transactions",
    "deploys_contracts",
    "updates_status_files",
}
EXPECTED_BOUNDARY_FLAGS = {
    "public_artifacts_only",
    "operator_records_only",
    "signing_material_external",
    "status_updates_manual",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify a public external-operator capability record against the deploy "
            "and optional metrics-oracle operator procedures. This checker accepts "
            "public metadata only; it does not accept keys, raw transactions, sign, "
            "assemble, broadcast, deploy, or update status files."
        )
    )
    parser.add_argument("--capability", type=Path, required=True, help="Public external operator capability JSON")
    parser.add_argument("--deploy-procedure", type=Path, required=True, help="Deploy operator procedure JSON")
    parser.add_argument("--metrics-procedure", type=Path, help="Optional metrics-oracle operator procedure JSON")
    parser.add_argument("--summary-out", type=Path, help="Optional JSON verification summary path")
    parser.add_argument("--runbook-out", type=Path, help="Optional Markdown verification runbook path")
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
                raise ValueError(f"{path}.{key}: secret-like fields are not allowed in operator capability records")
            if key_text not in ALLOWED_RAW_WORD_KEYS and RAW_TX_KEY_RE.search(key_text):
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


def require_int(data: dict[str, Any], key: str, path: str, *, minimum: int = 0) -> int:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{path}.{key}: expected integer")
    if value < minimum:
        raise ValueError(f"{path}.{key}: expected >= {minimum}")
    return value


def require_false_safety_flags(data: dict[str, Any], path: str) -> None:
    safety = require_dict(data.get("safety"), f"{path}.safety")
    missing = EXPECTED_FALSE_SAFETY_FLAGS - set(safety)
    extra = set(safety) - EXPECTED_FALSE_SAFETY_FLAGS
    if missing:
        raise ValueError(f"{path}.safety: missing flags: {', '.join(sorted(missing))}")
    if extra:
        raise ValueError(f"{path}.safety: unexpected flags: {', '.join(sorted(extra))}")
    for key in EXPECTED_FALSE_SAFETY_FLAGS:
        if safety[key] is not False:
            raise ValueError(f"{path}.safety.{key}: expected false")


def require_true_boundary_flags(data: dict[str, Any]) -> None:
    boundary = require_dict(data.get("repository_boundary"), "capability.repository_boundary")
    missing = EXPECTED_BOUNDARY_FLAGS - set(boundary)
    extra = set(boundary) - EXPECTED_BOUNDARY_FLAGS
    if missing:
        raise ValueError(f"capability.repository_boundary: missing flags: {', '.join(sorted(missing))}")
    if extra:
        raise ValueError(f"capability.repository_boundary: unexpected flags: {', '.join(sorted(extra))}")
    for key in EXPECTED_BOUNDARY_FLAGS:
        if boundary[key] is not True:
            raise ValueError(f"capability.repository_boundary.{key}: expected true")


def sha256_json(value: dict[str, Any]) -> str:
    return sha256(canonical_json_bytes(value)).hexdigest()


def validate_deploy_procedure(procedure: dict[str, Any]) -> dict[str, Any]:
    reject_forbidden_fields(procedure, "$deploy_procedure")
    if procedure.get("schema_version") != 1:
        raise ValueError("deploy_procedure.schema_version: expected 1")
    if procedure.get("kind") != DEPLOY_PROCEDURE_KIND:
        raise ValueError(f"deploy_procedure.kind: expected {DEPLOY_PROCEDURE_KIND}")
    if procedure.get("status") != DEPLOY_PROCEDURE_STATUS:
        raise ValueError(f"deploy_procedure.status: expected {DEPLOY_PROCEDURE_STATUS}")
    require_false_safety_flags(procedure, "deploy_procedure")
    if procedure.get("safety_scope") != "procedure_builder_only":
        raise ValueError("deploy_procedure.safety_scope: expected procedure_builder_only")
    request_set_sha256 = require_str(procedure, "request_set_sha256", "deploy_procedure")
    request_count = require_int(procedure, "request_count", "deploy_procedure", minimum=1)
    result_fields = require_dict(procedure.get("required_public_result_fields"), "deploy_procedure.required_public_result_fields")
    result_type = require_str(result_fields, "result_type", "deploy_procedure.required_public_result_fields")
    genesis_profile = require_dict(procedure.get("required_genesis_profile"), "deploy_procedure.required_genesis_profile")
    if genesis_profile != GENESIS_PROFILE:
        raise ValueError("deploy_procedure.required_genesis_profile mismatch")
    return {
        "network": require_str(procedure, "network", "deploy_procedure"),
        "status": procedure["status"],
        "kind": procedure["kind"],
        "request_set_sha256": request_set_sha256,
        "request_count": request_count,
        "result_type": result_type,
        "genesis_profile": genesis_profile,
        "procedure_sha256": sha256_json(procedure),
    }


def validate_metrics_procedure(procedure: dict[str, Any], network: str) -> dict[str, Any]:
    reject_forbidden_fields(procedure, "$metrics_procedure")
    if procedure.get("schema_version") != 1:
        raise ValueError("metrics_procedure.schema_version: expected 1")
    if procedure.get("kind") != METRICS_PROCEDURE_KIND:
        raise ValueError(f"metrics_procedure.kind: expected {METRICS_PROCEDURE_KIND}")
    if procedure.get("status") != METRICS_PROCEDURE_STATUS:
        raise ValueError(f"metrics_procedure.status: expected {METRICS_PROCEDURE_STATUS}")
    if procedure.get("network") != network:
        raise ValueError("metrics_procedure.network mismatch")
    require_false_safety_flags(procedure, "metrics_procedure")
    tx_request_sha256 = require_str(procedure, "tx_request_sha256", "metrics_procedure")
    contract = require_dict(procedure.get("contract"), "metrics_procedure.contract")
    result_fields = require_dict(
        procedure.get("required_public_result_fields"),
        "metrics_procedure.required_public_result_fields",
    )
    result_type = require_str(result_fields, "result_type", "metrics_procedure.required_public_result_fields")
    return {
        "network": procedure["network"],
        "status": procedure["status"],
        "kind": procedure["kind"],
        "tx_request_sha256": tx_request_sha256,
        "contract_instance_id": require_str(contract, "instance_id", "metrics_procedure.contract"),
        "result_type": result_type,
        "procedure_sha256": sha256_json(procedure),
    }


def validate_capability(
    capability: dict[str, Any],
    deploy: dict[str, Any],
    metrics: dict[str, Any] | None,
) -> dict[str, Any]:
    reject_forbidden_fields(capability, "$capability")
    if capability.get("schema_version") != 1:
        raise ValueError("capability.schema_version: expected 1")
    if capability.get("kind") != CAPABILITY_KIND:
        raise ValueError(f"capability.kind: expected {CAPABILITY_KIND}")
    if capability.get("status") != CAPABILITY_STATUS:
        raise ValueError(f"capability.status: expected {CAPABILITY_STATUS}")
    if capability.get("network") != deploy["network"]:
        raise ValueError("capability.network mismatch")
    require_false_safety_flags(capability, "capability")
    if capability.get("safety_scope") != "capability_record_only":
        raise ValueError("capability.safety_scope: expected capability_record_only")
    require_true_boundary_flags(capability)

    operator = require_dict(capability.get("operator"), "capability.operator")
    operator_id = require_str(operator, "id", "capability.operator")
    if not PUBLIC_ID_RE.match(operator_id):
        raise ValueError("capability.operator.id: expected public operator id")
    recorded_at = require_str(operator, "recorded_at", "capability.operator")
    if not UTC_TIMESTAMP_RE.match(recorded_at):
        raise ValueError("capability.operator.recorded_at: expected UTC timestamp")

    deploy_capability = require_dict(capability.get("deploy_operator"), "capability.deploy_operator")
    if deploy_capability.get("procedure_kind") != deploy["kind"]:
        raise ValueError("capability.deploy_operator.procedure_kind mismatch")
    if deploy_capability.get("procedure_status") != deploy["status"]:
        raise ValueError("capability.deploy_operator.procedure_status mismatch")
    if deploy_capability.get("request_set_sha256") != deploy["request_set_sha256"]:
        raise ValueError("capability.deploy_operator.request_set_sha256 mismatch")
    if deploy_capability.get("request_count") != deploy["request_count"]:
        raise ValueError("capability.deploy_operator.request_count mismatch")
    if deploy_capability.get("result_type") != deploy["result_type"]:
        raise ValueError("capability.deploy_operator.result_type mismatch")
    genesis_profile = require_dict(
        deploy_capability.get("genesis_profile"),
        "capability.deploy_operator.genesis_profile",
    )
    if set(genesis_profile) != set(deploy["genesis_profile"]):
        raise ValueError("capability.deploy_operator.genesis_profile fields mismatch")
    for key, expected in deploy["genesis_profile"].items():
        if genesis_profile.get(key) != expected:
            raise ValueError(f"capability.deploy_operator.genesis_profile.{key} mismatch")

    metrics_status = "NOT_PROVIDED"
    if metrics is not None:
        metrics_capability = require_dict(capability.get("metrics_oracle_operator"), "capability.metrics_oracle_operator")
        if metrics_capability.get("procedure_kind") != metrics["kind"]:
            raise ValueError("capability.metrics_oracle_operator.procedure_kind mismatch")
        if metrics_capability.get("procedure_status") != metrics["status"]:
            raise ValueError("capability.metrics_oracle_operator.procedure_status mismatch")
        if metrics_capability.get("tx_request_sha256") != metrics["tx_request_sha256"]:
            raise ValueError("capability.metrics_oracle_operator.tx_request_sha256 mismatch")
        if metrics_capability.get("contract_instance_id") != metrics["contract_instance_id"]:
            raise ValueError("capability.metrics_oracle_operator.contract_instance_id mismatch")
        if metrics_capability.get("result_type") != metrics["result_type"]:
            raise ValueError("capability.metrics_oracle_operator.result_type mismatch")
        metrics_status = metrics["status"]
    elif "metrics_oracle_operator" in capability:
        raise ValueError("capability.metrics_oracle_operator provided without --metrics-procedure")

    return {
        "schema_version": 1,
        "status": VERIFIED_STATUS,
        "network": deploy["network"],
        "operator_id": operator_id,
        "operator_recorded_at": recorded_at,
        "capability_sha256": sha256_json(capability),
        "deploy_operator_status": deploy["status"],
        "deploy_procedure_sha256": deploy["procedure_sha256"],
        "request_set_sha256": deploy["request_set_sha256"],
        "request_count": deploy["request_count"],
        "genesis_profile": deploy["genesis_profile"],
        "metrics_operator_status": metrics_status,
        "metrics_procedure_sha256": metrics["procedure_sha256"] if metrics else None,
        "tx_request_sha256": metrics["tx_request_sha256"] if metrics else None,
        "contract_instance_id": metrics["contract_instance_id"] if metrics else None,
        "safety": {
            "accepts_private_keys": False,
            "accepts_raw_transactions": False,
            "signs_transactions": False,
            "assembles_chain_transaction": False,
            "broadcasts_transactions": False,
            "deploys_contracts": False,
            "updates_status_files": False,
        },
        "safety_scope": "capability_verifier_only",
        "blockers": [],
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
        "# Prometheus External Operator Capability Verification",
        "",
        f"Status: {summary['status']}",
        f"Network: {summary['network']}",
        f"Operator ID: `{summary['operator_id']}`",
        f"Capability SHA-256: `{summary['capability_sha256']}`",
        "",
        "## Boundary",
        "",
        "- The safety flags below describe this capability verifier, not the Rust execution operator.",
        "- This verifier accepts public operator capability metadata only.",
        "- This verifier does not accept keys, raw transactions, signing material, deployment, broadcast, or status writes.",
        "- The repository genesis operator may assemble and broadcast verified transactions in memory; private signing material remains external.",
        "- This check binds the capability record to the public deploy and optional metrics-oracle operator procedures.",
        "",
        "## Bound Procedures",
        "",
        f"- Deploy operator procedure: `{summary['deploy_operator_status']}`",
        f"- Deploy request set SHA-256: `{summary['request_set_sha256']}`",
        f"- Deploy request count: `{summary['request_count']}`",
        f"- Genesis transaction version: `{summary['genesis_profile']['transaction_version']}`",
        f"- Genesis script builder: `{summary['genesis_profile']['script_public_key_builder']}`",
        f"- Genesis covenant-ID builder: `{summary['genesis_profile']['covenant_id_builder']}`",
        f"- Genesis binding order: `{summary['genesis_profile']['binding_order']}`",
        f"- Metrics operator procedure: `{summary['metrics_operator_status']}`",
    ]
    if summary["tx_request_sha256"]:
        lines.append(f"- Metrics tx request SHA-256: `{summary['tx_request_sha256']}`")
    if summary["contract_instance_id"]:
        lines.append(f"- GovernanceAutoTuning instance: `{summary['contract_instance_id']}`")
    lines.extend(["", "## Result", "", "- External capability record is verified against the public procedure hashes."])

    target = path.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    deploy = validate_deploy_procedure(load_json(args.deploy_procedure.expanduser().resolve()))
    metrics = (
        validate_metrics_procedure(load_json(args.metrics_procedure.expanduser().resolve()), deploy["network"])
        if args.metrics_procedure
        else None
    )
    capability = load_json(args.capability.expanduser().resolve())
    summary = validate_capability(capability, deploy, metrics)
    write_json(args.summary_out, summary)
    write_runbook(args.runbook_out, summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
