#!/usr/bin/env python3
"""Audit a Silverc operator handoff package for rollout readiness."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

READY_STATUS = "ROLLOUT_READY"
BLOCKED_STATUS = "ROLLOUT_BLOCKED"
HANDOFF_SUMMARY = "operator-handoff-summary.json"
ALLOWED_SECRET_WORD_KEYS = {"accepts_private_keys"}
ALLOWED_RAW_WORD_KEYS = {"accepts_raw_transactions"}
SECRET_KEY_RE = re.compile(
    r"(private|secret|seed|mnemonic|password|passwd|wallet|keystore|token)",
    re.IGNORECASE,
)
RAW_TX_KEY_RE = re.compile(r"(raw|signed|serialized).*transaction|transaction_(hex|bytes)", re.IGNORECASE)
EXPECTED_FALSE_SAFETY_FLAGS = {
    "accepts_private_keys",
    "signs_transactions",
    "assembles_chain_transaction",
    "broadcasts_transactions",
    "updates_status_files",
}
HANDOFF_FALSE_SAFETY_FLAGS = OPERATOR_PROCEDURE_FALSE_SAFETY_FLAGS = EXPECTED_FALSE_SAFETY_FLAGS | {
    "accepts_raw_transactions",
    "deploys_contracts",
}
BASE_REQUIRED_FILES = {
    HANDOFF_SUMMARY,
    "HANDOFF.md",
    "prometheus-silverc-artifacts.tar.gz",
    "deploy-preflight.json",
    "deploy-preflight.md",
    "deploy-request-set.json",
    "deploy-requests.md",
    "deploy-request-verification.json",
    "deploy-request-verification.md",
    "deploy-operator-procedure.json",
    "deploy-operator-procedure.md",
    "ci-fixture-receipt-summary.json",
    "ci-fixture-receipt-runbook.md",
    "metrics-oracle-report-preflight.json",
    "metrics-oracle-report-preflight.md",
    "metrics-oracle-tx-request.json",
    "metrics-oracle-tx-request.md",
}
OPERATOR_RECEIPT_FILES = {
    "operator-receipt-summary.json",
    "operator-receipt-runbook.md",
}
OPERATOR_RECEIPT_IMPORT_FILES = {
    "operator-receipts.from-results.json",
    "operator-receipts-import-summary.json",
    "operator-receipts-import.md",
}
METRICS_TX_RESULT_FILES = {
    "metrics-oracle-tx-result-summary.json",
    "metrics-oracle-tx-result.md",
    "metrics-oracle-status-draft.json",
    "metrics-oracle-status-draft.md",
}
METRICS_OPERATOR_PROCEDURE_FILES = {
    "metrics-oracle-operator-procedure.json",
    "metrics-oracle-operator-procedure.md",
}
EXTERNAL_OPERATOR_CAPABILITY_FILES = {
    "external-operator-capability.json",
    "external-operator-capability-summary.json",
    "external-operator-capability.md",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Audit a public Prometheus current-Silverc operator handoff package. "
            "This is a release-hardening verifier only: it does not accept keys, "
            "sign, assemble transactions, broadcast, deploy, or update status files."
        )
    )
    parser.add_argument("--handoff-dir", type=Path, required=True, help="Operator handoff directory to audit")
    parser.add_argument(
        "--require-ready",
        action="store_true",
        help="Fail unless the handoff is fully rollout-ready with no blockers",
    )
    parser.add_argument("--summary-out", type=Path, help="Optional JSON readiness summary path")
    parser.add_argument("--runbook-out", type=Path, help="Optional Markdown readiness runbook path")
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected JSON object")
    return data


def reject_forbidden_json_keys(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            if key_text not in ALLOWED_SECRET_WORD_KEYS and SECRET_KEY_RE.search(key_text):
                raise ValueError(f"{path}.{key}: secret-like fields are not allowed in readiness inputs")
            if key_text not in ALLOWED_RAW_WORD_KEYS and RAW_TX_KEY_RE.search(key_text):
                raise ValueError(f"{path}.{key}: raw or serialized transaction fields are not allowed")
            reject_forbidden_json_keys(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_forbidden_json_keys(item, f"{path}[{index}]")


def require_file(root: Path, name: str) -> Path:
    path = root / name
    if not path.is_file():
        raise ValueError(f"missing required handoff file: {name}")
    return path


def require_json(root: Path, name: str) -> dict[str, Any]:
    path = require_file(root, name)
    data = load_json(path)
    reject_forbidden_json_keys(data, f"${name}")
    return data


def actual_files(root: Path) -> list[str]:
    return sorted(str(path.relative_to(root)) for path in root.rglob("*") if path.is_file())


def validate_safety(summary: dict[str, Any], expected_flags: set[str], label: str) -> None:
    safety = summary.get("safety")
    if not isinstance(safety, dict):
        raise ValueError(f"{label}.safety: expected object")
    missing = expected_flags - set(safety)
    if missing:
        raise ValueError(f"{label}.safety: missing flags: {', '.join(sorted(missing))}")
    for flag in expected_flags:
        if safety.get(flag) is not False:
            raise ValueError(f"{label}.safety.{flag}: expected false")


def validate_included_files(root: Path, summary: dict[str, Any]) -> list[str]:
    included = summary.get("included_files")
    if not isinstance(included, list) or not all(isinstance(item, str) for item in included):
        raise ValueError("operator-handoff-summary.included_files: expected list of strings")
    actual = actual_files(root)
    if sorted(included) != actual:
        missing_from_summary = sorted(set(actual) - set(included))
        missing_on_disk = sorted(set(included) - set(actual))
        details = []
        if missing_from_summary:
            details.append("not listed: " + ", ".join(missing_from_summary))
        if missing_on_disk:
            details.append("not on disk: " + ", ".join(missing_on_disk))
        raise ValueError("operator-handoff-summary.included_files mismatch" + (": " + "; ".join(details) if details else ""))
    return actual


def required_files_for_summary(summary: dict[str, Any]) -> set[str]:
    required = set(BASE_REQUIRED_FILES)
    if summary.get("operator_receipts_status") == "READY_FOR_STATUS_RECORDING":
        required |= OPERATOR_RECEIPT_FILES
    if summary.get("operator_receipt_import_status") != "NOT_PROVIDED":
        required |= OPERATOR_RECEIPT_IMPORT_FILES
    if summary.get("metrics_tx_result_status") == "METRICS_ORACLE_TX_RESULT_VERIFIED":
        required |= METRICS_TX_RESULT_FILES
    if summary.get("metrics_tx_request_status") == "READY_FOR_EXTERNAL_TX_ASSEMBLER":
        required |= METRICS_OPERATOR_PROCEDURE_FILES
    if summary.get("external_operator_capability_status") == "EXTERNAL_OPERATOR_CAPABILITY_VERIFIED":
        required |= EXTERNAL_OPERATOR_CAPABILITY_FILES
    return required


def expect_status(doc: dict[str, Any], key: str, expected: str, label: str) -> None:
    if doc.get(key) != expected:
        raise ValueError(f"{label}.{key}: expected {expected}")


def validate_component_summaries(root: Path, handoff: dict[str, Any]) -> dict[str, str]:
    deploy_preflight = require_json(root, "deploy-preflight.json")
    deploy_request_set = require_json(root, "deploy-request-set.json")
    deploy_request_verification = require_json(root, "deploy-request-verification.json")
    deploy_operator_procedure = require_json(root, "deploy-operator-procedure.json")
    ci_receipts = require_json(root, "ci-fixture-receipt-summary.json")
    metrics_report = require_json(root, "metrics-oracle-report-preflight.json")
    metrics_tx_request = require_json(root, "metrics-oracle-tx-request.json")

    if deploy_preflight.get("deploy_supported") is not handoff.get("deploy_supported"):
        raise ValueError("deploy-preflight.deploy_supported mismatch")
    expect_status(deploy_request_set, "status", handoff["deploy_requests_status"], "deploy-request-set")
    expect_status(
        deploy_request_verification,
        "status",
        handoff["deploy_request_verification_status"],
        "deploy-request-verification",
    )
    expect_status(
        deploy_operator_procedure,
        "status",
        handoff["deploy_operator_procedure_status"],
        "deploy-operator-procedure",
    )
    validate_safety(
        deploy_operator_procedure,
        OPERATOR_PROCEDURE_FALSE_SAFETY_FLAGS,
        "deploy-operator-procedure",
    )
    expect_status(ci_receipts, "status", handoff["ci_receipts_status"], "ci-fixture-receipt-summary")
    expect_status(metrics_report, "status", handoff["metrics_report_status"], "metrics-oracle-report-preflight")
    expect_status(metrics_tx_request, "status", handoff["metrics_tx_request_status"], "metrics-oracle-tx-request")

    statuses = {
        "deploy_preflight": "READY_FOR_NETWORK_DEPLOY_TOOL" if deploy_preflight["deploy_supported"] else "BLOCKED",
        "deploy_request_set": deploy_request_set["status"],
        "deploy_request_verification": deploy_request_verification["status"],
        "deploy_operator_procedure": deploy_operator_procedure["status"],
        "ci_receipts": ci_receipts["status"],
        "metrics_report": metrics_report["status"],
        "metrics_tx_request": metrics_tx_request["status"],
    }

    if handoff.get("metrics_tx_request_status") == "READY_FOR_EXTERNAL_TX_ASSEMBLER":
        operator_procedure = require_json(root, "metrics-oracle-operator-procedure.json")
        expect_status(
            operator_procedure,
            "status",
            handoff["metrics_operator_procedure_status"],
            "metrics-oracle-operator-procedure",
        )
        validate_safety(
            operator_procedure,
            OPERATOR_PROCEDURE_FALSE_SAFETY_FLAGS,
            "metrics-oracle-operator-procedure",
        )
        statuses["metrics_operator_procedure"] = operator_procedure["status"]
    else:
        statuses["metrics_operator_procedure"] = handoff.get("metrics_operator_procedure_status", "UNKNOWN")

    if handoff.get("operator_receipts_status") == "READY_FOR_STATUS_RECORDING":
        operator_receipts = require_json(root, "operator-receipt-summary.json")
        expect_status(operator_receipts, "status", "READY_FOR_STATUS_RECORDING", "operator-receipt-summary")
        statuses["operator_receipts"] = operator_receipts["status"]
    else:
        statuses["operator_receipts"] = handoff.get("operator_receipts_status", "UNKNOWN")

    if handoff.get("operator_receipt_import_status") != "NOT_PROVIDED":
        receipt_import = require_json(root, "operator-receipts-import-summary.json")
        expect_status(
            receipt_import,
            "status",
            handoff["operator_receipt_import_status"],
            "operator-receipts-import-summary",
        )
        statuses["operator_receipt_import"] = receipt_import["status"]
    else:
        statuses["operator_receipt_import"] = "NOT_PROVIDED"

    if handoff.get("metrics_tx_result_status") == "METRICS_ORACLE_TX_RESULT_VERIFIED":
        tx_result = require_json(root, "metrics-oracle-tx-result-summary.json")
        expect_status(tx_result, "status", "METRICS_ORACLE_TX_RESULT_VERIFIED", "metrics-oracle-tx-result-summary")
        status_draft = require_json(root, "metrics-oracle-status-draft.json")
        expect_status(
            status_draft,
            "status",
            handoff["metrics_oracle_status_draft_status"],
            "metrics-oracle-status-draft",
        )
        validate_safety(status_draft, OPERATOR_PROCEDURE_FALSE_SAFETY_FLAGS, "metrics-oracle-status-draft")
        statuses["metrics_tx_result"] = tx_result["status"]
        statuses["metrics_oracle_status_draft"] = status_draft["status"]
    else:
        statuses["metrics_tx_result"] = handoff.get("metrics_tx_result_status", "UNKNOWN")
        statuses["metrics_oracle_status_draft"] = handoff.get("metrics_oracle_status_draft_status", "UNKNOWN")

    if handoff.get("external_operator_capability_status") == "EXTERNAL_OPERATOR_CAPABILITY_VERIFIED":
        capability = require_json(root, "external-operator-capability-summary.json")
        expect_status(
            capability,
            "status",
            "EXTERNAL_OPERATOR_CAPABILITY_VERIFIED",
            "external-operator-capability-summary",
        )
        if capability.get("operator_id") != handoff.get("external_operator_id"):
            raise ValueError("external-operator-capability-summary.operator_id mismatch")
        validate_safety(capability, OPERATOR_PROCEDURE_FALSE_SAFETY_FLAGS, "external-operator-capability-summary")
        statuses["external_operator_capability"] = capability["status"]
    else:
        statuses["external_operator_capability"] = handoff.get("external_operator_capability_status", "NOT_PROVIDED")

    return statuses


def validate_handoff(root: Path) -> dict[str, Any]:
    handoff = require_json(root, HANDOFF_SUMMARY)
    if handoff.get("schema_version") != 1:
        raise ValueError("operator-handoff-summary.schema_version: expected 1")
    if handoff.get("status") not in {"HANDOFF_BLOCKED", "READY_FOR_OPERATOR_DEPLOY"}:
        raise ValueError("operator-handoff-summary.status: unexpected value")
    validate_safety(handoff, HANDOFF_FALSE_SAFETY_FLAGS, "operator-handoff-summary")

    files = validate_included_files(root, handoff)
    required = required_files_for_summary(handoff)
    for name in sorted(required):
        require_file(root, name)

    component_statuses = validate_component_summaries(root, handoff)
    blockers = handoff.get("blockers")
    if not isinstance(blockers, list) or not all(isinstance(item, str) for item in blockers):
        raise ValueError("operator-handoff-summary.blockers: expected list of strings")

    readiness_blockers = list(blockers)
    if handoff["status"] == "HANDOFF_BLOCKED" and not readiness_blockers:
        raise ValueError("blocked handoff must include blockers")
    if handoff["status"] == "READY_FOR_OPERATOR_DEPLOY" and readiness_blockers:
        raise ValueError("ready handoff must not include blockers")

    ready = (
        handoff["status"] == "READY_FOR_OPERATOR_DEPLOY"
        and handoff.get("deploy_supported") is True
        and handoff.get("deploy_operator_procedure_status") == "READY_FOR_EXTERNAL_DEPLOY_OPERATOR"
        and handoff.get("operator_receipts_status") == "READY_FOR_STATUS_RECORDING"
        and handoff.get("metrics_tx_request_status") == "READY_FOR_EXTERNAL_TX_ASSEMBLER"
        and handoff.get("metrics_operator_procedure_status") == "READY_FOR_EXTERNAL_ORACLE_OPERATOR"
        and handoff.get("metrics_tx_result_status") == "METRICS_ORACLE_TX_RESULT_VERIFIED"
        and handoff.get("metrics_oracle_status_draft_status") == "READY_FOR_MANUAL_ORACLE_STATUS_UPDATE"
        and not readiness_blockers
    )

    return {
        "schema_version": 1,
        "status": READY_STATUS if ready else BLOCKED_STATUS,
        "handoff_status": handoff["status"],
        "network": handoff["network"],
        "release_archive_sha256": handoff["release_archive_sha256"],
        "silverscript_commit": handoff["silverscript_commit"],
        "deploy_supported": handoff["deploy_supported"],
        "component_statuses": component_statuses,
        "required_file_count": len(required),
        "included_file_count": len(files),
        "blockers": readiness_blockers,
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
            "Keep this audit green for every generated handoff package.",
            "Do not claim rollout readiness while blockers remain.",
            "Use only verified operator_record deployment receipts and verified metrics-oracle tx results for status updates.",
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
    lines = [
        "# Prometheus Silverc Release Readiness Audit",
        "",
        f"Status: {summary['status']}",
        f"Handoff status: {summary['handoff_status']}",
        f"Network: {summary['network']}",
        f"Silverscript commit: `{summary['silverscript_commit']}`",
        f"Release archive SHA-256: `{summary['release_archive_sha256']}`",
        "",
        "## Safety Rules",
        "",
        "- This audit accepts public handoff artifacts only.",
        "- This audit rejects secret-like keys and raw/serialized transaction fields in JSON artifacts.",
        "- This audit does not sign, assemble chain transactions, broadcast, deploy, or update status files.",
        "- `ROLLOUT_BLOCKED` is expected until real deploy/orchestration and external oracle operation evidence exist.",
        "",
        "## Component Status",
        "",
        "| Component | Status |",
        "|-----------|--------|",
    ]
    for name, status in sorted(summary["component_statuses"].items()):
        lines.append(f"| `{name}` | `{status}` |")

    lines.extend(["", "## Blockers", ""])
    blockers = summary["blockers"]
    lines.extend(f"- {blocker}" for blocker in blockers) if blockers else lines.append("- none")
    lines.extend(["", "## Operator Next Steps", ""])
    lines.extend(f"{index}. {step}" for index, step in enumerate(summary["operator_next_steps"], start=1))

    target = path.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    root = args.handoff_dir.expanduser().resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"handoff directory not found: {root}")
    summary = validate_handoff(root)
    if args.require_ready and summary["status"] != READY_STATUS:
        raise ValueError("release readiness audit is blocked: " + "; ".join(summary["blockers"]))
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
