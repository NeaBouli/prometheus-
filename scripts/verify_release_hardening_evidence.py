#!/usr/bin/env python3
"""Verify public release-hardening evidence for a Prometheus rollout handoff."""

from __future__ import annotations

import argparse
import json
import re
import sys
from hashlib import sha256
from pathlib import Path
from typing import Any

from preflight_metrics_oracle_report import canonical_json_bytes

EVIDENCE_TYPE = "prometheus.release_hardening.public_evidence"
EVIDENCE_STATUS = "PUBLIC_RELEASE_HARDENING_EVIDENCE_VERIFIED"
DEFAULT_REPOSITORY = "NeaBouli/prometheus-"
DEFAULT_BRANCH = "main"
REQUIRED_CHECKS = {"Prometheus CI", "Security Audit", "pages-build-deployment"}
UTC_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SECRET_KEY_RE = re.compile(
    r"(private|secret|seed|mnemonic|password|passwd|wallet|keystore|token)",
    re.IGNORECASE,
)
RAW_TX_KEY_RE = re.compile(r"(raw|signed|serialized).*transaction|transaction_(hex|bytes)", re.IGNORECASE)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify public release-hardening evidence for Prometheus. This "
            "checks public CI/Pages/branch-control evidence only; it does not "
            "query GitHub, accept credentials, change repository settings, "
            "deploy, sign, assemble transactions, broadcast, or update status files."
        )
    )
    parser.add_argument("--evidence", type=Path, required=True, help="Public release-hardening evidence JSON")
    parser.add_argument("--expected-repository", default=DEFAULT_REPOSITORY)
    parser.add_argument("--expected-branch", default=DEFAULT_BRANCH)
    parser.add_argument("--expected-commit", help="Optional expected 40-byte lowercase commit SHA")
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
            if SECRET_KEY_RE.search(key_text):
                raise ValueError(f"{path}.{key}: secret-like fields are not allowed in release-hardening evidence")
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


def require_bool(data: dict[str, Any], key: str, path: str, *, expected: bool = True) -> bool:
    value = data.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"{path}.{key}: expected boolean")
    if value is not expected:
        raise ValueError(f"{path}.{key}: expected {str(expected).lower()}")
    return value


def require_str_list(data: dict[str, Any], key: str, path: str) -> list[str]:
    value = data.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{path}.{key}: expected list of non-empty strings")
    return value


def sha256_json(value: dict[str, Any]) -> str:
    return sha256(canonical_json_bytes(value)).hexdigest()


def validate_evidence(
    evidence: dict[str, Any],
    expected_repository: str,
    expected_branch: str,
    expected_commit: str | None,
) -> dict[str, Any]:
    reject_forbidden_fields(evidence)

    if evidence.get("schema_version") != 1:
        raise ValueError("evidence.schema_version: expected 1")
    if evidence.get("evidence_type") != EVIDENCE_TYPE:
        raise ValueError(f"evidence.evidence_type: expected {EVIDENCE_TYPE}")

    provenance = require_dict(evidence.get("provenance"), "evidence.provenance")
    if provenance.get("type") not in {"github_public_snapshot", "operator_release_review"}:
        raise ValueError("evidence.provenance.type: expected github_public_snapshot or operator_release_review")
    observer = require_str(provenance, "observer", "evidence.provenance")
    observed_at = require_str(provenance, "observed_at", "evidence.provenance")
    if not UTC_TIMESTAMP_RE.match(observed_at):
        raise ValueError("evidence.provenance.observed_at: expected UTC timestamp")

    repository = require_dict(evidence.get("repository"), "evidence.repository")
    full_name = require_str(repository, "full_name", "evidence.repository")
    default_branch = require_str(repository, "default_branch", "evidence.repository")
    protected_branch = require_str(repository, "protected_branch", "evidence.repository")
    commit_sha = require_str(repository, "commit_sha", "evidence.repository")
    if full_name != expected_repository:
        raise ValueError("evidence.repository.full_name mismatch")
    if default_branch != expected_branch or protected_branch != expected_branch:
        raise ValueError("evidence.repository branch mismatch")
    if not COMMIT_RE.match(commit_sha):
        raise ValueError("evidence.repository.commit_sha: expected lowercase 40-byte git SHA")
    if expected_commit is not None and commit_sha != expected_commit:
        raise ValueError("evidence.repository.commit_sha mismatch")

    checks = require_dict(evidence.get("checks"), "evidence.checks")
    successful = set(require_str_list(checks, "successful_workflows", "evidence.checks"))
    missing_checks = sorted(REQUIRED_CHECKS - successful)
    if missing_checks:
        raise ValueError("evidence.checks.successful_workflows missing: " + ", ".join(missing_checks))
    require_bool(checks, "all_required_checks_green", "evidence.checks")
    require_bool(checks, "pages_deployment_green", "evidence.checks")
    require_bool(checks, "dependency_audit_green", "evidence.checks")
    require_bool(checks, "gitleaks_green", "evidence.checks")

    branch_rules = require_dict(evidence.get("branch_rules"), "evidence.branch_rules")
    require_bool(branch_rules, "pull_request_required", "evidence.branch_rules")
    require_bool(branch_rules, "required_status_checks_enforced", "evidence.branch_rules")
    required_status_checks = set(require_str_list(branch_rules, "required_status_checks", "evidence.branch_rules"))
    missing_required_status = sorted(REQUIRED_CHECKS - required_status_checks)
    if missing_required_status:
        raise ValueError(
            "evidence.branch_rules.required_status_checks missing: " + ", ".join(missing_required_status)
        )
    require_bool(branch_rules, "force_pushes_blocked", "evidence.branch_rules")
    require_bool(branch_rules, "branch_deletions_blocked", "evidence.branch_rules")
    require_bool(branch_rules, "admin_bypass_for_release", "evidence.branch_rules", expected=False)

    controls = require_dict(evidence.get("release_controls"), "evidence.release_controls")
    require_bool(controls, "operator_handoff_review_required", "evidence.release_controls")
    require_bool(controls, "rollback_plan_documented", "evidence.release_controls")
    require_bool(controls, "status_updates_manual_after_evidence", "evidence.release_controls")
    require_bool(controls, "public_pages_verified", "evidence.release_controls")
    require_bool(controls, "release_notes_required", "evidence.release_controls")

    return {
        "schema_version": 1,
        "status": EVIDENCE_STATUS,
        "repository": {
            "full_name": full_name,
            "protected_branch": protected_branch,
            "commit_sha": commit_sha,
        },
        "provenance_type": provenance["type"],
        "observer": observer,
        "observed_at": observed_at,
        "evidence_sha256": sha256_json(evidence),
        "required_workflows": sorted(REQUIRED_CHECKS),
        "branch_rules": {
            "pull_request_required": True,
            "required_status_checks_enforced": True,
            "force_pushes_blocked": True,
            "branch_deletions_blocked": True,
            "admin_bypass_for_release": False,
        },
        "release_controls": {
            "operator_handoff_review_required": True,
            "rollback_plan_documented": True,
            "status_updates_manual_after_evidence": True,
            "public_pages_verified": True,
            "release_notes_required": True,
        },
        "safety": {
            "accepts_private_keys": False,
            "accepts_raw_transactions": False,
            "signs_transactions": False,
            "assembles_chain_transaction": False,
            "broadcasts_transactions": False,
            "deploys_contracts": False,
            "updates_status_files": False,
            "changes_repository_settings": False,
        },
        "operator_next_steps": [
            "Keep this public evidence with the operator handoff package.",
            "Re-verify the evidence for the exact release commit before rollout.",
            "Do not use admin bypass for the release path.",
            "Update status files only after deploy receipts, receipt evidence, oracle tx evidence, and release-hardening evidence all verify.",
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
    repo = summary["repository"]
    lines = [
        "# Prometheus Release Hardening Evidence",
        "",
        f"Status: {summary['status']}",
        f"Repository: `{repo['full_name']}`",
        f"Protected branch: `{repo['protected_branch']}`",
        f"Commit SHA: `{repo['commit_sha']}`",
        f"Evidence SHA-256: `{summary['evidence_sha256']}`",
        f"Observed at: `{summary['observed_at']}`",
        "",
        "## Safety Rules",
        "",
        "- This verifier accepts public release-hardening evidence only.",
        "- This verifier rejects secret-like and raw/serialized transaction fields.",
        "- This verifier does not query GitHub, accept credentials, change repository settings, deploy, sign, assemble, broadcast, or update status files.",
        "",
        "## Required Workflows",
        "",
    ]
    lines.extend(f"- `{name}`" for name in summary["required_workflows"])
    lines.extend(["", "## Operator Next Steps", ""])
    lines.extend(f"{index}. {step}" for index, step in enumerate(summary["operator_next_steps"], start=1))

    target = path.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    expected_commit = args.expected_commit
    if expected_commit is not None and not COMMIT_RE.match(expected_commit):
        raise ValueError("--expected-commit must be a lowercase 40-byte git SHA")
    summary = validate_evidence(
        load_json(args.evidence.expanduser().resolve()),
        args.expected_repository,
        args.expected_branch,
        expected_commit,
    )
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
