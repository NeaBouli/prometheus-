#!/usr/bin/env python3
"""Verify the repository-public H-001 canary closeout evidence bindings."""

from __future__ import annotations

import argparse
import json
import re
from hashlib import sha256
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = ROOT / "docs" / "evidence"
DEFAULT_SUMMARY = EVIDENCE_DIR / "gh-9-h001-canary-confirmed-2026-08-12.json"
DEFAULT_RECEIPTS = EVIDENCE_DIR / "gh-9-h001-operator-receipts-2026-08-12.json"
DEFAULT_EVIDENCE = EVIDENCE_DIR / "gh-9-h001-public-evidence-2026-08-12.json"
HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
FORBIDDEN_KEY_RE = re.compile(
    r"private|secret|seed|mnemonic|password|passwd|wallet|keystore|"
    r"signature_(hex|bytes)|raw_?(signed_?)?transaction|transaction_(hex|bytes)",
    re.IGNORECASE,
)


class EvidenceValidationError(ValueError):
    """Raised when public closeout evidence is inconsistent or unsafe."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--receipts", type=Path, default=DEFAULT_RECEIPTS)
    parser.add_argument("--evidence", type=Path, default=DEFAULT_EVIDENCE)
    return parser.parse_args()


def load_document(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise EvidenceValidationError(f"{path}: expected a JSON object")
    return value


def canonical_sha256(value: dict[str, Any]) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(payload).hexdigest()


def reject_nonpublic_fields(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if FORBIDDEN_KEY_RE.search(key) and child is not False:
                raise EvidenceValidationError(f"{child_path}: forbidden public evidence field")
            reject_nonpublic_fields(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_nonpublic_fields(child, f"{path}[{index}]")


def require_equal(actual: Any, expected: Any, field: str) -> None:
    if actual != expected:
        raise EvidenceValidationError(f"{field}: expected {expected!r}, got {actual!r}")


def verify_documents(
    summary: dict[str, Any],
    receipts: dict[str, Any],
    evidence: dict[str, Any],
) -> None:
    for document in (summary, receipts, evidence):
        reject_nonpublic_fields(document)

    require_equal(summary.get("schema_version"), 1, "summary.schema_version")
    require_equal(
        summary.get("kind"),
        "prometheus.silverc.h001_confirmed_canary_evidence",
        "summary.kind",
    )
    require_equal(
        summary.get("status"),
        "PUBLIC_CANARY_DEPLOY_EVIDENCE_VERIFIED",
        "summary.status",
    )
    require_equal(receipts.get("schema_version"), 1, "receipts.schema_version")
    require_equal(evidence.get("schema_version"), 1, "evidence.schema_version")
    require_equal(
        evidence.get("evidence_type"),
        "prometheus_silverc_deploy_receipt_public_evidence",
        "evidence.evidence_type",
    )

    verification = summary.get("verification")
    binding = summary.get("hash_binding")
    if not isinstance(verification, dict) or not isinstance(binding, dict):
        raise EvidenceValidationError("summary verification/hash_binding must be objects")
    require_equal(
        binding.get("canonicalization"),
        "UTF-8 JSON with sorted keys and compact separators "
        "(comma and colon), without trailing newline",
        "summary.hash_binding.canonicalization",
    )
    require_equal(binding.get("summary_self_hash"), False, "summary.hash_binding.summary_self_hash")

    receipts_hash = canonical_sha256(receipts)
    evidence_hash = canonical_sha256(evidence)
    for digest, field in (
        (receipts_hash, "operator_receipts_sha256"),
        (evidence_hash, "public_evidence_sha256"),
    ):
        if not HEX_64_RE.fullmatch(digest):
            raise EvidenceValidationError(f"computed {field} is not canonical lowercase SHA-256")
        require_equal(verification.get(field), digest, f"summary.verification.{field}")
    require_equal(evidence.get("receipts_sha256"), receipts_hash, "evidence.receipts_sha256")

    profile = receipts.get("deployment_profile")
    if not isinstance(profile, dict):
        raise EvidenceValidationError("receipts.deployment_profile must be an object")
    require_equal(evidence.get("deployment_profile"), profile, "evidence.deployment_profile")
    require_equal(
        summary.get("deployment_profile"),
        profile.get("name"),
        "summary.deployment_profile",
    )
    require_equal(summary.get("network"), receipts.get("network"), "summary.network")
    require_equal(evidence.get("network"), receipts.get("network"), "evidence.network")

    receipt_rows = receipts.get("receipts")
    observations = evidence.get("observations")
    if not isinstance(receipt_rows, list) or len(receipt_rows) != 1:
        raise EvidenceValidationError("receipts.receipts must contain exactly one record")
    if not isinstance(observations, list) or len(observations) != 1:
        raise EvidenceValidationError("evidence.observations must contain exactly one record")
    receipt = receipt_rows[0]
    observation = observations[0]
    transaction = summary.get("transaction")
    if not all(isinstance(item, dict) for item in (receipt, observation, transaction)):
        raise EvidenceValidationError(
            "receipt, observation, and summary transaction must be objects"
        )
    for field in ("deploy_tx_id", "deployed_instance_id", "block_hash"):
        require_equal(observation.get(field), receipt.get(field), f"observation.{field}")
    require_equal(
        transaction.get("transaction_id"),
        receipt.get("deploy_tx_id"),
        "summary.transaction_id",
    )
    require_equal(transaction.get("block_hash"), receipt.get("block_hash"), "summary.block_hash")
    require_equal(transaction.get("accepted"), True, "summary.transaction.accepted")
    require_equal(receipt.get("status"), "confirmed", "receipt.status")
    require_equal(observation.get("status"), "confirmed", "observation.status")

    safety = summary.get("safety")
    if (
        not isinstance(safety, dict)
        or not safety
        or any(value is not False for value in safety.values())
    ):
        raise EvidenceValidationError("summary.safety must contain only explicit false values")
    scope = summary.get("scope")
    if not isinstance(scope, dict):
        raise EvidenceValidationError("summary.scope must be an object")
    require_equal(scope.get("canary_complete"), True, "summary.scope.canary_complete")
    require_equal(scope.get("promotes_full_rollout"), False, "summary.scope.promotes_full_rollout")
    require_equal(
        scope.get("remaining_gates_complete"),
        True,
        "summary.scope.remaining_gates_complete",
    )
    gates = scope.get("remaining_gates")
    if (
        not isinstance(gates, list)
        or len(gates) != 6
        or not all(isinstance(gate, str) for gate in gates)
    ):
        raise EvidenceValidationError("summary.scope.remaining_gates must contain six gate strings")


def verify_paths(summary_path: Path, receipts_path: Path, evidence_path: Path) -> None:
    summary = load_document(summary_path)
    receipts = load_document(receipts_path)
    evidence = load_document(evidence_path)
    binding = summary.get("hash_binding")
    if not isinstance(binding, dict):
        raise EvidenceValidationError("summary.hash_binding must be an object")
    require_equal(
        binding.get("operator_receipts_sha256_target"),
        receipts_path.name,
        "summary.hash_binding.operator_receipts_sha256_target",
    )
    require_equal(
        binding.get("public_evidence_sha256_target"),
        evidence_path.name,
        "summary.hash_binding.public_evidence_sha256_target",
    )
    verify_documents(summary, receipts, evidence)


def main() -> int:
    args = parse_args()
    verify_paths(args.summary, args.receipts, args.evidence)
    print("H001_CANARY_CLOSEOUT_EVIDENCE_VERIFIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
