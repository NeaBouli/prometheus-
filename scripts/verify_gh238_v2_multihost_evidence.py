#!/usr/bin/env python3
"""Validate schema and redaction policy for one public GH-238 v2 record.

This gate validates the closed public schema, the exact Guardian v2 protocol
binding, the non-authorizing outcome and the redaction policy for issue 238.
It cannot recompute private operator attestations because the challenge,
binaries and canonical payload intentionally remain outside Git. The record
never claims independent host proof, public networking, proof validity,
approval/membership/privacy authority, deployment, Mainnet or production.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any

LOWER_HEX_32 = re.compile(r"^[0-9a-f]{64}$")
LOWER_HEX_20 = re.compile(r"^[0-9a-f]{40}$")
UTC_TIMESTAMP = re.compile(
    r"^2026-[0-9]{2}-[0-9]{2}T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)
EARLIEST_OBSERVATION = dt.datetime(2026, 8, 30, tzinfo=dt.timezone.utc)
TOOLCHAIN = re.compile(
    r"^rustc 1\.95\.0 \([0-9a-f]{9} 2026-[0-9]{2}-[0-9]{2}\)(?: \(Homebrew\))?$"
)
PROTOCOL = "/prometheus/threat-hint/2.0.0"
IPV4_LITERAL = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
IPV6_LITERAL = re.compile(r"(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F]{0,4}")
FORBIDDEN_VALUE_FRAGMENTS = (
    "/ip4/",
    "/ip6/",
    "/dns",
    "/tcp/",
    "/udp/",
    "/quic",
    "/p2p/",
    "12D3Koo",
    "kaspa:",
    "kaspatest:",
    "BEGIN PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "PRIVATE KEY",
    "MNEMONIC",
    "SEED PHRASE",
    "SECRET",
    "PASSWORD",
    "KEYSTORE",
    "WALLET",
    "SIGNATURE",
)
TOP_LEVEL_KEYS = {
    "schema_version",
    "evidence_kind",
    "issue",
    "observed_at_utc",
    "source_commit",
    "network",
    "runtime",
    "transport",
    "protocol",
    "route_scope",
    "separation_claim",
    "challenge_sha256",
    "artifacts",
    "execution_attestations",
    "delivery",
    "safety",
}
ARTIFACT_KEYS = {"client_sha256", "guardian_sha256", "toolchain"}
ATTESTATION_KEYS = {"sender_sha256", "guardian_sha256"}
DELIVERY_KEYS = {
    "payload_sha256",
    "sender_status",
    "guardian_receipt_status",
    "ack_scope",
    "ack_authority",
    "attempts",
    "retries",
    "persisted",
}
SAFETY_KEYS = {
    "contains_network_identifiers",
    "contains_raw_payload",
    "contains_secrets",
    "chain_writes",
    "wallet_or_signing",
    "independent_host_proof",
    "public_networking",
    "proof_validity",
    "approval_membership_or_privacy_authority",
    "deployment",
    "mainnet",
    "production",
}


class EvidenceError(ValueError):
    """Raised when public evidence fails its closed schema or safety policy."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON object members at every nesting level."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("evidence contains duplicate object members")
        result[key] = value
    return result


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise EvidenceError(f"{label} must be an object")
    return value


def _require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise EvidenceError(f"{label} has an invalid field set")


def _require_lower_hex(value: Any, label: str, pattern: re.Pattern[str]) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise EvidenceError(f"{label} must be canonical lowercase hexadecimal")
    return value


def _reject_sensitive_content(value: Any, key: str = "root") -> None:
    if type(value) is dict:
        for child_key, child_value in value.items():
            if type(child_key) is not str:
                raise EvidenceError("evidence keys must be strings")
            _reject_sensitive_content(child_value, child_key)
    elif type(value) is list:
        raise EvidenceError("evidence arrays are not allowed")
    elif type(value) is str:
        if any(
            fragment.casefold() in value.casefold()
            for fragment in FORBIDDEN_VALUE_FRAGMENTS
        ):
            raise EvidenceError("evidence contains a prohibited value category")
        if IPV4_LITERAL.search(value):
            raise EvidenceError("evidence contains a network identifier")
        if UTC_TIMESTAMP.fullmatch(value) is None and IPV6_LITERAL.search(value):
            raise EvidenceError("evidence contains a network identifier")
        if value != PROTOCOL and (
            "/" in value or "\\" in value or value.startswith("~")
        ):
            raise EvidenceError("evidence contains a path category value")


def verify_evidence(data: dict[str, Any]) -> None:
    """Validate one strict public GH-238 v2 record's schema and redaction policy."""
    _require_exact_keys(data, TOP_LEVEL_KEYS, "evidence")
    _reject_sensitive_content(data)

    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise EvidenceError("evidence identity is invalid")
    if type(data["issue"]) is not int or data["issue"] != 238:
        raise EvidenceError("evidence identity is invalid")
    if (
        data["evidence_kind"]
        != "operator_attested_controlled_two_host_threat_hint_v2_delivery"
    ):
        raise EvidenceError("evidence kind is invalid")
    if (
        type(data["observed_at_utc"]) is not str
        or UTC_TIMESTAMP.fullmatch(data["observed_at_utc"]) is None
    ):
        raise EvidenceError("evidence timestamp is invalid")
    try:
        observed_at = dt.datetime.strptime(
            data["observed_at_utc"], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=dt.timezone.utc)
    except ValueError as error:
        raise EvidenceError("evidence timestamp is invalid") from error
    if observed_at < EARLIEST_OBSERVATION:
        raise EvidenceError("evidence predates the controlled run boundary")
    _require_lower_hex(data["source_commit"], "source commit", LOWER_HEX_20)
    if data["network"] != "testnet-10" or data["runtime"] != "development-only":
        raise EvidenceError("runtime or network boundary is invalid")
    if data["transport"] != "direct-quic-v1":
        raise EvidenceError("transport boundary is invalid")
    if data["protocol"] != PROTOCOL:
        raise EvidenceError("protocol binding is invalid")
    if data["route_scope"] != "single-static-controlled-remote-quic-peer":
        raise EvidenceError("route scope is invalid")
    if data["separation_claim"] != "operator-attested-not-independently-proven":
        raise EvidenceError("host separation claim is invalid")
    _require_lower_hex(data["challenge_sha256"], "challenge digest", LOWER_HEX_32)

    artifacts = _require_object(data["artifacts"], "artifacts")
    _require_exact_keys(artifacts, ARTIFACT_KEYS, "artifacts")
    client_artifact = _require_lower_hex(
        artifacts["client_sha256"], "client artifact", LOWER_HEX_32
    )
    guardian_artifact = _require_lower_hex(
        artifacts["guardian_sha256"], "guardian artifact", LOWER_HEX_32
    )
    if client_artifact == guardian_artifact:
        raise EvidenceError("host artifacts must be distinct")
    if (
        type(artifacts["toolchain"]) is not str
        or TOOLCHAIN.fullmatch(artifacts["toolchain"]) is None
    ):
        raise EvidenceError("toolchain binding is invalid")

    attestations = _require_object(
        data["execution_attestations"], "execution attestations"
    )
    _require_exact_keys(attestations, ATTESTATION_KEYS, "execution attestations")
    sender_attestation = _require_lower_hex(
        attestations["sender_sha256"], "sender attestation", LOWER_HEX_32
    )
    guardian_attestation = _require_lower_hex(
        attestations["guardian_sha256"], "guardian attestation", LOWER_HEX_32
    )
    if sender_attestation == guardian_attestation:
        raise EvidenceError("execution attestations must be distinct")

    delivery = _require_object(data["delivery"], "delivery")
    _require_exact_keys(delivery, DELIVERY_KEYS, "delivery")
    _require_lower_hex(delivery["payload_sha256"], "payload digest", LOWER_HEX_32)
    if delivery["sender_status"] != "rejected":
        raise EvidenceError("sender status must remain non-authorizing")
    if delivery["guardian_receipt_status"] != "rejected":
        raise EvidenceError("Guardian receipt must remain non-authorizing")
    if delivery["ack_scope"] != "remote-local-boundary-only":
        raise EvidenceError("acknowledgement scope is invalid")
    if delivery["ack_authority"] != "none":
        raise EvidenceError("acknowledgement authority must remain none")
    if (
        type(delivery["attempts"]) is not int
        or delivery["attempts"] != 1
        or type(delivery["retries"]) is not int
        or delivery["retries"] != 0
        or delivery["persisted"] is not False
    ):
        raise EvidenceError("delivery retry or persistence boundary is invalid")

    safety = _require_object(data["safety"], "safety")
    _require_exact_keys(safety, SAFETY_KEYS, "safety")
    if any(safety[field] is not False for field in SAFETY_KEYS):
        raise EvidenceError("all public safety flags must remain false")


def load_and_verify(path: Path) -> None:
    """Load and verify one evidence file without echoing its contents."""
    try:
        data = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError("evidence file is missing or invalid") from error
    verify_evidence(_require_object(data, "evidence"))


def main() -> int:
    """CLI entry point with data-minimal diagnostics."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--evidence",
        type=Path,
        required=True,
        help="path to the redacted operator-attested v2 evidence record",
    )
    args = parser.parse_args()
    try:
        load_and_verify(args.evidence)
    except EvidenceError as error:
        print(f"GH238_EVIDENCE_REJECTED: {error}", file=sys.stderr)
        return 1
    print("GH238_PUBLIC_RECORD_SCHEMA_REDACTION_VERIFIED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
