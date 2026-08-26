#!/usr/bin/env python3
"""Regression tests for the redacted GH-229 public evidence gate."""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("verify_gh229_multihost_evidence.py")
SPEC = importlib.util.spec_from_file_location("gh229_evidence", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def valid_evidence() -> dict[str, object]:
    """Return a synthetic, public-safe record used only by unit tests."""
    return {
        "schema_version": 1,
        "evidence_kind": "operator_attested_controlled_two_host_delivery",
        "issue": 229,
        "observed_at_utc": "2026-08-26T12:34:56Z",
        "source_commit": "1" * 40,
        "network": "testnet-10",
        "runtime": "development-only",
        "transport": "direct-quic-v1",
        "route_scope": "single-static-controlled-remote-quic-peer",
        "separation_claim": "operator-attested-not-independently-proven",
        "challenge_sha256": "2" * 64,
        "artifacts": {
            "client_sha256": "3" * 64,
            "guardian_sha256": "4" * 64,
            "toolchain": "rustc 1.95.0 (59807616e 2026-04-14) (Homebrew)",
        },
        "execution_attestations": {
            "sender_sha256": "5" * 64,
            "guardian_sha256": "6" * 64,
        },
        "delivery": {
            "payload_sha256": "7" * 64,
            "sender_status": "rejected",
            "guardian_receipt_status": "rejected",
            "ack_scope": "remote-local-boundary-only",
            "ack_authority": "none",
            "retries": 0,
            "persisted": False,
        },
        "safety": {
            "contains_network_identifiers": False,
            "contains_raw_payload": False,
            "contains_secrets": False,
            "chain_writes": False,
            "wallet_or_signing": False,
            "deployment": False,
            "mainnet": False,
            "production": False,
        },
    }


class Gh229EvidenceTests(unittest.TestCase):
    def test_cli_requires_explicit_evidence_path(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("--evidence", result.stderr)

    def test_cli_accepts_valid_explicit_evidence_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence_path = Path(directory) / "evidence.json"
            evidence_path.write_text(
                json.dumps(valid_evidence()), encoding="utf-8"
            )
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--evidence", str(evidence_path)],
                capture_output=True,
                check=False,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.strip(), "GH229_CONTROLLED_MULTIHOST_EVIDENCE_VERIFIED"
        )

    def test_valid_synthetic_record_passes(self) -> None:
        MODULE.verify_evidence(valid_evidence())

    def test_unknown_field_fails_closed(self) -> None:
        changed = valid_evidence()
        changed["extra"] = False
        with self.assertRaises(MODULE.EvidenceError):
            MODULE.verify_evidence(changed)

    def test_network_identifier_categories_are_rejected(self) -> None:
        cases = {
            "network_address": "redacted",
            "toolchain": "rustc 1.95.0 /ip4/redacted",
            "peer": "12D3KooWredacted",
            "ipv4": "rustc 1.95.0 192.0.2.1",
        }
        for category, value in cases.items():
            with self.subTest(category=category):
                changed = valid_evidence()
                if category == "network_address":
                    changed["network_address"] = value
                else:
                    artifacts = changed["artifacts"]
                    assert isinstance(artifacts, dict)
                    artifacts["toolchain"] = value
                with self.assertRaises(MODULE.EvidenceError):
                    MODULE.verify_evidence(changed)

    def test_equal_host_attestations_are_rejected(self) -> None:
        changed = valid_evidence()
        attestations = changed["execution_attestations"]
        assert isinstance(attestations, dict)
        attestations["guardian_sha256"] = attestations["sender_sha256"]
        with self.assertRaises(MODULE.EvidenceError):
            MODULE.verify_evidence(changed)

    def test_authorizing_or_operated_claims_are_rejected(self) -> None:
        changes = (
            ("sender_status", "accepted"),
            ("guardian_receipt_status", "accepted"),
            ("ack_authority", "proof"),
        )
        for field, value in changes:
            with self.subTest(field=field):
                changed = valid_evidence()
                delivery = changed["delivery"]
                assert isinstance(delivery, dict)
                delivery[field] = value
                with self.assertRaises(MODULE.EvidenceError):
                    MODULE.verify_evidence(changed)

    def test_safety_flags_must_all_remain_false(self) -> None:
        for field in MODULE.SAFETY_KEYS:
            with self.subTest(field=field):
                changed = valid_evidence()
                safety = changed["safety"]
                assert isinstance(safety, dict)
                safety[field] = True
                with self.assertRaises(MODULE.EvidenceError):
                    MODULE.verify_evidence(changed)

    def test_bad_commit_digest_timestamp_and_toolchain_are_rejected(self) -> None:
        mutators = (
            lambda value: value.__setitem__("source_commit", "A" * 40),
            lambda value: value.__setitem__("challenge_sha256", "0" * 63),
            lambda value: value.__setitem__(
                "observed_at_utc", "2026-08-25T12:34:56Z"
            ),
            lambda value: value["artifacts"].__setitem__(
                "toolchain", "rustc latest"
            ),
        )
        for index, mutate in enumerate(mutators):
            with self.subTest(index=index):
                changed = copy.deepcopy(valid_evidence())
                mutate(changed)
                with self.assertRaises(MODULE.EvidenceError):
                    MODULE.verify_evidence(changed)


if __name__ == "__main__":
    unittest.main()
