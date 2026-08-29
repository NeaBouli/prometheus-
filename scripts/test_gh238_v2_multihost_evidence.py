#!/usr/bin/env python3
"""Regression tests for the redacted GH-238 v2 public evidence gate."""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("verify_gh238_v2_multihost_evidence.py")
SPEC = importlib.util.spec_from_file_location("gh238_evidence", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

PROTOCOL = "/prometheus/threat-hint/2.0.0"


def valid_evidence() -> dict[str, object]:
    """Return a synthetic, public-safe record used only by unit tests."""
    return {
        "schema_version": 1,
        "evidence_kind": "operator_attested_controlled_two_host_threat_hint_v2_delivery",
        "issue": 238,
        "observed_at_utc": "2026-08-30T12:34:56Z",
        "source_commit": "1" * 40,
        "network": "testnet-10",
        "runtime": "development-only",
        "transport": "direct-quic-v1",
        "protocol": PROTOCOL,
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
            "attempts": 1,
            "retries": 0,
            "persisted": False,
        },
        "safety": {
            "contains_network_identifiers": False,
            "contains_raw_payload": False,
            "contains_secrets": False,
            "chain_writes": False,
            "wallet_or_signing": False,
            "independent_host_proof": False,
            "public_networking": False,
            "proof_validity": False,
            "approval_membership_or_privacy_authority": False,
            "deployment": False,
            "mainnet": False,
            "production": False,
        },
    }


class Gh238EvidenceTests(unittest.TestCase):
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
            evidence_path.write_text(json.dumps(valid_evidence()), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--evidence", str(evidence_path)],
                capture_output=True,
                check=False,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.strip(), "GH238_PUBLIC_RECORD_SCHEMA_REDACTION_VERIFIED"
        )

    def test_cli_rejection_is_data_minimal(self) -> None:
        marker = "sensitive-marker-value"
        with tempfile.TemporaryDirectory() as directory:
            evidence_path = Path(directory) / "evidence.json"
            changed = valid_evidence()
            changed["extra"] = marker
            evidence_path.write_text(json.dumps(changed), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--evidence", str(evidence_path)],
                capture_output=True,
                check=False,
                text=True,
            )
        self.assertEqual(result.returncode, 1)
        self.assertTrue(result.stderr.startswith("GH238_EVIDENCE_REJECTED: "))
        self.assertNotIn(marker, result.stderr)
        self.assertNotIn(str(evidence_path), result.stderr)
        self.assertEqual(result.stdout, "")

    def test_cli_rejects_duplicate_json_members(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence_path = Path(directory) / "evidence.json"
            wire = json.dumps(valid_evidence()).replace(
                '"issue": 238', '"issue": 238, "issue": 238', 1
            )
            evidence_path.write_text(wire, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--evidence", str(evidence_path)],
                capture_output=True,
                check=False,
                text=True,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("duplicate object members", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_cli_rejects_nested_duplicate_json_members(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence_path = Path(directory) / "evidence.json"
            wire = json.dumps(valid_evidence()).replace(
                '"retries": 0', '"retries": 0, "retries": 0', 1
            )
            evidence_path.write_text(wire, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--evidence", str(evidence_path)],
                capture_output=True,
                check=False,
                text=True,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("duplicate object members", result.stderr)

    def test_cli_rejects_malformed_json_without_echoing_content(self) -> None:
        marker = "private-marker"
        with tempfile.TemporaryDirectory() as directory:
            evidence_path = Path(directory) / "evidence.json"
            evidence_path.write_text('{"broken":"' + marker, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--evidence", str(evidence_path)],
                capture_output=True,
                check=False,
                text=True,
            )
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(marker, result.stderr)
        self.assertNotIn(str(evidence_path), result.stderr)
        with tempfile.TemporaryDirectory() as directory:
            evidence_path = Path(directory) / "non-utf8.json"
            evidence_path.write_bytes(b"{\xff}")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--evidence", str(evidence_path)],
                capture_output=True,
                check=False,
                text=True,
            )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("GH238_EVIDENCE_REJECTED", result.stderr)
        self.assertNotIn(str(evidence_path), result.stderr)

    def test_valid_synthetic_record_passes(self) -> None:
        MODULE.verify_evidence(valid_evidence())

    def test_unknown_field_fails_closed(self) -> None:
        for location in ("root", "artifacts", "delivery", "safety"):
            with self.subTest(location=location):
                changed = valid_evidence()
                target = changed if location == "root" else changed[location]
                assert isinstance(target, dict)
                target["extra"] = False
                with self.assertRaises(MODULE.EvidenceError):
                    MODULE.verify_evidence(changed)

    def test_missing_field_fails_closed(self) -> None:
        for field in ("protocol", "transport", "challenge_sha256"):
            with self.subTest(field=field):
                changed = valid_evidence()
                changed.pop(field)
                with self.assertRaises(MODULE.EvidenceError):
                    MODULE.verify_evidence(changed)

    def test_arrays_are_rejected_recursively(self) -> None:
        changed = valid_evidence()
        changed["artifacts"] = ["3" * 64]
        with self.assertRaises(MODULE.EvidenceError):
            MODULE.verify_evidence(changed)
        with self.assertRaises(MODULE.EvidenceError):
            MODULE._reject_sensitive_content({"nested": {"list": []}})

    def test_sensitive_content_scanner_categories(self) -> None:
        cases = {
            "ipv4": "192.0.2.1",
            "ipv6": "2001:db8::1",
            "multiaddr": "/ip4/192.0.2.1/udp/4101/quic-v1",
            "peer-id": "12D3KooWredacted",
            "kaspa": "kaspa:qredacted",
            "kaspatest": "kaspatest:qredacted",
            "path": "/tmp/evidence.json",
            "home-path": "~/evidence.json",
            "pem": "-----BEGIN PRIVATE KEY-----",
            "openssh": "-----BEGIN OPENSSH PRIVATE KEY-----",
            "secret": "api SECRET redacted",
            "wallet": "wallet.dat",
            "signature": "signature:ab",
            "mnemonic": "mnemonic phrase",
            "keystore": "keystore material",
        }
        for category, value in cases.items():
            with self.subTest(category=category):
                with self.assertRaises(MODULE.EvidenceError):
                    MODULE._reject_sensitive_content({"field": value})

    def test_sensitive_content_scanner_accepts_pinned_values(self) -> None:
        MODULE._reject_sensitive_content(valid_evidence())

    def test_protocol_is_pinned_exactly(self) -> None:
        for value in (
            "/prometheus/threat-hint/1.0.0",
            "/prometheus/threat-hint/2.0.0/",
            "prometheus/threat-hint/2.0.0",
            PROTOCOL.upper(),
        ):
            with self.subTest(value=value):
                changed = valid_evidence()
                changed["protocol"] = value
                with self.assertRaises(MODULE.EvidenceError):
                    MODULE.verify_evidence(changed)

    def test_transport_network_runtime_and_route_scope_are_pinned(self) -> None:
        changes = (
            ("transport", "direct-quic-v2"),
            ("network", "mainnet"),
            ("runtime", "production"),
            ("route_scope", "multi-peer"),
            ("separation_claim", "independently-proven"),
            ("evidence_kind", "independent_host_proof"),
        )
        for field, value in changes:
            with self.subTest(field=field):
                changed = valid_evidence()
                changed[field] = value
                with self.assertRaises(MODULE.EvidenceError):
                    MODULE.verify_evidence(changed)

    def test_equal_host_attestations_and_artifacts_are_rejected(self) -> None:
        changed = valid_evidence()
        attestations = changed["execution_attestations"]
        assert isinstance(attestations, dict)
        attestations["guardian_sha256"] = attestations["sender_sha256"]
        with self.assertRaises(MODULE.EvidenceError):
            MODULE.verify_evidence(changed)
        changed = valid_evidence()
        artifacts = changed["artifacts"]
        assert isinstance(artifacts, dict)
        artifacts["guardian_sha256"] = artifacts["client_sha256"]
        with self.assertRaises(MODULE.EvidenceError):
            MODULE.verify_evidence(changed)

    def test_authorizing_or_operated_claims_are_rejected(self) -> None:
        changes = (
            ("sender_status", "accepted"),
            ("guardian_receipt_status", "accepted"),
            ("sender_status", "busy"),
            ("ack_authority", "proof"),
            ("ack_scope", "guardian-network"),
            ("attempts", 2),
            ("attempts", True),
            ("retries", 1),
            ("retries", True),
            ("persisted", True),
        )
        for field, value in changes:
            with self.subTest(field=field, value=value):
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
            lambda value: value.__setitem__("observed_at_utc", "2026-08-29T23:59:59Z"),
            lambda value: value.__setitem__(
                "observed_at_utc", "2026-08-30T12:34:56+00:00"
            ),
            lambda value: value.__setitem__("observed_at_utc", "2026-13-30T12:34:56Z"),
            lambda value: value["artifacts"].__setitem__("toolchain", "rustc latest"),
            lambda value: value["artifacts"].__setitem__(
                "toolchain", "rustc 1.94.0 (59807616e 2026-04-14)"
            ),
        )
        for index, mutate in enumerate(mutators):
            with self.subTest(index=index):
                changed = copy.deepcopy(valid_evidence())
                mutate(changed)
                with self.assertRaises(MODULE.EvidenceError):
                    MODULE.verify_evidence(changed)
        future = valid_evidence()
        future["observed_at_utc"] = "2027-01-02T03:04:05Z"
        artifacts = future["artifacts"]
        assert isinstance(artifacts, dict)
        artifacts["toolchain"] = "rustc 1.95.0 (59807616e 2027-04-14)"
        MODULE.verify_evidence(future)

    def test_bool_identity_fields_are_rejected(self) -> None:
        for field, value in (
            ("schema_version", True),
            ("issue", True),
            ("issue", 229),
        ):
            with self.subTest(field=field, value=value):
                changed = valid_evidence()
                changed[field] = value
                with self.assertRaises(MODULE.EvidenceError):
                    MODULE.verify_evidence(changed)


if __name__ == "__main__":
    unittest.main()
