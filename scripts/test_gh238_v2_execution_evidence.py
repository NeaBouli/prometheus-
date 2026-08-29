#!/usr/bin/env python3
"""Focused tests for the GH-238 v2 execution challenge/attestation/record tool."""

import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "gh238_v2_execution_evidence.py",
)
SPEC = importlib.util.spec_from_file_location("gh238_v2_execution_evidence", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
CHALLENGE = bytes(range(32))
COMMIT = "0123456789abcdef0123456789abcdef01234567"
PAYLOAD = b'{"schema_version":2,"threat_hash":"ab"}'
ARTIFACT = b"gh238-v2-execution-evidence-test-artifact\n"
GUARDIAN_ARTIFACT = b"gh238-v2-execution-evidence-test-guardian-artifact\n"
PROTOCOL = "/prometheus/threat-hint/2.0.0"
CHALLENGE_SHA256 = hashlib.sha256(CHALLENGE).hexdigest()
ARTIFACT_SHA256 = hashlib.sha256(ARTIFACT).hexdigest()
GUARDIAN_ARTIFACT_SHA256 = hashlib.sha256(GUARDIAN_ARTIFACT).hexdigest()
PAYLOAD_SHA256 = hashlib.sha256(PAYLOAD).hexdigest()
SENDER_ATTESTATION = "b8a942171357e5e82f8b5d191c0eab287d6485d542edf8698cd54141d6596c12"
GUARDIAN_ATTESTATION = (
    "56b66a0ec8702e4dc729d771c41afc4d7f581851735ea8101c8bccd01363baf9"
)
OBSERVED_AT = "2026-08-30T12:34:56Z"
TOOLCHAIN = "rustc 1.95.0 (59807616e 2026-04-14) (Homebrew)"
ATTESTATION_KEYS = {
    "role",
    "source_commit",
    "challenge_sha256",
    "artifact_sha256",
    "payload_sha256",
    "protocol",
    "observed_at_utc",
    "observed_status",
    "attempts",
    "retries",
    "persisted",
    "execution_attestation_sha256",
}


def reference_attestation(role, challenge, commit_hex, artifact_bytes, payload_bytes):
    """Independent recomputation of the documented domain-separated framing."""
    frame = bytearray(b"prometheus-gh238-v2-execution-attestation")
    frame.append(0)
    frame.append(1)
    for field in (
        role.encode("ascii"),
        challenge,
        bytes.fromhex(commit_hex),
        hashlib.sha256(artifact_bytes).digest(),
        hashlib.sha256(payload_bytes).digest(),
        b"/prometheus/threat-hint/2.0.0",
        OBSERVED_AT.encode("ascii"),
        b"rejected",
        b"1",
        b"0",
        b"false",
    ):
        frame.append(len(field))
        frame += field
    return hashlib.sha256(bytes(frame)).hexdigest()


def expected_json(role, attestation):
    return (
        '{"role":"%s","source_commit":"%s","challenge_sha256":"%s",'
        '"artifact_sha256":"%s","payload_sha256":"%s","protocol":"%s",'
        '"observed_at_utc":"%s","observed_status":"rejected",'
        '"attempts":1,"retries":0,"persisted":false,'
        '"execution_attestation_sha256":"%s"}\n'
        % (
            role,
            COMMIT,
            CHALLENGE_SHA256,
            ARTIFACT_SHA256,
            PAYLOAD_SHA256,
            PROTOCOL,
            OBSERVED_AT,
            attestation,
        )
    )


class EvidenceTestCase(unittest.TestCase):
    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp(prefix="gh238-evidence-"))
        os.chmod(self.root, 0o700)
        self.challenge_path = os.path.join(self.root, "challenge.bin")
        self.artifact_path = os.path.join(self.root, "artifact.bin")
        self.guardian_artifact_path = os.path.join(self.root, "guardian.bin")
        self.payload_path = os.path.join(self.root, "payload.bin")
        self.write_challenge()
        self.write_executable(self.artifact_path, ARTIFACT)
        self.write_executable(self.guardian_artifact_path, GUARDIAN_ARTIFACT)
        self.write_owner_file(self.payload_path, PAYLOAD)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def write_challenge(self, content=CHALLENGE, mode=0o600, path=None):
        self.write_owner_file(path or self.challenge_path, content, mode)

    def write_owner_file(self, path, content, mode=0o600):
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            os.write(descriptor, content)
        finally:
            os.close(descriptor)
        os.chmod(path, mode)

    def write_executable(self, path, content):
        self.write_owner_file(path, content, 0o700)

    def run_cli(self, *arguments):
        return subprocess.run(
            [sys.executable, SCRIPT] + list(arguments),
            capture_output=True,
            check=False,
        )

    def run_attest(self, **overrides):
        one_shot = overrides.pop("one_shot", True)
        no_persistence = overrides.pop("no_persistence", True)
        options = {
            "--challenge": self.challenge_path,
            "--role": "sender",
            "--source-commit": COMMIT,
            "--artifact": self.artifact_path,
            "--payload": self.payload_path,
            "--observed-at-utc": OBSERVED_AT,
            "--observed-status": "rejected",
        }
        for key, value in overrides.items():
            options["--" + key.replace("_", "-")] = str(value)
        argv = ["attest"]
        for flag, value in options.items():
            argv.extend([flag, value])
        if one_shot:
            argv.append("--one-shot")
        if no_persistence:
            argv.append("--no-persistence")
        return self.run_cli(*argv)

    def write_attestation(self, name, record, mode=0o600):
        path = os.path.join(self.root, name)
        self.write_owner_file(
            path, json.dumps(record, separators=(",", ":")).encode("ascii"), mode
        )
        return path

    def attest_record(self, role, artifact_path=None, **overrides):
        options = {"role": role, "artifact": artifact_path or self.artifact_path}
        options.update(overrides)
        result = self.run_attest(**options)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout.decode("ascii"))

    def guardian_attest_record(self, **overrides):
        options = {"role": "guardian", "artifact": self.guardian_artifact_path}
        options.update(overrides)
        result = self.run_attest(**options)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout.decode("ascii"))

    def run_build_record(self, sender_path, guardian_path, output, **overrides):
        options = {
            "--sender-attestation": sender_path,
            "--guardian-attestation": guardian_path,
            "--toolchain": TOOLCHAIN,
            "--output": output,
        }
        for key, value in overrides.items():
            options["--" + key.replace("_", "-")] = str(value)
        argv = ["build-record"]
        for flag, value in options.items():
            argv.extend([flag, value])
        return self.run_cli(*argv)

    def build_record_paths(self, sender_record=None, guardian_record=None):
        sender_record = sender_record or self.attest_record("sender")
        guardian_record = guardian_record or self.guardian_attest_record()
        suffix = len(os.listdir(self.root))
        sender_path = self.write_attestation("sender-%d.json" % suffix, sender_record)
        guardian_path = self.write_attestation(
            "guardian-%d.json" % suffix, guardian_record
        )
        output = os.path.join(self.root, "record.json")
        return sender_path, guardian_path, output

    def expected_record(self, sender_record, guardian_record):
        return {
            "schema_version": 1,
            "evidence_kind": "operator_attested_controlled_two_host_threat_hint_v2_delivery",
            "issue": 238,
            "observed_at_utc": OBSERVED_AT,
            "source_commit": COMMIT,
            "network": "testnet-10",
            "runtime": "development-only",
            "transport": "direct-quic-v1",
            "protocol": PROTOCOL,
            "route_scope": "single-static-controlled-remote-quic-peer",
            "separation_claim": "operator-attested-not-independently-proven",
            "challenge_sha256": sender_record["challenge_sha256"],
            "artifacts": {
                "client_sha256": sender_record["artifact_sha256"],
                "guardian_sha256": guardian_record["artifact_sha256"],
                "toolchain": TOOLCHAIN,
            },
            "execution_attestations": {
                "sender_sha256": sender_record["execution_attestation_sha256"],
                "guardian_sha256": guardian_record["execution_attestation_sha256"],
            },
            "delivery": {
                "payload_sha256": sender_record["payload_sha256"],
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


class AttestTests(EvidenceTestCase):
    def test_payload_limit_matches_rust_transport_boundary(self):
        self.assertEqual(MODULE.PAYLOAD_MAX_BYTES, 9_265)
        vector_path = os.path.join(
            os.path.dirname(SCRIPT),
            "..",
            "modules",
            "threat-hint",
            "tests",
            "vectors",
            "threat-hint-v2-transport-v1.json",
        )
        with open(vector_path, encoding="utf-8") as handle:
            self.assertEqual(
                MODULE.PAYLOAD_MAX_BYTES,
                json.load(handle)["max_payload_bytes"],
            )

    def test_attest_deterministic_vector_exact_json(self):
        for role, attestation in (
            ("sender", SENDER_ATTESTATION),
            ("guardian", GUARDIAN_ATTESTATION),
        ):
            with self.subTest(role=role):
                result = self.run_attest(role=role)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    result.stdout.decode("ascii"),
                    expected_json(role, attestation),
                )
                self.assertEqual(result.stderr, b"")

    def test_attest_matches_independent_reference(self):
        result = self.run_attest()
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads(result.stdout.decode("ascii"))
        self.assertEqual(set(record), ATTESTATION_KEYS)
        self.assertEqual(record["protocol"], PROTOCOL)
        self.assertEqual(record["payload_sha256"], PAYLOAD_SHA256)
        self.assertEqual(
            record["execution_attestation_sha256"],
            reference_attestation("sender", CHALLENGE, COMMIT, ARTIFACT, PAYLOAD),
        )

    def test_attest_output_contains_no_paths_or_raw_data(self):
        result = self.run_attest()
        self.assertEqual(result.returncode, 0, result.stderr)
        for forbidden in (
            self.root,
            self.challenge_path,
            self.artifact_path,
            self.payload_path,
            CHALLENGE.hex(),
            PAYLOAD.decode("ascii"),
            ARTIFACT.decode("ascii"),
        ):
            self.assertNotIn(forbidden, result.stdout.decode("ascii"))

    def test_role_separation(self):
        sender = self.run_attest(role="sender")
        guardian = self.run_attest(role="guardian")
        self.assertEqual(sender.returncode, 0, sender.stderr)
        self.assertEqual(guardian.returncode, 0, guardian.stderr)
        sender_record = json.loads(sender.stdout.decode("ascii"))
        guardian_record = json.loads(guardian.stdout.decode("ascii"))
        self.assertNotEqual(
            sender_record["execution_attestation_sha256"],
            guardian_record["execution_attestation_sha256"],
        )
        self.assertEqual(
            sender_record["challenge_sha256"],
            guardian_record["challenge_sha256"],
        )
        self.assertEqual(
            sender_record["payload_sha256"],
            guardian_record["payload_sha256"],
        )

    def test_attestation_binds_protocol_and_observed_outcome(self):
        values = (
            "sender",
            CHALLENGE,
            bytes.fromhex(COMMIT),
            bytes.fromhex(ARTIFACT_SHA256),
            bytes.fromhex(PAYLOAD_SHA256),
        )
        baseline = MODULE.execution_attestation(
            *values, PROTOCOL, OBSERVED_AT, "rejected", 1, 0, False
        )
        rebound = MODULE.execution_attestation(
            *values,
            "/prometheus/threat-hint/1.0.0",
            OBSERVED_AT,
            "rejected",
            1,
            0,
            False,
        )
        changed_time = MODULE.execution_attestation(
            *values,
            PROTOCOL,
            "2026-08-30T12:34:57Z",
            "rejected",
            1,
            0,
            False,
        )
        self.assertNotEqual(baseline, rebound)
        self.assertNotEqual(baseline, changed_time)

    def test_attest_rejects_payload_mutated_while_reading(self):
        real_read = os.read
        mutated = False

        def racing_read(descriptor, size):
            nonlocal mutated
            chunk = real_read(descriptor, size)
            if chunk and not mutated:
                mutated = True
                metadata = os.stat(self.payload_path)
                os.utime(
                    self.payload_path,
                    ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000),
                )
            return chunk

        with mock.patch.object(MODULE.os, "read", side_effect=racing_read):
            with self.assertRaises(MODULE.EvidenceFailure) as failure:
                MODULE.hash_payload(self.payload_path)
        self.assertEqual(failure.exception.reason, "payload")

    def test_attest_binds_actual_artifact_bytes(self):
        result = self.run_attest()
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads(result.stdout.decode("ascii"))
        self.assertEqual(record["artifact_sha256"], ARTIFACT_SHA256)

        with open(self.artifact_path, "ab") as handle:
            handle.write(b"changed")
        changed = self.run_attest()
        self.assertEqual(changed.returncode, 0, changed.stderr)
        changed_record = json.loads(changed.stdout.decode("ascii"))
        self.assertNotEqual(
            changed_record["artifact_sha256"], record["artifact_sha256"]
        )
        self.assertNotEqual(
            changed_record["execution_attestation_sha256"],
            record["execution_attestation_sha256"],
        )

    def test_attest_binds_actual_payload_bytes(self):
        result = self.run_attest()
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads(result.stdout.decode("ascii"))
        self.assertEqual(record["payload_sha256"], PAYLOAD_SHA256)

        with open(self.payload_path, "ab") as handle:
            handle.write(b"changed")
        changed = self.run_attest()
        self.assertEqual(changed.returncode, 0, changed.stderr)
        changed_record = json.loads(changed.stdout.decode("ascii"))
        self.assertNotEqual(changed_record["payload_sha256"], record["payload_sha256"])
        self.assertNotEqual(
            changed_record["execution_attestation_sha256"],
            record["execution_attestation_sha256"],
        )

    def test_attest_rejects_non_executable_artifact(self):
        os.chmod(self.artifact_path, 0o600)
        result = self.run_attest()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"gh238-evidence: artifact\n")

    def test_attest_rejects_symlink_artifact(self):
        os.unlink(self.artifact_path)
        os.symlink(self.guardian_artifact_path, self.artifact_path)
        result = self.run_attest()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"gh238-evidence: artifact\n")

    def test_attest_rejects_non_regular_artifact(self):
        result = self.run_attest(artifact=self.root)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"gh238-evidence: artifact\n")

    def test_attest_rejects_group_or_world_writable_artifact(self):
        os.chmod(self.artifact_path, 0o766)
        result = self.run_attest()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"gh238-evidence: artifact\n")

    def test_attest_rejects_group_or_world_writable_artifact_parent(self):
        os.chmod(self.root, 0o722)
        result = self.run_attest()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"gh238-evidence: artifact\n")

    def test_attest_rejects_symlink_challenge(self):
        real_challenge = os.path.join(self.root, "real-challenge.bin")
        os.rename(self.challenge_path, real_challenge)
        os.symlink(real_challenge, self.challenge_path)
        result = self.run_attest()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"gh238-evidence: challenge\n")

    def test_attest_rejects_symlinked_challenge_parent(self):
        real_dir = os.path.realpath(tempfile.mkdtemp(prefix="gh238-real-"))
        self.addCleanup(shutil.rmtree, real_dir, True)
        os.chmod(real_dir, 0o700)
        linked = os.path.join(real_dir, "challenge.bin")
        self.write_challenge(path=linked)
        link = os.path.join(self.root, "linked")
        os.symlink(real_dir, link)
        result = self.run_attest(challenge=os.path.join(link, "challenge.bin"))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"gh238-evidence: paths\n")

    def test_attest_rejects_wrong_challenge_mode(self):
        os.chmod(self.challenge_path, 0o644)
        result = self.run_attest()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"gh238-evidence: challenge\n")

    def test_attest_rejects_wrong_challenge_size(self):
        for size in (0, 31, 33, 64):
            with self.subTest(size=size):
                path = os.path.join(self.root, "challenge-%d.bin" % size)
                self.write_challenge(content=b"c" * size, path=path)
                result = self.run_attest(challenge=path)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stderr, b"gh238-evidence: challenge\n")

    def test_attest_rejects_symlink_payload(self):
        real_payload = os.path.join(self.root, "real-payload.bin")
        os.rename(self.payload_path, real_payload)
        os.symlink(real_payload, self.payload_path)
        result = self.run_attest()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"gh238-evidence: payload\n")

    def test_attest_rejects_group_or_world_readable_payload(self):
        for mode in (0o640, 0o604, 0o644, 0o666):
            with self.subTest(mode=oct(mode)):
                os.chmod(self.payload_path, mode)
                result = self.run_attest()
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stderr, b"gh238-evidence: payload\n")

    def test_attest_rejects_non_regular_payload(self):
        result = self.run_attest(payload=self.root)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"gh238-evidence: payload\n")

    def test_attest_rejects_empty_and_oversized_payload(self):
        for size in (0, MODULE.PAYLOAD_MAX_BYTES + 1):
            with self.subTest(size=size):
                path = os.path.join(self.root, "payload-%d.bin" % size)
                self.write_owner_file(path, b"p" * size)
                result = self.run_attest(payload=path)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stderr, b"gh238-evidence: payload\n")

    def test_attest_accepts_bounded_payload_at_limit(self):
        path = os.path.join(self.root, "payload-max.bin")
        self.write_owner_file(path, b"p" * MODULE.PAYLOAD_MAX_BYTES)
        result = self.run_attest(payload=path)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_attest_rejects_missing_challenge_artifact_and_payload(self):
        missing = os.path.join(self.root, "missing.bin")
        for overrides, reason in (
            ({"challenge": missing}, b"gh238-evidence: challenge\n"),
            ({"artifact": missing}, b"gh238-evidence: artifact\n"),
            ({"payload": missing}, b"gh238-evidence: payload\n"),
        ):
            with self.subTest(**overrides):
                result = self.run_attest(**overrides)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(result.stderr, reason)


class CreateChallengeTests(EvidenceTestCase):
    def test_create_challenge_writes_owner_only_32_bytes_and_fixed_token(self):
        os.unlink(self.challenge_path)
        result = self.run_cli("create-challenge", "--output", self.challenge_path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"GH238_CHALLENGE_CREATED\n")
        self.assertEqual(result.stderr, b"")
        metadata = os.lstat(self.challenge_path)
        self.assertTrue(stat.S_ISREG(metadata.st_mode))
        self.assertEqual(metadata.st_mode & 0o777, 0o600)
        self.assertEqual(metadata.st_uid, os.geteuid())
        self.assertEqual(metadata.st_nlink, 1)
        self.assertEqual(metadata.st_size, 32)
        with open(self.challenge_path, "rb") as handle:
            self.assertEqual(len(handle.read()), 32)

    def test_create_challenge_refuses_existing_output_and_preserves_it(self):
        result = self.run_cli("create-challenge", "--output", self.challenge_path)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"gh238-evidence: paths\n")
        with open(self.challenge_path, "rb") as handle:
            self.assertEqual(handle.read(), CHALLENGE)

    def test_create_challenge_preserves_file_won_by_concurrent_creator(self):
        os.unlink(self.challenge_path)
        concurrent_content = b"concurrent-owner-file"
        real_open = os.open

        def racing_open(path, flags, mode=0o777):
            if path == self.challenge_path and flags & os.O_CREAT:
                descriptor = real_open(
                    path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
                )
                try:
                    os.write(descriptor, concurrent_content)
                finally:
                    os.close(descriptor)
            return real_open(path, flags, mode)

        with mock.patch.object(MODULE.os, "open", side_effect=racing_open):
            with self.assertRaises(MODULE.EvidenceFailure) as failure:
                MODULE.create_challenge(self.challenge_path)
        self.assertEqual(failure.exception.reason, "paths")
        with open(self.challenge_path, "rb") as handle:
            self.assertEqual(handle.read(), concurrent_content)

    def test_create_challenge_refuses_symlink_output(self):
        os.unlink(self.challenge_path)
        os.symlink(os.path.join(self.root, "elsewhere"), self.challenge_path)
        result = self.run_cli("create-challenge", "--output", self.challenge_path)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"gh238-evidence: paths\n")
        self.assertTrue(os.path.islink(self.challenge_path))
        self.assertFalse(os.path.lexists(os.path.join(self.root, "elsewhere")))

    def test_create_challenge_rejects_unsafe_parent_mode(self):
        os.unlink(self.challenge_path)
        os.chmod(self.root, 0o755)
        result = self.run_cli("create-challenge", "--output", self.challenge_path)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"gh238-evidence: paths\n")
        self.assertFalse(os.path.lexists(self.challenge_path))

    def test_create_challenge_rejects_symlink_parent(self):
        real_dir = os.path.realpath(tempfile.mkdtemp(prefix="gh238-real-"))
        self.addCleanup(shutil.rmtree, real_dir, True)
        os.chmod(real_dir, 0o700)
        link = os.path.join(self.root, "linked")
        os.symlink(real_dir, link)
        result = self.run_cli(
            "create-challenge", "--output", os.path.join(link, "challenge.bin")
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"gh238-evidence: paths\n")
        self.assertEqual(os.listdir(real_dir), [])


class BuildRecordTests(EvidenceTestCase):
    def test_build_record_writes_exact_owner_only_record(self):
        sender_record = self.attest_record("sender")
        guardian_record = self.guardian_attest_record()
        sender_path, guardian_path, output = self.build_record_paths(
            sender_record, guardian_record
        )
        result = self.run_build_record(sender_path, guardian_path, output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"GH238_RECORD_WRITTEN\n")
        self.assertEqual(result.stderr, b"")
        metadata = os.lstat(output)
        self.assertTrue(stat.S_ISREG(metadata.st_mode))
        self.assertEqual(metadata.st_mode & 0o777, 0o600)
        self.assertEqual(metadata.st_uid, os.geteuid())
        self.assertEqual(metadata.st_nlink, 1)
        with open(output, "r", encoding="utf-8") as handle:
            record = json.load(handle)
        self.assertEqual(record, self.expected_record(sender_record, guardian_record))
        self.assertFalse(
            any(name.startswith(".gh238-record-") for name in os.listdir(self.root))
        )

    def test_write_record_fsyncs_file_and_parent_directory(self):
        sender_path, guardian_path, output = self.build_record_paths()
        sender = MODULE.read_attestation(sender_path, "sender")
        guardian = MODULE.read_attestation(guardian_path, "guardian")
        record = MODULE.build_record_document(sender, guardian, TOOLCHAIN)
        real_fsync = os.fsync
        with mock.patch.object(MODULE.os, "fsync", wraps=real_fsync) as fsync:
            MODULE.write_record(output, record)
        self.assertGreaterEqual(fsync.call_count, 2)

    def test_built_record_passes_public_verifier(self):
        verifier = os.path.join(
            os.path.dirname(SCRIPT), "verify_gh238_v2_multihost_evidence.py"
        )
        sender_path, guardian_path, output = self.build_record_paths()
        result = self.run_build_record(sender_path, guardian_path, output)
        self.assertEqual(result.returncode, 0, result.stderr)
        verified = subprocess.run(
            [sys.executable, verifier, "--evidence", output],
            capture_output=True,
            check=False,
        )
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertEqual(
            verified.stdout,
            b"GH238_PUBLIC_RECORD_SCHEMA_REDACTION_VERIFIED\n",
        )

    def test_build_record_refuses_existing_output_and_preserves_it(self):
        sender_path, guardian_path, output = self.build_record_paths()
        existing = b'{"prior":true}\n'
        self.write_owner_file(output, existing)
        result = self.run_build_record(sender_path, guardian_path, output)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"gh238-evidence: paths\n")
        with open(output, "rb") as handle:
            self.assertEqual(handle.read(), existing)

    def test_build_record_rejects_unsafe_output_parent_mode(self):
        sender_path, guardian_path, output = self.build_record_paths()
        os.chmod(self.root, 0o755)
        result = self.run_build_record(sender_path, guardian_path, output)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"gh238-evidence: paths\n")
        self.assertFalse(os.path.lexists(output))

    def test_build_record_preserves_output_won_by_concurrent_creator(self):
        sender_path, guardian_path, output = self.build_record_paths()
        concurrent_content = b"concurrent-owner-file"
        real_link = os.link

        def racing_link(source, target, **kwargs):
            if target == output:
                descriptor = os.open(
                    target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
                )
                try:
                    os.write(descriptor, concurrent_content)
                finally:
                    os.close(descriptor)
            return real_link(source, target, **kwargs)

        sender = MODULE.read_attestation(sender_path, "sender")
        guardian = MODULE.read_attestation(guardian_path, "guardian")
        record = MODULE.build_record_document(sender, guardian, TOOLCHAIN)
        with mock.patch.object(MODULE.os, "link", side_effect=racing_link):
            with self.assertRaises(MODULE.EvidenceFailure) as failure:
                MODULE.write_record(output, record)
        self.assertEqual(failure.exception.reason, "paths")
        with open(output, "rb") as handle:
            self.assertEqual(handle.read(), concurrent_content)
        self.assertFalse(
            any(name.startswith(".gh238-record-") for name in os.listdir(self.root))
        )

    def test_build_record_rejects_mismatched_challenge_source_payload(self):
        other_challenge = os.path.join(self.root, "other-challenge.bin")
        self.write_challenge(content=bytes(reversed(range(32))), path=other_challenge)
        other_payload = os.path.join(self.root, "other-payload.bin")
        self.write_owner_file(other_payload, b'{"schema_version":2,"other":true}')
        cases = {
            "challenge": self.guardian_attest_record(challenge=other_challenge),
            "source": self.guardian_attest_record(source_commit="f" * 40),
            "payload": self.guardian_attest_record(payload=other_payload),
            "observation": self.guardian_attest_record(
                observed_at_utc="2026-08-30T12:34:57Z"
            ),
        }
        for category, guardian_record in cases.items():
            with self.subTest(category=category):
                sender_path, guardian_path, output = self.build_record_paths(
                    guardian_record=guardian_record
                )
                result = self.run_build_record(sender_path, guardian_path, output)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stderr, b"gh238-evidence: mismatch\n")
                self.assertFalse(os.path.lexists(output))

    def test_build_record_rejects_protocol_mismatch(self):
        guardian_record = self.guardian_attest_record()
        guardian_record["protocol"] = "/prometheus/threat-hint/1.0.0"
        sender_path, guardian_path, output = self.build_record_paths(
            guardian_record=guardian_record
        )
        result = self.run_build_record(sender_path, guardian_path, output)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"gh238-evidence: attestation\n")
        self.assertFalse(os.path.lexists(output))

    def test_build_record_rejects_same_artifact_and_same_attestation(self):
        guardian_same_artifact = self.guardian_attest_record(
            artifact=self.artifact_path
        )
        sender_record = self.attest_record("sender")
        same_attestation = dict(sender_record)
        same_attestation["role"] = "guardian"
        same_attestation["execution_attestation_sha256"] = sender_record[
            "execution_attestation_sha256"
        ]
        for category, guardian_record in (
            ("same-artifact", guardian_same_artifact),
            ("same-attestation", same_attestation),
        ):
            with self.subTest(category=category):
                sender_path, guardian_path, output = self.build_record_paths(
                    sender_record=sender_record, guardian_record=guardian_record
                )
                result = self.run_build_record(sender_path, guardian_path, output)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stderr, b"gh238-evidence: mismatch\n")
                self.assertFalse(os.path.lexists(output))

    def test_build_record_rejects_wrong_role_files(self):
        sender_path, guardian_path, output = self.build_record_paths()
        result = self.run_build_record(guardian_path, sender_path, output)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"gh238-evidence: attestation\n")
        self.assertFalse(os.path.lexists(output))

    def test_build_record_rejects_malformed_attestation_json(self):
        sender_path, guardian_path, output = self.build_record_paths()
        for name, blob in (
            ("truncated", b'{"role":"sender"'),
            ("array", b"[]"),
            ("text", b"not-json"),
            ("duplicate-keys", None),
        ):
            with self.subTest(name=name):
                if blob is None:
                    sender_record = self.attest_record("sender")
                    pairs = ",".join(
                        '"%s":%s' % (key, json.dumps(value))
                        for key, value in sender_record.items()
                    )
                    blob = ('{"role":"sender",%s}' % pairs).encode("ascii")
                bad_path = os.path.join(self.root, "bad-%s.json" % name)
                self.write_owner_file(bad_path, blob)
                result = self.run_build_record(bad_path, guardian_path, output)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stderr, b"gh238-evidence: attestation\n")
                self.assertFalse(os.path.lexists(output))

    def test_build_record_rejects_unknown_or_missing_attestation_fields(self):
        sender_record = self.attest_record("sender")
        for name, mutate in (
            ("unknown", lambda record: record.__setitem__("extra", "x")),
            ("missing", lambda record: record.pop("protocol")),
        ):
            with self.subTest(name=name):
                changed = dict(sender_record)
                mutate(changed)
                sender_path, guardian_path, output = self.build_record_paths(
                    sender_record=changed
                )
                result = self.run_build_record(sender_path, guardian_path, output)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stderr, b"gh238-evidence: attestation\n")
                self.assertFalse(os.path.lexists(output))

    def test_attestation_size_boundary_is_enforced(self):
        record = self.attest_record("sender")
        wire = json.dumps(record, separators=(",", ":")).encode("ascii")
        accepted = os.path.join(self.root, "attestation-at-limit.json")
        rejected = os.path.join(self.root, "attestation-over-limit.json")
        self.write_owner_file(
            accepted, wire + b" " * (MODULE.ATTESTATION_MAX_BYTES - len(wire))
        )
        self.write_owner_file(
            rejected,
            wire + b" " * (MODULE.ATTESTATION_MAX_BYTES + 1 - len(wire)),
        )
        self.assertEqual(MODULE.read_attestation(accepted, "sender"), record)
        with self.assertRaises(MODULE.EvidenceFailure) as failure:
            MODULE.read_attestation(rejected, "sender")
        self.assertEqual(failure.exception.reason, "attestation")

    def test_build_record_rejects_group_readable_attestation_file(self):
        sender_path, guardian_path, output = self.build_record_paths()
        os.chmod(sender_path, 0o640)
        result = self.run_build_record(sender_path, guardian_path, output)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"gh238-evidence: attestation\n")
        self.assertFalse(os.path.lexists(output))

    def test_build_record_rejects_symlink_attestation_file(self):
        sender_path, guardian_path, output = self.build_record_paths()
        linked = os.path.join(self.root, "sender-link.json")
        os.symlink(sender_path, linked)
        result = self.run_build_record(linked, guardian_path, output)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"gh238-evidence: attestation\n")
        self.assertFalse(os.path.lexists(output))

    def test_build_record_rejects_invalid_toolchain(self):
        sender_path, guardian_path, _ = self.build_record_paths()
        sender = MODULE.read_attestation(sender_path, "sender")
        guardian = MODULE.read_attestation(guardian_path, "guardian")
        with self.assertRaises(MODULE.EvidenceFailure) as failure:
            MODULE.build_record_document(sender, guardian, "rustc latest")
        self.assertEqual(failure.exception.reason, "toolchain")

    def test_cli_rejects_invalid_attested_observation_and_toolchain_forms(self):
        sender_path, guardian_path, output = self.build_record_paths()
        for observed_at in (
            "2026-08-30 12:34:56Z",
            "2026-08-30T12:34:56+00:00",
        ):
            with self.subTest(observed_at=observed_at):
                result = self.run_attest(observed_at_utc=observed_at)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")
        before_boundary = self.run_attest(observed_at_utc="2025-08-30T12:34:56Z")
        self.assertEqual(before_boundary.returncode, 1)
        self.assertEqual(before_boundary.stdout, b"")
        self.assertEqual(before_boundary.stderr, b"gh238-evidence: timestamp\n")
        result = self.run_build_record(
            sender_path,
            guardian_path,
            output,
            toolchain="rustc 1.94.0 (59807616e 2026-04-14)",
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        MODULE.validate_observation("2027-01-02T03:04:05Z")
        self.assertIsNotNone(
            MODULE.TOOLCHAIN.fullmatch("rustc 1.95.0 (59807616e 2027-04-14)")
        )

    def test_cli_offers_no_option_to_promote_delivery_or_safety(self):
        sender_path, guardian_path, output = self.build_record_paths()
        for flag in (
            "--sender-status",
            "--guardian-receipt-status",
            "--ack-authority",
            "--retries",
            "--persisted",
            "--mainnet",
            "--production",
            "--independent-host-proof",
        ):
            with self.subTest(flag=flag):
                result = self.run_build_record(sender_path, guardian_path, output)
                promoted = self.run_cli(
                    "build-record",
                    "--sender-attestation",
                    sender_path,
                    "--guardian-attestation",
                    guardian_path,
                    "--toolchain",
                    TOOLCHAIN,
                    "--output",
                    output,
                    flag,
                    "accepted",
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                os.unlink(output)
                self.assertEqual(promoted.returncode, 2)
                self.assertEqual(promoted.stdout, b"")


class CliTests(EvidenceTestCase):
    def test_cli_rejects_malformed_arguments(self):
        for overrides in (
            {"role": "operator"},
            {"role": "SENDER"},
            {"source_commit": COMMIT.upper()},
            {"source_commit": "g" * 40},
            {"source_commit": COMMIT[:-1]},
            {"observed_status": "accepted"},
            {"observed_status": "busy"},
        ):
            with self.subTest(**overrides):
                result = self.run_attest(**overrides)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")

    def test_attest_requires_explicit_one_shot_and_no_persistence_assertions(self):
        for overrides in (
            {"one_shot": False},
            {"no_persistence": False},
        ):
            with self.subTest(**overrides):
                result = self.run_attest(**overrides)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")

    def test_cli_rejects_relative_and_noncanonical_paths(self):
        relative = os.path.relpath(self.challenge_path)
        noncanonical = os.path.join(self.root, ".", "challenge.bin")
        for value in (relative, noncanonical, self.root + "/"):
            with self.subTest(value=value):
                result = self.run_attest(challenge=value)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stderr, b"gh238-evidence: args\n")

    def test_cli_requires_subcommand(self):
        result = self.run_cli()
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")

    def test_failure_diagnostics_are_data_minimal(self):
        os.chmod(self.challenge_path, 0o644)
        result = self.run_attest()
        self.assertEqual(result.returncode, 1)
        for blob in (result.stdout, result.stderr):
            for forbidden in (
                self.root.encode(),
                self.challenge_path.encode(),
                self.artifact_path.encode(),
                self.payload_path.encode(),
                CHALLENGE.hex().encode(),
                CHALLENGE_SHA256.encode(),
                PAYLOAD_SHA256.encode(),
            ):
                self.assertNotIn(forbidden, blob)


if __name__ == "__main__":
    unittest.main()
