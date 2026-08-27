#!/usr/bin/env python3
"""Focused tests for the GH-229 execution challenge/attestation tool."""

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
    "gh229_execution_attestation.py",
)
SPEC = importlib.util.spec_from_file_location("gh229_execution_attestation", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
CHALLENGE = bytes(range(32))
COMMIT = "0123456789abcdef0123456789abcdef01234567"
PAYLOAD = b'{"schema_version":1,"threat_hash":"ab"}'
PAYLOAD_SHA256 = hashlib.sha256(PAYLOAD).hexdigest()
ARTIFACT = b"gh229-execution-attestation-test-artifact\n"
CHALLENGE_SHA256 = hashlib.sha256(CHALLENGE).hexdigest()
ARTIFACT_SHA256 = hashlib.sha256(ARTIFACT).hexdigest()
SENDER_ATTESTATION = (
    "ebc089ef3aef968b51e09337fb81817fcc301e10cf82d3614db9a7598341908b"
)
GUARDIAN_ATTESTATION = (
    "a27e6afb92b889d584f5ae9d09672022d10ce7cdb85eef5a84147539b9854d84"
)


def reference_attestation(role, challenge, commit_hex, artifact_bytes, payload_hex):
    """Independent recomputation of the documented domain-separated framing."""
    frame = bytearray(b"prometheus-gh229-execution-attestation")
    frame.append(0)
    frame.append(1)
    for field in (
        role.encode("ascii"),
        challenge,
        bytes.fromhex(commit_hex),
        hashlib.sha256(artifact_bytes).digest(),
        bytes.fromhex(payload_hex),
    ):
        frame.append(len(field))
        frame += field
    return hashlib.sha256(bytes(frame)).hexdigest()


def expected_json(role, attestation):
    return (
        '{"role":"%s","challenge_sha256":"%s","artifact_sha256":"%s",'
        '"execution_attestation_sha256":"%s"}\n'
        % (role, CHALLENGE_SHA256, ARTIFACT_SHA256, attestation)
    )


class AttestationTestCase(unittest.TestCase):
    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp(prefix="gh229-attest-"))
        os.chmod(self.root, 0o700)
        self.challenge_path = os.path.join(self.root, "challenge.bin")
        self.artifact_path = os.path.join(self.root, "artifact.bin")
        self.write_challenge()
        with open(self.artifact_path, "wb") as handle:
            handle.write(ARTIFACT)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def write_challenge(self, content=CHALLENGE, mode=0o600, path=None):
        target = path or self.challenge_path
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            os.write(descriptor, content)
        finally:
            os.close(descriptor)
        os.chmod(target, mode)

    def run_cli(self, *arguments):
        return subprocess.run(
            [sys.executable, SCRIPT] + list(arguments),
            capture_output=True,
            check=False,
        )

    def run_attest(self, **overrides):
        options = {
            "--challenge": self.challenge_path,
            "--role": "sender",
            "--source-commit": COMMIT,
            "--artifact": self.artifact_path,
            "--payload-sha256": PAYLOAD_SHA256,
        }
        for key, value in overrides.items():
            options["--" + key.replace("_", "-")] = str(value)
        argv = ["attest"]
        for flag, value in options.items():
            argv.extend([flag, value])
        return self.run_cli(*argv)

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
        self.assertEqual(
            set(record),
            {
                "role",
                "challenge_sha256",
                "artifact_sha256",
                "execution_attestation_sha256",
            },
        )
        self.assertEqual(
            record["execution_attestation_sha256"],
            reference_attestation(
                "sender", CHALLENGE, COMMIT, ARTIFACT, PAYLOAD_SHA256
            ),
        )

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
            sender_record["artifact_sha256"],
            guardian_record["artifact_sha256"],
        )

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

    def test_create_challenge_writes_owner_only_32_bytes_and_fixed_token(self):
        os.unlink(self.challenge_path)
        result = self.run_cli("create-challenge", "--output", self.challenge_path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"GH229_CHALLENGE_CREATED\n")
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
        self.assertEqual(result.stderr, b"attestation: paths\n")
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
            with self.assertRaises(MODULE.AttestationFailure) as failure:
                MODULE.create_challenge(self.challenge_path)
        self.assertEqual(failure.exception.reason, "paths")
        with open(self.challenge_path, "rb") as handle:
            self.assertEqual(handle.read(), concurrent_content)

    def test_create_challenge_refuses_symlink_output(self):
        os.unlink(self.challenge_path)
        os.symlink(os.path.join(self.root, "elsewhere"), self.challenge_path)
        result = self.run_cli("create-challenge", "--output", self.challenge_path)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"attestation: paths\n")
        self.assertTrue(os.path.islink(self.challenge_path))
        self.assertFalse(
            os.path.lexists(os.path.join(self.root, "elsewhere"))
        )

    def test_create_challenge_rejects_unsafe_parent_mode(self):
        os.unlink(self.challenge_path)
        os.chmod(self.root, 0o755)
        result = self.run_cli("create-challenge", "--output", self.challenge_path)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"attestation: paths\n")
        self.assertFalse(os.path.lexists(self.challenge_path))

    def test_create_challenge_rejects_symlink_parent(self):
        real_dir = os.path.realpath(tempfile.mkdtemp(prefix="gh229-real-"))
        self.addCleanup(shutil.rmtree, real_dir, True)
        os.chmod(real_dir, 0o700)
        link = os.path.join(self.root, "linked")
        os.symlink(real_dir, link)
        result = self.run_cli(
            "create-challenge", "--output", os.path.join(link, "challenge.bin")
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"attestation: paths\n")
        self.assertEqual(os.listdir(real_dir), [])

    def test_attest_rejects_symlink_challenge(self):
        real_challenge = os.path.join(self.root, "real-challenge.bin")
        os.rename(self.challenge_path, real_challenge)
        os.symlink(real_challenge, self.challenge_path)
        result = self.run_attest()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"attestation: challenge\n")

    def test_attest_rejects_symlinked_challenge_parent(self):
        real_dir = os.path.realpath(tempfile.mkdtemp(prefix="gh229-real-"))
        self.addCleanup(shutil.rmtree, real_dir, True)
        os.chmod(real_dir, 0o700)
        linked = os.path.join(real_dir, "challenge.bin")
        self.write_challenge(path=linked)
        link = os.path.join(self.root, "linked")
        os.symlink(real_dir, link)
        result = self.run_attest(challenge=os.path.join(link, "challenge.bin"))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"attestation: paths\n")

    def test_attest_rejects_wrong_challenge_mode(self):
        os.chmod(self.challenge_path, 0o644)
        result = self.run_attest()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"attestation: challenge\n")

    def test_attest_rejects_wrong_challenge_size(self):
        for size in (0, 31, 33, 64):
            with self.subTest(size=size):
                path = os.path.join(self.root, "challenge-%d.bin" % size)
                self.write_challenge(content=b"c" * size, path=path)
                result = self.run_attest(challenge=path)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stderr, b"attestation: challenge\n")

    def test_attest_rejects_symlink_artifact(self):
        os.unlink(self.artifact_path)
        os.symlink(os.path.join(self.root, "real-artifact.bin"), self.artifact_path)
        result = self.run_attest()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"attestation: artifact\n")

    def test_attest_rejects_non_regular_artifact(self):
        result = self.run_attest(artifact=self.root)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"attestation: artifact\n")

    def test_attest_rejects_missing_challenge_and_artifact(self):
        missing = os.path.join(self.root, "missing.bin")
        for overrides, reason in (
            ({"challenge": missing}, b"attestation: challenge\n"),
            ({"artifact": missing}, b"attestation: artifact\n"),
        ):
            with self.subTest(**overrides):
                result = self.run_attest(**overrides)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(result.stderr, reason)

    def test_cli_rejects_malformed_arguments(self):
        for overrides in (
            {"role": "operator"},
            {"role": "SENDER"},
            {"source_commit": COMMIT.upper()},
            {"source_commit": "g" * 40},
            {"source_commit": COMMIT[:-1]},
            {"payload_sha256": PAYLOAD_SHA256.upper()},
            {"payload_sha256": "g" * 64},
            {"payload_sha256": PAYLOAD_SHA256[:-1]},
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
                self.assertEqual(result.stderr, b"attestation: args\n")

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
                CHALLENGE.hex().encode(),
                CHALLENGE_SHA256.encode(),
            ):
                self.assertNotIn(forbidden, blob)


if __name__ == "__main__":
    unittest.main()
