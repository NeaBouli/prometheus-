#!/usr/bin/env python3
"""Focused tests for the GH-229 Development-only ThreatHint v1 boundary."""

import hashlib
import json
import os
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "development_threat_hint_v1_boundary.py",
)
PAYLOAD = b'{"schema_version":1,"threat_hash":"ab"}'
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()
WRONG_DIGEST = "0" * 64
READY_DEADLINE_SECS = 10.0
PROCESS_DEADLINE_SECS = 15.0


def canonical_ack(status, digest):
    ack_digest = "" if status == "busy" else digest
    body = (
        '{"payload_digest":"%s","protocol_version":1,"status":"%s"}'
        % (ack_digest, status)
    ).encode("ascii")
    return struct.pack(">I", len(body)) + body


def expected_receipt(status, digest, payload_bytes):
    return json.dumps(
        {
            "schema_version": 1,
            "event": "development-threat-hint-v1-boundary",
            "status": status,
            "payload_sha256": digest,
            "payload_bytes": payload_bytes,
        },
        separators=(",", ":"),
    ).encode("ascii")


class BoundaryTestCase(unittest.TestCase):
    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp(prefix="boundary-test-"))
        os.chmod(self.root, 0o700)
        self.socket_path = os.path.join(self.root, "threat-hint.sock")
        self.receipt_path = os.path.join(self.root, "receipt.json")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def spawn(self, **overrides):
        options = {
            "--socket": self.socket_path,
            "--receipt": self.receipt_path,
            "--expected-sha256": DIGEST,
            "--status": "rejected",
            "--timeout": "10",
        }
        for key, value in overrides.items():
            options["--" + key.replace("_", "-")] = str(value)
        argv = [sys.executable, SCRIPT]
        for flag, value in options.items():
            argv.extend([flag, value])
        process = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.addCleanup(self._reap, process)
        return process

    @staticmethod
    def _reap(process):
        if process.poll() is None:
            process.kill()
        process.communicate()

    def wait_ready(self, process, path=None):
        """Block until the bound socket appears or the process exits."""
        target = path or self.socket_path
        deadline = time.monotonic() + READY_DEADLINE_SECS
        while time.monotonic() < deadline:
            if process.poll() is not None:
                self.fail(
                    "boundary exited before readiness: %r"
                    % (process.communicate(),)
                )
            if os.path.exists(target):
                return
            time.sleep(0.01)
        process.kill()
        self.fail("boundary did not bind within the readiness deadline")

    def finish(self, process):
        stdout, stderr = process.communicate(timeout=PROCESS_DEADLINE_SECS)
        return process.returncode, stdout, stderr

    def exchange(self, payload=PAYLOAD, length=None, trailing=b""):
        """Drive one client frame and return everything the boundary sent.

        Retries refused connections until the listener transitions from bind
        to listen, bounded by the readiness deadline.
        """
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(PROCESS_DEADLINE_SECS)
        deadline = time.monotonic() + READY_DEADLINE_SECS
        while True:
            try:
                client.connect(self.socket_path)
                break
            except ConnectionRefusedError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.01)
        client.sendall(
            struct.pack(">I", len(payload) if length is None else length)
        )
        client.sendall(payload)
        if trailing:
            client.sendall(trailing)
        client.shutdown(socket.SHUT_WR)
        response = b""
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            response += chunk
        client.close()
        return response

    def assert_receipt(self, status, digest=DIGEST, payload_bytes=len(PAYLOAD)):
        with open(self.receipt_path, "rb") as handle:
            content = handle.read()
        self.assertEqual(content, expected_receipt(status, digest, payload_bytes))
        metadata = os.lstat(self.receipt_path)
        self.assertTrue(stat.S_ISREG(metadata.st_mode))
        self.assertEqual(metadata.st_mode & 0o777, 0o600)
        self.assertEqual(metadata.st_uid, os.geteuid())
        self.assertEqual(metadata.st_nlink, 1)
        self.assertEqual(os.listdir(self.root), ["receipt.json"])

    def assert_redacted(self, *blobs):
        for blob in blobs:
            for forbidden in (
                self.root.encode(),
                self.socket_path.encode(),
                self.receipt_path.encode(),
                DIGEST.encode(),
                PAYLOAD,
            ):
                self.assertNotIn(forbidden, blob)

    def test_rejected_roundtrip_canonical_ack_and_receipt(self):
        process = self.spawn()
        self.wait_ready(process)
        metadata = os.lstat(self.socket_path)
        self.assertTrue(stat.S_ISSOCK(metadata.st_mode))
        self.assertEqual(metadata.st_mode & 0o777, 0o600)

        response = self.exchange()
        self.assertEqual(response, canonical_ack("rejected", DIGEST))

        returncode, stdout, stderr = self.finish(process)
        self.assertEqual(returncode, 0)
        self.assertEqual(stdout, b"rejected\n")
        self.assertEqual(stderr, b"")
        self.assert_receipt("rejected")
        self.assertFalse(os.path.lexists(self.socket_path))
        self.assert_redacted(stdout, stderr)

    def test_busy_roundtrip_has_empty_digest(self):
        process = self.spawn(status="busy")
        self.wait_ready(process)
        response = self.exchange()
        self.assertEqual(response, canonical_ack("busy", DIGEST))

        returncode, stdout, stderr = self.finish(process)
        self.assertEqual(returncode, 0)
        self.assertEqual(stdout, b"busy\n")
        self.assertEqual(stderr, b"")
        self.assert_receipt("busy")
        self.assertFalse(os.path.lexists(self.socket_path))

    def test_digest_mismatch_fails_closed(self):
        process = self.spawn(expected_sha256=WRONG_DIGEST)
        self.wait_ready(process)
        response = self.exchange()
        self.assertEqual(response, b"", "mismatch must not receive an ack")

        returncode, stdout, stderr = self.finish(process)
        self.assertEqual(returncode, 1)
        self.assertEqual(stdout, b"")
        self.assertEqual(stderr, b"boundary: digest\n")
        self.assertFalse(os.path.lexists(self.receipt_path))
        self.assertFalse(os.path.lexists(self.socket_path))
        self.assert_redacted(stdout, stderr)

    def test_oversize_frame_rejected(self):
        process = self.spawn()
        self.wait_ready(process)
        response = self.exchange(payload=b"x" * 2049)
        self.assertEqual(response, b"")

        returncode, _, stderr = self.finish(process)
        self.assertEqual(returncode, 1)
        self.assertEqual(stderr, b"boundary: framing\n")
        self.assertFalse(os.path.lexists(self.receipt_path))
        self.assertFalse(os.path.lexists(self.socket_path))

    def test_truncated_frame_rejected(self):
        process = self.spawn()
        self.wait_ready(process)
        response = self.exchange(payload=b"12345", length=10)
        self.assertEqual(response, b"")

        returncode, _, stderr = self.finish(process)
        self.assertEqual(returncode, 1)
        self.assertEqual(stderr, b"boundary: framing\n")
        self.assertFalse(os.path.lexists(self.receipt_path))
        self.assertFalse(os.path.lexists(self.socket_path))

    def test_trailing_bytes_rejected(self):
        process = self.spawn()
        self.wait_ready(process)
        response = self.exchange(trailing=b"x")
        self.assertEqual(response, b"")

        returncode, _, stderr = self.finish(process)
        self.assertEqual(returncode, 1)
        self.assertEqual(stderr, b"boundary: framing\n")
        self.assertFalse(os.path.lexists(self.receipt_path))
        self.assertFalse(os.path.lexists(self.socket_path))

    def test_unsafe_parent_mode_rejected(self):
        os.chmod(self.root, 0o755)
        process = self.spawn()
        returncode, stdout, stderr = self.finish(process)
        self.assertEqual(returncode, 1)
        self.assertEqual(stdout, b"")
        self.assertEqual(stderr, b"boundary: paths\n")
        self.assertFalse(os.path.lexists(self.socket_path))
        self.assertFalse(os.path.lexists(self.receipt_path))
        self.assert_redacted(stdout, stderr)

    def test_symlink_parent_rejected(self):
        real_dir = os.path.realpath(tempfile.mkdtemp(prefix="boundary-real-"))
        self.addCleanup(shutil.rmtree, real_dir, True)
        os.chmod(real_dir, 0o700)
        link = os.path.join(self.root, "linked")
        os.symlink(real_dir, link)
        process = self.spawn(
            socket=os.path.join(link, "threat-hint.sock"),
            receipt=os.path.join(link, "receipt.json"),
        )
        returncode, _, stderr = self.finish(process)
        self.assertEqual(returncode, 1)
        self.assertEqual(stderr, b"boundary: paths\n")
        self.assertEqual(os.listdir(real_dir), [])

    def test_existing_socket_path_rejected_and_preserved(self):
        marker = os.path.join(self.root, "taken.sock")
        with open(marker, "wb") as handle:
            handle.write(b"keep")
        process = self.spawn(socket=marker)
        returncode, _, stderr = self.finish(process)
        self.assertEqual(returncode, 1)
        self.assertEqual(stderr, b"boundary: paths\n")
        with open(marker, "rb") as handle:
            self.assertEqual(handle.read(), b"keep")

    def test_symlink_socket_path_rejected(self):
        target = os.path.join(self.root, "elsewhere")
        os.symlink(target, self.socket_path)
        process = self.spawn()
        returncode, _, stderr = self.finish(process)
        self.assertEqual(returncode, 1)
        self.assertEqual(stderr, b"boundary: paths\n")
        self.assertTrue(os.path.islink(self.socket_path))

    def test_existing_receipt_rejected(self):
        with open(self.receipt_path, "wb") as handle:
            handle.write(b"previous")
        os.chmod(self.receipt_path, 0o600)
        process = self.spawn()
        returncode, _, stderr = self.finish(process)
        self.assertEqual(returncode, 1)
        self.assertEqual(stderr, b"boundary: paths\n")
        with open(self.receipt_path, "rb") as handle:
            self.assertEqual(handle.read(), b"previous")
        self.assertFalse(os.path.lexists(self.socket_path))

    def test_timeout_cleans_up_socket(self):
        process = self.spawn(timeout=1)
        self.wait_ready(process)
        self.assertTrue(os.path.exists(self.socket_path))
        returncode, stdout, stderr = self.finish(process)
        self.assertEqual(returncode, 1)
        self.assertEqual(stdout, b"")
        self.assertEqual(stderr, b"boundary: timeout\n")
        self.assertFalse(os.path.lexists(self.socket_path))
        self.assertFalse(os.path.lexists(self.receipt_path))

    def test_cli_rejects_non_development_statuses_and_bad_values(self):
        for overrides in (
            {"status": "accepted"},
            {"status": "duplicate"},
            {"expected_sha256": DIGEST.upper()},
            {"expected_sha256": "g" * 64},
            {"expected_sha256": DIGEST[:-1]},
            {"timeout": 0},
            {"timeout": 61},
        ):
            with self.subTest(**overrides):
                process = self.spawn(**overrides)
                returncode, _, _ = self.finish(process)
                self.assertEqual(returncode, 2)
                self.assertFalse(os.path.lexists(self.socket_path))
                self.assertFalse(os.path.lexists(self.receipt_path))

    def test_maximum_frame_accepted(self):
        payload = b"y" * 2048
        digest = hashlib.sha256(payload).hexdigest()
        process = self.spawn(expected_sha256=digest)
        self.wait_ready(process)
        response = self.exchange(payload=payload)
        self.assertEqual(response, canonical_ack("rejected", digest))

        returncode, stdout, _ = self.finish(process)
        self.assertEqual(returncode, 0)
        self.assertEqual(stdout, b"rejected\n")
        self.assert_receipt("rejected", digest, len(payload))


if __name__ == "__main__":
    unittest.main()
