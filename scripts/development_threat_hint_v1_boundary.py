#!/usr/bin/env python3
"""Development-only GH-229 bounded ThreatHint v1 local boundary (Unix).

This is a single-shot mock verifier boundary for Development/Testnet-10
evidence only. It accepts exactly one length-prefixed v1 frame on an
owner-only AF_UNIX socket, verifies the expected payload digest, sends the
exact canonical acknowledgement the Rust ingress requires, and writes one
owner-only redacted receipt. It never supports ``accepted`` or ``duplicate``
because this tool records Development evidence and holds no proof, consensus,
membership, or reward authority. Standard library only.
"""

import argparse
import hashlib
import hmac
import json
import os
import re
import socket
import stat
import struct
import sys
import tempfile

# Matches MAX_THREAT_HINT_BYTES in prometheus-guardian-p2p (schema v1).
MAX_FRAME_BYTES = 2048
PROTOCOL_VERSION = 1
SCHEMA_VERSION = 1
EVENT = "development-threat-hint-v1-boundary"
STATUSES = ("rejected", "busy")
MIN_TIMEOUT_SECS = 1
MAX_TIMEOUT_SECS = 60
DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}")
FRAME_PREFIX_BYTES = 4


class BoundaryFailure(Exception):
    """A fail-closed rejection with a fixed data-minimal reason key."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def fail(reason):
    raise BoundaryFailure(reason)


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description=(
            "Development-only single-shot ThreatHint v1 verifier boundary; "
            "records redacted evidence and never claims proof authority."
        )
    )
    parser.add_argument("--socket", required=True, dest="socket_path")
    parser.add_argument("--receipt", required=True, dest="receipt_path")
    parser.add_argument("--expected-sha256", required=True, dest="expected_sha256")
    parser.add_argument("--status", required=True, choices=STATUSES)
    parser.add_argument("--timeout", required=True, type=int)
    args = parser.parse_args(argv)
    if not DIGEST_PATTERN.fullmatch(args.expected_sha256):
        parser.error("expected sha256 must be 64 lowercase hex characters")
    if not MIN_TIMEOUT_SECS <= args.timeout <= MAX_TIMEOUT_SECS:
        parser.error("timeout must be within 1..60 seconds")
    return args


def validate_target(path, euid):
    """Require an absolute canonical non-existent path with an owner-only
    parent (mode 0700, current effective uid, no symlinks anywhere)."""
    if not os.path.isabs(path) or path != os.path.normpath(path):
        fail("args")
    parent = os.path.dirname(path)
    if not parent or not os.path.basename(path):
        fail("args")
    try:
        if os.path.realpath(parent) != parent:
            fail("paths")
        parent_stat = os.lstat(parent)
    except OSError:
        fail("paths")
    if (
        stat.S_ISLNK(parent_stat.st_mode)
        or not stat.S_ISDIR(parent_stat.st_mode)
        or parent_stat.st_mode & 0o777 != 0o700
        or parent_stat.st_uid != euid
    ):
        fail("paths")
    if os.path.lexists(path):
        fail("paths")


def recv_exact(connection, count):
    chunks = bytearray()
    while len(chunks) < count:
        try:
            chunk = connection.recv(count - len(chunks))
        except socket.timeout:
            fail("timeout")
        except OSError:
            fail("io")
        if not chunk:
            fail("framing")
        chunks += chunk
    return bytes(chunks)


def read_frame(connection):
    """Read one big-endian u32 length, the exact capped payload, and EOF."""
    (length,) = struct.unpack(">I", recv_exact(connection, FRAME_PREFIX_BYTES))
    if length == 0 or length > MAX_FRAME_BYTES:
        fail("framing")
    payload = recv_exact(connection, length)
    try:
        trailing = connection.recv(1)
    except socket.timeout:
        fail("timeout")
    except OSError:
        fail("io")
    if trailing:
        fail("framing")
    return payload


def canonical_ack(status, digest):
    """Exact canonical acknowledgement the Rust ingress requires: field order
    payload_digest, protocol_version, status; busy carries an empty digest."""
    ack_digest = "" if status == "busy" else digest
    return (
        '{"payload_digest":"%s","protocol_version":%d,"status":"%s"}'
        % (ack_digest, PROTOCOL_VERSION, status)
    ).encode("ascii")


def write_receipt(path, status, digest, payload_bytes):
    """Atomically create one owner-only 0600 receipt with allowlisted data."""
    record = json.dumps(
        {
            "schema_version": SCHEMA_VERSION,
            "event": EVENT,
            "status": status,
            "payload_sha256": digest,
            "payload_bytes": payload_bytes,
        },
        separators=(",", ":"),
    ).encode("ascii")
    parent = os.path.dirname(path)
    descriptor = None
    temporary_path = None
    temporary_identity = None
    published = False
    completed = False
    try:
        descriptor, temporary_path = tempfile.mkstemp(
            prefix=".gh229-receipt-", dir=parent
        )
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        temporary_identity = (metadata.st_dev, metadata.st_ino)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
        ):
            fail("paths")
        view = memoryview(record)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None

        # Publishing by hard link is atomic and refuses an existing target.
        os.link(temporary_path, path, follow_symlinks=False)
        published = True
        published_metadata = os.lstat(path)
        if (
            not stat.S_ISREG(published_metadata.st_mode)
            or published_metadata.st_uid != os.geteuid()
            or (published_metadata.st_dev, published_metadata.st_ino)
            != temporary_identity
        ):
            fail("paths")
        os.unlink(temporary_path)
        temporary_path = None
        if os.lstat(path).st_nlink != 1:
            fail("paths")
        completed = True
    except BoundaryFailure:
        raise
    except OSError:
        fail("paths")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if published and not completed and temporary_identity is not None:
            try:
                metadata = os.lstat(path)
                if (metadata.st_dev, metadata.st_ino) == temporary_identity:
                    os.unlink(path)
            except OSError:
                pass
        if temporary_path is not None and temporary_identity is not None:
            try:
                metadata = os.lstat(temporary_path)
                if (metadata.st_dev, metadata.st_ino) == temporary_identity:
                    os.unlink(temporary_path)
            except OSError:
                pass


def cleanup_socket(path, identity, euid):
    """Unlink only the owned socket this process created, by identity."""
    try:
        metadata = os.lstat(path)
    except OSError:
        return
    if (
        stat.S_ISSOCK(metadata.st_mode)
        and metadata.st_uid == euid
        and (metadata.st_dev, metadata.st_ino) == identity
    ):
        try:
            os.unlink(path)
        except OSError:
            pass


def run(args):
    euid = os.geteuid()
    validate_target(args.socket_path, euid)
    validate_target(args.receipt_path, euid)

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    socket_identity = None
    try:
        # Restrict the umask so the socket is never observable with a mode
        # wider than 0600, then chmod explicitly as the contract requires.
        saved_umask = os.umask(0o077)
        try:
            listener.bind(args.socket_path)
        finally:
            os.umask(saved_umask)
        os.chmod(args.socket_path, 0o600)
        metadata = os.lstat(args.socket_path)
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_uid != euid
            or metadata.st_mode & 0o777 != 0o600
        ):
            fail("paths")
        socket_identity = (metadata.st_dev, metadata.st_ino)
        listener.listen(1)
        listener.settimeout(args.timeout)
        try:
            connection, _ = listener.accept()
        except socket.timeout:
            fail("timeout")
        with connection:
            connection.settimeout(args.timeout)
            payload = read_frame(connection)
            digest = hashlib.sha256(payload).hexdigest()
            if not hmac.compare_digest(digest, args.expected_sha256):
                fail("digest")
            write_receipt(args.receipt_path, args.status, digest, len(payload))
            ack = canonical_ack(args.status, digest)
            connection.sendall(struct.pack(">I", len(ack)) + ack)
    finally:
        listener.close()
        if socket_identity is not None:
            cleanup_socket(args.socket_path, socket_identity, euid)
    return args.status


def main(argv=None):
    if os.name != "posix" or not hasattr(socket, "AF_UNIX"):
        print("boundary: unsupported-platform", file=sys.stderr)
        return 1
    args = parse_args(argv)
    try:
        status = run(args)
    except BoundaryFailure as failure:
        print("boundary: %s" % failure.reason, file=sys.stderr)
        return 1
    except OSError:
        print("boundary: io", file=sys.stderr)
        return 1
    print(status)
    return 0


if __name__ == "__main__":
    sys.exit(main())
