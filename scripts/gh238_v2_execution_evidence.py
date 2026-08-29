#!/usr/bin/env python3
"""GH-238 ThreatHint-v2 execution evidence tool (Unix, repository-only).

This Development-only helper prepares the GH-238 evidence inputs before any
separately authorized real two-host v2 run. ``create-challenge`` creates
exactly 32 cryptographically random bytes in a new owner-only 0600 regular
file under an existing canonical owner-only 0700 parent, refusing symlinks
and existing paths. ``attest`` reads that exact owner-only challenge without
following symlinks, hashes the actual trusted non-group/world-writable
regular executable artifact bytes and the actual owner-only no-symlink
bounded payload file bytes, and computes a deterministic domain-separated
SHA-256 over versioned canonical binary framing that binds the role,
challenge bytes, source commit bytes, artifact digest bytes, payload digest
bytes, and the exact Guardian v2 protocol ``/prometheus/threat-hint/2.0.0``.
``build-record`` reads two strict owner-only attestation JSON files and writes
one new owner-only redacted public JSON record atomically and fail-closed.
Both roles must bind the same observed rejected outcome, one attempt, zero
retries and no persistence; no CLI option can promote those values. All
evidence is operator attestation, never
independent host proof, and carries no proof, membership, privacy, wallet,
chain, reward, deployment, Mainnet, or production authority. Standard
library only.
"""

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from typing import NoReturn

CHALLENGE_BYTES = 32
COMMIT_HEX = re.compile(r"[0-9a-f]{40}")
DIGEST_HEX = re.compile(r"[0-9a-f]{64}")
ROLES = ("sender", "guardian")
PROTOCOL = "/prometheus/threat-hint/2.0.0"
OBSERVED_STATUS = "rejected"
OBSERVED_ATTEMPTS = 1
OBSERVED_RETRIES = 0
OBSERVED_PERSISTED = False
DOMAIN_SEPARATOR = b"prometheus-gh238-v2-execution-attestation"
FRAMING_VERSION = 1
READ_CHUNK_BYTES = 1024 * 1024
# Mirrors prometheus_threat_hint::MAX_TRANSPORT_PAYLOAD_BYTES exactly:
# 49-byte frame header + 4096-byte envelope + 4096-byte bundle + 1024-byte approval.
PAYLOAD_MAX_BYTES = 9_265
ATTESTATION_MAX_BYTES = 4096
CHALLENGE_TOKEN = "GH238_CHALLENGE_CREATED"
RECORD_TOKEN = "GH238_RECORD_WRITTEN"
DIAGNOSTIC_PREFIX = "gh238-evidence"
UTC_TIMESTAMP = re.compile(
    r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z"
)
EARLIEST_OBSERVATION = dt.datetime(2026, 8, 30, tzinfo=dt.timezone.utc)
TOOLCHAIN = re.compile(
    r"rustc 1\.95\.0 \([0-9a-f]{9} 20[0-9]{2}-[0-9]{2}-[0-9]{2}\)(?: \(Homebrew\))?"
)
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


class EvidenceFailure(Exception):
    """A fail-closed rejection with a fixed data-minimal reason key."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def fail(reason: str) -> NoReturn:
    raise EvidenceFailure(reason)


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description=(
            "GH-238 ThreatHint-v2 execution challenge, operator attestation "
            "and redacted record construction; operator-attested Development "
            "evidence only, never independent host proof or any authorizing "
            "authority."
        )
    )
    subcommands = parser.add_subparsers(dest="subcommand", required=True)
    create = subcommands.add_parser(
        "create-challenge",
        help="create one owner-only 32-byte random challenge file",
    )
    create.add_argument("--output", required=True)
    attest = subcommands.add_parser(
        "attest",
        help="emit one canonical v2 execution attestation JSON line",
    )
    attest.add_argument("--challenge", required=True)
    attest.add_argument("--role", required=True, choices=ROLES)
    attest.add_argument("--source-commit", required=True)
    attest.add_argument("--artifact", required=True)
    attest.add_argument("--payload", required=True)
    attest.add_argument("--observed-at-utc", required=True)
    attest.add_argument("--observed-status", required=True, choices=(OBSERVED_STATUS,))
    attest.add_argument("--one-shot", required=True, action="store_true")
    attest.add_argument("--no-persistence", required=True, action="store_true")
    record = subcommands.add_parser(
        "build-record",
        help="write one owner-only redacted public record atomically",
    )
    record.add_argument("--sender-attestation", required=True)
    record.add_argument("--guardian-attestation", required=True)
    record.add_argument("--toolchain", required=True)
    record.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    if args.subcommand == "attest":
        if COMMIT_HEX.fullmatch(args.source_commit) is None:
            parser.error("source commit must be 40 lowercase hex characters")
        if UTC_TIMESTAMP.fullmatch(args.observed_at_utc) is None:
            parser.error("observation timestamp must be strict UTC form")
    if args.subcommand == "build-record":
        if TOOLCHAIN.fullmatch(args.toolchain) is None:
            parser.error("toolchain must be the pinned rustc 1.95.0 form")
    return args


def require_canonical_absolute(path):
    """Require an absolute normalized path with a real final component name."""
    if not os.path.isabs(path) or path != os.path.normpath(path):
        fail("args")
    if not os.path.basename(path):
        fail("args")


def require_real_parent(path):
    """Require an existing canonical directory parent with no symlink anywhere."""
    parent = os.path.dirname(path)
    if not parent:
        fail("args")
    try:
        if os.path.realpath(parent) != parent:
            fail("paths")
        parent_stat = os.lstat(parent)
    except OSError:
        fail("paths")
    if stat.S_ISLNK(parent_stat.st_mode) or not stat.S_ISDIR(parent_stat.st_mode):
        fail("paths")
    return parent_stat


def create_challenge(output_path):
    """Create exactly 32 random bytes in a new owner-only 0600 regular file."""
    euid = os.geteuid()
    require_canonical_absolute(output_path)
    parent_stat = require_real_parent(output_path)
    if parent_stat.st_uid != euid or parent_stat.st_mode & 0o777 != 0o700:
        fail("paths")
    if os.path.lexists(output_path):
        fail("paths")
    challenge = os.urandom(CHALLENGE_BYTES)
    descriptor = None
    created_identity = None
    completed = False
    try:
        try:
            descriptor = os.open(
                output_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
        except OSError:
            fail("paths")
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        created_identity = (metadata.st_dev, metadata.st_ino)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != euid
            or metadata.st_mode & 0o777 != 0o600
            or metadata.st_nlink != 1
        ):
            fail("paths")
        view = memoryview(challenge)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                fail("io")
            view = view[written:]
        os.fsync(descriptor)
        completed = True
    except EvidenceFailure:
        raise
    except OSError:
        fail("io")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if not completed and created_identity is not None:
            try:
                created = os.lstat(output_path)
                if (
                    stat.S_ISREG(created.st_mode)
                    and created.st_uid == euid
                    and (created.st_dev, created.st_ino) == created_identity
                ):
                    os.unlink(output_path)
            except OSError:
                pass


def open_owner_file(path, reason):
    """Open one canonical path without following a final symlink."""
    require_canonical_absolute(path)
    require_real_parent(path)
    try:
        return os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        fail(reason)


def read_challenge(path):
    """Read the exact owner-only 32-byte challenge without following symlinks."""
    euid = os.geteuid()
    descriptor = open_owner_file(path, "challenge")
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != euid
            or metadata.st_mode & 0o777 != 0o600
            or metadata.st_size != CHALLENGE_BYTES
            or metadata.st_nlink != 1
        ):
            fail("challenge")
        chunks = bytearray()
        while len(chunks) < CHALLENGE_BYTES:
            try:
                chunk = os.read(descriptor, CHALLENGE_BYTES - len(chunks))
            except OSError:
                fail("io")
            if not chunk:
                break
            chunks += chunk
        if len(chunks) != CHALLENGE_BYTES:
            fail("challenge")
        try:
            if os.read(descriptor, 1) or _file_snapshot(
                os.fstat(descriptor)
            ) != _file_snapshot(metadata):
                fail("challenge")
        except OSError:
            fail("io")
        return bytes(chunks)
    finally:
        os.close(descriptor)


def hash_artifact(path):
    """Stream-hash trusted non-writable regular executable artifact bytes."""
    euid = os.geteuid()
    require_canonical_absolute(path)
    parent_stat = require_real_parent(path)
    if parent_stat.st_uid not in (0, euid) or parent_stat.st_mode & 0o022:
        fail("artifact")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        fail("artifact")
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid not in (0, euid)
            or metadata.st_mode & 0o022
            or not metadata.st_mode & 0o100
            or metadata.st_size < 1
        ):
            fail("artifact")
        return _stream_digest(descriptor, "artifact", metadata)
    finally:
        os.close(descriptor)


def hash_payload(path):
    """Stream-hash one owner-only no-symlink bounded payload file."""
    euid = os.geteuid()
    descriptor = open_owner_file(path, "payload")
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != euid
            or metadata.st_mode & 0o077
            or metadata.st_size < 1
            or metadata.st_size > PAYLOAD_MAX_BYTES
            or metadata.st_nlink != 1
        ):
            fail("payload")
        return _stream_digest(descriptor, "payload", metadata)
    finally:
        os.close(descriptor)


def _file_snapshot(metadata):
    """Return fields that must remain stable while evidence bytes are read."""
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _stream_digest(descriptor, reason, initial_metadata):
    """Hash exactly the initially observed bytes and reject concurrent mutation."""
    digest = hashlib.sha256()
    total = 0
    while True:
        try:
            remaining = initial_metadata.st_size - total
            chunk = os.read(descriptor, min(READ_CHUNK_BYTES, remaining + 1))
        except OSError:
            fail("io")
        if not chunk:
            break
        total += len(chunk)
        if total > initial_metadata.st_size:
            fail(reason)
        digest.update(chunk)
    try:
        final_metadata = os.fstat(descriptor)
    except OSError:
        fail("io")
    if total != initial_metadata.st_size or _file_snapshot(
        final_metadata
    ) != _file_snapshot(initial_metadata):
        fail(reason)
    return digest.digest()


def execution_attestation(
    role,
    challenge,
    commit,
    artifact_digest,
    payload_digest,
    protocol,
    observed_at,
    observed_status,
    attempts,
    retries,
    persisted,
):
    """Domain-separated SHA-256 over versioned canonical binary framing.

    frame = DOMAIN_SEPARATOR || 0x00 || u8(FRAMING_VERSION) ||
            u8(len)||role || u8(len)||challenge || u8(len)||commit ||
            u8(len)||artifact_digest || u8(len)||payload_digest ||
            u8(len)||protocol || u8(len)||observed_at ||
            u8(len)||observed_status || u8(len)||attempts ||
            u8(len)||retries || u8(len)||persisted
    where u8(len) is one unsigned byte and all values are raw bytes.
    """
    frame = bytearray(DOMAIN_SEPARATOR)
    frame.append(0)
    frame.append(FRAMING_VERSION)
    for field in (
        role.encode("ascii"),
        challenge,
        commit,
        artifact_digest,
        payload_digest,
        protocol.encode("ascii"),
        observed_at.encode("ascii"),
        observed_status.encode("ascii"),
        str(attempts).encode("ascii"),
        str(retries).encode("ascii"),
        str(persisted).lower().encode("ascii"),
    ):
        frame.append(len(field))
        frame += field
    return hashlib.sha256(bytes(frame)).digest()


def attest(args):
    """Emit the canonical compact attestation JSON line for one host role."""
    validate_observation(args.observed_at_utc)
    challenge = read_challenge(args.challenge)
    artifact_digest = hash_artifact(args.artifact)
    payload_digest = hash_payload(args.payload)
    commit = bytes.fromhex(args.source_commit)
    attestation = execution_attestation(
        args.role,
        challenge,
        commit,
        artifact_digest,
        payload_digest,
        PROTOCOL,
        args.observed_at_utc,
        args.observed_status,
        OBSERVED_ATTEMPTS,
        OBSERVED_RETRIES,
        OBSERVED_PERSISTED,
    )
    print(
        '{"role":"%s","source_commit":"%s","challenge_sha256":"%s",'
        '"artifact_sha256":"%s","payload_sha256":"%s","protocol":"%s",'
        '"observed_at_utc":"%s","observed_status":"%s",'
        '"attempts":%d,"retries":%d,"persisted":false,'
        '"execution_attestation_sha256":"%s"}'
        % (
            args.role,
            args.source_commit,
            hashlib.sha256(challenge).hexdigest(),
            artifact_digest.hex(),
            payload_digest.hex(),
            PROTOCOL,
            args.observed_at_utc,
            args.observed_status,
            OBSERVED_ATTEMPTS,
            OBSERVED_RETRIES,
            attestation.hex(),
        )
    )


def _reject_duplicate_keys(pairs):
    """Strict JSON object hook: duplicate keys fail closed."""
    result = {}
    for key, value in pairs:
        if key in result:
            fail("attestation")
        result[key] = value
    return result


def read_attestation(path, expected_role):
    """Read and strictly validate one owner-only attestation JSON file."""
    euid = os.geteuid()
    descriptor = open_owner_file(path, "attestation")
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != euid
            or metadata.st_mode & 0o077
            or metadata.st_size < 1
            or metadata.st_size > ATTESTATION_MAX_BYTES
            or metadata.st_nlink != 1
        ):
            fail("attestation")
        chunks = bytearray()
        while True:
            try:
                chunk = os.read(descriptor, READ_CHUNK_BYTES)
            except OSError:
                fail("io")
            if not chunk:
                break
            chunks += chunk
            if len(chunks) > metadata.st_size:
                fail("attestation")
        if len(chunks) != metadata.st_size or _file_snapshot(
            os.fstat(descriptor)
        ) != _file_snapshot(metadata):
            fail("attestation")
    finally:
        os.close(descriptor)
    try:
        data = json.loads(
            bytes(chunks).decode("ascii"), object_pairs_hook=_reject_duplicate_keys
        )
    except (UnicodeDecodeError, ValueError):
        fail("attestation")
    if type(data) is not dict or set(data) != ATTESTATION_KEYS:
        fail("attestation")
    if data["role"] != expected_role:
        fail("attestation")
    if (
        type(data["source_commit"]) is not str
        or COMMIT_HEX.fullmatch(data["source_commit"]) is None
    ):
        fail("attestation")
    for field in (
        "challenge_sha256",
        "artifact_sha256",
        "payload_sha256",
        "execution_attestation_sha256",
    ):
        if type(data[field]) is not str or DIGEST_HEX.fullmatch(data[field]) is None:
            fail("attestation")
    if data["protocol"] != PROTOCOL:
        fail("attestation")
    if type(data["observed_at_utc"]) is not str:
        fail("attestation")
    validate_observation(data["observed_at_utc"])
    if data["observed_status"] != OBSERVED_STATUS:
        fail("attestation")
    if type(data["attempts"]) is not int or data["attempts"] != OBSERVED_ATTEMPTS:
        fail("attestation")
    if type(data["retries"]) is not int or data["retries"] != OBSERVED_RETRIES:
        fail("attestation")
    if data["persisted"] is not OBSERVED_PERSISTED:
        fail("attestation")
    return data


def validate_observation(observed_at):
    """Require a strict UTC timestamp at or after the GH-238 boundary."""
    if UTC_TIMESTAMP.fullmatch(observed_at) is None:
        fail("timestamp")
    try:
        parsed = dt.datetime.strptime(observed_at, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=dt.timezone.utc
        )
    except ValueError:
        fail("timestamp")
    if parsed < EARLIEST_OBSERVATION:
        fail("timestamp")


def build_record_document(sender, guardian, toolchain):
    """Construct a redacted record from matching non-authorizing attestations."""
    if TOOLCHAIN.fullmatch(toolchain) is None:
        fail("toolchain")
    validate_observation(sender["observed_at_utc"])
    if (
        sender["observed_status"] != OBSERVED_STATUS
        or sender["attempts"] != OBSERVED_ATTEMPTS
        or sender["retries"] != OBSERVED_RETRIES
        or sender["persisted"] is not OBSERVED_PERSISTED
    ):
        fail("attestation")
    for field in (
        "source_commit",
        "challenge_sha256",
        "payload_sha256",
        "protocol",
        "observed_at_utc",
        "observed_status",
        "attempts",
        "retries",
        "persisted",
    ):
        if sender[field] != guardian[field]:
            fail("mismatch")
    if sender["artifact_sha256"] == guardian["artifact_sha256"]:
        fail("mismatch")
    if (
        sender["execution_attestation_sha256"]
        == guardian["execution_attestation_sha256"]
    ):
        fail("mismatch")
    return {
        "schema_version": 1,
        "evidence_kind": "operator_attested_controlled_two_host_threat_hint_v2_delivery",
        "issue": 238,
        "observed_at_utc": sender["observed_at_utc"],
        "source_commit": sender["source_commit"],
        "network": "testnet-10",
        "runtime": "development-only",
        "transport": "direct-quic-v1",
        "protocol": PROTOCOL,
        "route_scope": "single-static-controlled-remote-quic-peer",
        "separation_claim": "operator-attested-not-independently-proven",
        "challenge_sha256": sender["challenge_sha256"],
        "artifacts": {
            "client_sha256": sender["artifact_sha256"],
            "guardian_sha256": guardian["artifact_sha256"],
            "toolchain": toolchain,
        },
        "execution_attestations": {
            "sender_sha256": sender["execution_attestation_sha256"],
            "guardian_sha256": guardian["execution_attestation_sha256"],
        },
        "delivery": {
            "payload_sha256": sender["payload_sha256"],
            "sender_status": sender["observed_status"],
            "guardian_receipt_status": guardian["observed_status"],
            "ack_scope": "remote-local-boundary-only",
            "ack_authority": "none",
            "attempts": sender["attempts"],
            "retries": sender["retries"],
            "persisted": sender["persisted"],
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


def write_record(path, record):
    """Atomically publish one new owner-only 0600 record, refusing clobbers."""
    euid = os.geteuid()
    require_canonical_absolute(path)
    parent_stat = require_real_parent(path)
    if parent_stat.st_uid != euid or parent_stat.st_mode & 0o777 != 0o700:
        fail("paths")
    if os.path.lexists(path):
        fail("paths")
    blob = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("ascii")
    parent = os.path.dirname(path)
    descriptor = None
    temporary_path = None
    temporary_identity = None
    published = False
    completed = False
    try:
        descriptor, temporary_path = tempfile.mkstemp(
            prefix=".gh238-record-", dir=parent
        )
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        temporary_identity = (metadata.st_dev, metadata.st_ino)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != euid
            or metadata.st_nlink != 1
        ):
            fail("paths")
        view = memoryview(blob)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                fail("io")
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
            or published_metadata.st_uid != euid
            or published_metadata.st_mode & 0o777 != 0o600
            or (published_metadata.st_dev, published_metadata.st_ino)
            != temporary_identity
        ):
            fail("paths")
        os.unlink(temporary_path)
        temporary_path = None
        if os.lstat(path).st_nlink != 1:
            fail("paths")
        directory_descriptor = os.open(
            parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            current_parent = os.fstat(directory_descriptor)
            if (current_parent.st_dev, current_parent.st_ino) != (
                parent_stat.st_dev,
                parent_stat.st_ino,
            ):
                fail("paths")
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        completed = True
    except EvidenceFailure:
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


def build_record(args):
    """Read both attestations and write the redacted record fail-closed."""
    sender = read_attestation(args.sender_attestation, "sender")
    guardian = read_attestation(args.guardian_attestation, "guardian")
    record = build_record_document(sender, guardian, args.toolchain)
    write_record(args.output, record)


def main(argv=None):
    if os.name != "posix":
        print("%s: unsupported-platform" % DIAGNOSTIC_PREFIX, file=sys.stderr)
        return 1
    args = parse_args(argv)
    try:
        if args.subcommand == "create-challenge":
            create_challenge(args.output)
            print(CHALLENGE_TOKEN)
            return 0
        if args.subcommand == "attest":
            attest(args)
            return 0
        build_record(args)
        print(RECORD_TOKEN)
        return 0
    except EvidenceFailure as failure:
        print("%s: %s" % (DIAGNOSTIC_PREFIX, failure.reason), file=sys.stderr)
        return 1
    except OSError:
        print("%s: io" % DIAGNOSTIC_PREFIX, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
