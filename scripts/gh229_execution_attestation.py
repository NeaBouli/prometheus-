#!/usr/bin/env python3
"""GH-229 execution challenge and operator attestation tool (Unix).

This Development-only helper closes the GH-229 evidence-construction
ambiguity before a real two-host run. ``create-challenge`` creates exactly
32 cryptographically random bytes in a new owner-only 0600 regular file
under an existing canonical owner-only 0700 parent, refusing symlinks and
existing paths. ``attest`` reads that exact owner-only challenge without
following symlinks, hashes the actual regular artifact bytes, and computes
a deterministic domain-separated SHA-256 over versioned canonical binary
framing that binds the role, challenge bytes, source commit bytes, artifact
digest bytes, and payload digest bytes. It is operator attestation, not
independent host proof, and carries no proof, membership, wallet, chain,
reward, deployment, or production authority. Standard library only.
"""

import argparse
import hashlib
import os
import re
import stat
import sys

CHALLENGE_BYTES = 32
COMMIT_HEX = re.compile(r"[0-9a-f]{40}")
DIGEST_HEX = re.compile(r"[0-9a-f]{64}")
ROLES = ("sender", "guardian")
DOMAIN_SEPARATOR = b"prometheus-gh229-execution-attestation"
FRAMING_VERSION = 1
READ_CHUNK_BYTES = 1024 * 1024
SUCCESS_TOKEN = "GH229_CHALLENGE_CREATED"
DIAGNOSTIC_PREFIX = "attestation"


class AttestationFailure(Exception):
    """A fail-closed rejection with a fixed data-minimal reason key."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def fail(reason):
    raise AttestationFailure(reason)


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description=(
            "GH-229 execution challenge creation and operator attestation; "
            "operator-attested Development evidence only, never independent "
            "host proof or any authorizing authority."
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
        help="emit one canonical execution attestation JSON line",
    )
    attest.add_argument("--challenge", required=True)
    attest.add_argument("--role", required=True, choices=ROLES)
    attest.add_argument("--source-commit", required=True)
    attest.add_argument("--artifact", required=True)
    attest.add_argument("--payload-sha256", required=True, dest="payload_sha256")
    args = parser.parse_args(argv)
    if args.subcommand == "attest":
        if COMMIT_HEX.fullmatch(args.source_commit) is None:
            parser.error("source commit must be 40 lowercase hex characters")
        if DIGEST_HEX.fullmatch(args.payload_sha256) is None:
            parser.error("payload sha256 must be 64 lowercase hex characters")
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
    if (
        stat.S_ISLNK(parent_stat.st_mode)
        or not stat.S_ISDIR(parent_stat.st_mode)
    ):
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
    except AttestationFailure:
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


def read_challenge(path):
    """Read the exact owner-only 32-byte challenge without following symlinks."""
    euid = os.geteuid()
    require_canonical_absolute(path)
    require_real_parent(path)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        fail("challenge")
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != euid
            or metadata.st_mode & 0o777 != 0o600
            or metadata.st_size != CHALLENGE_BYTES
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
        return bytes(chunks)
    finally:
        os.close(descriptor)


def hash_artifact(path):
    """Stream-hash trusted, non-writable regular artifact bytes."""
    euid = os.geteuid()
    require_canonical_absolute(path)
    parent_stat = require_real_parent(path)
    if (
        parent_stat.st_uid not in (0, euid)
        or parent_stat.st_mode & 0o022
    ):
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
        ):
            fail("artifact")
        digest = hashlib.sha256()
        while True:
            try:
                chunk = os.read(descriptor, READ_CHUNK_BYTES)
            except OSError:
                fail("io")
            if not chunk:
                break
            digest.update(chunk)
        return digest.digest()
    finally:
        os.close(descriptor)


def execution_attestation(role, challenge, commit, artifact_digest, payload_digest):
    """Domain-separated SHA-256 over versioned canonical binary framing.

    frame = DOMAIN_SEPARATOR || 0x00 || u8(FRAMING_VERSION) ||
            u8(len)||role || u8(len)||challenge || u8(len)||commit ||
            u8(len)||artifact_digest || u8(len)||payload_digest
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
    ):
        frame.append(len(field))
        frame += field
    return hashlib.sha256(bytes(frame)).digest()


def attest(args):
    """Emit the canonical compact attestation JSON line for one host role."""
    challenge = read_challenge(args.challenge)
    artifact_digest = hash_artifact(args.artifact)
    commit = bytes.fromhex(args.source_commit)
    payload_digest = bytes.fromhex(args.payload_sha256)
    attestation = execution_attestation(
        args.role, challenge, commit, artifact_digest, payload_digest
    )
    print(
        '{"role":"%s","challenge_sha256":"%s","artifact_sha256":"%s",'
        '"execution_attestation_sha256":"%s"}'
        % (
            args.role,
            hashlib.sha256(challenge).hexdigest(),
            artifact_digest.hex(),
            attestation.hex(),
        )
    )


def main(argv=None):
    if os.name != "posix":
        print("%s: unsupported-platform" % DIAGNOSTIC_PREFIX, file=sys.stderr)
        return 1
    args = parse_args(argv)
    try:
        if args.subcommand == "create-challenge":
            create_challenge(args.output)
            print(SUCCESS_TOKEN)
            return 0
        attest(args)
        return 0
    except AttestationFailure as failure:
        print("%s: %s" % (DIAGNOSTIC_PREFIX, failure.reason), file=sys.stderr)
        return 1
    except OSError:
        print("%s: io" % DIAGNOSTIC_PREFIX, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
