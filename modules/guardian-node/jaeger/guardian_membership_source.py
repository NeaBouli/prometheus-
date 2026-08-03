"""Canonical local Guardian membership source (schema v1).

This module defines and validates the missing canonical source behind
``membership_source_sha256`` and the Guardian-ID-to-public-BIP340-key
bindings consumed by the existing ensemble and signed-ballot boundaries. It
is a pure read-only parser and loader: it opens no database, holds no
private key or signing capability, performs no transport, discovery, key
rotation, trust, Sybil-resistance, on-chain attestation, or reputation
claim, and performs no write of any kind. A successful parse returns an
immutable data-only source object that grants no authority; it only pins
which network, epoch, and committee this caller is willing to derive the
existing ``MembershipSnapshot`` and ``BallotSigner`` views from.

The exact schema-v1 document is compact canonical JSON with exactly these
top-level fields in exactly this order: ``schema_version`` (exact built-in
int 1), ``protocol_id`` (exactly ``/prometheus/guardian-membership/1.0.0``),
``network_id`` (a valid Prometheus network id that must equal the caller's
trusted expected network id), ``epoch`` (exact built-in int in 0..2^63-1),
and ``members`` (at least 5 and at most 1024 member objects). Each member
object has exactly these fields in exactly this order: ``guardian_id``,
``xonly_public_key``, ``model_tier``, and ``model_artifact_sha256``. The
Guardian ID and model-artifact digest are exactly 64 lowercase hex characters
decoding to 32 bytes; the public key has the same encoding and must be accepted
by ``coincurve.PublicKeyXOnly`` as a structurally valid x-only public key. The
model tier is exactly ``8b``.
Members are strictly sorted by ``guardian_id``; Guardian IDs and x-only
public keys are each unique across the committee.

Canonical bytes are compact exact JSON: no whitespace, no duplicate keys,
no reordered, extra, or missing fields, no trailing newline, ASCII-only,
and byte-identical to the re-serialization of the validated document.
``membership_source_sha256`` is the SHA-256 of those exact bytes. Every
failure raises the one stable redacted ``GuardianMembershipSourceError``;
no error message contains source paths, keys, ids, digests, or values.
Direct construction of both data classes is disabled; canonical parsing is
the only supported construction path.

Trusted file handling is fail-closed and follows the threat-hint v2
governance owner-only pattern: the path must be an exact absolute
``pathlib.Path`` with no empty, dot, or dotdot basename and no ``..``
component; the resolved parent must be an owner-only directory; the source
must be an owner-only regular file without setid or sticky bits and between
one and ``MAX_MEMBERSHIP_SOURCE_BYTES`` bytes. The file is lstat'd before
open, opened with the required ``O_RDONLY | O_NOFOLLOW`` flags, fstat'd for
exact device, inode, and size identity, read through a bounded descriptor
loop, and closed in a ``finally`` block. Short reads, growth, swaps,
symlinks, and any ``OSError``, ``UnicodeError``, ``RecursionError``, or
``ValueError`` all fail closed into the stable error. Platforms without the
required POSIX owner and no-follow controls are rejected before file access.
"""

# Exact built-in types are protocol requirements.
# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PosixPath, WindowsPath
from typing import Final

from coincurve import PublicKeyXOnly

from .ensemble import GuardianMember, MembershipSnapshot, ModelTier
from .signed_ballots import BallotSigner
from .threat_observable import validate_network_id

MEMBERSHIP_SOURCE_SCHEMA_VERSION: Final[int] = 1
MEMBERSHIP_SOURCE_PROTOCOL_ID: Final[str] = "/prometheus/guardian-membership/1.0.0"
MIN_MEMBERSHIP_MEMBERS: Final[int] = 5
MAX_MEMBERSHIP_MEMBERS: Final[int] = 1_024
MAX_MEMBERSHIP_EPOCH: Final[int] = 2**63 - 1
# A canonical 1024-member document is approximately 284 kB; bound well above.
MAX_MEMBERSHIP_SOURCE_BYTES: Final[int] = 300_000
MEMBERSHIP_MODEL_TIER: Final[ModelTier] = "8b"
_FIXED_HEX_32 = re.compile(r"[0-9a-f]{64}")
_SOURCE_FIELDS: Final[frozenset] = frozenset(
    {"schema_version", "protocol_id", "network_id", "epoch", "members"}
)
_MEMBER_FIELDS: Final[frozenset] = frozenset(
    {"guardian_id", "xonly_public_key", "model_tier", "model_artifact_sha256"}
)


class GuardianMembershipSourceError(ValueError):
    """Stable redacted rejection for any invalid source, path, or identity."""

    _MESSAGE = "invalid guardian membership source"

    def __init__(self) -> None:
        super().__init__(self._MESSAGE)


@dataclass(frozen=True, init=False, eq=False)
class GuardianSourceMember:
    """Immutable validated Guardian-to-key binding from a canonical source.

    Direct construction is disabled; ``parse_guardian_membership_source``
    and ``load_guardian_membership_source`` are the only supported
    construction paths. All fields are public, non-secret material.
    """

    guardian_id: str
    xonly_public_key: str
    model_tier: ModelTier
    model_artifact_sha256: str

    def __init__(self) -> None:
        raise TypeError("direct guardian source member construction is disabled")

    def __reduce__(self) -> object:
        raise TypeError("guardian source member is not serializable")


@dataclass(frozen=True, init=False, eq=False)
class GuardianMembershipSource:
    """Immutable validated canonical committee source; it grants no authority.

    Direct construction is disabled; canonical parsing is the only supported
    construction path. The source binds the parsed network id, epoch, the
    strictly ordered validated members, the exact canonical source bytes,
    and the SHA-256 digest of those exact bytes. It holds no private key
    material and performs no signing, transport, trust, or on-chain claim.
    """

    network_id: str
    epoch: int
    members: tuple[GuardianSourceMember, ...]
    canonical_bytes: bytes
    membership_source_sha256: str

    def __init__(self) -> None:
        raise TypeError("direct guardian membership source construction is disabled")

    def __reduce__(self) -> object:
        raise TypeError("guardian membership source is not serializable")

    def to_membership_snapshot(self) -> MembershipSnapshot:
        """Derive the existing ensemble snapshot pinned to this exact source."""
        return MembershipSnapshot.create(
            members=[
                GuardianMember(
                    guardian_id=member.guardian_id,
                    model_tier=member.model_tier,
                    model_artifact_sha256=member.model_artifact_sha256,
                )
                for member in self.members
            ],
            membership_source_sha256=self.membership_source_sha256,
        )

    def to_ballot_signers(self) -> tuple[BallotSigner, ...]:
        """Derive the existing signed-ballot signer bindings in source order."""
        return tuple(
            BallotSigner(
                guardian_id=member.guardian_id,
                xonly_public_key=member.xonly_public_key,
            )
            for member in self.members
        )


def parse_guardian_membership_source(
    contents: bytes,
    *,
    expected_network_id: str,
) -> GuardianMembershipSource:
    """Parse and validate one exact-schema canonical membership source.

    The expected network id is a restriction only and is validated first:
    it must be an exact built-in ``str`` and a valid Prometheus network id,
    and it must equal the parsed source network id. Every failure raises the
    one stable redacted ``GuardianMembershipSourceError``. This function
    performs no file access and no writes.
    """
    _validate_expected_network_id(expected_network_id)
    if (
        type(contents) is not bytes
        or not contents
        or len(contents) > MAX_MEMBERSHIP_SOURCE_BYTES
    ):
        raise GuardianMembershipSourceError()
    data = _parse_source_document(contents)
    network_id = _parse_network_id(data["network_id"])
    if network_id != expected_network_id:
        raise GuardianMembershipSourceError()
    epoch = _parse_epoch(data["epoch"])
    members = _parse_members(data["members"])
    canonical = _canonical_bytes(network_id, epoch, members)
    if canonical != contents:
        raise GuardianMembershipSourceError()

    source = object.__new__(GuardianMembershipSource)
    object.__setattr__(source, "network_id", network_id)
    object.__setattr__(source, "epoch", epoch)
    object.__setattr__(source, "members", members)
    object.__setattr__(source, "canonical_bytes", canonical)
    object.__setattr__(
        source,
        "membership_source_sha256",
        hashlib.sha256(canonical).hexdigest(),
    )
    return source


def load_guardian_membership_source(
    path: Path,
    *,
    expected_network_id: str,
) -> GuardianMembershipSource:
    """Load one canonical membership source from an owner-only local file.

    The expected network id restriction is validated before any file state
    exists. The file boundary follows the threat-hint v2 governance
    owner-only pattern and is fail-closed. This function performs no writes.
    """
    _validate_expected_network_id(expected_network_id)
    contents = _read_owner_source_file(path)
    return parse_guardian_membership_source(
        contents, expected_network_id=expected_network_id
    )


def _validate_expected_network_id(expected_network_id: object) -> None:
    if type(expected_network_id) is not str:
        raise GuardianMembershipSourceError()
    try:
        validate_network_id(expected_network_id)
    except ValueError:
        raise GuardianMembershipSourceError() from None


def _parse_source_document(contents: bytes) -> dict[str, object]:
    try:
        data = json.loads(contents.decode("utf-8"), object_pairs_hook=_unique_object)
    except (
        UnicodeError,
        json.JSONDecodeError,
        RecursionError,
        GuardianMembershipSourceError,
    ):
        raise GuardianMembershipSourceError() from None
    if not isinstance(data, dict) or set(data) != _SOURCE_FIELDS:
        raise GuardianMembershipSourceError()
    if (
        type(data["schema_version"]) is not int
        or data["schema_version"] != MEMBERSHIP_SOURCE_SCHEMA_VERSION
    ):
        raise GuardianMembershipSourceError()
    if (
        type(data["protocol_id"]) is not str
        or data["protocol_id"] != MEMBERSHIP_SOURCE_PROTOCOL_ID
    ):
        raise GuardianMembershipSourceError()
    return data


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise GuardianMembershipSourceError()
        result[key] = value
    return result


def _parse_network_id(value: object) -> str:
    if type(value) is not str:
        raise GuardianMembershipSourceError()
    try:
        validate_network_id(value)
    except ValueError:
        raise GuardianMembershipSourceError() from None
    return value


def _parse_epoch(value: object) -> int:
    if type(value) is not int or value < 0 or value > MAX_MEMBERSHIP_EPOCH:
        raise GuardianMembershipSourceError()
    return value


def _parse_fixed_hex_32(value: object) -> str:
    if type(value) is not str or _FIXED_HEX_32.fullmatch(value) is None:
        raise GuardianMembershipSourceError()
    return value


def _parse_members(value: object) -> tuple[GuardianSourceMember, ...]:
    if (
        type(value) is not list
        or len(value) < MIN_MEMBERSHIP_MEMBERS
        or len(value) > MAX_MEMBERSHIP_MEMBERS
    ):
        raise GuardianMembershipSourceError()
    members = tuple(_parse_member(item) for item in value)
    guardian_ids = [member.guardian_id for member in members]
    public_keys = [member.xonly_public_key for member in members]
    if (
        guardian_ids != sorted(guardian_ids)
        or len(set(guardian_ids)) != len(guardian_ids)
        or len(set(public_keys)) != len(public_keys)
    ):
        raise GuardianMembershipSourceError()
    return members


def _parse_member(item: object) -> GuardianSourceMember:
    if type(item) is not dict or set(item) != _MEMBER_FIELDS:
        raise GuardianMembershipSourceError()
    guardian_id = _parse_fixed_hex_32(item["guardian_id"])
    xonly_public_key = _parse_fixed_hex_32(item["xonly_public_key"])
    model_artifact = _parse_fixed_hex_32(item["model_artifact_sha256"])
    if (
        type(item["model_tier"]) is not str
        or item["model_tier"] != MEMBERSHIP_MODEL_TIER
    ):
        raise GuardianMembershipSourceError()
    try:
        PublicKeyXOnly(bytes.fromhex(xonly_public_key))
    except ValueError:
        raise GuardianMembershipSourceError() from None

    member = object.__new__(GuardianSourceMember)
    object.__setattr__(member, "guardian_id", guardian_id)
    object.__setattr__(member, "xonly_public_key", xonly_public_key)
    object.__setattr__(member, "model_tier", MEMBERSHIP_MODEL_TIER)
    object.__setattr__(member, "model_artifact_sha256", model_artifact)
    return member


def _canonical_bytes(
    network_id: str,
    epoch: int,
    members: tuple[GuardianSourceMember, ...],
) -> bytes:
    document: dict[str, object] = {
        "schema_version": MEMBERSHIP_SOURCE_SCHEMA_VERSION,
        "protocol_id": MEMBERSHIP_SOURCE_PROTOCOL_ID,
        "network_id": network_id,
        "epoch": epoch,
        "members": [
            {
                "guardian_id": member.guardian_id,
                "xonly_public_key": member.xonly_public_key,
                "model_tier": member.model_tier,
                "model_artifact_sha256": member.model_artifact_sha256,
            }
            for member in members
        ],
    }
    return json.dumps(document, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def _read_owner_source_file(path: Path) -> bytes:
    if os.name != "posix" or not hasattr(os, "getuid") or not hasattr(os, "O_NOFOLLOW"):
        raise GuardianMembershipSourceError()
    if (
        not isinstance(path, Path)
        or type(path) not in (Path, PosixPath, WindowsPath)
        or not path.is_absolute()
        or path.name in {"", ".", ".."}
        or ".." in path.parts
    ):
        raise GuardianMembershipSourceError()
    try:
        parent = path.parent.resolve(strict=True)
        parent_stat = parent.stat()
        before = path.lstat()
        candidate = parent / path.name
        if (
            candidate != path
            or not _is_safe_source_parent(parent_stat)
            or not _is_safe_source_file(before)
        ):
            raise GuardianMembershipSourceError()
        flags = os.O_RDONLY | os.O_NOFOLLOW
        descriptor = os.open(candidate, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                before.st_dev != opened.st_dev
                or before.st_ino != opened.st_ino
                or before.st_size != opened.st_size
                or not _is_safe_source_file(opened)
            ):
                raise GuardianMembershipSourceError()
            contents = _read_source_descriptor(descriptor)
        finally:
            os.close(descriptor)
    except (OSError, ValueError):
        raise GuardianMembershipSourceError() from None
    if len(contents) != before.st_size:
        raise GuardianMembershipSourceError()
    return contents


def _read_source_descriptor(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    remaining = MAX_MEMBERSHIP_SOURCE_BYTES + 1
    while remaining:
        chunk = os.read(descriptor, min(remaining, 64 * 1_024))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    contents = b"".join(chunks)
    if len(contents) > MAX_MEMBERSHIP_SOURCE_BYTES:
        raise GuardianMembershipSourceError()
    return contents


def _is_safe_source_parent(current: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(current.st_mode)
        and current.st_uid == os.getuid()
        and not current.st_mode & 0o077
    )


def _is_safe_source_file(current: os.stat_result) -> bool:
    return (
        stat.S_ISREG(current.st_mode)
        and current.st_uid == os.getuid()
        and not current.st_mode & 0o077
        and not current.st_mode & 0o7000
        and 0 < current.st_size <= MAX_MEMBERSHIP_SOURCE_BYTES
    )
