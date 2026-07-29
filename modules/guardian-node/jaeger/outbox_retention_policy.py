"""Local-only owner outbox retention policy loader.

This module loads one owner-configured TOML retention declaration for a
future local recoverable analysis queue. It is a pure read-only parser: it
opens no SQLite database, creates or migrates no outbox table, imports no
promotion, acceptance, consumption, analyzer, worker, dequeue, transport, or
publication module, and performs no write of any kind. The only public call
is ``load_outbox_retention_policy``; a successful load returns an immutable
data-only policy object that grants no authority.

The exact schema-v1 document is ASCII TOML with exactly these fields:
``schema_version`` (exact built-in int 1), ``network_id`` (a valid existing
Prometheus network id), ``approver_xonly_public_key`` and ``recipient_scope``
(each exactly 64 lowercase hex characters decoding to 32 bytes),
``retention_purpose`` (exactly ``local_recoverable_analysis_queue_v1``),
``payload_form`` (exactly ``canonical_observable_bundle_v1``),
``durable_observable_kinds`` (a non-empty duplicate-free exact built-in list
of exact built-in strings drawn from the current ObservableKind values
``file_sha256``, ``api_import``, and ``byte_pattern``),
``max_pending_records`` (exact built-in int in 1..100000), and
``max_retention_seconds`` (exact built-in int in 1..2592000, thirty days).

Per-kind retention risks are explicit and differ by kind. ``file_sha256``
digests can reveal possession or identity of a file by dictionary or corpus
matching against known hashes. ``api_import`` names can fingerprint software
capabilities and versions of the analyzed artifact. ``byte_pattern`` values
can retain proprietary or otherwise content-derived bytes of the artifact
itself and are therefore the highest-sensitivity kind to retain.

The policy is only an owner-local retention declaration. Loading it does not
prove ownership of the approver key, recipient authorization or semantics,
extractor provenance, privacy safety of the retained observables, analyzer,
transport, or disclosure authority, or rollout readiness of any queue. The
expected identity arguments are restrictions only: they pin which network,
approver key, and recipient scope this caller is willing to load a policy
for, and both byte identities are compared with ``hmac.compare_digest``.
Every failure raises the one stable redacted ``OutboxRetentionPolicyError``;
no error message contains policy paths, keys, scopes, or values.

Trusted file handling is fail-closed: the path must be an exact absolute
``pathlib.Path`` with no empty, dot, or dotdot basename and no ``..``
component; the resolved parent must be an owner-only directory; the policy
must be an owner-only regular file without setid or sticky bits and between
one and 4096 bytes. The file is lstat'd before open, opened with the required
``O_RDONLY | O_NOFOLLOW`` flags, fstat'd for exact device, inode, and size
identity, read through a bounded descriptor loop, and closed in a
``finally`` block. Short reads, growth, swaps, symlinks, and any
``OSError``, ``UnicodeError``, ``TOMLDecodeError``, ``RecursionError``, or
``ValueError`` all fail closed into the stable error. Platforms without the
required POSIX owner and no-follow controls are rejected before file access.
"""

# Exact built-in types are protocol requirements.
# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

import hashlib
import hmac
import os
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path, PosixPath, WindowsPath
from typing import Final

from jaeger.threat_observable import ObservableKind, validate_network_id

RETENTION_POLICY_SCHEMA_VERSION: Final[int] = 1
MAX_RETENTION_POLICY_BYTES: Final[int] = 4_096
FIXED_HASH_BYTES: Final[int] = 32
RETENTION_PURPOSE_V1: Final[str] = "local_recoverable_analysis_queue_v1"
PAYLOAD_FORM_V1: Final[str] = "canonical_observable_bundle_v1"
MAX_PENDING_RECORDS: Final[int] = 100_000
MAX_RETENTION_SECONDS: Final[int] = 2_592_000
_POLICY_FIELDS: Final[frozenset] = frozenset(
    {
        "schema_version",
        "network_id",
        "approver_xonly_public_key",
        "recipient_scope",
        "retention_purpose",
        "payload_form",
        "durable_observable_kinds",
        "max_pending_records",
        "max_retention_seconds",
    }
)


class OutboxRetentionPolicyError(ValueError):
    """Stable redacted rejection for any invalid policy, path, or identity."""

    _MESSAGE = "invalid outbox retention policy"

    def __init__(self) -> None:
        super().__init__(self._MESSAGE)


@dataclass(frozen=True, init=False, repr=False, eq=False)
class OutboxRetentionPolicy:  # pylint: disable=too-many-instance-attributes
    """Immutable data-only retention declaration; it grants no authority.

    Direct construction is disabled; ``load_outbox_retention_policy`` is the
    only supported construction path. The policy binds the parsed network id,
    approver x-only public key bytes, recipient scope bytes, retention
    purpose, payload form, durable observable kinds as an immutable frozenset
    of ``ObservableKind``, the two integer retention bounds, and the SHA-256
    digest of the exact owner-read policy bytes. It is not serializable and
    its repr exposes no key, scope, or value material.
    """

    network_id: str
    approver_xonly_public_key: bytes
    recipient_scope: bytes
    retention_purpose: str
    payload_form: str
    durable_observable_kinds: frozenset[ObservableKind]
    max_pending_records: int
    max_retention_seconds: int
    policy_sha256: bytes

    def __init__(self) -> None:
        raise TypeError("direct outbox retention policy construction is disabled")

    def __reduce__(self) -> object:
        raise TypeError("outbox retention policy is not serializable")


def load_outbox_retention_policy(
    path: Path,
    *,
    expected_network_id: str,
    expected_approver_xonly_public_key: bytes,
    expected_recipient_scope: bytes,
) -> OutboxRetentionPolicy:
    """Load and pin one exact-schema owner retention policy; read-only.

    The expected identity arguments are restrictions only and are validated
    first, before any file state exists: exact built-in types, a valid
    expected network id, and exact 32-byte expected identities. Both byte
    identities are then compared against the parsed policy with
    ``hmac.compare_digest``; any mismatch fails closed. This function
    performs no writes.
    """
    _validate_expected_identity(
        expected_network_id,
        expected_approver_xonly_public_key,
        expected_recipient_scope,
    )
    contents = _read_owner_policy_file(path)
    data = _parse_policy_document(contents)
    network_id = _parse_network_id(data["network_id"])
    approver = _decode_fixed_lower_hex(data["approver_xonly_public_key"])
    scope = _decode_fixed_lower_hex(data["recipient_scope"])
    if network_id != expected_network_id:
        raise OutboxRetentionPolicyError()
    if not hmac.compare_digest(approver, expected_approver_xonly_public_key):
        raise OutboxRetentionPolicyError()
    if not hmac.compare_digest(scope, expected_recipient_scope):
        raise OutboxRetentionPolicyError()
    retention_purpose = _parse_fixed_string(
        data["retention_purpose"], RETENTION_PURPOSE_V1
    )
    payload_form = _parse_fixed_string(data["payload_form"], PAYLOAD_FORM_V1)
    kinds = _parse_durable_kinds(data["durable_observable_kinds"])
    max_pending_records = _parse_bounded_int(
        data["max_pending_records"], MAX_PENDING_RECORDS
    )
    max_retention_seconds = _parse_bounded_int(
        data["max_retention_seconds"], MAX_RETENTION_SECONDS
    )

    policy = object.__new__(OutboxRetentionPolicy)
    object.__setattr__(policy, "network_id", network_id)
    object.__setattr__(policy, "approver_xonly_public_key", approver)
    object.__setattr__(policy, "recipient_scope", scope)
    object.__setattr__(policy, "retention_purpose", retention_purpose)
    object.__setattr__(policy, "payload_form", payload_form)
    object.__setattr__(policy, "durable_observable_kinds", kinds)
    object.__setattr__(policy, "max_pending_records", max_pending_records)
    object.__setattr__(policy, "max_retention_seconds", max_retention_seconds)
    object.__setattr__(policy, "policy_sha256", hashlib.sha256(contents).digest())
    return policy


def _validate_expected_identity(
    expected_network_id: object,
    expected_approver_xonly_public_key: object,
    expected_recipient_scope: object,
) -> None:
    if (
        type(expected_network_id) is not str
        or type(expected_approver_xonly_public_key) is not bytes
        or len(expected_approver_xonly_public_key) != FIXED_HASH_BYTES
        or type(expected_recipient_scope) is not bytes
        or len(expected_recipient_scope) != FIXED_HASH_BYTES
    ):
        raise OutboxRetentionPolicyError()
    try:
        validate_network_id(expected_network_id)
    except ValueError:
        raise OutboxRetentionPolicyError() from None


def _parse_policy_document(contents: bytes) -> dict:
    try:
        data = tomllib.loads(contents.decode("ascii"))
    except (UnicodeError, tomllib.TOMLDecodeError, RecursionError):
        raise OutboxRetentionPolicyError() from None
    if not isinstance(data, dict) or set(data) != _POLICY_FIELDS:
        raise OutboxRetentionPolicyError()
    if (
        type(data["schema_version"]) is not int
        or data["schema_version"] != RETENTION_POLICY_SCHEMA_VERSION
    ):
        raise OutboxRetentionPolicyError()
    return data


def _parse_network_id(value: object) -> str:
    if type(value) is not str:
        raise OutboxRetentionPolicyError()
    try:
        validate_network_id(value)
    except ValueError:
        raise OutboxRetentionPolicyError() from None
    return value


def _decode_fixed_lower_hex(value: object) -> bytes:
    if (
        type(value) is not str
        or len(value) != FIXED_HASH_BYTES * 2
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise OutboxRetentionPolicyError()
    return bytes.fromhex(value)


def _parse_fixed_string(value: object, expected: str) -> str:
    if type(value) is not str or value != expected:
        raise OutboxRetentionPolicyError()
    return value


def _parse_durable_kinds(value: object) -> frozenset[ObservableKind]:
    if type(value) is not list or not value:
        raise OutboxRetentionPolicyError()
    kinds = []
    for item in value:
        if type(item) is not str:
            raise OutboxRetentionPolicyError()
        try:
            kind = ObservableKind(item)
        except ValueError:
            raise OutboxRetentionPolicyError() from None
        if kind in kinds:
            raise OutboxRetentionPolicyError()
        kinds.append(kind)
    return frozenset(kinds)


def _parse_bounded_int(value: object, maximum: int) -> int:
    if type(value) is not int or value < 1 or value > maximum:
        raise OutboxRetentionPolicyError()
    return value


def _read_owner_policy_file(path: Path) -> bytes:
    if os.name != "posix" or not hasattr(os, "getuid") or not hasattr(os, "O_NOFOLLOW"):
        raise OutboxRetentionPolicyError()
    if (
        not isinstance(path, Path)
        or type(path) not in (Path, PosixPath, WindowsPath)
        or not path.is_absolute()
        or path.name in {"", ".", ".."}
        or ".." in path.parts
    ):
        raise OutboxRetentionPolicyError()
    try:
        parent = path.parent.resolve(strict=True)
        parent_stat = parent.stat()
        before = path.lstat()
        candidate = parent / path.name
        if (
            candidate != path
            or not _is_safe_policy_parent(parent_stat)
            or not _is_safe_policy_file(before)
        ):
            raise OutboxRetentionPolicyError()
        flags = os.O_RDONLY | os.O_NOFOLLOW
        descriptor = os.open(candidate, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                before.st_dev != opened.st_dev
                or before.st_ino != opened.st_ino
                or before.st_size != opened.st_size
                or not _is_safe_policy_file(opened)
            ):
                raise OutboxRetentionPolicyError()
            contents = _read_policy_descriptor(descriptor)
        finally:
            os.close(descriptor)
    except (OSError, ValueError):
        raise OutboxRetentionPolicyError() from None
    if len(contents) != before.st_size:
        raise OutboxRetentionPolicyError()
    return contents


def _read_policy_descriptor(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    remaining = MAX_RETENTION_POLICY_BYTES + 1
    while remaining:
        chunk = os.read(descriptor, min(remaining, 64 * 1_024))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    contents = b"".join(chunks)
    if len(contents) > MAX_RETENTION_POLICY_BYTES:
        raise OutboxRetentionPolicyError()
    return contents


def _is_safe_policy_parent(current: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(current.st_mode)
        and current.st_uid == os.getuid()
        and not current.st_mode & 0o077
    )


def _is_safe_policy_file(current: os.stat_result) -> bool:
    return (
        stat.S_ISREG(current.st_mode)
        and current.st_uid == os.getuid()
        and not current.st_mode & 0o077
        and not current.st_mode & 0o7000
        and 0 < current.st_size <= MAX_RETENTION_POLICY_BYTES
    )
