"""Local-only owner threat-hint v2 governance policy loader.

This module loads one owner-configured TOML governance declaration for the
future enforceable threat-hint v2 boundary. It is a pure read-only parser: it
opens no SQLite database, pins or advances no authority epoch, consumes no
approval, imports no promotion, acceptance, consumption, analyzer, worker,
transport, or disclosure module, and performs no write of any kind. The only
public call is ``load_threat_hint_v2_governance_policy``; a successful load
returns an immutable data-only policy object that grants no authority. Epoch
activation and persistence are deliberately outside this loader and will be
implemented by Sol transactionally with ledger high-water and approval
consumption.

The exact schema-v1 document is ASCII TOML with exactly these top-level
fields: ``schema_version`` (exact built-in int 1), ``network_id`` (a valid
existing Prometheus network id), ``approver_xonly_public_key`` and
``recipient_scope`` (each exactly 64 lowercase hex characters decoding to 32
bytes), ``authority_epoch`` (exact built-in int in 1..2^63-1),
``authority_not_before`` and ``authority_not_after`` (exact built-in ints in
1..2^64-1 with ``authority_not_after`` strictly greater than
``authority_not_before``), ``recipient_purpose`` (exactly
``guardian_local_analysis_v1``), ``recipient_boundary`` (exactly
``same_guardian_owner_v1``), ``external_disclosure`` (exactly ``deny_v1``),
and exactly one nested ``[observable_decisions]`` table containing exactly
the three closed observable kinds. Each kind accepts only ``deny_v1`` or its
own risk-acknowledging local-analysis token: ``file_sha256`` accepts
``allow_local_analysis_corpus_matchable_v1``, ``api_import`` accepts
``allow_local_analysis_software_fingerprint_v1``, and ``byte_pattern``
accepts ``allow_local_analysis_content_derived_v1``. Cross-kind tokens fail,
and at least one kind must be allowed.

Per-kind decision risks are explicit and differ by kind. ``file_sha256``
digests remain corpus-matchable: they can reveal possession or identity of a
file by dictionary or corpus matching against known hashes. ``api_import``
names fingerprint software capabilities and versions of the analyzed
artifact. ``byte_pattern`` values may retain content-derived, proprietary, or
otherwise sensitive bytes of the artifact itself and are therefore the
highest-sensitivity kind.

The fixed labels and tokens are owner policy semantics only. Loading a policy
does not prove real-world ownership of the approver key, recipient identity
or authorization, extractor provenance, privacy safety of the governed
observables, transport or disclosure authority, or rollout readiness of any
governance boundary. The expected identity arguments are restrictions only:
they pin which network, approver key, and recipient scope this caller is
willing to load a policy for, and both byte identities are compared with
``hmac.compare_digest``. Every failure raises the one stable redacted
``ThreatHintV2GovernancePolicyError``; no error message contains policy
paths, keys, scopes, digests, or values.

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
The returned ``policy_sha256`` is the exact SHA-256 digest of the raw
owner-read policy bytes.
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
from types import MappingProxyType
from typing import Final, Mapping

from jaeger.threat_observable import ObservableKind, validate_network_id

GOVERNANCE_POLICY_SCHEMA_VERSION: Final[int] = 1
MAX_GOVERNANCE_POLICY_BYTES: Final[int] = 4_096
FIXED_HASH_BYTES: Final[int] = 32
MAX_AUTHORITY_EPOCH: Final[int] = 2**63 - 1
MAX_AUTHORITY_INSTANT: Final[int] = 2**64 - 1
RECIPIENT_PURPOSE_V1: Final[str] = "guardian_local_analysis_v1"
RECIPIENT_BOUNDARY_V1: Final[str] = "same_guardian_owner_v1"
EXTERNAL_DISCLOSURE_DENY_V1: Final[str] = "deny_v1"
DECISION_DENY_V1: Final[str] = "deny_v1"
ALLOW_FILE_SHA256_V1: Final[str] = "allow_local_analysis_corpus_matchable_v1"
ALLOW_API_IMPORT_V1: Final[str] = "allow_local_analysis_software_fingerprint_v1"
ALLOW_BYTE_PATTERN_V1: Final[str] = "allow_local_analysis_content_derived_v1"
_DECISION_ALLOW_TOKENS: Final[Mapping[ObservableKind, str]] = MappingProxyType(
    {
        ObservableKind.FILE_SHA256: ALLOW_FILE_SHA256_V1,
        ObservableKind.API_IMPORT: ALLOW_API_IMPORT_V1,
        ObservableKind.BYTE_PATTERN: ALLOW_BYTE_PATTERN_V1,
    }
)
_POLICY_FIELDS: Final[frozenset] = frozenset(
    {
        "schema_version",
        "network_id",
        "approver_xonly_public_key",
        "recipient_scope",
        "authority_epoch",
        "authority_not_before",
        "authority_not_after",
        "recipient_purpose",
        "recipient_boundary",
        "external_disclosure",
        "observable_decisions",
    }
)


class ThreatHintV2GovernancePolicyError(ValueError):
    """Stable redacted rejection for any invalid policy, path, or identity."""

    _MESSAGE = "invalid threat hint v2 governance policy"

    def __init__(self) -> None:
        super().__init__(self._MESSAGE)


@dataclass(frozen=True, init=False, repr=False, eq=False)
class ThreatHintV2GovernancePolicy:  # pylint: disable=too-many-instance-attributes
    """Immutable data-only governance declaration; it grants no authority.

    Direct construction is disabled; ``load_threat_hint_v2_governance_policy``
    is the only supported construction path. The policy binds the parsed
    network id, approver x-only public key bytes, recipient scope bytes,
    authority epoch and validity window, the three fixed recipient and
    disclosure labels, the per-kind decisions as a truly immutable mapping of
    ``ObservableKind`` to its decision token, the derived immutable frozenset
    of allowed ``ObservableKind`` values, and the exact SHA-256 digest of the
    raw owner-read policy bytes. It is not serializable and its repr exposes
    no key, scope, digest, or value material.
    """

    network_id: str
    approver_xonly_public_key: bytes
    recipient_scope: bytes
    authority_epoch: int
    authority_not_before: int
    authority_not_after: int
    recipient_purpose: str
    recipient_boundary: str
    external_disclosure: str
    observable_decisions: Mapping[ObservableKind, str]
    allowed_observable_kinds: frozenset[ObservableKind]
    policy_sha256: bytes

    def __init__(self) -> None:
        raise TypeError(
            "direct threat hint v2 governance policy construction is disabled"
        )

    def __reduce__(self) -> object:
        raise TypeError("threat hint v2 governance policy is not serializable")


def load_threat_hint_v2_governance_policy(  # pylint: disable=too-many-locals
    path: Path,
    *,
    expected_network_id: str,
    expected_approver_xonly_public_key: bytes,
    expected_recipient_scope: bytes,
) -> ThreatHintV2GovernancePolicy:
    """Load and pin one exact-schema owner governance policy; read-only.

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
        raise ThreatHintV2GovernancePolicyError()
    if not hmac.compare_digest(approver, expected_approver_xonly_public_key):
        raise ThreatHintV2GovernancePolicyError()
    if not hmac.compare_digest(scope, expected_recipient_scope):
        raise ThreatHintV2GovernancePolicyError()
    authority_epoch = _parse_bounded_int(data["authority_epoch"], MAX_AUTHORITY_EPOCH)
    not_before, not_after = _parse_authority_window(
        data["authority_not_before"], data["authority_not_after"]
    )
    recipient_purpose = _parse_fixed_string(
        data["recipient_purpose"], RECIPIENT_PURPOSE_V1
    )
    recipient_boundary = _parse_fixed_string(
        data["recipient_boundary"], RECIPIENT_BOUNDARY_V1
    )
    external_disclosure = _parse_fixed_string(
        data["external_disclosure"], EXTERNAL_DISCLOSURE_DENY_V1
    )
    decisions, allowed = _parse_observable_decisions(data["observable_decisions"])

    policy = object.__new__(ThreatHintV2GovernancePolicy)
    object.__setattr__(policy, "network_id", network_id)
    object.__setattr__(policy, "approver_xonly_public_key", approver)
    object.__setattr__(policy, "recipient_scope", scope)
    object.__setattr__(policy, "authority_epoch", authority_epoch)
    object.__setattr__(policy, "authority_not_before", not_before)
    object.__setattr__(policy, "authority_not_after", not_after)
    object.__setattr__(policy, "recipient_purpose", recipient_purpose)
    object.__setattr__(policy, "recipient_boundary", recipient_boundary)
    object.__setattr__(policy, "external_disclosure", external_disclosure)
    object.__setattr__(policy, "observable_decisions", decisions)
    object.__setattr__(policy, "allowed_observable_kinds", allowed)
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
        raise ThreatHintV2GovernancePolicyError()
    try:
        validate_network_id(expected_network_id)
    except ValueError:
        raise ThreatHintV2GovernancePolicyError() from None


def _parse_policy_document(contents: bytes) -> dict:
    try:
        data = tomllib.loads(contents.decode("ascii"))
    except (UnicodeError, tomllib.TOMLDecodeError, RecursionError):
        raise ThreatHintV2GovernancePolicyError() from None
    if not isinstance(data, dict) or set(data) != _POLICY_FIELDS:
        raise ThreatHintV2GovernancePolicyError()
    if (
        type(data["schema_version"]) is not int
        or data["schema_version"] != GOVERNANCE_POLICY_SCHEMA_VERSION
    ):
        raise ThreatHintV2GovernancePolicyError()
    return data


def _parse_network_id(value: object) -> str:
    if type(value) is not str:
        raise ThreatHintV2GovernancePolicyError()
    try:
        validate_network_id(value)
    except ValueError:
        raise ThreatHintV2GovernancePolicyError() from None
    return value


def _decode_fixed_lower_hex(value: object) -> bytes:
    if (
        type(value) is not str
        or len(value) != FIXED_HASH_BYTES * 2
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ThreatHintV2GovernancePolicyError()
    return bytes.fromhex(value)


def _parse_bounded_int(value: object, maximum: int) -> int:
    if type(value) is not int or value < 1 or value > maximum:
        raise ThreatHintV2GovernancePolicyError()
    return value


def _parse_authority_window(not_before: object, not_after: object) -> tuple[int, int]:
    before = _parse_bounded_int(not_before, MAX_AUTHORITY_INSTANT)
    after = _parse_bounded_int(not_after, MAX_AUTHORITY_INSTANT)
    if after <= before:
        raise ThreatHintV2GovernancePolicyError()
    return before, after


def _parse_fixed_string(value: object, expected: str) -> str:
    if type(value) is not str or value != expected:
        raise ThreatHintV2GovernancePolicyError()
    return value


def _parse_observable_decisions(
    value: object,
) -> tuple[Mapping[ObservableKind, str], frozenset[ObservableKind]]:
    if type(value) is not dict or set(value) != {kind.value for kind in ObservableKind}:
        raise ThreatHintV2GovernancePolicyError()
    decisions: dict[ObservableKind, str] = {}
    allowed = []
    for kind in ObservableKind:
        decision = value[kind.value]
        if type(decision) is not str or decision not in (
            DECISION_DENY_V1,
            _DECISION_ALLOW_TOKENS[kind],
        ):
            raise ThreatHintV2GovernancePolicyError()
        decisions[kind] = decision
        if decision != DECISION_DENY_V1:
            allowed.append(kind)
    if not allowed:
        raise ThreatHintV2GovernancePolicyError()
    return MappingProxyType(decisions), frozenset(allowed)


def _read_owner_policy_file(path: Path) -> bytes:
    if os.name != "posix" or not hasattr(os, "getuid") or not hasattr(os, "O_NOFOLLOW"):
        raise ThreatHintV2GovernancePolicyError()
    if (
        not isinstance(path, Path)
        or type(path) not in (Path, PosixPath, WindowsPath)
        or not path.is_absolute()
        or path.name in {"", ".", ".."}
        or ".." in path.parts
    ):
        raise ThreatHintV2GovernancePolicyError()
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
            raise ThreatHintV2GovernancePolicyError()
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
                raise ThreatHintV2GovernancePolicyError()
            contents = _read_policy_descriptor(descriptor)
        finally:
            os.close(descriptor)
    except (OSError, ValueError):
        raise ThreatHintV2GovernancePolicyError() from None
    if len(contents) != before.st_size:
        raise ThreatHintV2GovernancePolicyError()
    return contents


def _read_policy_descriptor(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    remaining = MAX_GOVERNANCE_POLICY_BYTES + 1
    while remaining:
        chunk = os.read(descriptor, min(remaining, 64 * 1_024))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    contents = b"".join(chunks)
    if len(contents) > MAX_GOVERNANCE_POLICY_BYTES:
        raise ThreatHintV2GovernancePolicyError()
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
        and 0 < current.st_size <= MAX_GOVERNANCE_POLICY_BYTES
    )
