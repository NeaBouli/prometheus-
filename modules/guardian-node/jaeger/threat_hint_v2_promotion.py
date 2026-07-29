"""Local fail-closed ThreatHint-v2 privacy promotion and pairing boundary.

The promotion service sits strictly above the ThreatHint-v2 acceptance
boundary. It applies one owner-only exact-schema promotion policy to raw
candidate bytes before the acceptance call: one pinned scope platform, one
pinned scope format, a non-empty duplicate-free allowed observable-kind list,
and a maximum observable count. It duplicates no network, approver-key,
recipient-scope, or manifest trust anchors; those stay with the acceptance
configuration.

The public call is raw-only. ``promote`` accepts only raw wire bytes (one
canonical v2 proof envelope, one canonical observable bundle, one canonical
Observable Approval), the trusted report nonce, and the trusted current time.
It never accepts a caller-supplied preflight, verification, consumption,
promotion, or acceptance receipt, a pre-verified object, a policy value, or
any derived statement. The fail-closed order is fixed: exact built-in input
type validation, canonical bundle parsing, review-required disclosure,
policy platform and format equality, allowed-kind restriction, and the count
restriction all run before the acceptance call. A failed promotion check
therefore never invokes the verifier subprocess and never consumes an
approval or advances the ledger high-water mark; the approval remains
available for a later valid call. Only after every promotion restriction
passes are the same original bytes forwarded to ``acceptance.accept``.

Errors are stable and redacted. ``ThreatHintV2PromotionError`` (invalid)
rejects bad candidate data, including any failed promotion restriction or
acceptance candidate failure. ``ThreatHintV2PromotionUnavailableError``
covers unavailable or mismatched trusted material, including any promotion
policy, configuration, or consumption policy failure at construction.
``ThreatHintV2PromotionReplayError`` reports an already-consumed approval
identity, authority nonce, or a high-water rollback; it is final.
``ThreatHintV2PromotionBusyError`` is the only retryable classification and
covers the occupied verifier slot and a temporarily locked ledger. No error
message contains policy keys, scopes, nonces, digests, or wire material.

Concurrency is inherited from acceptance and stays fail-closed: concurrent
calls serialize on the single verifier slot (the loser gets busy) and on the
atomic ledger insert (exactly one winner; losers get busy or replay).
Promotion restrictions themselves are read-only and consume nothing.

Crash semantics are inherited from acceptance: the durable consume inside the
acceptance call is the only write and it is atomic. A governed promotion
service enables the durable outbox, so its successful consume commits one
recoverable approval-bound outbox record holding the full canonical bundle
wire in the same transaction; a full outbox or enqueue failure rolls back
authority, high-water, consumption, and outbox together and leaves the
approval usable. If the process crashes
after that commit but before the caller receives the result, the approval is
consumed; a retry of the same inputs fails as replay and never
double-consumes. Result construction performs no I/O and cannot roll the
ledger back.

The returned result grants no authority. It exposes only the verified
statement digest, approval identifier, observable commitment, consumption
time, the policy-pinned scope platform and format, and the canonical
observables as an immutable tuple of (kind, value) string pairs. It never
contains proof, approval wire, policy key or scope, nonce, raw manifest,
verifier executable hash, or any caller receipt, and it is not privacy
finality, transport, analyzer, outbox, wallet, chain, deployment,
reputation, KAS/PROM, slash, commit-reveal, or rollout evidence.
"""

# Exact built-in types are protocol requirements.
# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

import hashlib
import os
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path, PosixPath, WindowsPath
from typing import Final

from jaeger.threat_hint_v2_acceptance import (
    ThreatHintV2AcceptanceBusyError,
    ThreatHintV2AcceptanceError,
    ThreatHintV2AcceptanceReceipt,
    ThreatHintV2AcceptanceReplayError,
    ThreatHintV2AcceptanceService,
    ThreatHintV2AcceptanceUnavailableError,
)
from jaeger.threat_observable import (
    MAX_OBSERVABLES,
    DisclosurePolicy,
    ObservableBundle,
    ObservableKind,
    ScopeFormat,
    ScopePlatform,
)

PROMOTION_POLICY_SCHEMA_VERSION: Final[int] = 1
MAX_PROMOTION_POLICY_BYTES: Final[int] = 4_096
FIXED_HASH_BYTES: Final[int] = 32
U64_MAX: Final[int] = (1 << 64) - 1
_POLICY_FIELDS: Final[frozenset] = frozenset(
    {
        "schema_version",
        "scope_platform",
        "scope_format",
        "allowed_observable_kinds",
        "max_observables",
    }
)


class ThreatHintV2PromotionError(ValueError):
    """Stable redacted rejection for invalid candidate data."""

    _MESSAGE = "invalid threat-hint v2 promotion"

    def __init__(self) -> None:
        super().__init__(self._MESSAGE)


class ThreatHintV2PromotionUnavailableError(ThreatHintV2PromotionError):
    """Stable redacted failure for unavailable trusted material or state."""

    _MESSAGE = "threat-hint v2 promotion unavailable"


class ThreatHintV2PromotionReplayError(ThreatHintV2PromotionError):
    """The approval identity, authority nonce, or time was already consumed."""

    _MESSAGE = "threat-hint v2 promotion replay"


class ThreatHintV2PromotionBusyError(ThreatHintV2PromotionError):
    """Retryable failure while the verifier slot or ledger is occupied."""

    _MESSAGE = "threat-hint v2 promotion busy"


@dataclass(frozen=True)
class ThreatHintV2PromotionPolicy:
    """Owner-configured promotion restrictions; the data grants no authority."""

    scope_platform: ScopePlatform
    scope_format: ScopeFormat
    allowed_observable_kinds: frozenset
    max_observables: int
    policy_sha256: bytes


@dataclass(frozen=True, init=False, repr=False, eq=False)
class ThreatHintV2PromotionResult:
    """Immutable data-only promotion result; it grants no authority.

    Direct construction is disabled; ``promote`` is the only supported
    construction path. The result binds the verified statement digest,
    approval identifier, observable commitment, and consumption time to the
    policy-pinned scope platform and format and the canonical observables as
    an immutable tuple of (kind, value) string pairs. It never contains
    proof, approval wire, policy key or scope, nonce, raw manifest, verifier
    executable hash, or any caller receipt, and it is not serializable.
    """

    statement_digest: bytes
    approval_id: bytes
    observable_commitment: bytes
    consumed_at: int
    scope_platform: str
    scope_format: str
    observables: tuple[tuple[str, str], ...]

    def __init__(self) -> None:
        raise TypeError(
            "direct threat-hint v2 promotion result construction is disabled"
        )

    def __reduce__(self) -> object:
        raise TypeError("threat-hint v2 promotion result is not serializable")


class ThreatHintV2PromotionService:  # pylint: disable=too-few-public-methods
    """Restrict raw candidates by policy, then run acceptance in one call."""

    def __init__(
        self,
        config_path: Path,
        preflight_policy_path: Path,
        consumption_policy_path: Path,
        promotion_policy_path: Path,
    ) -> None:
        try:
            self._policy = _load_promotion_policy(promotion_policy_path)
        except ThreatHintV2PromotionError:
            raise ThreatHintV2PromotionUnavailableError() from None
        try:
            self._acceptance = ThreatHintV2AcceptanceService(
                config_path, preflight_policy_path, consumption_policy_path
            )
        except ThreatHintV2AcceptanceBusyError:
            raise ThreatHintV2PromotionBusyError() from None
        except ThreatHintV2AcceptanceError:
            raise ThreatHintV2PromotionUnavailableError() from None

    @classmethod
    def from_governed_policies(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        cls,
        config_path: Path,
        preflight_policy_path: Path,
        consumption_policy_path: Path,
        promotion_policy_path: Path,
        governance_policy_path: Path,
        retention_policy_path: Path,
    ) -> ThreatHintV2PromotionService:
        """Load one promotion snapshot, then bind governance before ledger open."""
        service = object.__new__(cls)
        try:
            service._policy = _load_promotion_policy(promotion_policy_path)
        except ThreatHintV2PromotionError:
            raise ThreatHintV2PromotionUnavailableError() from None
        try:
            service._acceptance = ThreatHintV2AcceptanceService.from_governed_policies(
                config_path,
                preflight_policy_path,
                consumption_policy_path,
                governance_policy_path,
                retention_policy_path,
                expected_allowed_observable_kinds=(
                    service._policy.allowed_observable_kinds
                ),
                expected_promotion_policy_sha256=service._policy.policy_sha256,
                durable_outbox=True,
            )
        except ThreatHintV2AcceptanceBusyError:
            raise ThreatHintV2PromotionBusyError() from None
        except ThreatHintV2AcceptanceError:
            raise ThreatHintV2PromotionUnavailableError() from None
        return service

    # pylint: disable-next=too-many-arguments
    def promote(
        self,
        envelope_wire: bytes,
        bundle_wire: bytes,
        approval_wire: bytes,
        *,
        report_nonce: bytes,
        current_time: int,
    ) -> ThreatHintV2PromotionResult:
        """Apply every promotion restriction, then accept the same raw bytes.

        Every promotion restriction is re-derived from the raw bundle bytes
        and consumes nothing; only its success reaches the acceptance call.
        Nested parser, value, and type errors are redacted into one stable
        public error.
        """
        try:
            return self._promote(
                envelope_wire,
                bundle_wire,
                approval_wire,
                report_nonce=report_nonce,
                current_time=current_time,
            )
        except ThreatHintV2PromotionError:
            raise
        except (TypeError, ValueError, OverflowError, RecursionError):
            raise ThreatHintV2PromotionError() from None

    # pylint: disable-next=too-many-arguments
    def _promote(
        self,
        envelope_wire: bytes,
        bundle_wire: bytes,
        approval_wire: bytes,
        *,
        report_nonce: bytes,
        current_time: int,
    ) -> ThreatHintV2PromotionResult:
        if (
            type(envelope_wire) is not bytes
            or type(bundle_wire) is not bytes
            or type(approval_wire) is not bytes
        ):
            raise ThreatHintV2PromotionError()
        if (
            type(report_nonce) is not bytes
            or len(report_nonce) != FIXED_HASH_BYTES
            or type(current_time) is not int
            or current_time < 1
            or current_time > U64_MAX
        ):
            raise ThreatHintV2PromotionError()
        policy = self._policy

        # Step 1: parse the canonical bundle and require review-required
        # disclosure before any restriction is evaluated.
        bundle = ObservableBundle.parse_canonical(bundle_wire)
        if bundle.disclosure_policy is not DisclosurePolicy.REVIEW_REQUIRED_V1:
            raise ThreatHintV2PromotionError()

        # Step 2: require the exact policy platform and format.
        if (
            bundle.scope.platform is not policy.scope_platform
            or bundle.scope.format is not policy.scope_format
        ):
            raise ThreatHintV2PromotionError()

        # Step 3: require every observable kind to be policy-allowed.
        if any(
            observable.kind not in policy.allowed_observable_kinds
            for observable in bundle.observables
        ):
            raise ThreatHintV2PromotionError()

        # Step 4: require the observable count within the policy maximum.
        if len(bundle.observables) > policy.max_observables:
            raise ThreatHintV2PromotionError()

        # Step 5: only now run acceptance with the same original bytes.
        try:
            receipt = self._acceptance.accept(
                envelope_wire,
                bundle_wire,
                approval_wire,
                report_nonce=report_nonce,
                current_time=current_time,
            )
        except ThreatHintV2AcceptanceBusyError:
            raise ThreatHintV2PromotionBusyError() from None
        except ThreatHintV2AcceptanceReplayError:
            raise ThreatHintV2PromotionReplayError() from None
        except ThreatHintV2AcceptanceUnavailableError:
            raise ThreatHintV2PromotionUnavailableError() from None
        except ThreatHintV2AcceptanceError:
            raise ThreatHintV2PromotionError() from None
        return _build_result(receipt, bundle)


def _build_result(
    receipt: ThreatHintV2AcceptanceReceipt,
    bundle: ObservableBundle,
) -> ThreatHintV2PromotionResult:
    """Build the restricted result from in-memory data only; no I/O."""
    result = object.__new__(ThreatHintV2PromotionResult)
    object.__setattr__(result, "statement_digest", receipt.statement_digest)
    object.__setattr__(result, "approval_id", receipt.approval_id)
    object.__setattr__(result, "observable_commitment", receipt.observable_commitment)
    object.__setattr__(result, "consumed_at", receipt.consumed_at)
    object.__setattr__(result, "scope_platform", bundle.scope.platform.value)
    object.__setattr__(result, "scope_format", bundle.scope.format.value)
    object.__setattr__(
        result,
        "observables",
        tuple(
            (observable.kind.value, observable.value)
            for observable in bundle.observables
        ),
    )
    return result


def _load_promotion_policy(path: Path) -> ThreatHintV2PromotionPolicy:
    """Load one exact-schema policy from an owner-only regular TOML file.

    Loading performs no writes: the file is only read as ASCII and parsed.
    """
    try:
        contents = _read_owner_policy_file(path)
        data = tomllib.loads(contents.decode("ascii"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, RecursionError):
        raise ThreatHintV2PromotionError() from None
    if not isinstance(data, dict) or set(data) != _POLICY_FIELDS:
        raise ThreatHintV2PromotionError()
    if (
        type(data["schema_version"]) is not int
        or data["schema_version"] != PROMOTION_POLICY_SCHEMA_VERSION
    ):
        raise ThreatHintV2PromotionError()

    return ThreatHintV2PromotionPolicy(
        scope_platform=_parse_scope_platform(data["scope_platform"]),
        scope_format=_parse_scope_format(data["scope_format"]),
        allowed_observable_kinds=_parse_allowed_kinds(data["allowed_observable_kinds"]),
        max_observables=_parse_max_observables(data["max_observables"]),
        policy_sha256=hashlib.sha256(contents).digest(),
    )


def _parse_scope_platform(value: object) -> ScopePlatform:
    if type(value) is not str:
        raise ThreatHintV2PromotionError()
    try:
        return ScopePlatform(value)
    except ValueError:
        raise ThreatHintV2PromotionError() from None


def _parse_scope_format(value: object) -> ScopeFormat:
    if type(value) is not str:
        raise ThreatHintV2PromotionError()
    try:
        return ScopeFormat(value)
    except ValueError:
        raise ThreatHintV2PromotionError() from None


def _parse_allowed_kinds(value: object) -> frozenset:
    if type(value) is not list or not value:
        raise ThreatHintV2PromotionError()
    kinds = []
    for item in value:
        if type(item) is not str:
            raise ThreatHintV2PromotionError()
        try:
            kind = ObservableKind(item)
        except ValueError:
            raise ThreatHintV2PromotionError() from None
        if kind in kinds:
            raise ThreatHintV2PromotionError()
        kinds.append(kind)
    return frozenset(kinds)


def _parse_max_observables(value: object) -> int:
    if type(value) is not int or value < 1 or value > MAX_OBSERVABLES:
        raise ThreatHintV2PromotionError()
    return value


def _read_owner_policy_file(path: Path) -> bytes:
    if os.name != "posix" or not hasattr(os, "getuid") or not hasattr(os, "O_NOFOLLOW"):
        raise ThreatHintV2PromotionError()
    if (
        not isinstance(path, Path)
        or type(path) not in (Path, PosixPath, WindowsPath)
        or not path.is_absolute()
        or path.name in {"", ".", ".."}
        or ".." in path.parts
    ):
        raise ThreatHintV2PromotionError()
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
            raise ThreatHintV2PromotionError()
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
                raise ThreatHintV2PromotionError()
            contents = _read_policy_descriptor(descriptor)
        finally:
            os.close(descriptor)
    except (OSError, ValueError):
        raise ThreatHintV2PromotionError() from None
    if len(contents) != before.st_size:
        raise ThreatHintV2PromotionError()
    return contents


def _read_policy_descriptor(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    remaining = MAX_PROMOTION_POLICY_BYTES + 1
    while remaining:
        chunk = os.read(descriptor, min(remaining, 64 * 1_024))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    contents = b"".join(chunks)
    if len(contents) > MAX_PROMOTION_POLICY_BYTES:
        raise ThreatHintV2PromotionError()
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
        and 0 < current.st_size <= MAX_PROMOTION_POLICY_BYTES
    )
