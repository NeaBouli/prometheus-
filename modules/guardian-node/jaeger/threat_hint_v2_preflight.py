"""Local-only data-only and non-consuming ThreatHint-v2 preflight.

The preflight binds one canonical v2 proof envelope and RelationManifest-v2
against one owner-only policy, derives the claimed statement exclusively from
the bound envelope, re-derives the observable commitment from the canonical
bundle, and verifies one canonical Observable Approval in the same call path.
It consumes nothing: no approval is consumed and no ledger or SQLite file is
opened, created, migrated, or written. No proof is verified either; the proof
bytes remain opaque. A successful preflight is data-only compatibility
evidence that stays incomplete until a real approved v2 Groth16 verifier runs
in the same future acceptance call path.

The fail-closed order is fixed: owner-only policy loading (read-only, exactly
one TOML schema-v1 document with no ``ledger_path``), exact built-in input
type validation, canonical binding against the policy network and manifest
anchor, statement derivation from ``binding.envelope.parsed_statement`` only,
``review_required_v1`` statement disclosure, trusted report-nonce equality,
canonical bundle parsing with ``review_required_v1`` disclosure, commitment
recomputation against the one policy network and nonce, approval verification
from an exact policy-derived context, verified commitment/network equality,
and a final binding/statement digest assertion.
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
from pathlib import Path
from typing import Final

from jaeger.observable_approval import (
    ObservableApprovalContext,
    verify_observable_approval,
)
from jaeger.threat_hint_v2_proof_binding import ThreatHintV2ProofBinding
from jaeger.threat_hint_v2_statement import ThreatHintV2DisclosureClass
from jaeger.threat_observable import (
    DisclosurePolicy,
    ObservableBundle,
    validate_network_id,
)

PREFLIGHT_POLICY_SCHEMA_VERSION: Final[int] = 1
MAX_PREFLIGHT_POLICY_BYTES: Final[int] = 4_096
FIXED_HASH_BYTES: Final[int] = 32
U64_MAX: Final[int] = (1 << 64) - 1
_POLICY_FIELDS: Final[frozenset] = frozenset(
    {
        "schema_version",
        "network_id",
        "approver_xonly_public_key",
        "recipient_scope",
        "relation_manifest_sha256",
    }
)


class ThreatHintV2PreflightError(ValueError):
    """Redacted failure for every invalid policy, input, or verification."""

    def __init__(self) -> None:
        super().__init__("invalid threat-hint v2 preflight")


@dataclass(frozen=True)
class ThreatHintV2PreflightPolicy:
    """Owner-configured trusted anchors; the data grants no authority."""

    network_id: str
    approver_xonly_public_key: bytes
    recipient_scope: bytes
    relation_manifest_sha256_hex: str


@dataclass(frozen=True, init=False, repr=False, eq=False)
class ThreatHintV2PreflightReceipt:
    """Immutable data-only preflight receipt; it grants no authority.

    Direct construction is disabled; ``preflight`` is the only supported
    construction path. The receipt never contains proof, statement, bundle,
    approval, policy key or scope, or observable material, and it is not
    evidence of proof acceptance, approval consumption, or any durable state.
    A consumer must rerun verification in the same trusted call path and must
    never accept a caller-supplied receipt as evidence of anything.
    """

    statement_digest: bytes
    approval_id: bytes
    observable_commitment: bytes
    raw_manifest_sha256_hex: str
    envelope_sha256_hex: str

    def __init__(self) -> None:
        """Reject direct construction outside a successful preflight."""
        raise TypeError(
            "direct threat-hint v2 preflight receipt construction is disabled"
        )

    def __reduce__(self) -> object:
        raise TypeError("threat-hint v2 preflight receipt is not serializable")


class ThreatHintV2PreflightService:  # pylint: disable=too-few-public-methods
    """Run the fixed-order local preflight without any external side effect."""

    def __init__(self, policy_path: Path) -> None:
        self._policy = _load_preflight_policy(policy_path)

    @property
    def trusted_network_id(self) -> str:
        """Return the immutable owner-pinned policy network identifier."""
        return self._policy.network_id

    @property
    def trusted_relation_manifest_sha256_hex(self) -> str:
        """Return the immutable owner-pinned raw manifest SHA-256 anchor."""
        return self._policy.relation_manifest_sha256_hex

    @property
    def trusted_approver_xonly_public_key(self) -> bytes:
        """Return the immutable owner-pinned approver x-only public key."""
        return self._policy.approver_xonly_public_key

    @property
    def trusted_recipient_scope(self) -> bytes:
        """Return the immutable owner-pinned opaque recipient scope."""
        return self._policy.recipient_scope

    # pylint: disable-next=too-many-arguments
    def preflight(
        self,
        envelope_wire: bytes,
        manifest_wire: bytes,
        bundle_wire: bytes,
        approval_wire: bytes,
        *,
        report_nonce: bytes,
        current_time: int,
    ) -> ThreatHintV2PreflightReceipt:
        """Run the data-only non-consuming preflight in one fail-closed call.

        The statement is derived only from the bound envelope; callers cannot
        supply a statement, network, manifest anchor, approver key, or scope.
        Nested parser, value, and type errors are redacted into one stable
        public error.
        """
        try:
            return self._preflight(
                envelope_wire,
                manifest_wire,
                bundle_wire,
                approval_wire,
                report_nonce=report_nonce,
                current_time=current_time,
            )
        except ThreatHintV2PreflightError:
            raise
        except (TypeError, ValueError, OverflowError, RecursionError):
            raise ThreatHintV2PreflightError() from None

    # pylint: disable-next=too-many-locals,too-many-arguments
    def _preflight(
        self,
        envelope_wire: bytes,
        manifest_wire: bytes,
        bundle_wire: bytes,
        approval_wire: bytes,
        *,
        report_nonce: bytes,
        current_time: int,
    ) -> ThreatHintV2PreflightReceipt:
        if (
            type(envelope_wire) is not bytes
            or type(manifest_wire) is not bytes
            or type(bundle_wire) is not bytes
            or type(approval_wire) is not bytes
        ):
            raise ThreatHintV2PreflightError()
        if (
            type(report_nonce) is not bytes
            or len(report_nonce) != FIXED_HASH_BYTES
            or type(current_time) is not int
            or current_time < 1
            or current_time > U64_MAX
        ):
            raise ThreatHintV2PreflightError()
        policy = self._policy

        # Step 1: bind both canonical wires against the policy network and
        # the policy-pinned raw manifest anchor. No proof is verified.
        binding = ThreatHintV2ProofBinding.bind_canonical(
            envelope_wire,
            manifest_wire,
            policy.network_id,
            policy.relation_manifest_sha256_hex,
        )

        # Step 2: derive the claimed statement only from the bound envelope.
        statement = binding.envelope.parsed_statement

        # Step 3: require the review-required disclosure class.
        if (
            statement.disclosure_class
            is not ThreatHintV2DisclosureClass.REVIEW_REQUIRED_V1
        ):
            raise ThreatHintV2PreflightError()

        # Step 4: require the statement nonce to equal the trusted nonce.
        if statement.report_nonce != report_nonce.hex():
            raise ThreatHintV2PreflightError()

        # Step 5: parse the canonical bundle and require review-required
        # disclosure before any commitment is recomputed.
        bundle = ObservableBundle.parse_canonical(bundle_wire)
        if bundle.disclosure_policy is not DisclosurePolicy.REVIEW_REQUIRED_V1:
            raise ThreatHintV2PreflightError()

        # Step 6: recompute the commitment against the one policy network
        # and trusted nonce and match it against the derived statement.
        commitment = bundle.commitment(policy.network_id, report_nonce.hex())
        if not hmac.compare_digest(
            commitment, bytes.fromhex(statement.observable_commitment)
        ):
            raise ThreatHintV2PreflightError()

        # Step 7: build the exact approval context from the policy and
        # verify the approval in the same call. Nothing is consumed.
        context = ObservableApprovalContext(
            report_nonce=report_nonce,
            approver_xonly_public_key=policy.approver_xonly_public_key,
            recipient_scope=policy.recipient_scope,
            network_id=policy.network_id,
            current_time=current_time,
        )
        verified = verify_observable_approval(approval_wire, bundle_wire, context)

        # Step 8: match the verified commitment and network against the one
        # policy network and the recomputed commitment.
        if (
            not hmac.compare_digest(verified.observable_commitment, commitment)
            or verified.network_id != policy.network_id
        ):
            raise ThreatHintV2PreflightError()

        # Step 9: assert the binding statement digest equals the digest
        # recomputed from the derived statement.
        statement_digest = statement.statement_digest()
        if statement_digest.hex() != binding.statement_digest_hex:
            raise ThreatHintV2PreflightError()

        receipt = object.__new__(ThreatHintV2PreflightReceipt)
        object.__setattr__(receipt, "statement_digest", statement_digest)
        object.__setattr__(receipt, "approval_id", verified.approval_id)
        object.__setattr__(receipt, "observable_commitment", commitment)
        object.__setattr__(
            receipt, "raw_manifest_sha256_hex", binding.raw_manifest_sha256_hex
        )
        object.__setattr__(
            receipt,
            "envelope_sha256_hex",
            hashlib.sha256(envelope_wire).hexdigest(),
        )
        return receipt


def _load_preflight_policy(path: Path) -> ThreatHintV2PreflightPolicy:
    """Load one exact-schema policy from an owner-only regular TOML file.

    Loading performs no writes: the file is only read as ASCII and parsed.
    """
    policy_path = _validate_owner_policy_path(path)
    try:
        data = tomllib.loads(policy_path.read_text(encoding="ascii"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, RecursionError):
        raise ThreatHintV2PreflightError() from None
    if not isinstance(data, dict) or set(data) != _POLICY_FIELDS:
        raise ThreatHintV2PreflightError()
    if (
        type(data["schema_version"]) is not int
        or data["schema_version"] != PREFLIGHT_POLICY_SCHEMA_VERSION
    ):
        raise ThreatHintV2PreflightError()

    network_id = data["network_id"]
    if type(network_id) is not str:
        raise ThreatHintV2PreflightError()
    try:
        validate_network_id(network_id)
    except ValueError:
        raise ThreatHintV2PreflightError() from None

    return ThreatHintV2PreflightPolicy(
        network_id=network_id,
        approver_xonly_public_key=_decode_fixed_lower_hex(
            data["approver_xonly_public_key"]
        ),
        recipient_scope=_decode_fixed_lower_hex(data["recipient_scope"]),
        relation_manifest_sha256_hex=_decode_manifest_anchor(
            data["relation_manifest_sha256"]
        ),
    )


def _validate_owner_policy_path(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ThreatHintV2PreflightError()
    try:
        parent = path.parent.resolve(strict=True)
        parent_stat = parent.stat()
        current = path.lstat()
    except OSError:
        raise ThreatHintV2PreflightError() from None
    candidate = parent / path.name
    if (
        candidate != path
        or not _is_safe_policy_parent(parent_stat)
        or not _is_safe_policy_file(current)
    ):
        raise ThreatHintV2PreflightError()
    return candidate


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
        and 0 < current.st_size <= MAX_PREFLIGHT_POLICY_BYTES
    )


def _decode_fixed_lower_hex(value: object) -> bytes:
    if (
        type(value) is not str
        or len(value) != FIXED_HASH_BYTES * 2
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ThreatHintV2PreflightError()
    return bytes.fromhex(value)


def _decode_manifest_anchor(value: object) -> str:
    if (
        type(value) is not str
        or len(value) != FIXED_HASH_BYTES * 2
        or any(character not in "0123456789abcdef" for character in value)
        or not any(character != "0" for character in value)
    ):
        raise ThreatHintV2PreflightError()
    return value
