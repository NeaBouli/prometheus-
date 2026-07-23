"""Local-only verification of canonical Observable Approval statements."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable

from coincurve import PublicKeyXOnly

from jaeger.threat_observable import (
    DisclosurePolicy,
    ObservableBundle,
    validate_network_id,
)

APPROVAL_SCHEMA_VERSION = 1
APPROVAL_PURPOSE = "guardian_analysis_v1"
APPROVAL_SIGNING_DOMAIN = b"prometheus-observable-approval-v1\x00"
APPROVAL_ID_DOMAIN = b"prometheus-observable-approval-id-v1\x00"
MAX_CANONICAL_APPROVAL_BYTES = 1024
MAX_APPROVAL_LIFETIME_SECONDS = 60 * 60
FIXED_HASH_BYTES = 32
SCHNORR_SIGNATURE_BYTES = 64
UINT64_MAX = (1 << 64) - 1


class ObservableApprovalError(ValueError):
    """Redacted failure for every invalid approval or trusted context."""

    def __init__(self) -> None:
        super().__init__("invalid observable approval")


@dataclass(frozen=True)
class ObservableApprovalContext:
    """Independently trusted local approval-verification context."""

    report_nonce: bytes
    approver_xonly_public_key: bytes
    recipient_scope: bytes
    network_id: str
    current_time: int

    def validate(self) -> None:
        if (
            type(self.report_nonce) is not bytes
            or len(self.report_nonce) != FIXED_HASH_BYTES
            or type(self.approver_xonly_public_key) is not bytes
            or len(self.approver_xonly_public_key) != FIXED_HASH_BYTES
            or type(self.recipient_scope) is not bytes
            or len(self.recipient_scope) != FIXED_HASH_BYTES
            or type(self.network_id) is not str
            or type(self.current_time) is not int
            or self.current_time <= 0
            or self.current_time > UINT64_MAX
        ):
            raise ObservableApprovalError()
        try:
            validate_network_id(self.network_id)
        except ValueError:
            raise ObservableApprovalError() from None


@dataclass(frozen=True, init=False)
class VerifiedObservableApproval:
    """Data-only result; its Python object identity grants no authority.

    A consumer must invoke the verifier in the same trusted call path and must
    never accept a caller-supplied instance as evidence of verification. The
    nonce identifies but does not prevent replay.
    """

    approval_id: bytes
    observable_commitment: bytes
    approver_xonly_public_key: bytes
    recipient_scope: bytes
    approval_nonce: bytes
    network_id: str
    not_before: int
    expires_at: int

    def __init__(self) -> None:
        raise TypeError("direct verified approval construction is disabled")


def verify_observable_approval(
    approval_wire: bytes,
    bundle_wire: bytes,
    context: ObservableApprovalContext,
) -> VerifiedObservableApproval:
    """Verify one canonical, short-lived approval for one exact bundle."""
    try:
        return _verify_observable_approval(approval_wire, bundle_wire, context)
    except ObservableApprovalError:
        raise
    except (TypeError, ValueError):
        raise ObservableApprovalError() from None


def _verify_observable_approval(
    approval_wire: bytes,
    bundle_wire: bytes,
    context: ObservableApprovalContext,
) -> VerifiedObservableApproval:
    if type(approval_wire) is not bytes or not (
        0 < len(approval_wire) <= MAX_CANONICAL_APPROVAL_BYTES
    ):
        raise ObservableApprovalError()
    if type(bundle_wire) is not bytes:
        raise ObservableApprovalError()
    # Exact type prevents subclasses from overriding validation or comparisons.
    if type(context) is not ObservableApprovalContext:  # pylint: disable=C0123
        raise ObservableApprovalError()
    context.validate()

    try:
        decoded = json.loads(
            approval_wire.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except (UnicodeDecodeError, ValueError):
        raise ObservableApprovalError() from None
    if not isinstance(decoded, dict) or set(decoded.keys()) != {
        "schema_version",
        "observable_commitment",
        "approver_xonly_public_key",
        "purpose",
        "recipient_scope",
        "network_id",
        "not_before",
        "expires_at",
        "approval_nonce",
        "signature",
    }:
        raise ObservableApprovalError()

    canonical = _canonical_json_bytes(
        {
            "schema_version": decoded["schema_version"],
            "observable_commitment": decoded["observable_commitment"],
            "approver_xonly_public_key": decoded["approver_xonly_public_key"],
            "purpose": decoded["purpose"],
            "recipient_scope": decoded["recipient_scope"],
            "network_id": decoded["network_id"],
            "not_before": decoded["not_before"],
            "expires_at": decoded["expires_at"],
            "approval_nonce": decoded["approval_nonce"],
            "signature": decoded["signature"],
        }
    )
    if canonical != approval_wire:
        raise ObservableApprovalError()

    if (
        type(decoded["schema_version"]) is not int
        or decoded["schema_version"] != APPROVAL_SCHEMA_VERSION
        or type(decoded["purpose"]) is not str
        or decoded["purpose"] != APPROVAL_PURPOSE
        or type(decoded["network_id"]) is not str
        or decoded["network_id"] != context.network_id
        or type(decoded["not_before"]) is not int
        or type(decoded["expires_at"]) is not int
        or decoded["not_before"] > UINT64_MAX
        or decoded["expires_at"] > UINT64_MAX
    ):
        raise ObservableApprovalError()

    not_before = decoded["not_before"]
    expires_at = decoded["expires_at"]
    lifetime = expires_at - not_before
    if (
        not_before <= 0
        or lifetime <= 0
        or lifetime > MAX_APPROVAL_LIFETIME_SECONDS
        or context.current_time < not_before
        or context.current_time > expires_at
    ):
        raise ObservableApprovalError()

    observable_commitment = _decode_fixed_hex(
        decoded["observable_commitment"], FIXED_HASH_BYTES
    )
    approver_xonly_public_key = _decode_fixed_hex(
        decoded["approver_xonly_public_key"], FIXED_HASH_BYTES
    )
    recipient_scope = _decode_fixed_hex(decoded["recipient_scope"], FIXED_HASH_BYTES)
    approval_nonce = _decode_fixed_hex(decoded["approval_nonce"], FIXED_HASH_BYTES)
    signature = _decode_fixed_hex(decoded["signature"], SCHNORR_SIGNATURE_BYTES)

    if not hmac.compare_digest(
        approver_xonly_public_key, context.approver_xonly_public_key
    ) or not hmac.compare_digest(recipient_scope, context.recipient_scope):
        raise ObservableApprovalError()

    try:
        bundle = ObservableBundle.parse_canonical(bundle_wire)
    except ValueError:
        raise ObservableApprovalError() from None
    if bundle.disclosure_policy != DisclosurePolicy.REVIEW_REQUIRED_V1:
        raise ObservableApprovalError()
    expected_commitment = bundle.commitment(
        context.network_id, context.report_nonce.hex()
    )
    if not hmac.compare_digest(observable_commitment, expected_commitment):
        raise ObservableApprovalError()

    signing_body = {
        "schema_version": decoded["schema_version"],
        "observable_commitment": decoded["observable_commitment"],
        "approver_xonly_public_key": decoded["approver_xonly_public_key"],
        "purpose": decoded["purpose"],
        "recipient_scope": decoded["recipient_scope"],
        "network_id": decoded["network_id"],
        "not_before": not_before,
        "expires_at": expires_at,
        "approval_nonce": decoded["approval_nonce"],
    }
    signing_digest = _domain_digest(
        APPROVAL_SIGNING_DOMAIN, _canonical_json_bytes(signing_body)
    )
    try:
        signature_valid = PublicKeyXOnly(approver_xonly_public_key).verify(
            signature, signing_digest
        )
    except ValueError:
        raise ObservableApprovalError() from None
    if not signature_valid:
        raise ObservableApprovalError()

    verified = object.__new__(VerifiedObservableApproval)
    object.__setattr__(
        verified, "approval_id", _domain_digest(APPROVAL_ID_DOMAIN, approval_wire)
    )
    object.__setattr__(verified, "observable_commitment", observable_commitment)
    object.__setattr__(verified, "approver_xonly_public_key", approver_xonly_public_key)
    object.__setattr__(verified, "recipient_scope", recipient_scope)
    object.__setattr__(verified, "approval_nonce", approval_nonce)
    object.__setattr__(verified, "network_id", decoded["network_id"])
    object.__setattr__(verified, "not_before", not_before)
    object.__setattr__(verified, "expires_at", expires_at)
    return verified


def _reject_duplicate_keys(items: Iterable[tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ObservableApprovalError()
        result[key] = value
    return result


def _canonical_json_bytes(value: Dict[str, Any]) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _decode_fixed_hex(value: Any, expected_bytes: int) -> bytes:
    if (
        type(value) is not str
        or len(value) != expected_bytes * 2
        or _LOWER_HEX_RE.fullmatch(value) is None
    ):
        raise ObservableApprovalError()
    return bytes.fromhex(value)


def _domain_digest(domain: bytes, value: bytes) -> bytes:
    digest = hashlib.sha256()
    digest.update(domain)
    digest.update(len(value).to_bytes(4, byteorder="big", signed=False))
    digest.update(value)
    return digest.digest()


_LOWER_HEX_RE = re.compile(r"[0-9a-f]*$")
