"""Local-only canonical ThreatHint v2 transport payload framing."""

# Exact built-in types and fixed framing are protocol requirements.
# pylint: disable=too-many-instance-attributes,unidiomatic-typecheck

from __future__ import annotations

import json
import re
import weakref
from dataclasses import dataclass
from typing import Any, Dict, Iterable

from jaeger.threat_hint_v2_proof_envelope import (
    MAX_CANONICAL_V2_PROOF_ENVELOPE_BYTES,
    ThreatHintV2ProofEnvelope,
    ThreatHintV2ProofEnvelopeError,
)
from jaeger.observable_approval import (
    MAX_APPROVAL_LIFETIME_SECONDS,
    MAX_CANONICAL_APPROVAL_BYTES,
)
from jaeger.threat_observable import (
    MAX_CANONICAL_BYTES,
    ObservableBundle,
    validate_network_id,
)

TRANSPORT_MAGIC = b"PHT2"
TRANSPORT_VERSION = 1
REPORT_NONCE_BYTES = 32
LENGTH_FIELD_BYTES = 4
HEADER_BYTES = len(TRANSPORT_MAGIC) + 1 + REPORT_NONCE_BYTES + 3 * LENGTH_FIELD_BYTES
NONCE_OFFSET = len(TRANSPORT_MAGIC) + 1
ENVELOPE_LEN_OFFSET = NONCE_OFFSET + REPORT_NONCE_BYTES
BUNDLE_LEN_OFFSET = ENVELOPE_LEN_OFFSET + LENGTH_FIELD_BYTES
APPROVAL_LEN_OFFSET = BUNDLE_LEN_OFFSET + LENGTH_FIELD_BYTES

MAX_TRANSPORT_ENVELOPE_BYTES = MAX_CANONICAL_V2_PROOF_ENVELOPE_BYTES
MAX_TRANSPORT_BUNDLE_BYTES = MAX_CANONICAL_BYTES
MAX_TRANSPORT_APPROVAL_BYTES = MAX_CANONICAL_APPROVAL_BYTES
MAX_TRANSPORT_PAYLOAD_BYTES = (
    HEADER_BYTES
    + MAX_TRANSPORT_ENVELOPE_BYTES
    + MAX_TRANSPORT_BUNDLE_BYTES
    + MAX_TRANSPORT_APPROVAL_BYTES
)

APPROVAL_SHAPE_SCHEMA_VERSION = 1
APPROVAL_SHAPE_PURPOSE = "guardian_analysis_v1"
UINT64_MAX = (1 << 64) - 1


class ThreatHintV2TransportError(ValueError):
    """Redacted failure for every invalid payload or trusted network."""

    def __init__(self) -> None:
        super().__init__("invalid threat-hint v2 transport payload")


@dataclass(frozen=True, init=False, repr=False, eq=False)
class ThreatHintV2TransportPayload:
    """Canonical local v2 transport payload with no authority of its own.

    The payload carries exactly three untrusted candidate wires (a canonical
    v2 proof envelope, a canonical observable bundle, and a canonical
    approval). It never carries a relation manifest, current time, trusted
    network, authority, policy, recipient scope, or any signer key.

    The report nonce is an UNTRUSTED session lookup key only: parsing checks
    that it equals the envelope statement nonce for internal consistency, but
    equality with attacker-controlled bytes grants nothing. Downstream
    consumers must resolve the nonce against separately trusted active local
    state before calling promotion.

    The nested approval passed a canonical shape check only. Trusted key and
    recipient-scope equality, the current-time validity window, bundle
    commitment binding, and Schnorr signature verification all remain
    downstream; shape validity is not approval.
    """

    report_nonce: bytes
    envelope_wire: bytes
    bundle_wire: bytes
    approval_wire: bytes
    parsed_envelope: ThreatHintV2ProofEnvelope
    parsed_bundle: ObservableBundle

    def __init__(self) -> None:
        """Reject direct construction outside canonical parsing."""
        raise TypeError("direct transport payload construction is disabled")

    @classmethod
    def parse_canonical(
        cls, wire_bytes: bytes, trusted_network_id: str
    ) -> "ThreatHintV2TransportPayload":
        """Parse exact framing against a separately trusted local network."""
        if cls is not ThreatHintV2TransportPayload or type(wire_bytes) is not bytes:
            raise ThreatHintV2TransportError()
        if type(trusted_network_id) is not str:
            raise ThreatHintV2TransportError()
        if (
            len(wire_bytes) == 0
            or len(wire_bytes) > MAX_TRANSPORT_PAYLOAD_BYTES
            or len(wire_bytes) < HEADER_BYTES + 3
        ):
            raise ThreatHintV2TransportError()
        if (
            wire_bytes[: len(TRANSPORT_MAGIC)] != TRANSPORT_MAGIC
            or wire_bytes[NONCE_OFFSET - 1] != TRANSPORT_VERSION
        ):
            raise ThreatHintV2TransportError()

        report_nonce = wire_bytes[NONCE_OFFSET : NONCE_OFFSET + REPORT_NONCE_BYTES]
        envelope_len = _read_be_len(wire_bytes, ENVELOPE_LEN_OFFSET)
        bundle_len = _read_be_len(wire_bytes, BUNDLE_LEN_OFFSET)
        approval_len = _read_be_len(wire_bytes, APPROVAL_LEN_OFFSET)
        if (
            not 1 <= envelope_len <= MAX_TRANSPORT_ENVELOPE_BYTES
            or not 1 <= bundle_len <= MAX_TRANSPORT_BUNDLE_BYTES
            or not 1 <= approval_len <= MAX_TRANSPORT_APPROVAL_BYTES
        ):
            raise ThreatHintV2TransportError()
        if HEADER_BYTES + envelope_len + bundle_len + approval_len != len(wire_bytes):
            raise ThreatHintV2TransportError()

        bundle_start = HEADER_BYTES + envelope_len
        approval_start = bundle_start + bundle_len
        envelope_wire = wire_bytes[HEADER_BYTES:bundle_start]
        bundle_wire = wire_bytes[bundle_start:approval_start]
        approval_wire = wire_bytes[approval_start:]

        try:
            envelope = ThreatHintV2ProofEnvelope.parse_canonical(
                envelope_wire, trusted_network_id
            )
        except ThreatHintV2ProofEnvelopeError:
            raise ThreatHintV2TransportError() from None
        if envelope.parsed_statement.report_nonce != report_nonce.hex():
            raise ThreatHintV2TransportError()

        try:
            bundle = ObservableBundle.parse_canonical(bundle_wire)
        except ValueError:
            raise ThreatHintV2TransportError() from None

        _validate_approval_shape(approval_wire)

        payload = object.__new__(cls)
        object.__setattr__(payload, "report_nonce", report_nonce)
        object.__setattr__(payload, "envelope_wire", envelope_wire)
        object.__setattr__(payload, "bundle_wire", bundle_wire)
        object.__setattr__(payload, "approval_wire", approval_wire)
        object.__setattr__(payload, "parsed_envelope", envelope)
        object.__setattr__(payload, "parsed_bundle", bundle)
        _PARSED_CANONICAL[payload] = wire_bytes
        if payload.canonical_bytes != wire_bytes:
            raise ThreatHintV2TransportError()
        return payload

    @property
    def canonical_bytes(self) -> bytes:
        """Return the revalidated exact canonical framing bytes."""
        canonical_at_parse = _PARSED_CANONICAL.get(self)
        if canonical_at_parse is None:
            raise ThreatHintV2TransportError()
        self._validate_state()
        canonical = b"".join(
            [
                TRANSPORT_MAGIC,
                bytes([TRANSPORT_VERSION]),
                self.report_nonce,
                len(self.envelope_wire).to_bytes(LENGTH_FIELD_BYTES, "big"),
                len(self.bundle_wire).to_bytes(LENGTH_FIELD_BYTES, "big"),
                len(self.approval_wire).to_bytes(LENGTH_FIELD_BYTES, "big"),
                self.envelope_wire,
                self.bundle_wire,
                self.approval_wire,
            ]
        )
        if (
            len(canonical) == 0
            or len(canonical) > MAX_TRANSPORT_PAYLOAD_BYTES
            or canonical != canonical_at_parse
        ):
            raise ThreatHintV2TransportError()
        return canonical

    def _validate_state(self) -> None:
        """Revalidate private state before serialization."""
        if type(self) is not ThreatHintV2TransportPayload:
            raise ThreatHintV2TransportError()
        for wire, cap in (
            (self.envelope_wire, MAX_TRANSPORT_ENVELOPE_BYTES),
            (self.bundle_wire, MAX_TRANSPORT_BUNDLE_BYTES),
            (self.approval_wire, MAX_TRANSPORT_APPROVAL_BYTES),
        ):
            if type(wire) is not bytes or not 1 <= len(wire) <= cap:
                raise ThreatHintV2TransportError()
        if type(self.report_nonce) is not bytes:
            raise ThreatHintV2TransportError()
        if len(self.report_nonce) != REPORT_NONCE_BYTES:
            raise ThreatHintV2TransportError()
        if type(self.parsed_envelope) is not ThreatHintV2ProofEnvelope:
            raise ThreatHintV2TransportError()
        if type(self.parsed_bundle) is not ObservableBundle:
            raise ThreatHintV2TransportError()
        if self.parsed_envelope.canonical_bytes != self.envelope_wire:
            raise ThreatHintV2TransportError()
        if self.parsed_bundle.canonical_bytes != self.bundle_wire:
            raise ThreatHintV2TransportError()
        if (
            self.parsed_envelope.parsed_statement.report_nonce
            != self.report_nonce.hex()
        ):
            raise ThreatHintV2TransportError()
        _validate_approval_shape(self.approval_wire)


def _read_be_len(wire_bytes: bytes, offset: int) -> int:
    return int.from_bytes(
        wire_bytes[offset : offset + LENGTH_FIELD_BYTES], byteorder="big", signed=False
    )


def _validate_approval_shape(wire_bytes: bytes) -> None:
    """Apply the canonical approval shape check possible without context.

    Trusted key equality, recipient-scope equality, the current-time validity
    window, bundle commitment binding, and Schnorr signature verification all
    remain downstream in ``verify_observable_approval``.
    """
    if type(wire_bytes) is not bytes or not (
        0 < len(wire_bytes) <= MAX_TRANSPORT_APPROVAL_BYTES
    ):
        raise ThreatHintV2TransportError()

    try:
        decoded = json.loads(
            wire_bytes.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except (UnicodeDecodeError, ValueError):
        raise ThreatHintV2TransportError() from None
    if type(decoded) is not dict or set(decoded.keys()) != {
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
        raise ThreatHintV2TransportError()

    canonical = json.dumps(
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
        },
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    if canonical != wire_bytes:
        raise ThreatHintV2TransportError()

    if (
        type(decoded["schema_version"]) is not int
        or decoded["schema_version"] != APPROVAL_SHAPE_SCHEMA_VERSION
        or type(decoded["purpose"]) is not str
        or decoded["purpose"] != APPROVAL_SHAPE_PURPOSE
    ):
        raise ThreatHintV2TransportError()
    if type(decoded["network_id"]) is not str:
        raise ThreatHintV2TransportError()
    for field in ("not_before", "expires_at"):
        if type(decoded[field]) is not int or decoded[field] > UINT64_MAX:
            raise ThreatHintV2TransportError()

    lifetime = decoded["expires_at"] - decoded["not_before"]
    if (
        decoded["not_before"] <= 0
        or lifetime <= 0
        or lifetime > MAX_APPROVAL_LIFETIME_SECONDS
    ):
        raise ThreatHintV2TransportError()

    try:
        validate_network_id(decoded["network_id"])
    except ValueError:
        raise ThreatHintV2TransportError() from None

    for field, hex_len in (
        ("observable_commitment", 64),
        ("approver_xonly_public_key", 64),
        ("recipient_scope", 64),
        ("approval_nonce", 64),
        ("signature", 128),
    ):
        value = decoded[field]
        if (
            type(value) is not str
            or len(value) != hex_len
            or _LOWER_HEX_RE.fullmatch(value) is None
        ):
            raise ThreatHintV2TransportError()


def _reject_duplicate_keys(items: Iterable[tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ThreatHintV2TransportError()
        result[key] = value
    return result


_LOWER_HEX_RE = re.compile(r"[0-9a-f]*$")
_PARSED_CANONICAL: weakref.WeakKeyDictionary[Any, bytes] = weakref.WeakKeyDictionary()
