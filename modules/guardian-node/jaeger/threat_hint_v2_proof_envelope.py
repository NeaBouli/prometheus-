"""Local-only canonical ThreatHint v2 proof envelope parsing and binding."""

# Exact built-in types and a fixed six-field wire are protocol requirements.
# pylint: disable=too-many-instance-attributes,unidiomatic-typecheck

from __future__ import annotations

import json
import re
import weakref
from dataclasses import dataclass
from typing import Any, Dict, Iterable

from jaeger.threat_hint_v2_statement import (
    ThreatHintV2Statement,
    ThreatHintV2StatementError,
)

MAX_CANONICAL_V2_PROOF_ENVELOPE_BYTES = 4096
SCHEMA_VERSION = 2
PROTOCOL_ID = "/prometheus/threat-hint/2.0.0"
RELATION_ID = "prometheus-threat-hint-v2"
MIN_PROOF_BYTES = 1
MAX_PROOF_BYTES = 1024


class ThreatHintV2ProofEnvelopeError(ValueError):
    """Redacted local parser/validator failure."""

    def __init__(self) -> None:
        super().__init__("invalid threat-hint v2 proof envelope")


@dataclass(frozen=True, init=False, repr=False, eq=False)
class ThreatHintV2ProofEnvelope:
    """Canonical local v2 proof envelope with no proof or transport authority.

    Structural validity is not proof acceptance: the proof bytes are opaque,
    no proof system is named here, and this type grants no authority against
    arbitrary in-process code. A later RelationManifest v2 binds the relation
    to a separately approved proof system and keys.
    """

    schema_version: int
    protocol_id: str
    relation_id: str
    statement: str
    statement_digest: str
    proof: str
    parsed_statement: ThreatHintV2Statement

    def __init__(self) -> None:
        """Reject direct construction outside canonical parsing."""
        raise TypeError("direct threat-hint v2 proof envelope construction is disabled")

    @classmethod
    def parse_canonical(
        cls, wire_bytes: bytes, trusted_network_id: str
    ) -> "ThreatHintV2ProofEnvelope":
        """Parse exact bytes against a separately trusted local network."""
        if cls is not ThreatHintV2ProofEnvelope or type(wire_bytes) is not bytes:
            raise ThreatHintV2ProofEnvelopeError()
        if (
            len(wire_bytes) == 0
            or len(wire_bytes) > MAX_CANONICAL_V2_PROOF_ENVELOPE_BYTES
        ):
            raise ThreatHintV2ProofEnvelopeError()
        if type(trusted_network_id) is not str:
            raise ThreatHintV2ProofEnvelopeError()

        try:
            decoded = json.loads(
                wire_bytes.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
            )
        except (UnicodeDecodeError, ValueError):
            raise ThreatHintV2ProofEnvelopeError() from None

        envelope = cls._parse_object(decoded, trusted_network_id)
        _PARSED_CANONICAL[envelope] = wire_bytes
        if envelope.canonical_bytes != wire_bytes:
            raise ThreatHintV2ProofEnvelopeError()
        return envelope

    @classmethod
    def _parse_object(
        cls, value: Any, trusted_network_id: str
    ) -> "ThreatHintV2ProofEnvelope":
        """Validate one decoded exact-shape envelope object."""
        if type(value) is not dict or list(value.keys()) != [
            "schema_version",
            "protocol_id",
            "relation_id",
            "statement",
            "statement_digest",
            "proof",
        ]:
            raise ThreatHintV2ProofEnvelopeError()

        schema_version = _exact_schema_version(value["schema_version"])
        protocol_id = _exact_identifier(value["protocol_id"], PROTOCOL_ID)
        relation_id = _exact_identifier(value["relation_id"], RELATION_ID)
        statement_digest = _fixed_lower_hex(value["statement_digest"])
        proof = _proof_hex(value["proof"])

        statement = value["statement"]
        if type(statement) is not str:
            raise ThreatHintV2ProofEnvelopeError()
        try:
            parsed_statement = ThreatHintV2Statement.parse_canonical(
                statement.encode("utf-8"), trusted_network_id
            )
        except ThreatHintV2StatementError:
            raise ThreatHintV2ProofEnvelopeError() from None
        if parsed_statement.statement_digest().hex() != statement_digest:
            raise ThreatHintV2ProofEnvelopeError()

        envelope = object.__new__(cls)
        object.__setattr__(envelope, "schema_version", schema_version)
        object.__setattr__(envelope, "protocol_id", protocol_id)
        object.__setattr__(envelope, "relation_id", relation_id)
        object.__setattr__(envelope, "statement", statement)
        object.__setattr__(envelope, "statement_digest", statement_digest)
        object.__setattr__(envelope, "proof", proof)
        object.__setattr__(envelope, "parsed_statement", parsed_statement)
        return envelope

    @property
    def canonical_bytes(self) -> bytes:
        """Return the revalidated exact canonical JSON bytes."""
        canonical_at_parse = _PARSED_CANONICAL.get(self)
        if canonical_at_parse is None:
            raise ThreatHintV2ProofEnvelopeError()
        self._validate_state()
        payload = {
            "schema_version": self.schema_version,
            "protocol_id": self.protocol_id,
            "relation_id": self.relation_id,
            "statement": self.statement,
            "statement_digest": self.statement_digest,
            "proof": self.proof,
        }
        canonical = json.dumps(
            payload, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        if (
            len(canonical) == 0
            or len(canonical) > MAX_CANONICAL_V2_PROOF_ENVELOPE_BYTES
        ):
            raise ThreatHintV2ProofEnvelopeError()
        if canonical != canonical_at_parse:
            raise ThreatHintV2ProofEnvelopeError()
        return canonical

    def proof_bytes(self) -> bytes:
        """Return the opaque proof bytes without interpreting them."""
        if _PARSED_CANONICAL.get(self) is None:
            raise ThreatHintV2ProofEnvelopeError()
        self._validate_state()
        return bytes.fromhex(self.proof)

    def _validate_state(self) -> None:
        """Revalidate private state before serialization or decoding."""
        if type(self) is not ThreatHintV2ProofEnvelope:
            raise ThreatHintV2ProofEnvelopeError()
        _exact_schema_version(self.schema_version)
        _exact_identifier(self.protocol_id, PROTOCOL_ID)
        _exact_identifier(self.relation_id, RELATION_ID)
        _fixed_lower_hex(self.statement_digest)
        _proof_hex(self.proof)
        if type(self.statement) is not str:
            raise ThreatHintV2ProofEnvelopeError()
        if type(self.parsed_statement) is not ThreatHintV2Statement:
            raise ThreatHintV2ProofEnvelopeError()
        if self.parsed_statement.canonical_bytes != self.statement.encode("utf-8"):
            raise ThreatHintV2ProofEnvelopeError()
        if self.parsed_statement.statement_digest().hex() != self.statement_digest:
            raise ThreatHintV2ProofEnvelopeError()


def _reject_duplicate_keys(items: Iterable[tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ThreatHintV2ProofEnvelopeError()
        result[key] = value
    return result


def _exact_schema_version(value: Any) -> int:
    if type(value) is not int or value != SCHEMA_VERSION:
        raise ThreatHintV2ProofEnvelopeError()
    return value


def _exact_identifier(value: Any, expected: str) -> str:
    if type(value) is not str or value != expected:
        raise ThreatHintV2ProofEnvelopeError()
    return value


def _fixed_lower_hex(value: Any) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or _LOWER_HEX_RE.fullmatch(value) is None
    ):
        raise ThreatHintV2ProofEnvelopeError()
    return value


def _proof_hex(value: Any) -> str:
    if (
        type(value) is not str
        or len(value) % 2 != 0
        or _PROOF_HEX_RE.fullmatch(value) is None
    ):
        raise ThreatHintV2ProofEnvelopeError()
    if not MIN_PROOF_BYTES <= len(value) // 2 <= MAX_PROOF_BYTES:
        raise ThreatHintV2ProofEnvelopeError()
    return value


_LOWER_HEX_RE = re.compile(r"[0-9a-f]{64}")
_PROOF_HEX_RE = re.compile(r"[0-9a-f]*")
_PARSED_CANONICAL: weakref.WeakKeyDictionary[Any, bytes] = weakref.WeakKeyDictionary()
