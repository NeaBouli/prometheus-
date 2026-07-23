"""Local-only canonical ThreatHint v2 statement parsing and binding."""

# Exact built-in types and a fixed eight-field wire are protocol requirements.
# pylint: disable=too-many-instance-attributes,unidiomatic-typecheck

from __future__ import annotations

import hashlib
import json
import re
import weakref
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Iterable, Mapping

MAX_CANONICAL_V2_STATEMENT_BYTES = 1024
SCHEMA_VERSION = 2
CONFIDENCE_BPS_MAX = 10_000
U64_MAX = (1 << 64) - 1
STATEMENT_DIGEST_DOMAIN = b"prometheus-threat-hint-statement-v2\x00"


class ThreatHintV2StatementError(ValueError):
    """Redacted local parser/validator failure."""

    def __init__(self) -> None:
        super().__init__("invalid threat-hint v2 statement")


class ThreatHintV2DisclosureClass(str, Enum):
    """Structural disclosure metadata that grants no authority."""

    PUBLIC_AUTO_V1 = "public_auto_v1"
    REVIEW_REQUIRED_V1 = "review_required_v1"


@dataclass(frozen=True, init=False, repr=False, eq=False)
class ThreatHintV2Statement:
    """Canonical local v2 statement with no transport or proof authority."""

    schema_version: int
    artifact_hash: str
    observable_commitment: str
    confidence_bps: int
    disclosure_class: ThreatHintV2DisclosureClass
    report_nonce: str
    observed_at: int
    network_id: str

    def __init__(self) -> None:
        """Reject direct construction outside canonical parsing."""
        raise TypeError("direct threat-hint v2 statement construction is disabled")

    @classmethod
    def parse_canonical(
        cls, wire_bytes: bytes, trusted_network_id: str
    ) -> "ThreatHintV2Statement":
        """Parse exact bytes against a separately trusted local network."""
        if cls is not ThreatHintV2Statement or type(wire_bytes) is not bytes:
            raise ThreatHintV2StatementError()
        if len(wire_bytes) == 0 or len(wire_bytes) > MAX_CANONICAL_V2_STATEMENT_BYTES:
            raise ThreatHintV2StatementError()
        _validate_network_id(trusted_network_id)

        try:
            decoded = json.loads(
                wire_bytes.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
            )
        except (UnicodeDecodeError, ValueError):
            raise ThreatHintV2StatementError() from None

        statement = cls._parse_object(decoded)
        if statement.network_id != trusted_network_id:
            raise ThreatHintV2StatementError()
        _PARSED_CANONICAL[statement] = wire_bytes
        if statement.canonical_bytes != wire_bytes:
            raise ThreatHintV2StatementError()
        return statement

    @classmethod
    def _parse_object(cls, value: Mapping[str, Any]) -> "ThreatHintV2Statement":
        """Validate one decoded exact-shape statement object."""
        if type(value) is not dict or list(value.keys()) != [
            "schema_version",
            "artifact_hash",
            "observable_commitment",
            "confidence_bps",
            "disclosure_class",
            "report_nonce",
            "observed_at",
            "network_id",
        ]:
            raise ThreatHintV2StatementError()

        schema_version = _exact_int(value["schema_version"])
        confidence_bps = _exact_int(value["confidence_bps"])
        observed_at = _exact_int(value["observed_at"])
        if (
            schema_version != SCHEMA_VERSION
            or confidence_bps < 1
            or confidence_bps > CONFIDENCE_BPS_MAX
            or observed_at < 1
            or observed_at > U64_MAX
        ):
            raise ThreatHintV2StatementError()

        artifact_hash = _fixed_lower_hex(value["artifact_hash"])
        observable_commitment = _fixed_lower_hex(value["observable_commitment"])
        report_nonce = _fixed_lower_hex(value["report_nonce"])
        try:
            disclosure_class = ThreatHintV2DisclosureClass(value["disclosure_class"])
        except (TypeError, ValueError):
            raise ThreatHintV2StatementError() from None
        network_id = _validate_network_id(value["network_id"])

        statement = object.__new__(cls)
        object.__setattr__(statement, "schema_version", schema_version)
        object.__setattr__(statement, "artifact_hash", artifact_hash)
        object.__setattr__(statement, "observable_commitment", observable_commitment)
        object.__setattr__(statement, "confidence_bps", confidence_bps)
        object.__setattr__(statement, "disclosure_class", disclosure_class)
        object.__setattr__(statement, "report_nonce", report_nonce)
        object.__setattr__(statement, "observed_at", observed_at)
        object.__setattr__(statement, "network_id", network_id)
        return statement

    @property
    def canonical_bytes(self) -> bytes:
        """Return the revalidated exact canonical JSON bytes."""
        canonical_at_parse = _PARSED_CANONICAL.get(self)
        if canonical_at_parse is None:
            raise ThreatHintV2StatementError()
        self._validate_state()
        payload = {
            "schema_version": self.schema_version,
            "artifact_hash": self.artifact_hash,
            "observable_commitment": self.observable_commitment,
            "confidence_bps": self.confidence_bps,
            "disclosure_class": self.disclosure_class.value,
            "report_nonce": self.report_nonce,
            "observed_at": self.observed_at,
            "network_id": self.network_id,
        }
        canonical = json.dumps(
            payload, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        if len(canonical) == 0 or len(canonical) > MAX_CANONICAL_V2_STATEMENT_BYTES:
            raise ThreatHintV2StatementError()
        if canonical != canonical_at_parse:
            raise ThreatHintV2StatementError()
        return canonical

    def statement_digest(self) -> bytes:
        """Return the domain-separated digest binding every canonical field."""
        canonical = self.canonical_bytes
        digest = hashlib.sha256()
        digest.update(STATEMENT_DIGEST_DOMAIN)
        digest.update(len(canonical).to_bytes(4, byteorder="big", signed=False))
        digest.update(canonical)
        return digest.digest()

    def _validate_state(self) -> None:
        """Revalidate private state before serialization or digesting."""
        if type(self) is not ThreatHintV2Statement:
            raise ThreatHintV2StatementError()
        if (
            type(self.schema_version) is not int
            or self.schema_version != SCHEMA_VERSION
        ):
            raise ThreatHintV2StatementError()
        if (
            type(self.confidence_bps) is not int
            or not 1 <= self.confidence_bps <= CONFIDENCE_BPS_MAX
        ):
            raise ThreatHintV2StatementError()
        if not isinstance(self.disclosure_class, ThreatHintV2DisclosureClass):
            raise ThreatHintV2StatementError()
        if type(self.observed_at) is not int or not 1 <= self.observed_at <= U64_MAX:
            raise ThreatHintV2StatementError()
        _fixed_lower_hex(self.artifact_hash)
        _fixed_lower_hex(self.observable_commitment)
        _fixed_lower_hex(self.report_nonce)
        _validate_network_id(self.network_id)


def _reject_duplicate_keys(items: Iterable[tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ThreatHintV2StatementError()
        result[key] = value
    return result


def _exact_int(value: Any) -> int:
    if type(value) is not int or value < 0 or value > U64_MAX:
        raise ThreatHintV2StatementError()
    return value


def _fixed_lower_hex(value: Any) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or _LOWER_HEX_RE.fullmatch(value) is None
    ):
        raise ThreatHintV2StatementError()
    return value


def _validate_network_id(value: Any) -> str:
    if (
        type(value) is not str
        or len(value) < 2
        or len(value) > 64
        or _NETWORK_RE.fullmatch(value) is None
    ):
        raise ThreatHintV2StatementError()
    return value


_LOWER_HEX_RE = re.compile(r"[0-9a-f]{64}")
_NETWORK_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}[a-z0-9]")
_PARSED_CANONICAL: weakref.WeakKeyDictionary[Any, bytes] = weakref.WeakKeyDictionary()
