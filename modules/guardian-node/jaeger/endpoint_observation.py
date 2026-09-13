"""Canonical, local-only parsing for EndpointObservationStatementV1."""

# Exact built-in types and a fixed eight-field wire are protocol requirements.
# pylint: disable=too-many-boolean-expressions,too-many-instance-attributes,unidiomatic-typecheck

from __future__ import annotations

import hashlib
import json
import re
import weakref
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Iterable, Mapping

MAX_CANONICAL_ENDPOINT_OBSERVATION_BYTES = 512
SCHEMA_VERSION = 1
U64_MAX = (1 << 64) - 1
STATEMENT_DIGEST_DOMAIN = b"prometheus-endpoint-observation-v1\x00"
ALLOWED_WINDOW_SECONDS = frozenset((60, 300, 900, 3600))


class EndpointObservationError(ValueError):
    """Redacted local parser and validator failure."""

    def __init__(self) -> None:
        super().__init__("invalid endpoint observation statement")


class EndpointObservationDomain(str, Enum):
    """Closed structural observation domains with no detection authority."""

    PROCESS = "process"
    FILE = "file"
    NETWORK = "network"
    PERSISTENCE = "persistence"
    CREDENTIAL_ACCESS = "credential_access"
    MODEL_TOOL = "model_tool"
    RESOURCE_UTILIZATION = "resource_utilization"


class EndpointObservationSignal(str, Enum):
    """Closed structural observation signals with no truth authority."""

    UNEXPECTED_CHILD_PROCESS = "unexpected_child_process"
    RAPID_PROCESS_SPAWN = "rapid_process_spawn"
    PROTECTED_FILE_CHANGE = "protected_file_change"
    EXECUTABLE_FILE_CHANGE = "executable_file_change"
    UNEXPECTED_EGRESS = "unexpected_egress"
    CONNECTION_FANOUT = "connection_fanout"
    STARTUP_ENTRY_CHANGE = "startup_entry_change"
    SCHEDULED_TASK_CHANGE = "scheduled_task_change"
    CREDENTIAL_STORE_ACCESS = "credential_store_access"
    BULK_SECRET_READ_ATTEMPT = "bulk_secret_read_attempt"
    PROMPT_INJECTION_INDICATOR = "prompt_injection_indicator"
    TOOL_POLICY_VIOLATION = "tool_policy_violation"
    MODEL_RUNTIME_CHANGE = "model_runtime_change"
    SUSTAINED_COMPUTE_SATURATION = "sustained_compute_saturation"
    ACCELERATOR_UTILIZATION_SPIKE = "accelerator_utilization_spike"

    @property
    def domain(self) -> EndpointObservationDomain:
        """Return the only valid domain for this structural signal."""
        return _SIGNAL_DOMAINS[self]


_SIGNAL_DOMAINS = {
    EndpointObservationSignal.UNEXPECTED_CHILD_PROCESS: EndpointObservationDomain.PROCESS,
    EndpointObservationSignal.RAPID_PROCESS_SPAWN: EndpointObservationDomain.PROCESS,
    EndpointObservationSignal.PROTECTED_FILE_CHANGE: EndpointObservationDomain.FILE,
    EndpointObservationSignal.EXECUTABLE_FILE_CHANGE: EndpointObservationDomain.FILE,
    EndpointObservationSignal.UNEXPECTED_EGRESS: EndpointObservationDomain.NETWORK,
    EndpointObservationSignal.CONNECTION_FANOUT: EndpointObservationDomain.NETWORK,
    EndpointObservationSignal.STARTUP_ENTRY_CHANGE: EndpointObservationDomain.PERSISTENCE,
    EndpointObservationSignal.SCHEDULED_TASK_CHANGE: EndpointObservationDomain.PERSISTENCE,
    EndpointObservationSignal.CREDENTIAL_STORE_ACCESS: EndpointObservationDomain.CREDENTIAL_ACCESS,
    EndpointObservationSignal.BULK_SECRET_READ_ATTEMPT: EndpointObservationDomain.CREDENTIAL_ACCESS,
    EndpointObservationSignal.PROMPT_INJECTION_INDICATOR: EndpointObservationDomain.MODEL_TOOL,
    EndpointObservationSignal.TOOL_POLICY_VIOLATION: EndpointObservationDomain.MODEL_TOOL,
    EndpointObservationSignal.MODEL_RUNTIME_CHANGE: EndpointObservationDomain.MODEL_TOOL,
    EndpointObservationSignal.SUSTAINED_COMPUTE_SATURATION: (
        EndpointObservationDomain.RESOURCE_UTILIZATION
    ),
    EndpointObservationSignal.ACCELERATOR_UTILIZATION_SPIKE: (
        EndpointObservationDomain.RESOURCE_UTILIZATION
    ),
}


@dataclass(frozen=True, init=False, repr=False, eq=False)
class EndpointObservationStatementV1:
    """Validated structural bytes with no collection or response authority."""

    schema_version: int
    domain: EndpointObservationDomain
    signal: EndpointObservationSignal
    event_count: int
    window_seconds: int
    report_nonce: str
    observed_at: int
    network_id: str

    def __init__(self) -> None:
        """Reject direct construction outside canonical parsing."""
        raise TypeError("direct endpoint observation construction is disabled")

    @classmethod
    def parse_canonical(
        cls, wire_bytes: bytes, trusted_network_id: str
    ) -> "EndpointObservationStatementV1":
        """Parse exact bytes against a separately trusted local network."""
        if cls is not EndpointObservationStatementV1 or type(wire_bytes) is not bytes:
            raise EndpointObservationError()
        if (
            len(wire_bytes) == 0
            or len(wire_bytes) > MAX_CANONICAL_ENDPOINT_OBSERVATION_BYTES
        ):
            raise EndpointObservationError()
        _validate_network_id(trusted_network_id)

        try:
            decoded = json.loads(
                wire_bytes.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
            )
        except (UnicodeDecodeError, ValueError):
            raise EndpointObservationError() from None

        statement = cls._parse_object(decoded)
        if statement.network_id != trusted_network_id:
            raise EndpointObservationError()
        _PARSED_CANONICAL[statement] = wire_bytes
        if statement.canonical_bytes != wire_bytes:
            raise EndpointObservationError()
        return statement

    @classmethod
    def _parse_object(
        cls, value: Mapping[str, Any]
    ) -> "EndpointObservationStatementV1":
        """Validate one decoded exact-shape statement object."""
        if type(value) is not dict or list(value.keys()) != [
            "schema_version",
            "domain",
            "signal",
            "event_count",
            "window_seconds",
            "report_nonce",
            "observed_at",
            "network_id",
        ]:
            raise EndpointObservationError()

        schema_version = _exact_int(value["schema_version"])
        event_count = _exact_int(value["event_count"])
        window_seconds = _exact_int(value["window_seconds"])
        observed_at = _exact_int(value["observed_at"])
        if (
            schema_version != SCHEMA_VERSION
            or not 1 <= event_count <= 255
            or window_seconds not in ALLOWED_WINDOW_SECONDS
            or observed_at == 0
            or observed_at % 60 != 0
        ):
            raise EndpointObservationError()

        try:
            domain = EndpointObservationDomain(value["domain"])
            signal = EndpointObservationSignal(value["signal"])
        except (TypeError, ValueError):
            raise EndpointObservationError() from None
        if signal.domain is not domain:
            raise EndpointObservationError()

        statement = object.__new__(cls)
        object.__setattr__(statement, "schema_version", schema_version)
        object.__setattr__(statement, "domain", domain)
        object.__setattr__(statement, "signal", signal)
        object.__setattr__(statement, "event_count", event_count)
        object.__setattr__(statement, "window_seconds", window_seconds)
        object.__setattr__(
            statement, "report_nonce", _fixed_lower_hex(value["report_nonce"])
        )
        object.__setattr__(statement, "observed_at", observed_at)
        object.__setattr__(
            statement, "network_id", _validate_network_id(value["network_id"])
        )
        return statement

    @property
    def canonical_bytes(self) -> bytes:
        """Return the revalidated exact canonical JSON bytes."""
        canonical_at_parse = _PARSED_CANONICAL.get(self)
        if canonical_at_parse is None:
            raise EndpointObservationError()
        self._validate_state()
        payload = {
            "schema_version": self.schema_version,
            "domain": self.domain.value,
            "signal": self.signal.value,
            "event_count": self.event_count,
            "window_seconds": self.window_seconds,
            "report_nonce": self.report_nonce,
            "observed_at": self.observed_at,
            "network_id": self.network_id,
        }
        canonical = json.dumps(
            payload, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        if (
            len(canonical) == 0
            or len(canonical) > MAX_CANONICAL_ENDPOINT_OBSERVATION_BYTES
            or canonical != canonical_at_parse
        ):
            raise EndpointObservationError()
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
        if (
            type(self) is not EndpointObservationStatementV1
            or type(self.schema_version) is not int
            or self.schema_version != SCHEMA_VERSION
            or type(self.domain) is not EndpointObservationDomain
            or type(self.signal) is not EndpointObservationSignal
            or self.signal.domain is not self.domain
            or type(self.event_count) is not int
            or not 1 <= self.event_count <= 255
            or type(self.window_seconds) is not int
            or self.window_seconds not in ALLOWED_WINDOW_SECONDS
            or type(self.observed_at) is not int
            or not 1 <= self.observed_at <= U64_MAX
            or self.observed_at % 60 != 0
        ):
            raise EndpointObservationError()
        _fixed_lower_hex(self.report_nonce)
        _validate_network_id(self.network_id)


def _reject_duplicate_keys(items: Iterable[tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise EndpointObservationError()
        result[key] = value
    return result


def _exact_int(value: Any) -> int:
    if type(value) is not int or value < 0 or value > U64_MAX:
        raise EndpointObservationError()
    return value


def _fixed_lower_hex(value: Any) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or _LOWER_HEX_RE.fullmatch(value) is None
    ):
        raise EndpointObservationError()
    return value


def _validate_network_id(value: Any) -> str:
    if (
        type(value) is not str
        or len(value) < 2
        or len(value) > 64
        or _NETWORK_RE.fullmatch(value) is None
    ):
        raise EndpointObservationError()
    return value


_LOWER_HEX_RE = re.compile(r"[0-9a-f]{64}")
_NETWORK_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}[a-z0-9]")
_PARSED_CANONICAL: weakref.WeakKeyDictionary[Any, bytes] = weakref.WeakKeyDictionary()
