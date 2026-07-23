"""Canonical Threat Observable Bundle v1 parser and commitment logic."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Tuple

MAX_CANONICAL_BYTES = 4096
MIN_OBSERVABLES = 1
MAX_OBSERVABLES = 16
SCHEMA_VERSION = 1

MIN_NETWORK_LEN = 2
MAX_NETWORK_LEN = 64
NONCE_BYTES = 32
MIN_BYTE_PATTERN_TOKENS = 8
MAX_BYTE_PATTERN_TOKENS = 64
MAX_API_IMPORT_LEN = 96
COMMITMENT_DOMAIN = b"prometheus-threat-observable-bundle-v1\x00"


class ObservableBundleError(ValueError):
    """Local parser/validator error with stable canonical messages."""


class ObservableBundleErrorCode(Enum):
    INVALID_PAYLOAD = "invalid observable bundle payload"
    INVALID_SCHEMA_VERSION = "invalid schema version"
    INVALID_DISCLOSURE_POLICY = "invalid disclosure policy"
    INVALID_OBSERVABLE = "invalid observable"
    INVALID_OBSERVABLES = "invalid observables"
    BUNDLE_TOO_LARGE = "bundle exceeds 4096-byte canonical limit"
    UNSORTED_OBSERVABLES = "observables must be strictly sorted"
    DUPLICATE_OBSERVABLE = "duplicate observable detected"
    NOT_CANONICAL = "non-canonical payload"
    INVALID_COMMITMENT = "invalid commitment"
    INVALID_NETWORK_ID = "invalid network id"
    INVALID_REPORT_NONCE = "invalid report nonce"


class _ObservableBundleException(ObservableBundleError):
    def __init__(self, code: ObservableBundleErrorCode):
        super().__init__(code.value)
        self.code = code


class DisclosurePolicy(str, Enum):
    PUBLIC_AUTO_V1 = "public_auto_v1"
    REVIEW_REQUIRED_V1 = "review_required_v1"


class ScopePlatform(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    ANY = "any"


class ScopeFormat(str, Enum):
    PE = "pe"
    ELF = "elf"
    MACHO = "macho"
    SCRIPT = "script"
    DOCUMENT = "document"
    UNKNOWN = "unknown"


class ObservableKind(str, Enum):
    FILE_SHA256 = "file_sha256"
    API_IMPORT = "api_import"
    BYTE_PATTERN = "byte_pattern"


@dataclass(frozen=True, init=False)
class ObservableScope:
    platform: ScopePlatform
    format: ScopeFormat

    def __init__(self) -> None:
        raise TypeError("direct observable scope construction is disabled")


@dataclass(frozen=True, init=False, repr=False)
class Observable:
    kind: ObservableKind
    value: str

    def __init__(self) -> None:
        raise TypeError("direct observable construction is disabled")


@dataclass(frozen=True, init=False, repr=False)
class ObservableBundle:
    schema_version: int
    disclosure_policy: DisclosurePolicy
    scope: ObservableScope
    observables: Tuple[Observable, ...]

    def __init__(self) -> None:
        raise TypeError("direct observable bundle construction is disabled")

    @classmethod
    def parse_canonical(cls, wire_bytes: bytes) -> "ObservableBundle":
        if not isinstance(wire_bytes, bytes):
            raise _ObservableBundleException(ObservableBundleErrorCode.INVALID_PAYLOAD)

        if len(wire_bytes) == 0:
            raise _ObservableBundleException(ObservableBundleErrorCode.INVALID_PAYLOAD)

        if len(wire_bytes) > MAX_CANONICAL_BYTES:
            raise _ObservableBundleException(ObservableBundleErrorCode.BUNDLE_TOO_LARGE)

        try:
            wire_text = wire_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise _ObservableBundleException(
                ObservableBundleErrorCode.INVALID_PAYLOAD
            ) from None

        try:
            decoded = json.loads(wire_text, object_pairs_hook=_reject_duplicate_keys)
        except ValueError:
            raise _ObservableBundleException(
                ObservableBundleErrorCode.INVALID_PAYLOAD
            ) from None

        bundle = cls._parse_object(decoded)
        canonical = bundle._to_canonical_bytes_for_validation()
        if canonical != wire_bytes:
            raise _ObservableBundleException(ObservableBundleErrorCode.NOT_CANONICAL)

        return bundle

    @classmethod
    def _parse_object(cls, value: Mapping[str, Any]) -> "ObservableBundle":
        if not isinstance(value, dict):
            raise _ObservableBundleException(ObservableBundleErrorCode.INVALID_PAYLOAD)

        if set(value.keys()) != {
            "schema_version",
            "disclosure_policy",
            "scope",
            "observables",
        }:
            raise _ObservableBundleException(ObservableBundleErrorCode.INVALID_PAYLOAD)

        schema_version = value["schema_version"]
        if not isinstance(schema_version, int) or isinstance(schema_version, bool):
            raise _ObservableBundleException(ObservableBundleErrorCode.INVALID_PAYLOAD)
        if schema_version != SCHEMA_VERSION:
            raise _ObservableBundleException(
                ObservableBundleErrorCode.INVALID_SCHEMA_VERSION
            )

        disclosure_policy = _parse_disclosure_policy(value["disclosure_policy"])
        scope = _parse_scope(value["scope"])
        observables = _parse_observables(disclosure_policy, value["observables"])

        bundle = object.__new__(cls)
        object.__setattr__(bundle, "schema_version", schema_version)
        object.__setattr__(bundle, "disclosure_policy", disclosure_policy)
        object.__setattr__(bundle, "scope", scope)
        object.__setattr__(bundle, "observables", observables)
        return bundle

    @property
    def canonical_bytes(self) -> bytes:
        return self._to_canonical_bytes_for_validation()

    def _to_canonical_bytes_for_validation(self) -> bytes:
        self._validate_state()
        payload = {
            "schema_version": self.schema_version,
            "disclosure_policy": self.disclosure_policy.value,
            "scope": {
                "platform": self.scope.platform.value,
                "format": self.scope.format.value,
            },
            "observables": [
                {"kind": observable.kind.value, "value": observable.value}
                for observable in self.observables
            ],
        }
        bytes_wire = json.dumps(
            payload, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        if len(bytes_wire) < 1 or len(bytes_wire) > MAX_CANONICAL_BYTES:
            raise _ObservableBundleException(ObservableBundleErrorCode.BUNDLE_TOO_LARGE)
        return bytes_wire

    def _validate_state(self) -> None:
        schema_version = getattr(self, "schema_version", None)
        disclosure_policy = getattr(self, "disclosure_policy", None)
        scope = getattr(self, "scope", None)
        observables = getattr(self, "observables", None)

        if not isinstance(schema_version, int) or isinstance(schema_version, bool):
            raise _ObservableBundleException(ObservableBundleErrorCode.INVALID_PAYLOAD)
        if schema_version != SCHEMA_VERSION:
            raise _ObservableBundleException(
                ObservableBundleErrorCode.INVALID_SCHEMA_VERSION
            )
        if not isinstance(disclosure_policy, DisclosurePolicy):
            raise _ObservableBundleException(
                ObservableBundleErrorCode.INVALID_DISCLOSURE_POLICY
            )
        if not isinstance(scope, ObservableScope):
            raise _ObservableBundleException(ObservableBundleErrorCode.INVALID_PAYLOAD)
        scope_platform = getattr(scope, "platform", None)
        scope_format = getattr(scope, "format", None)
        if not isinstance(scope_platform, ScopePlatform) or not isinstance(
            scope_format, ScopeFormat
        ):
            raise _ObservableBundleException(ObservableBundleErrorCode.INVALID_PAYLOAD)
        if not isinstance(observables, tuple):
            raise _ObservableBundleException(
                ObservableBundleErrorCode.INVALID_OBSERVABLES
            )
        if len(observables) < MIN_OBSERVABLES or len(observables) > MAX_OBSERVABLES:
            raise _ObservableBundleException(
                ObservableBundleErrorCode.INVALID_OBSERVABLES
            )

        _validate_observable_state(disclosure_policy, observables)

    def commitment(self, network_id: str, report_nonce_hex: str) -> bytes:
        if not isinstance(network_id, str):
            raise _ObservableBundleException(
                ObservableBundleErrorCode.INVALID_NETWORK_ID
            )
        if not isinstance(report_nonce_hex, str):
            raise _ObservableBundleException(
                ObservableBundleErrorCode.INVALID_REPORT_NONCE
            )

        validate_network_id(network_id)
        report_nonce = _decode_hex(report_nonce_hex)
        if len(report_nonce) != NONCE_BYTES:
            raise _ObservableBundleException(
                ObservableBundleErrorCode.INVALID_REPORT_NONCE
            )

        canonical = self._to_canonical_bytes_for_validation()
        digest = hashlib.sha256()
        digest.update(COMMITMENT_DOMAIN)
        digest.update(bytes([len(network_id)]))
        digest.update(network_id.encode("ascii"))
        digest.update(report_nonce)
        digest.update(len(canonical).to_bytes(4, byteorder="big", signed=False))
        digest.update(canonical)
        return digest.digest()

    @staticmethod
    def commitment_matches(
        expected: bytes,
        network_id: str,
        report_nonce_hex: str,
        wire_bytes: bytes,
    ) -> bool:
        if not isinstance(expected, bytes):
            raise _ObservableBundleException(
                ObservableBundleErrorCode.INVALID_COMMITMENT
            )
        if len(expected) != 32:
            raise _ObservableBundleException(
                ObservableBundleErrorCode.INVALID_COMMITMENT
            )

        bundle = ObservableBundle.parse_canonical(wire_bytes)
        observed = bundle.commitment(network_id, report_nonce_hex)
        return hmac.compare_digest(expected, observed)


def _reject_duplicate_keys(items: Iterable[tuple[str, Any]]) -> Dict[str, Any]:
    obj: Dict[str, Any] = {}
    for key, value in items:
        if key in obj:
            raise _ObservableBundleException(ObservableBundleErrorCode.INVALID_PAYLOAD)
        obj[key] = value
    return obj


def _parse_disclosure_policy(value: Any) -> DisclosurePolicy:
    if not isinstance(value, str):
        raise _ObservableBundleException(
            ObservableBundleErrorCode.INVALID_DISCLOSURE_POLICY
        )
    if value in {item.value for item in DisclosurePolicy}:
        return DisclosurePolicy(value)
    raise _ObservableBundleException(
        ObservableBundleErrorCode.INVALID_DISCLOSURE_POLICY
    )


def _parse_scope(value: Any) -> ObservableScope:
    if not isinstance(value, dict):
        raise _ObservableBundleException(ObservableBundleErrorCode.INVALID_PAYLOAD)
    if set(value.keys()) != {"platform", "format"}:
        raise _ObservableBundleException(ObservableBundleErrorCode.INVALID_PAYLOAD)

    platform_raw = value["platform"]
    format_raw = value["format"]
    if not isinstance(platform_raw, str) or not isinstance(format_raw, str):
        raise _ObservableBundleException(ObservableBundleErrorCode.INVALID_PAYLOAD)

    try:
        platform = ScopePlatform(platform_raw)
        artifact_format = ScopeFormat(format_raw)
    except ValueError:
        raise _ObservableBundleException(
            ObservableBundleErrorCode.INVALID_PAYLOAD
        ) from None

    return _new_scope(platform, artifact_format)


def _parse_observables(
    disclosure_policy: DisclosurePolicy,
    value: Any,
) -> Tuple[Observable, ...]:
    if not isinstance(value, list):
        raise _ObservableBundleException(ObservableBundleErrorCode.INVALID_PAYLOAD)

    if len(value) < MIN_OBSERVABLES or len(value) > MAX_OBSERVABLES:
        raise _ObservableBundleException(ObservableBundleErrorCode.INVALID_OBSERVABLES)

    parsed: List[Observable] = []
    previous: tuple[bytes, bytes] | None = None
    seen: set[tuple[bytes, bytes]] = set()

    for raw in value:
        if not isinstance(raw, dict):
            raise _ObservableBundleException(
                ObservableBundleErrorCode.INVALID_OBSERVABLE
            )
        if set(raw.keys()) != {"kind", "value"}:
            raise _ObservableBundleException(
                ObservableBundleErrorCode.INVALID_OBSERVABLE
            )

        kind_raw = raw["kind"]
        value_raw = raw["value"]
        if not isinstance(kind_raw, str) or not isinstance(value_raw, str):
            raise _ObservableBundleException(
                ObservableBundleErrorCode.INVALID_OBSERVABLE
            )

        try:
            kind = ObservableKind(kind_raw)
        except ValueError:
            raise _ObservableBundleException(
                ObservableBundleErrorCode.INVALID_OBSERVABLE
            ) from None

        if (
            disclosure_policy == DisclosurePolicy.PUBLIC_AUTO_V1
            and kind == ObservableKind.BYTE_PATTERN
        ):
            raise _ObservableBundleException(
                ObservableBundleErrorCode.INVALID_DISCLOSURE_POLICY
            )

        _validate_observable(kind, value_raw)

        current = (kind.value.encode("utf-8"), value_raw.encode("utf-8"))
        if current in seen:
            raise _ObservableBundleException(
                ObservableBundleErrorCode.DUPLICATE_OBSERVABLE
            )
        if previous is not None:
            if current < previous:
                raise _ObservableBundleException(
                    ObservableBundleErrorCode.UNSORTED_OBSERVABLES
                )

        parsed.append(_new_observable(kind, value_raw))
        seen.add(current)
        previous = current

    return tuple(parsed)


def _validate_observable_state(
    disclosure_policy: DisclosurePolicy, observables: Tuple[Observable, ...]
) -> None:
    previous: tuple[bytes, bytes] | None = None
    seen: set[tuple[bytes, bytes]] = set()
    for observable in observables:
        if not isinstance(observable, Observable):
            raise _ObservableBundleException(
                ObservableBundleErrorCode.INVALID_OBSERVABLE
            )
        observable_kind = getattr(observable, "kind", None)
        observable_value = getattr(observable, "value", None)
        if not isinstance(observable_kind, ObservableKind) or not isinstance(
            observable_value, str
        ):
            raise _ObservableBundleException(
                ObservableBundleErrorCode.INVALID_OBSERVABLE
            )

        _validate_observable(observable_kind, observable_value)
        if (
            disclosure_policy == DisclosurePolicy.PUBLIC_AUTO_V1
            and observable_kind == ObservableKind.BYTE_PATTERN
        ):
            raise _ObservableBundleException(
                ObservableBundleErrorCode.INVALID_DISCLOSURE_POLICY
            )

        current = (
            observable_kind.value.encode("utf-8"),
            observable_value.encode("utf-8"),
        )
        if current in seen:
            raise _ObservableBundleException(
                ObservableBundleErrorCode.DUPLICATE_OBSERVABLE
            )
        if previous is not None and current < previous:
            raise _ObservableBundleException(
                ObservableBundleErrorCode.UNSORTED_OBSERVABLES
            )
        seen.add(current)
        previous = current


def _new_scope(
    platform: ScopePlatform, artifact_format: ScopeFormat
) -> ObservableScope:
    scope = object.__new__(ObservableScope)
    object.__setattr__(scope, "platform", platform)
    object.__setattr__(scope, "format", artifact_format)
    return scope


def _new_observable(kind: ObservableKind, value: str) -> Observable:
    observable = object.__new__(Observable)
    object.__setattr__(observable, "kind", kind)
    object.__setattr__(observable, "value", value)
    return observable


def _validate_observable(kind: ObservableKind, value: str) -> None:
    if kind == ObservableKind.FILE_SHA256:
        _validate_file_sha256(value)
    elif kind == ObservableKind.API_IMPORT:
        _validate_api_import(value)
    else:
        _validate_byte_pattern(value)


def _validate_file_sha256(value: str) -> None:
    if len(value) != 64:
        raise _ObservableBundleException(ObservableBundleErrorCode.INVALID_OBSERVABLE)
    if not _FILE_SHA256_RE.fullmatch(value):
        raise _ObservableBundleException(ObservableBundleErrorCode.INVALID_OBSERVABLE)


def _validate_api_import(value: str) -> None:
    if len(value) > MAX_API_IMPORT_LEN:
        raise _ObservableBundleException(ObservableBundleErrorCode.INVALID_OBSERVABLE)
    if not _API_IMPORT_RE.fullmatch(value):
        raise _ObservableBundleException(ObservableBundleErrorCode.INVALID_OBSERVABLE)


def _validate_byte_pattern(value: str) -> None:
    if not value.isascii():
        raise _ObservableBundleException(ObservableBundleErrorCode.INVALID_OBSERVABLE)
    if value == "" or value.startswith(" ") or value.endswith(" "):
        raise _ObservableBundleException(ObservableBundleErrorCode.INVALID_OBSERVABLE)

    tokens = value.split(" ")
    if len(tokens) < MIN_BYTE_PATTERN_TOKENS or len(tokens) > MAX_BYTE_PATTERN_TOKENS:
        raise _ObservableBundleException(ObservableBundleErrorCode.INVALID_OBSERVABLE)

    fixed = 0
    for token in tokens:
        if token == "":
            raise _ObservableBundleException(
                ObservableBundleErrorCode.INVALID_OBSERVABLE
            )
        if token == "??":
            continue
        if not _BYTE_TOKEN_RE.fullmatch(token):
            raise _ObservableBundleException(
                ObservableBundleErrorCode.INVALID_OBSERVABLE
            )
        fixed += 1

    if fixed < MIN_BYTE_PATTERN_TOKENS:
        raise _ObservableBundleException(ObservableBundleErrorCode.INVALID_OBSERVABLE)


def validate_network_id(network_id: str) -> None:
    if len(network_id) < MIN_NETWORK_LEN or len(network_id) > MAX_NETWORK_LEN:
        raise _ObservableBundleException(ObservableBundleErrorCode.INVALID_NETWORK_ID)

    if network_id[0] == "-" or network_id[-1] == "-":
        raise _ObservableBundleException(ObservableBundleErrorCode.INVALID_NETWORK_ID)

    for byte in network_id.encode("utf-8"):
        if byte == 45:
            continue
        if 48 <= byte <= 57:
            continue
        if 97 <= byte <= 122:
            continue
        raise _ObservableBundleException(ObservableBundleErrorCode.INVALID_NETWORK_ID)


def _decode_hex(value: str) -> bytes:
    if len(value) != NONCE_BYTES * 2:
        raise _ObservableBundleException(ObservableBundleErrorCode.INVALID_REPORT_NONCE)
    if not _HEX_LOWER_RE.fullmatch(value):
        raise _ObservableBundleException(ObservableBundleErrorCode.INVALID_REPORT_NONCE)

    return bytes.fromhex(value)


_BYTE_TOKEN_RE = re.compile(r"[0-9a-f]{2}$")
_API_IMPORT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.@-]{0,95}$")
_FILE_SHA256_RE = re.compile(r"[0-9a-f]{64}$")
_HEX_LOWER_RE = re.compile(r"[0-9a-f]*$")
