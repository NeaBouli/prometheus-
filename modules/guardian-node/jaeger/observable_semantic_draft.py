"""Deterministic semantic-draft derivation for observable bundles (GH-173).

This module is one pure, deterministic, repository-local boundary. It maps
one exact :class:`jaeger.threat_observable.ObservableBundle` to one
immutable, non-constructible, digest-only semantic draft result.

The derivation emits exactly one bounded ASCII YARA candidate source with a
fixed bounded rule name, in memory only:

* ``api_import`` observables become YARA text strings (their values are
  already a bounded ASCII grammar and are re-checked before encoding);
* ``byte_pattern`` observables become YARA hex strings (their values are
  already canonical YARA-compatible hex tokens and are re-checked);
* ``file_sha256`` observables are counted only. They are never emitted into
  the candidate source and the YARA ``hash`` module is never used or
  imported.

When a bundle carries no ``api_import`` or ``byte_pattern`` observables the
candidate has no strings section and an always-false condition, so it
remains syntactically valid and can never match. A literal ``false``
condition cannot be used here: the pinned YARA-X compiler emits an
``invariant_expr`` warning for it and the GH-170 boundary fails closed on
any warning. The emitted contradictory ``filesize`` comparison is
semantically always false yet compiles with zero errors and zero warnings.
Otherwise the condition is ``any of them``: any single generated pattern
satisfies it, never all of them.

The candidate source is validated only through the GH-170 compile-only
boundary :func:`jaeger.yara_validation.validate_candidate_rule_source`. No
scan API is ever used. The source is asserted under
``MAX_YARA_SOURCE_BYTES`` before that invocation, is hashed exactly once,
and is never exposed on or persisted through the result object.

The result carries only the exact per-kind observable counts, the SHA-256
of the exact candidate source bytes, and the exact compile verdict. Any
invalid input, invariant failure, oversized source, non-boolean verdict, or
validation exception fails closed with one stable redacted
:class:`ObservableSemanticDraftError`. There are no timestamps, randomness,
filesystem, network, model, logging, or other external effects; observable
ordering is inherited unchanged from the canonical bundle.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Final, List, Tuple

from .threat_observable import Observable, ObservableBundle, ObservableKind
from .yara_validation import MAX_YARA_SOURCE_BYTES, validate_candidate_rule_source

_RULE_NAME: Final[str] = "prometheus_observable_semantic_draft_v1"
_HEX_DIGITS: Final[frozenset] = frozenset("0123456789abcdef")
_API_IMPORT_START_CHARS: Final[frozenset] = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_"
)
_API_IMPORT_CHARS: Final[frozenset] = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.@-"
)
_MAX_API_IMPORT_LEN: Final[int] = 96
_MIN_BYTE_PATTERN_TOKENS: Final[int] = 8
_MAX_BYTE_PATTERN_TOKENS: Final[int] = 64


class ObservableSemanticDraftError(ValueError):
    """Closed failure for invalid input, invariant failure, or validation failure.

    The message is stable and redacted: it never carries any observable
    value, candidate source fragment, or upstream exception detail.
    """

    _MESSAGE = "observable semantic draft derivation failed"

    def __init__(self) -> None:
        super().__init__(self._MESSAGE)


@dataclass(frozen=True, init=False, repr=False, eq=False)
class ObservableSemanticDraft:
    """Immutable digest-only semantic draft result.

    Direct construction is disabled; :func:`derive_semantic_draft` is the
    only supported construction path. The draft carries no candidate source
    and grants no downstream authority. It is not serializable.
    """

    file_sha256_count: int
    api_import_count: int
    byte_pattern_count: int
    candidate_rule_sha256: bytes
    rule_compile_ok: bool

    def __init__(self) -> None:
        raise TypeError("direct observable semantic draft construction is disabled")

    def __reduce__(self) -> object:
        raise TypeError("observable semantic draft is not serializable")


def derive_semantic_draft(bundle: ObservableBundle) -> ObservableSemanticDraft:
    """Derive one deterministic digest-only semantic draft from a bundle.

    Raises:
        ObservableSemanticDraftError: on any invalid input, invariant
            failure, oversized candidate source, non-boolean compile
            verdict, or validation exception.
    """
    if type(bundle) is not ObservableBundle:  # pylint: disable=unidiomatic-typecheck
        raise ObservableSemanticDraftError()
    try:
        bundle.canonical_bytes
    except (AttributeError, ValueError):
        raise ObservableSemanticDraftError() from None
    observables = bundle.observables
    if not isinstance(observables, tuple) or not observables:
        raise ObservableSemanticDraftError()

    file_sha256_count = 0
    patterns: List[Tuple[ObservableKind, str]] = []
    for observable in observables:
        kind, value = _checked_observable(observable)
        if kind is ObservableKind.FILE_SHA256:
            file_sha256_count += 1
        else:
            patterns.append((kind, value))

    api_import_count = sum(
        1 for kind, _ in patterns if kind is ObservableKind.API_IMPORT
    )
    byte_pattern_count = len(patterns) - api_import_count

    source = _render_candidate_source(patterns)
    source_bytes = source.encode("ascii")
    if len(source_bytes) > MAX_YARA_SOURCE_BYTES:
        raise ObservableSemanticDraftError()
    digest = hashlib.sha256(source_bytes).digest()

    try:
        verdict = validate_candidate_rule_source(source)
    except Exception:  # noqa: BLE001  # pylint: disable=broad-except
        raise ObservableSemanticDraftError() from None
    if type(verdict) is not bool:  # pylint: disable=unidiomatic-typecheck
        raise ObservableSemanticDraftError()

    return _new_draft(
        file_sha256_count=file_sha256_count,
        api_import_count=api_import_count,
        byte_pattern_count=byte_pattern_count,
        candidate_rule_sha256=digest,
        rule_compile_ok=verdict,
    )


def _checked_observable(observable: object) -> Tuple[ObservableKind, str]:
    """Re-check one observable against the canonical grammar, fail closed."""
    if type(observable) is not Observable:  # pylint: disable=unidiomatic-typecheck
        raise ObservableSemanticDraftError()
    kind = getattr(observable, "kind", None)
    value = getattr(observable, "value", None)
    # pylint: disable-next=unidiomatic-typecheck
    if type(kind) is not ObservableKind or type(value) is not str:
        raise ObservableSemanticDraftError()
    if kind is ObservableKind.FILE_SHA256:
        _check_file_sha256(value)
    elif kind is ObservableKind.API_IMPORT:
        _check_api_import(value)
    elif kind is ObservableKind.BYTE_PATTERN:
        _check_byte_pattern(value)
    else:
        raise ObservableSemanticDraftError()
    return kind, value


def _check_file_sha256(value: str) -> None:
    """Re-check the 64-character lowercase hex digest grammar."""
    if len(value) != 64 or any(char not in _HEX_DIGITS for char in value):
        raise ObservableSemanticDraftError()


def _check_api_import(value: str) -> None:
    """Re-check the bounded ASCII import grammar before text encoding."""
    if not 1 <= len(value) <= _MAX_API_IMPORT_LEN:
        raise ObservableSemanticDraftError()
    if value[0] not in _API_IMPORT_START_CHARS:
        raise ObservableSemanticDraftError()
    if any(char not in _API_IMPORT_CHARS for char in value):
        raise ObservableSemanticDraftError()


def _check_byte_pattern(value: str) -> None:
    """Re-check the canonical YARA-compatible hex token grammar."""
    if not value.isascii():
        raise ObservableSemanticDraftError()
    tokens = value.split(" ")
    if not _MIN_BYTE_PATTERN_TOKENS <= len(tokens) <= _MAX_BYTE_PATTERN_TOKENS:
        raise ObservableSemanticDraftError()
    fixed = 0
    for token in tokens:
        if token == "??":
            continue
        if len(token) != 2 or any(char not in _HEX_DIGITS for char in token):
            raise ObservableSemanticDraftError()
        fixed += 1
    if fixed < _MIN_BYTE_PATTERN_TOKENS:
        raise ObservableSemanticDraftError()


def _render_candidate_source(patterns: List[Tuple[ObservableKind, str]]) -> str:
    """Render the one bounded ASCII candidate source for the pattern list."""
    lines = [f"rule {_RULE_NAME} {{"]
    if patterns:
        lines.append("    strings:")
        for index, (kind, value) in enumerate(patterns):
            if kind is ObservableKind.API_IMPORT:
                lines.append(f'        $p{index} = "{value}"')
            else:
                lines.append(f"        $p{index} = {{ {value} }}")
        lines.append("    condition:")
        lines.append("        any of them")
    else:
        lines.append("    condition:")
        lines.append("        filesize == 0 and filesize > 0")
    lines.append("}")
    return "\n".join(lines)


def _new_draft(
    *,
    file_sha256_count: int,
    api_import_count: int,
    byte_pattern_count: int,
    candidate_rule_sha256: bytes,
    rule_compile_ok: bool,
) -> ObservableSemanticDraft:
    """Build the frozen result behind the disabled public constructor."""
    draft = object.__new__(ObservableSemanticDraft)
    object.__setattr__(draft, "file_sha256_count", file_sha256_count)
    object.__setattr__(draft, "api_import_count", api_import_count)
    object.__setattr__(draft, "byte_pattern_count", byte_pattern_count)
    object.__setattr__(draft, "candidate_rule_sha256", candidate_rule_sha256)
    object.__setattr__(draft, "rule_compile_ok", rule_compile_ok)
    return draft
