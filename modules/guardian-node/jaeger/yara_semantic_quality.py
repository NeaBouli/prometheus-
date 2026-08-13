"""Deterministic offline synthetic YARA semantic-quality evaluation (GH-177).

This module is a standalone evidence evaluator. It compiles exactly one
pinned synthetic GH-173-shaped candidate rule with the pinned YARA-X engine
(``yara-x==1.4.0``) and scans only transient in-memory byte buffers derived
from a closed, deterministic synthetic recipe/segment schema. It never
touches files, processes, networks, wallets, or chains for scanning, never
embeds real binaries, and never persists rule source or payload bytes in
its report.

The evaluator is intentionally isolated: it imports only the Python
standard library plus ``yara_x``. It must not be imported by worker,
outbox, result, model, transport, submission, wallet, chain, reward, or
deployment paths, and it does not import any such jaeger module. It
establishes no semantic detection quality, adversarial robustness, or
production authority; synthetic metrics are evidence only, never
production detection-quality certification.
"""

# Closed schemas intentionally require exact built-in types and key order.
# pylint: disable=too-many-boolean-expressions,too-many-locals
# pylint: disable=too-many-branches,unidiomatic-typecheck

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

import yara_x

SCHEMA_VERSION = 1
EVALUATOR_VERSION = "guardian-yara-semantic-quality-eval-v1"
EVIDENCE_KIND = "synthetic_offline"
AUTHORITY = "none"
NON_AUTHORITY_DISCLAIMER = (
    "Synthetic offline evaluation only; not production detection quality, "
    "adversarial robustness, certification, or authorization."
)
PINNED_YARA_X_VERSION = "1.4.0"
RECIPE_DOMAIN = b"prometheus-guardian-yara-semantic-quality-recipe-v1\x00"

MIN_CASES = 20
MAX_CASES = 64
MIN_CLASS_CASES = 8
MIN_PRECISION_BPS = 10_000
MIN_RECALL_BPS = 10_000
MIN_SPECIFICITY_BPS = 10_000
MAX_CORPUS_BYTES = 262_144
MAX_POLICY_BYTES = 4_096
MAX_MANIFEST_BYTES = 4_096
MAX_REPORT_BYTES = 65_536
MAX_IMPLEMENTATION_BYTES = 262_144
MAX_LINE_BYTES = 16_384
MAX_SEGMENTS_PER_CASE = 8
MAX_PAYLOAD_BYTES = 4_096
MAX_RULE_BYTES = 8_192

CORPUS_ID = "yara-semantic-quality-corpus-v1"
POLICY_ID = "guardian-yara-semantic-quality-gate-v1"

# The one pinned synthetic GH-173-shaped candidate rule: bounded ASCII,
# no import/include directives, no modules, ``any of them`` condition.
# It compiles with zero errors and zero warnings under yara-x==1.4.0.
CANDIDATE_RULE_SOURCE = (
    "rule prometheus_gh177_synthetic_probe {\n"
    "    strings:\n"
    '        $p0 = "PROM-SYNTH-177-ALPHA"\n'
    "        $p1 = { 50 52 4F 4D 2D 31 37 37 2D 42 45 54 41 00 1F }\n"
    "    condition:\n"
    "        any of them\n"
    "}"
)
CANDIDATE_RULE_SHA256 = hashlib.sha256(
    CANDIDATE_RULE_SOURCE.encode("ascii")
).hexdigest()

# Binary magic values rejected at payload offset zero so synthetic buffers
# can never masquerade as real executables.
_FORBIDDEN_PAYLOAD_MAGICS: Tuple[bytes, ...] = (
    b"MZ",  # PE/DOS
    b"\x7fELF",  # ELF
    b"\xfe\xed\xfa\xce",  # Mach-O 32-bit
    b"\xfe\xed\xfa\xcf",  # Mach-O 64-bit
    b"\xce\xfa\xed\xfe",  # Mach-O 32-bit reverse
    b"\xcf\xfa\xed\xfe",  # Mach-O 64-bit reverse
    b"\xca\xfe\xba\xbe",  # Mach-O fat / universal
)

_SEGMENT_KINDS: Tuple[str, ...] = ("fill", "ascii", "hex", "digest_walk")


class YaraSemanticQualityError(ValueError):
    """Stable, redacted semantic-quality evidence validation failure."""

    def __init__(self) -> None:
        """Create one content-free public validation error."""
        super().__init__("invalid yara semantic quality evidence")


@dataclass(frozen=True)
class Segment:
    """One validated closed-schema synthetic payload segment."""

    kind: str
    value: Any
    count: int


@dataclass(frozen=True)
class QualityCase:
    """One validated synthetic case: recipe plus derived in-memory payload."""

    case_id: str
    expected_match: bool
    segments: Tuple[Segment, ...]
    payload: bytes


@dataclass(frozen=True)
class QualityCorpus:
    """Validated canonical synthetic corpus plus its exact-byte digest."""

    corpus_id: str
    cases: Tuple[QualityCase, ...]
    sha256: str


@dataclass(frozen=True)
class QualityPolicy:
    """Pinned development-only semantic-quality gate policy."""

    minimum_cases: int
    minimum_class_cases: int
    minimum_precision_bps: int
    minimum_recall_bps: int
    minimum_specificity_bps: int
    rule_sha256: str
    sha256: str


@dataclass(frozen=True)
class QualityIntegrityManifest:
    """Exact hashes for the complete deterministic CI fixture set."""

    corpus_sha256: str
    policy_sha256: str
    implementation_sha256: str
    expected_report_sha256: str


def parse_corpus(raw_bytes: bytes) -> QualityCorpus:
    """Parse a canonical JSONL synthetic corpus and enforce class coverage."""
    lines = _parse_canonical_jsonl(raw_bytes, MAX_CORPUS_BYTES)
    header = lines[0]
    expected_header = [
        "schema_version",
        "evidence_kind",
        "authority",
        "disclaimer",
        "corpus_id",
    ]
    if type(header) is not dict or list(header) != expected_header:
        raise YaraSemanticQualityError()
    if _exact_int(header["schema_version"]) != SCHEMA_VERSION:
        raise YaraSemanticQualityError()
    if (
        header["evidence_kind"] != EVIDENCE_KIND
        or header["authority"] != AUTHORITY
        or header["disclaimer"] != NON_AUTHORITY_DISCLAIMER
        or header["corpus_id"] != CORPUS_ID
    ):
        raise YaraSemanticQualityError()

    cases = tuple(_parse_case(value) for value in lines[1:])
    if not MIN_CASES <= len(cases) <= MAX_CASES:
        raise YaraSemanticQualityError()
    case_ids = [case.case_id for case in cases]
    if len(set(case_ids)) != len(case_ids) or case_ids != sorted(case_ids):
        raise YaraSemanticQualityError()
    positive_count = sum(case.expected_match for case in cases)
    negative_count = len(cases) - positive_count
    if positive_count < MIN_CLASS_CASES or negative_count < MIN_CLASS_CASES:
        raise YaraSemanticQualityError()
    return QualityCorpus(
        corpus_id=CORPUS_ID,
        cases=cases,
        sha256=hashlib.sha256(raw_bytes).hexdigest(),
    )


def parse_policy(raw_bytes: bytes) -> QualityPolicy:
    """Parse the exact development policy and reject weakened variants."""
    value = _parse_canonical_json(raw_bytes, MAX_POLICY_BYTES)
    expected_keys = [
        "schema_version",
        "policy_id",
        "rule_sha256",
        "minimum_cases",
        "minimum_class_cases",
        "minimum_precision_bps",
        "minimum_recall_bps",
        "minimum_specificity_bps",
        "authority",
        "disclaimer",
    ]
    if list(value) != expected_keys:
        raise YaraSemanticQualityError()
    if (
        _exact_int(value["schema_version"]) != SCHEMA_VERSION
        or value["policy_id"] != POLICY_ID
        or _nonzero_lower_hex_32(value["rule_sha256"]) != CANDIDATE_RULE_SHA256
        or _exact_int(value["minimum_cases"]) != MIN_CASES
        or _exact_int(value["minimum_class_cases"]) != MIN_CLASS_CASES
        or _exact_int(value["minimum_precision_bps"]) != MIN_PRECISION_BPS
        or _exact_int(value["minimum_recall_bps"]) != MIN_RECALL_BPS
        or _exact_int(value["minimum_specificity_bps"]) != MIN_SPECIFICITY_BPS
        or value["authority"] != AUTHORITY
        or value["disclaimer"] != NON_AUTHORITY_DISCLAIMER
    ):
        raise YaraSemanticQualityError()
    return QualityPolicy(
        minimum_cases=MIN_CASES,
        minimum_class_cases=MIN_CLASS_CASES,
        minimum_precision_bps=MIN_PRECISION_BPS,
        minimum_recall_bps=MIN_RECALL_BPS,
        minimum_specificity_bps=MIN_SPECIFICITY_BPS,
        rule_sha256=CANDIDATE_RULE_SHA256,
        sha256=hashlib.sha256(raw_bytes).hexdigest(),
    )


def parse_integrity_manifest(raw_bytes: bytes) -> QualityIntegrityManifest:
    """Parse exact fixture hashes without granting evidence authority."""
    value = _parse_canonical_json(raw_bytes, MAX_MANIFEST_BYTES)
    if list(value) != [
        "schema_version",
        "evaluator_version",
        "corpus_sha256",
        "policy_sha256",
        "implementation_sha256",
        "expected_report_sha256",
    ]:
        raise YaraSemanticQualityError()
    if (
        _exact_int(value["schema_version"]) != SCHEMA_VERSION
        or value["evaluator_version"] != EVALUATOR_VERSION
    ):
        raise YaraSemanticQualityError()
    return QualityIntegrityManifest(
        corpus_sha256=_nonzero_lower_hex_32(value["corpus_sha256"]),
        policy_sha256=_nonzero_lower_hex_32(value["policy_sha256"]),
        implementation_sha256=_nonzero_lower_hex_32(value["implementation_sha256"]),
        expected_report_sha256=_nonzero_lower_hex_32(value["expected_report_sha256"]),
    )


def evaluate_quality(corpus: QualityCorpus, policy: QualityPolicy) -> Dict[str, Any]:
    """Build one deterministic, non-authorizing semantic-quality report.

    The pinned rule is compiled once and scanned only against transient
    in-memory payload bytes. No payload bytes, payload hex, or rule source
    are persisted in the report; only exact SHA-256 bindings appear.
    """
    if type(corpus) is not QualityCorpus or type(policy) is not QualityPolicy:
        raise YaraSemanticQualityError()
    _validate_evaluation_inputs(corpus, policy)
    implementation_sha256 = _implementation_sha256()
    yara_x_version = _pinned_yara_x_version()
    rules = _compile_pinned_rule()

    true_positive = false_positive = true_negative = false_negative = 0
    for case in corpus.cases:
        matched = _scan_in_memory(rules, case.payload)
        if case.expected_match and matched:
            true_positive += 1
        elif case.expected_match:
            false_negative += 1
        elif matched:
            false_positive += 1
        else:
            true_negative += 1

    sample_count = len(corpus.cases)
    precision_denominator = true_positive + false_positive
    recall_denominator = true_positive + false_negative
    specificity_denominator = true_negative + false_positive
    precision_bps = _ratio_bps(true_positive, precision_denominator)
    recall_bps = _ratio_bps(true_positive, recall_denominator)
    specificity_bps = _ratio_bps(true_negative, specificity_denominator)

    checks = {
        "minimum_sample_count": sample_count >= policy.minimum_cases,
        "minimum_class_count": (
            recall_denominator >= policy.minimum_class_cases
            and specificity_denominator >= policy.minimum_class_cases
        ),
        "minimum_precision": (
            precision_denominator > 0
            and true_positive * 10_000
            >= policy.minimum_precision_bps * precision_denominator
        ),
        "minimum_recall": (
            recall_denominator > 0
            and true_positive * 10_000 >= policy.minimum_recall_bps * recall_denominator
        ),
        "minimum_specificity": (
            specificity_denominator > 0
            and true_negative * 10_000
            >= policy.minimum_specificity_bps * specificity_denominator
        ),
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "evaluator_version": EVALUATOR_VERSION,
        "evidence_kind": EVIDENCE_KIND,
        "authority": AUTHORITY,
        "production_authorized": False,
        "disclaimer": NON_AUTHORITY_DISCLAIMER,
        "corpus_id": corpus.corpus_id,
        "corpus_sha256": corpus.sha256,
        "policy_sha256": policy.sha256,
        "implementation_sha256": implementation_sha256,
        "yara_x_version": yara_x_version,
        "rule_sha256": policy.rule_sha256,
        "sample_count": sample_count,
        "confusion_matrix": {
            "true_positive": true_positive,
            "false_positive": false_positive,
            "true_negative": true_negative,
            "false_negative": false_negative,
        },
        "metrics": {
            "precision": {
                "numerator": true_positive,
                "denominator": precision_denominator,
                "bps": precision_bps,
            },
            "recall": {
                "numerator": true_positive,
                "denominator": recall_denominator,
                "bps": recall_bps,
            },
            "specificity": {
                "numerator": true_negative,
                "denominator": specificity_denominator,
                "bps": specificity_bps,
            },
        },
        "policy": {
            "minimum_cases": policy.minimum_cases,
            "minimum_class_cases": policy.minimum_class_cases,
            "minimum_precision_bps": policy.minimum_precision_bps,
            "minimum_recall_bps": policy.minimum_recall_bps,
            "minimum_specificity_bps": policy.minimum_specificity_bps,
        },
        "checks": checks,
        "gate_pass": all(checks.values()),
    }


def canonical_report_bytes(report: Mapping[str, Any]) -> bytes:
    """Serialize one report in stable compact JSON with a final newline."""
    if type(report) is not dict:
        raise YaraSemanticQualityError()
    return (json.dumps(report, separators=(",", ":"), ensure_ascii=True) + "\n").encode(
        "ascii"
    )


def verify_fixture_set(
    corpus_bytes: bytes,
    policy_bytes: bytes,
    expected_report_bytes: bytes,
    manifest_bytes: bytes,
) -> bytes:
    """Verify all fixture hashes and return the reproduced exact report.

    Verification fails closed on any corpus, policy, implementation, or
    expected-report hash mismatch and on any byte-level report drift.
    """
    corpus = parse_corpus(corpus_bytes)
    policy = parse_policy(policy_bytes)
    manifest = parse_integrity_manifest(manifest_bytes)
    if (
        manifest.corpus_sha256 != corpus.sha256
        or manifest.policy_sha256 != policy.sha256
        or manifest.implementation_sha256 != _implementation_sha256()
        or manifest.expected_report_sha256
        != hashlib.sha256(expected_report_bytes).hexdigest()
    ):
        raise YaraSemanticQualityError()
    expected_report = _parse_canonical_json(expected_report_bytes, MAX_REPORT_BYTES)
    reproduced = canonical_report_bytes(evaluate_quality(corpus, policy))
    if reproduced != expected_report_bytes or expected_report != json.loads(reproduced):
        raise YaraSemanticQualityError()
    return reproduced


def _parse_case(value: Mapping[str, Any]) -> QualityCase:
    """Validate one exact-shape synthetic case and derive its payload."""
    expected_keys = ["case_id", "expected_match", "segments"]
    if type(value) is not dict or list(value) != expected_keys:
        raise YaraSemanticQualityError()
    expected_match = value["expected_match"]
    if type(expected_match) is not bool:
        raise YaraSemanticQualityError()
    raw_segments = value["segments"]
    if (
        type(raw_segments) is not list
        or not 1 <= len(raw_segments) <= MAX_SEGMENTS_PER_CASE
    ):
        raise YaraSemanticQualityError()
    segments = tuple(_parse_segment(segment) for segment in raw_segments)
    payload = _derive_payload(segments)
    return QualityCase(
        case_id=_identifier(value["case_id"], 64),
        expected_match=expected_match,
        segments=segments,
        payload=payload,
    )


def _parse_segment(value: Mapping[str, Any]) -> Segment:
    """Validate one closed-schema recipe segment with exact key order."""
    if type(value) is not dict:
        raise YaraSemanticQualityError()
    kind = value.get("kind")
    if kind == "fill":
        if list(value) != ["kind", "value", "count"]:
            raise YaraSemanticQualityError()
        byte_value = _exact_int(value["value"])
        if byte_value > 255:
            raise YaraSemanticQualityError()
        return Segment(
            kind="fill",
            value=byte_value,
            count=_bounded_count(value["count"]),
        )
    if kind == "ascii":
        if list(value) != ["kind", "text"]:
            raise YaraSemanticQualityError()
        text = value["text"]
        if (
            type(text) is not str
            or not 1 <= len(text) <= 512
            or any(character < " " or character > "~" for character in text)
        ):
            raise YaraSemanticQualityError()
        return Segment(kind="ascii", value=text, count=len(text))
    if kind == "hex":
        if list(value) != ["kind", "value"]:
            raise YaraSemanticQualityError()
        hex_value = value["value"]
        if (
            type(hex_value) is not str
            or not 2 <= len(hex_value) <= 1_024
            or len(hex_value) % 2 != 0
            or _LOWER_HEX_RE.fullmatch(hex_value) is None
        ):
            raise YaraSemanticQualityError()
        return Segment(kind="hex", value=hex_value, count=len(hex_value) // 2)
    if kind == "digest_walk":
        if list(value) != ["kind", "seed", "count"]:
            raise YaraSemanticQualityError()
        seed = _exact_int(value["seed"])
        if seed > 4_294_967_295:
            raise YaraSemanticQualityError()
        return Segment(
            kind="digest_walk", value=seed, count=_bounded_count(value["count"])
        )
    raise YaraSemanticQualityError()


def _derive_payload(segments: Sequence[Segment]) -> bytes:
    """Derive one bounded synthetic payload and reject binary magic."""
    output = bytearray()
    for segment in segments:
        if segment.kind == "fill":
            output += bytes([segment.value]) * segment.count
        elif segment.kind == "ascii":
            output += segment.value.encode("ascii")
        elif segment.kind == "hex":
            output += bytes.fromhex(segment.value)
        elif segment.kind == "digest_walk":
            output += _digest_walk(segment.value, segment.count)
        else:
            raise YaraSemanticQualityError()
    payload = bytes(output)
    if not payload or len(payload) > MAX_PAYLOAD_BYTES:
        raise YaraSemanticQualityError()
    if any(payload.startswith(magic) for magic in _FORBIDDEN_PAYLOAD_MAGICS):
        raise YaraSemanticQualityError()
    return payload


def _digest_walk(seed: int, count: int) -> bytes:
    """Derive deterministic pseudo-random bytes from a closed hash walk."""
    produced = bytearray()
    block = 0
    while len(produced) < count:
        produced += hashlib.sha256(
            RECIPE_DOMAIN + seed.to_bytes(8, "little") + block.to_bytes(4, "little")
        ).digest()
        block += 1
    return bytes(produced[:count])


def _compile_pinned_rule() -> Any:
    """Compile the one pinned synthetic rule with zero findings.

    The source is re-checked as bounded ASCII with no NUL bytes, exactly
    one top-level rule declaration, and no import/include directives, then
    compiled by the pinned YARA-X engine with includes disabled. Any
    error, warning, or unexpected compiler failure fails closed.
    """
    source = CANDIDATE_RULE_SOURCE
    if (
        type(source) is not str
        or not source
        or not source.isascii()
        or "\x00" in source
        or len(source.encode("ascii")) > MAX_RULE_BYTES
    ):
        raise YaraSemanticQualityError()
    rule_declarations = 0
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("import") or stripped.startswith("include"):
            raise YaraSemanticQualityError()
        if stripped.startswith("rule "):
            rule_declarations += 1
    if rule_declarations != 1:
        raise YaraSemanticQualityError()
    try:
        # pylint: disable-next=no-member
        compiler = yara_x.Compiler()
        compiler.enable_includes(False)
        compiler.add_source(source)
        if compiler.errors() or compiler.warnings():
            raise YaraSemanticQualityError()
        return compiler.build()
    except YaraSemanticQualityError:
        raise
    except Exception as error:  # noqa: BLE001  # pylint: disable=broad-except
        raise YaraSemanticQualityError() from error


def _scan_in_memory(rules: Any, payload: bytes) -> bool:
    """Scan one transient in-memory buffer and return match presence.

    Only the YARA-X in-memory byte scan API is used. No path, file, or
    process scan API is reachable from this module.
    """
    if type(payload) is not bytes or not payload:
        raise YaraSemanticQualityError()
    try:
        # pylint: disable-next=no-member
        scanner = yara_x.Scanner(rules)
        return bool(scanner.scan(payload).matching_rules)
    except YaraSemanticQualityError:
        raise
    except Exception as error:  # noqa: BLE001  # pylint: disable=broad-except
        raise YaraSemanticQualityError() from error


def _implementation_sha256() -> str:
    """Hash this module's exact bytes for report and manifest binding."""
    try:
        raw_bytes = Path(__file__).resolve().read_bytes()
    except OSError as error:
        raise YaraSemanticQualityError() from error
    if not raw_bytes or len(raw_bytes) > MAX_IMPLEMENTATION_BYTES:
        raise YaraSemanticQualityError()
    return hashlib.sha256(raw_bytes).hexdigest()


def _pinned_yara_x_version() -> str:
    """Return the installed engine version, requiring the exact pin."""
    try:
        version = importlib.metadata.version("yara-x")
    except importlib.metadata.PackageNotFoundError as error:
        raise YaraSemanticQualityError() from error
    if version != PINNED_YARA_X_VERSION:
        raise YaraSemanticQualityError()
    return version


def _validate_evaluation_inputs(corpus: QualityCorpus, policy: QualityPolicy) -> None:
    """Revalidate parsed runtime objects before metric calculation."""
    if (
        _lower_hex_32(corpus.sha256) != corpus.sha256
        or corpus.corpus_id != CORPUS_ID
        or not MIN_CASES <= len(corpus.cases) <= MAX_CASES
        or policy.minimum_cases != MIN_CASES
        or policy.minimum_class_cases != MIN_CLASS_CASES
        or policy.minimum_precision_bps != MIN_PRECISION_BPS
        or policy.minimum_recall_bps != MIN_RECALL_BPS
        or policy.minimum_specificity_bps != MIN_SPECIFICITY_BPS
        or policy.rule_sha256 != CANDIDATE_RULE_SHA256
        or _lower_hex_32(policy.sha256) != policy.sha256
        or hashlib.sha256(_canonical_policy_bytes(policy)).hexdigest() != policy.sha256
    ):
        raise YaraSemanticQualityError()
    case_ids: List[str] = []
    for case in corpus.cases:
        if (
            type(case) is not QualityCase
            or type(case.expected_match) is not bool
            or type(case.segments) is not tuple
            or not 1 <= len(case.segments) <= MAX_SEGMENTS_PER_CASE
        ):
            raise YaraSemanticQualityError()
        _identifier(case.case_id, 64)
        for segment in case.segments:
            _revalidate_segment(segment)
        derived_payload = _derive_payload(case.segments)
        if (
            type(case.payload) is not bytes
            or not case.payload
            or len(case.payload) > MAX_PAYLOAD_BYTES
            or case.payload != derived_payload
            or any(
                case.payload.startswith(magic) for magic in _FORBIDDEN_PAYLOAD_MAGICS
            )
        ):
            raise YaraSemanticQualityError()
        case_ids.append(case.case_id)
    if (
        case_ids != sorted(case_ids)
        or len(set(case_ids)) != len(case_ids)
        or sum(case.expected_match for case in corpus.cases) < MIN_CLASS_CASES
        or sum(not case.expected_match for case in corpus.cases) < MIN_CLASS_CASES
        or hashlib.sha256(_canonical_corpus_bytes(corpus)).hexdigest() != corpus.sha256
    ):
        raise YaraSemanticQualityError()


def _revalidate_segment(segment: Segment) -> None:
    """Revalidate one parsed segment before every evaluation."""
    if type(segment) is not Segment:
        raise YaraSemanticQualityError()
    if segment.kind == "fill":
        if (
            type(segment.value) is not int
            or not 0 <= segment.value <= 255
            or _bounded_count(segment.count) != segment.count
        ):
            raise YaraSemanticQualityError()
        return
    if segment.kind == "ascii":
        if (
            type(segment.value) is not str
            or not 1 <= len(segment.value) <= 512
            or any(character < " " or character > "~" for character in segment.value)
            or segment.count != len(segment.value)
        ):
            raise YaraSemanticQualityError()
        return
    if segment.kind == "hex":
        if (
            type(segment.value) is not str
            or not 2 <= len(segment.value) <= 1_024
            or len(segment.value) % 2 != 0
            or _LOWER_HEX_RE.fullmatch(segment.value) is None
            or segment.count != len(segment.value) // 2
        ):
            raise YaraSemanticQualityError()
        return
    if segment.kind == "digest_walk":
        if (
            type(segment.value) is not int
            or not 0 <= segment.value <= 4_294_967_295
            or _bounded_count(segment.count) != segment.count
        ):
            raise YaraSemanticQualityError()
        return
    raise YaraSemanticQualityError()


def _canonical_corpus_bytes(corpus: QualityCorpus) -> bytes:
    """Reconstruct the exact canonical corpus bytes from validated objects."""
    values: List[Dict[str, Any]] = [
        {
            "schema_version": SCHEMA_VERSION,
            "evidence_kind": EVIDENCE_KIND,
            "authority": AUTHORITY,
            "disclaimer": NON_AUTHORITY_DISCLAIMER,
            "corpus_id": CORPUS_ID,
        }
    ]
    for case in corpus.cases:
        values.append(
            {
                "case_id": case.case_id,
                "expected_match": case.expected_match,
                "segments": [_canonical_segment(segment) for segment in case.segments],
            }
        )
    return b"".join(
        (json.dumps(value, separators=(",", ":"), ensure_ascii=True) + "\n").encode(
            "ascii"
        )
        for value in values
    )


def _canonical_segment(segment: Segment) -> Dict[str, Any]:
    """Return one exact canonical segment mapping after revalidation."""
    _revalidate_segment(segment)
    if segment.kind == "fill":
        return {"kind": "fill", "value": segment.value, "count": segment.count}
    if segment.kind == "ascii":
        return {"kind": "ascii", "text": segment.value}
    if segment.kind == "hex":
        return {"kind": "hex", "value": segment.value}
    if segment.kind == "digest_walk":
        return {
            "kind": "digest_walk",
            "seed": segment.value,
            "count": segment.count,
        }
    raise YaraSemanticQualityError()


def _canonical_policy_bytes(policy: QualityPolicy) -> bytes:
    """Reconstruct the exact canonical policy bytes from validated objects."""
    value = {
        "schema_version": SCHEMA_VERSION,
        "policy_id": POLICY_ID,
        "rule_sha256": policy.rule_sha256,
        "minimum_cases": policy.minimum_cases,
        "minimum_class_cases": policy.minimum_class_cases,
        "minimum_precision_bps": policy.minimum_precision_bps,
        "minimum_recall_bps": policy.minimum_recall_bps,
        "minimum_specificity_bps": policy.minimum_specificity_bps,
        "authority": AUTHORITY,
        "disclaimer": NON_AUTHORITY_DISCLAIMER,
    }
    return (json.dumps(value, separators=(",", ":"), ensure_ascii=True) + "\n").encode(
        "ascii"
    )


def _parse_canonical_jsonl(
    raw_bytes: bytes, maximum_bytes: int
) -> List[Dict[str, Any]]:
    """Parse size-bounded compact ASCII JSONL with exact byte identity."""
    if (
        type(raw_bytes) is not bytes
        or not raw_bytes
        or len(raw_bytes) > maximum_bytes
        or not raw_bytes.endswith(b"\n")
    ):
        raise YaraSemanticQualityError()
    raw_lines = raw_bytes.splitlines(keepends=True)
    if len(raw_lines) < 2:
        raise YaraSemanticQualityError()
    decoded: List[Dict[str, Any]] = []
    for raw_line in raw_lines:
        if not raw_line.endswith(b"\n") or len(raw_line) > MAX_LINE_BYTES:
            raise YaraSemanticQualityError()
        try:
            value = json.loads(
                raw_line[:-1].decode("ascii"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_json_constant,
            )
        except (UnicodeDecodeError, ValueError):
            raise YaraSemanticQualityError() from None
        if type(value) is not dict:
            raise YaraSemanticQualityError()
        canonical = (
            json.dumps(value, separators=(",", ":"), ensure_ascii=True) + "\n"
        ).encode("ascii")
        if canonical != raw_line:
            raise YaraSemanticQualityError()
        decoded.append(value)
    return decoded


def _parse_canonical_json(raw_bytes: bytes, maximum_bytes: int) -> Dict[str, Any]:
    """Parse one size-bounded compact ASCII JSON object exactly."""
    if (
        type(raw_bytes) is not bytes
        or not raw_bytes
        or len(raw_bytes) > maximum_bytes
        or not raw_bytes.endswith(b"\n")
    ):
        raise YaraSemanticQualityError()
    try:
        value = json.loads(
            raw_bytes[:-1].decode("ascii"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, ValueError):
        raise YaraSemanticQualityError() from None
    if type(value) is not dict:
        raise YaraSemanticQualityError()
    canonical = (
        json.dumps(value, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("ascii")
    if canonical != raw_bytes:
        raise YaraSemanticQualityError()
    return value


def _reject_duplicate_keys(items: Iterable[Tuple[str, Any]]) -> Dict[str, Any]:
    """Build a mapping while rejecting duplicate JSON member names."""
    output: Dict[str, Any] = {}
    for key, value in items:
        if key in output:
            raise YaraSemanticQualityError()
        output[key] = value
    return output


def _reject_json_constant(_value: str) -> None:
    """Reject non-standard JSON numeric constants."""
    raise YaraSemanticQualityError()


def _exact_int(value: Any) -> int:
    """Require a non-negative literal integer, excluding booleans."""
    if type(value) is not int or value < 0:
        raise YaraSemanticQualityError()
    return value


def _bounded_count(value: Any) -> int:
    """Require one literal segment byte count within payload bounds."""
    count = _exact_int(value)
    if not 1 <= count <= MAX_PAYLOAD_BYTES:
        raise YaraSemanticQualityError()
    return count


def _identifier(value: Any, maximum_length: int) -> str:
    """Validate one bounded lowercase identifier."""
    if (
        type(value) is not str
        or len(value) < 3
        or len(value) > maximum_length
        or _IDENTIFIER_RE.fullmatch(value) is None
    ):
        raise YaraSemanticQualityError()
    return value


def _lower_hex_32(value: Any) -> str:
    """Validate one canonical lowercase 32-byte hexadecimal value."""
    if type(value) is not str or _LOWER_HEX_32_RE.fullmatch(value) is None:
        raise YaraSemanticQualityError()
    return value


def _nonzero_lower_hex_32(value: Any) -> str:
    """Validate one nonzero canonical lowercase 32-byte hash."""
    parsed = _lower_hex_32(value)
    if parsed == "0" * 64:
        raise YaraSemanticQualityError()
    return parsed


def _round_ratio(numerator: int, denominator: int) -> int:
    """Round a non-negative rational to the nearest integer, halves up."""
    if denominator <= 0 or numerator < 0:
        raise YaraSemanticQualityError()
    return (2 * numerator + denominator) // (2 * denominator)


def _ratio_bps(numerator: int, denominator: int) -> int | None:
    """Return a rounded basis-point ratio or None when undefined."""
    if denominator == 0:
        return None
    return _round_ratio(numerator * 10_000, denominator)


def _read_bounded(path: Path, maximum_bytes: int) -> bytes:
    """Read a regular non-symlink file with pre- and post-read bounds."""
    try:
        if not path.is_file() or path.is_symlink():
            raise YaraSemanticQualityError()
        if path.stat().st_size > maximum_bytes:
            raise YaraSemanticQualityError()
        raw_bytes = path.read_bytes()
    except OSError:
        raise YaraSemanticQualityError() from None
    if len(raw_bytes) > maximum_bytes:
        raise YaraSemanticQualityError()
    return raw_bytes


def _main(argv: Sequence[str] | None = None) -> int:
    """Run closed fixture verification offline and print the exact report."""
    parser = argparse.ArgumentParser(
        description="Verify canonical synthetic YARA semantic-quality evidence."
    )
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--expected-report", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report_bytes = verify_fixture_set(
            _read_bounded(args.corpus, MAX_CORPUS_BYTES),
            _read_bounded(args.policy, MAX_POLICY_BYTES),
            _read_bounded(args.expected_report, MAX_REPORT_BYTES),
            _read_bounded(args.manifest, MAX_MANIFEST_BYTES),
        )
    except YaraSemanticQualityError:
        print("yara semantic quality evaluation failed", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(report_bytes)
    return 0 if json.loads(report_bytes)["gate_pass"] else 1


_IDENTIFIER_RE = re.compile(r"[a-z0-9][a-z0-9._-]*")
_LOWER_HEX_RE = re.compile(r"[0-9a-f]+")
_LOWER_HEX_32_RE = re.compile(r"[0-9a-f]{64}")


if __name__ == "__main__":
    raise SystemExit(_main())
