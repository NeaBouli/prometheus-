"""Deterministic offline evaluation for Guardian YARA confidence evidence.

This module evaluates already collected confidence predictions against a
versioned synthetic benchmark. Synthetic CI and local model candidate
prediction modes share the closed schema but produce strictly separate,
non-authorizing evidence classes. It performs no model, network, YARA,
telemetry, transport, wallet, or chain operation and grants no production
authority.
"""

# Closed schemas intentionally require exact built-in types and key order.
# pylint: disable=too-many-boolean-expressions,too-many-instance-attributes
# pylint: disable=too-many-locals,unidiomatic-typecheck

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Sequence

SCHEMA_VERSION = 1
EVALUATOR_VERSION = "guardian-confidence-eval-v1"
EVIDENCE_KIND = "synthetic_offline"
AUTHORITY = "none"
NON_AUTHORITY_DISCLAIMER = (
    "Synthetic offline evaluation only; not live-model quality, production "
    "calibration, or authorization."
)
EVALUATION_INPUT_DOMAIN = b"prometheus-guardian-confidence-evaluation-v1\x00"
SUBMISSION_THRESHOLD_BPS = 8_500
CALIBRATION_BIN_WIDTH_BPS = 1_000
CALIBRATION_BIN_COUNT = 10
MIN_CASES = 20
MAX_CASES = 256
MIN_CLASS_CASES = 8
MIN_PRECISION_BPS = 9_000
MIN_RECALL_BPS = 8_000
MAX_BRIER_PPM = 150_000
MAX_ECE_BPS = 1_000
MAX_CORPUS_BYTES = 1_048_576
MAX_PREDICTIONS_BYTES = 131_072
MAX_POLICY_BYTES = 4_096
MAX_MANIFEST_BYTES = 4_096
MAX_REPORT_BYTES = 131_072
MAX_LINE_BYTES = 16_384
EVALUATION_MODE = "synthetic_ci"
LOCAL_MODEL_EVALUATION_MODE = "local_model_candidate"
LOCAL_MODEL_NON_AUTHORITY_DISCLAIMER = (
    "Local model candidate evaluation only; development metrics are not "
    "production calibration, quality certification, or authorization."
)


class ConfidenceEvaluationError(ValueError):
    """Stable, redacted confidence-evidence validation failure."""

    def __init__(self) -> None:
        """Create one content-free public validation error."""
        super().__init__("invalid confidence evaluation evidence")


@dataclass(frozen=True)
class BenchmarkCase:
    """One public synthetic rule-assessment benchmark case."""

    case_id: str
    category: str
    threat_description: str
    yara_rule: str
    expected_acceptable: bool

    @property
    def assessment_input(self) -> tuple[str, str]:
        """Return only model-facing fields, never the expected label."""
        return self.threat_description, self.yara_rule


@dataclass(frozen=True)
class BenchmarkCorpus:
    """Validated canonical benchmark plus its exact-byte digest."""

    corpus_id: str
    cases: tuple[BenchmarkCase, ...]
    sha256: str


@dataclass(frozen=True)
class ConfidencePrediction:
    """One exact case identifier and model-provided confidence value."""

    case_id: str
    confidence_bps: int


@dataclass(frozen=True)
class PredictionSet:
    """Validated canonical predictions bound to one exact benchmark."""

    evaluation_mode: str
    corpus_sha256: str
    subject_id: str
    subject_sha256: str
    prompt_sha256: str
    predictions: tuple[ConfidencePrediction, ...]
    sha256: str


@dataclass(frozen=True)
class GatePolicy:
    """Pinned development-only metric policy."""

    threshold_bps: int
    calibration_bin_width_bps: int
    minimum_cases: int
    minimum_class_cases: int
    minimum_precision_bps: int
    minimum_recall_bps: int
    maximum_brier_score_ppm: int
    maximum_expected_calibration_error_bps: int
    sha256: str


@dataclass(frozen=True)
class IntegrityManifest:
    """Exact hashes for the complete deterministic CI fixture set."""

    corpus_sha256: str
    predictions_sha256: str
    policy_sha256: str
    expected_report_sha256: str


def parse_corpus(raw_bytes: bytes) -> BenchmarkCorpus:
    """Parse a canonical JSONL benchmark and enforce class coverage."""
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
        raise ConfidenceEvaluationError()
    if _exact_int(header["schema_version"]) != SCHEMA_VERSION:
        raise ConfidenceEvaluationError()
    if (
        header["evidence_kind"] != EVIDENCE_KIND
        or header["authority"] != AUTHORITY
        or header["disclaimer"] != NON_AUTHORITY_DISCLAIMER
    ):
        raise ConfidenceEvaluationError()
    corpus_id = _identifier(header["corpus_id"], 64)

    cases = tuple(_parse_case(value) for value in lines[1:])
    if not MIN_CASES <= len(cases) <= MAX_CASES:
        raise ConfidenceEvaluationError()
    case_ids = [case.case_id for case in cases]
    if len(set(case_ids)) != len(case_ids) or case_ids != sorted(case_ids):
        raise ConfidenceEvaluationError()
    positive_count = sum(case.expected_acceptable for case in cases)
    negative_count = len(cases) - positive_count
    if positive_count < MIN_CLASS_CASES or negative_count < MIN_CLASS_CASES:
        raise ConfidenceEvaluationError()
    return BenchmarkCorpus(
        corpus_id=corpus_id,
        cases=cases,
        sha256=hashlib.sha256(raw_bytes).hexdigest(),
    )


def parse_predictions(raw_bytes: bytes, corpus: BenchmarkCorpus) -> PredictionSet:
    """Parse canonical JSONL predictions and bind every row to the corpus."""
    if type(corpus) is not BenchmarkCorpus:
        raise ConfidenceEvaluationError()
    lines = _parse_canonical_jsonl(raw_bytes, MAX_PREDICTIONS_BYTES)
    header = lines[0]
    expected_header = [
        "schema_version",
        "evaluation_mode",
        "corpus_sha256",
        "subject_id",
        "subject_sha256",
        "prompt_sha256",
    ]
    if type(header) is not dict or list(header) != expected_header:
        raise ConfidenceEvaluationError()
    if _exact_int(header["schema_version"]) != SCHEMA_VERSION:
        raise ConfidenceEvaluationError()
    evaluation_mode = header["evaluation_mode"]
    if evaluation_mode not in (EVALUATION_MODE, LOCAL_MODEL_EVALUATION_MODE):
        raise ConfidenceEvaluationError()
    corpus_sha256 = _lower_hex_32(header["corpus_sha256"])
    if corpus_sha256 != corpus.sha256:
        raise ConfidenceEvaluationError()
    subject_id = _subject_identifier(header["subject_id"], 128)
    subject_sha256 = _nonzero_lower_hex_32(header["subject_sha256"])
    prompt_sha256 = _nonzero_lower_hex_32(header["prompt_sha256"])

    predictions = tuple(_parse_prediction(value) for value in lines[1:])
    expected_ids = tuple(case.case_id for case in corpus.cases)
    actual_ids = tuple(prediction.case_id for prediction in predictions)
    if actual_ids != expected_ids:
        raise ConfidenceEvaluationError()
    return PredictionSet(
        evaluation_mode=evaluation_mode,
        corpus_sha256=corpus_sha256,
        subject_id=subject_id,
        subject_sha256=subject_sha256,
        prompt_sha256=prompt_sha256,
        predictions=predictions,
        sha256=hashlib.sha256(raw_bytes).hexdigest(),
    )


def parse_policy(raw_bytes: bytes) -> GatePolicy:
    """Parse the exact development policy and reject weakened variants."""
    value = _parse_canonical_json(raw_bytes, MAX_POLICY_BYTES)
    expected_keys = [
        "schema_version",
        "policy_id",
        "threshold_bps",
        "calibration_bin_width_bps",
        "minimum_cases",
        "minimum_class_cases",
        "minimum_precision_bps",
        "minimum_recall_bps",
        "maximum_brier_score_ppm",
        "maximum_expected_calibration_error_bps",
        "authority",
        "disclaimer",
    ]
    if list(value) != expected_keys:
        raise ConfidenceEvaluationError()
    if (
        _exact_int(value["schema_version"]) != SCHEMA_VERSION
        or value["policy_id"] != "guardian-confidence-development-gate-v1"
        or _exact_int(value["threshold_bps"]) != SUBMISSION_THRESHOLD_BPS
        or _exact_int(value["calibration_bin_width_bps"]) != CALIBRATION_BIN_WIDTH_BPS
        or _exact_int(value["minimum_cases"]) != MIN_CASES
        or _exact_int(value["minimum_class_cases"]) != MIN_CLASS_CASES
        or _exact_int(value["minimum_precision_bps"]) != MIN_PRECISION_BPS
        or _exact_int(value["minimum_recall_bps"]) != MIN_RECALL_BPS
        or _exact_int(value["maximum_brier_score_ppm"]) != MAX_BRIER_PPM
        or _exact_int(value["maximum_expected_calibration_error_bps"]) != MAX_ECE_BPS
        or value["authority"] != AUTHORITY
        or value["disclaimer"] != NON_AUTHORITY_DISCLAIMER
    ):
        raise ConfidenceEvaluationError()
    return GatePolicy(
        threshold_bps=SUBMISSION_THRESHOLD_BPS,
        calibration_bin_width_bps=CALIBRATION_BIN_WIDTH_BPS,
        minimum_cases=MIN_CASES,
        minimum_class_cases=MIN_CLASS_CASES,
        minimum_precision_bps=MIN_PRECISION_BPS,
        minimum_recall_bps=MIN_RECALL_BPS,
        maximum_brier_score_ppm=MAX_BRIER_PPM,
        maximum_expected_calibration_error_bps=MAX_ECE_BPS,
        sha256=hashlib.sha256(raw_bytes).hexdigest(),
    )


def parse_integrity_manifest(raw_bytes: bytes) -> IntegrityManifest:
    """Parse exact fixture hashes without granting evidence authority."""
    value = _parse_canonical_json(raw_bytes, MAX_MANIFEST_BYTES)
    if list(value) != [
        "schema_version",
        "evaluator_version",
        "corpus_sha256",
        "predictions_sha256",
        "policy_sha256",
        "expected_report_sha256",
    ]:
        raise ConfidenceEvaluationError()
    if (
        _exact_int(value["schema_version"]) != SCHEMA_VERSION
        or value["evaluator_version"] != EVALUATOR_VERSION
    ):
        raise ConfidenceEvaluationError()
    return IntegrityManifest(
        corpus_sha256=_nonzero_lower_hex_32(value["corpus_sha256"]),
        predictions_sha256=_nonzero_lower_hex_32(value["predictions_sha256"]),
        policy_sha256=_nonzero_lower_hex_32(value["policy_sha256"]),
        expected_report_sha256=_nonzero_lower_hex_32(value["expected_report_sha256"]),
    )


def evaluate_confidence(
    corpus: BenchmarkCorpus, prediction_set: PredictionSet, policy: GatePolicy
) -> Dict[str, Any]:
    """Build one deterministic, non-authorizing calibration report."""
    if (
        type(corpus) is not BenchmarkCorpus
        or type(prediction_set) is not PredictionSet
        or type(policy) is not GatePolicy
    ):
        raise ConfidenceEvaluationError()
    if prediction_set.corpus_sha256 != corpus.sha256:
        raise ConfidenceEvaluationError()
    if len(corpus.cases) != len(prediction_set.predictions):
        raise ConfidenceEvaluationError()
    _validate_evaluation_inputs(corpus, prediction_set, policy)
    if prediction_set.evaluation_mode == EVALUATION_MODE:
        evidence_class = "synthetic_ci_only"
        disclaimer = NON_AUTHORITY_DISCLAIMER
    elif prediction_set.evaluation_mode == LOCAL_MODEL_EVALUATION_MODE:
        evidence_class = "local_model_candidate_only"
        disclaimer = LOCAL_MODEL_NON_AUTHORITY_DISCLAIMER
    else:
        raise ConfidenceEvaluationError()

    true_positive = false_positive = true_negative = false_negative = 0
    squared_error_sum = 0
    bins = [
        {"count": 0, "positive_count": 0, "confidence_sum_bps": 0}
        for _ in range(CALIBRATION_BIN_COUNT)
    ]
    for case, prediction in zip(corpus.cases, prediction_set.predictions):
        if case.case_id != prediction.case_id:
            raise ConfidenceEvaluationError()
        predicted_acceptable = prediction.confidence_bps >= policy.threshold_bps
        if case.expected_acceptable and predicted_acceptable:
            true_positive += 1
        elif case.expected_acceptable:
            false_negative += 1
        elif predicted_acceptable:
            false_positive += 1
        else:
            true_negative += 1

        target_bps = 10_000 if case.expected_acceptable else 0
        squared_error_sum += (prediction.confidence_bps - target_bps) ** 2
        bin_index = min(
            prediction.confidence_bps // CALIBRATION_BIN_WIDTH_BPS,
            CALIBRATION_BIN_COUNT - 1,
        )
        bins[bin_index]["count"] += 1
        bins[bin_index]["positive_count"] += int(case.expected_acceptable)
        bins[bin_index]["confidence_sum_bps"] += prediction.confidence_bps

    sample_count = len(corpus.cases)
    precision_bps = _ratio_bps(true_positive, true_positive + false_positive)
    recall_bps = _ratio_bps(true_positive, true_positive + false_negative)
    brier_ppm = _round_ratio(squared_error_sum, sample_count * 100)
    calibration_bins, ece_bps = _build_calibration_bins(bins, sample_count)

    precision_denominator = true_positive + false_positive
    recall_denominator = true_positive + false_negative
    absolute_gap_sum = sum(
        values["absolute_gap_sum_bps"] for values in calibration_bins
    )
    checks = {
        "minimum_sample_count": sample_count >= policy.minimum_cases,
        "minimum_class_count": (
            true_positive + false_negative >= policy.minimum_class_cases
            and true_negative + false_positive >= policy.minimum_class_cases
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
        "maximum_brier_score": (
            squared_error_sum <= policy.maximum_brier_score_ppm * sample_count * 100
        ),
        "maximum_expected_calibration_error": (
            absolute_gap_sum
            <= policy.maximum_expected_calibration_error_bps * sample_count
        ),
    }
    input_digest = hashlib.sha256(
        EVALUATION_INPUT_DOMAIN
        + bytes.fromhex(corpus.sha256)
        + bytes.fromhex(prediction_set.sha256)
        + bytes.fromhex(policy.sha256)
    ).hexdigest()
    return {
        "schema_version": SCHEMA_VERSION,
        "evaluator_version": EVALUATOR_VERSION,
        "evidence_class": evidence_class,
        "production_authorized": False,
        "disclaimer": disclaimer,
        "corpus_id": corpus.corpus_id,
        "corpus_sha256": corpus.sha256,
        "predictions_sha256": prediction_set.sha256,
        "policy_sha256": policy.sha256,
        "evaluation_input_digest": input_digest,
        "evaluation_mode": prediction_set.evaluation_mode,
        "subject_id": prediction_set.subject_id,
        "subject_sha256": prediction_set.subject_sha256,
        "prompt_sha256": prediction_set.prompt_sha256,
        "sample_count": sample_count,
        "threshold_bps": policy.threshold_bps,
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
            "brier_score": {
                "sum_squared_error_bps2": squared_error_sum,
                "sample_count": sample_count,
                "ppm": brier_ppm,
            },
            "expected_calibration_error": {
                "absolute_gap_sum_bps": absolute_gap_sum,
                "sample_count": sample_count,
                "bps": ece_bps,
            },
        },
        "calibration_bins": calibration_bins,
        "policy": {
            "minimum_cases": policy.minimum_cases,
            "minimum_class_cases": policy.minimum_class_cases,
            "minimum_precision_bps": policy.minimum_precision_bps,
            "minimum_recall_bps": policy.minimum_recall_bps,
            "maximum_brier_score_ppm": policy.maximum_brier_score_ppm,
            "maximum_expected_calibration_error_bps": (
                policy.maximum_expected_calibration_error_bps
            ),
        },
        "checks": checks,
        "gate_pass": all(checks.values()),
    }


def canonical_report_bytes(report: Mapping[str, Any]) -> bytes:
    """Serialize one report in stable compact JSON with a final newline."""
    if type(report) is not dict:
        raise ConfidenceEvaluationError()
    return (json.dumps(report, separators=(",", ":"), ensure_ascii=True) + "\n").encode(
        "ascii"
    )


def evaluate_candidate_set(
    corpus_bytes: bytes, predictions_bytes: bytes, policy_bytes: bytes
) -> bytes:
    """Evaluate canonical local-model candidate predictions offline."""
    corpus = parse_corpus(corpus_bytes)
    predictions = parse_predictions(predictions_bytes, corpus)
    if predictions.evaluation_mode != LOCAL_MODEL_EVALUATION_MODE:
        raise ConfidenceEvaluationError()
    policy = parse_policy(policy_bytes)
    return canonical_report_bytes(evaluate_confidence(corpus, predictions, policy))


def verify_fixture_set(
    corpus_bytes: bytes,
    predictions_bytes: bytes,
    policy_bytes: bytes,
    expected_report_bytes: bytes,
    manifest_bytes: bytes,
) -> bytes:
    """Verify all fixture hashes and return the reproduced exact report."""
    corpus = parse_corpus(corpus_bytes)
    predictions = parse_predictions(predictions_bytes, corpus)
    policy = parse_policy(policy_bytes)
    manifest = parse_integrity_manifest(manifest_bytes)
    if (
        manifest.corpus_sha256 != corpus.sha256
        or manifest.predictions_sha256 != predictions.sha256
        or manifest.policy_sha256 != policy.sha256
        or manifest.expected_report_sha256
        != hashlib.sha256(expected_report_bytes).hexdigest()
    ):
        raise ConfidenceEvaluationError()
    expected_report = _parse_canonical_json(expected_report_bytes, MAX_REPORT_BYTES)
    reproduced = canonical_report_bytes(
        evaluate_confidence(corpus, predictions, policy)
    )
    if reproduced != expected_report_bytes or expected_report != json.loads(reproduced):
        raise ConfidenceEvaluationError()
    return reproduced


def _build_calibration_bins(
    bins: Sequence[Mapping[str, int]], sample_count: int
) -> tuple[list[Dict[str, Any]], int]:
    """Render fixed bins and return their exact aggregate gap."""
    output: list[Dict[str, Any]] = []
    absolute_gap_sum = 0
    for index, values in enumerate(bins):
        count = values["count"]
        positive_count = values["positive_count"]
        confidence_sum_bps = values["confidence_sum_bps"]
        lower_bps = index * CALIBRATION_BIN_WIDTH_BPS
        upper_bps = (
            10_000
            if index == CALIBRATION_BIN_COUNT - 1
            else lower_bps + CALIBRATION_BIN_WIDTH_BPS - 1
        )
        if count == 0:
            mean_confidence_bps = None
            observed_positive_bps = None
            absolute_gap_bps = None
        else:
            mean_confidence_bps = _round_ratio(confidence_sum_bps, count)
            observed_positive_bps = _ratio_bps(positive_count, count)
            absolute_gap_bps = _round_ratio(
                abs(confidence_sum_bps - positive_count * 10_000), count
            )
            absolute_gap_sum += abs(confidence_sum_bps - positive_count * 10_000)
        output.append(
            {
                "index": index,
                "lower_bps": lower_bps,
                "upper_bps": upper_bps,
                "count": count,
                "positive_count": positive_count,
                "mean_confidence_bps": mean_confidence_bps,
                "observed_positive_bps": observed_positive_bps,
                "absolute_gap_bps": absolute_gap_bps,
                "absolute_gap_sum_bps": abs(
                    confidence_sum_bps - positive_count * 10_000
                ),
            }
        )
    return output, _round_ratio(absolute_gap_sum, sample_count)


def _parse_case(value: Mapping[str, Any]) -> BenchmarkCase:
    """Validate one exact-shape synthetic benchmark case."""
    expected_keys = [
        "case_id",
        "category",
        "threat_description",
        "yara_rule",
        "expected_acceptable",
    ]
    if type(value) is not dict or list(value) != expected_keys:
        raise ConfidenceEvaluationError()
    expected_acceptable = value["expected_acceptable"]
    if type(expected_acceptable) is not bool:
        raise ConfidenceEvaluationError()
    return BenchmarkCase(
        case_id=_identifier(value["case_id"], 64),
        category=_identifier(value["category"], 64),
        threat_description=_bounded_ascii_text(value["threat_description"], 2_048),
        yara_rule=_bounded_ascii_text(value["yara_rule"], 4_096),
        expected_acceptable=expected_acceptable,
    )


def _parse_prediction(value: Mapping[str, Any]) -> ConfidencePrediction:
    """Validate one exact-shape confidence prediction."""
    if type(value) is not dict or list(value) != ["case_id", "confidence_bps"]:
        raise ConfidenceEvaluationError()
    confidence_bps = _exact_int(value["confidence_bps"])
    if confidence_bps > 10_000:
        raise ConfidenceEvaluationError()
    return ConfidencePrediction(
        case_id=_identifier(value["case_id"], 64),
        confidence_bps=confidence_bps,
    )


def _validate_evaluation_inputs(
    corpus: BenchmarkCorpus, prediction_set: PredictionSet, policy: GatePolicy
) -> None:
    """Revalidate parsed runtime objects before metric calculation."""
    if (
        _lower_hex_32(corpus.sha256) != prediction_set.corpus_sha256
        or _lower_hex_32(prediction_set.sha256) != prediction_set.sha256
        or _nonzero_lower_hex_32(prediction_set.subject_sha256)
        != prediction_set.subject_sha256
        or _nonzero_lower_hex_32(prediction_set.prompt_sha256)
        != prediction_set.prompt_sha256
        or prediction_set.evaluation_mode
        not in (EVALUATION_MODE, LOCAL_MODEL_EVALUATION_MODE)
        or _subject_identifier(prediction_set.subject_id, 128)
        != prediction_set.subject_id
        or policy.threshold_bps != SUBMISSION_THRESHOLD_BPS
        or policy.calibration_bin_width_bps != CALIBRATION_BIN_WIDTH_BPS
        or policy.minimum_cases != MIN_CASES
        or policy.minimum_class_cases != MIN_CLASS_CASES
        or policy.minimum_precision_bps != MIN_PRECISION_BPS
        or policy.minimum_recall_bps != MIN_RECALL_BPS
        or policy.maximum_brier_score_ppm != MAX_BRIER_PPM
        or policy.maximum_expected_calibration_error_bps != MAX_ECE_BPS
        or _lower_hex_32(policy.sha256) != policy.sha256
    ):
        raise ConfidenceEvaluationError()
    case_ids = []
    prediction_ids = []
    for case, prediction in zip(corpus.cases, prediction_set.predictions):
        if (
            type(case) is not BenchmarkCase
            or type(prediction) is not ConfidencePrediction
        ):
            raise ConfidenceEvaluationError()
        if type(case.expected_acceptable) is not bool:
            raise ConfidenceEvaluationError()
        _identifier(case.case_id, 64)
        _identifier(case.category, 64)
        _bounded_ascii_text(case.threat_description, 2_048)
        _bounded_ascii_text(case.yara_rule, 4_096)
        if (
            type(prediction.confidence_bps) is not int
            or not 0 <= prediction.confidence_bps <= 10_000
            or prediction.case_id != case.case_id
        ):
            raise ConfidenceEvaluationError()
        case_ids.append(case.case_id)
        prediction_ids.append(prediction.case_id)
    if (
        case_ids != sorted(case_ids)
        or len(set(case_ids)) != len(case_ids)
        or prediction_ids != case_ids
        or sum(case.expected_acceptable for case in corpus.cases) < MIN_CLASS_CASES
        or sum(not case.expected_acceptable for case in corpus.cases) < MIN_CLASS_CASES
    ):
        raise ConfidenceEvaluationError()


def _parse_canonical_jsonl(
    raw_bytes: bytes, maximum_bytes: int
) -> list[Dict[str, Any]]:
    """Parse size-bounded compact ASCII JSONL with exact byte identity."""
    if (
        type(raw_bytes) is not bytes
        or not raw_bytes
        or len(raw_bytes) > maximum_bytes
        or not raw_bytes.endswith(b"\n")
    ):
        raise ConfidenceEvaluationError()
    raw_lines = raw_bytes.splitlines(keepends=True)
    if len(raw_lines) < 2:
        raise ConfidenceEvaluationError()
    decoded: list[Dict[str, Any]] = []
    for raw_line in raw_lines:
        if not raw_line.endswith(b"\n") or len(raw_line) > MAX_LINE_BYTES:
            raise ConfidenceEvaluationError()
        try:
            value = json.loads(
                raw_line[:-1].decode("ascii"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_json_constant,
            )
        except (UnicodeDecodeError, ValueError):
            raise ConfidenceEvaluationError() from None
        if type(value) is not dict:
            raise ConfidenceEvaluationError()
        canonical = (
            json.dumps(value, separators=(",", ":"), ensure_ascii=True) + "\n"
        ).encode("ascii")
        if canonical != raw_line:
            raise ConfidenceEvaluationError()
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
        raise ConfidenceEvaluationError()
    try:
        value = json.loads(
            raw_bytes[:-1].decode("ascii"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, ValueError):
        raise ConfidenceEvaluationError() from None
    if type(value) is not dict:
        raise ConfidenceEvaluationError()
    canonical = (
        json.dumps(value, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("ascii")
    if canonical != raw_bytes:
        raise ConfidenceEvaluationError()
    return value


def _reject_duplicate_keys(items: Iterable[tuple[str, Any]]) -> Dict[str, Any]:
    """Build a mapping while rejecting duplicate JSON member names."""
    output: Dict[str, Any] = {}
    for key, value in items:
        if key in output:
            raise ConfidenceEvaluationError()
        output[key] = value
    return output


def _reject_json_constant(_value: str) -> None:
    """Reject non-standard JSON numeric constants."""
    raise ConfidenceEvaluationError()


def _exact_int(value: Any) -> int:
    """Require a non-negative literal integer, excluding booleans."""
    if type(value) is not int or value < 0:
        raise ConfidenceEvaluationError()
    return value


def _identifier(value: Any, maximum_length: int) -> str:
    """Validate one bounded lowercase identifier."""
    if (
        type(value) is not str
        or len(value) < 3
        or len(value) > maximum_length
        or _IDENTIFIER_RE.fullmatch(value) is None
    ):
        raise ConfidenceEvaluationError()
    return value


def _subject_identifier(value: Any, maximum_length: int) -> str:
    """Validate one relative public model/subject identifier."""
    if (
        type(value) is not str
        or not 1 <= len(value) <= maximum_length
        or _SUBJECT_IDENTIFIER_RE.fullmatch(value) is None
    ):
        raise ConfidenceEvaluationError()
    components = value.split("/")
    if any(component in ("", ".", "..") for component in components):
        raise ConfidenceEvaluationError()
    return value


def _bounded_ascii_text(value: Any, maximum_length: int) -> str:
    """Validate bounded printable ASCII plus normal text whitespace."""
    if (
        type(value) is not str
        or not value
        or len(value) > maximum_length
        or any(
            character not in "\n\r\t" and not " " <= character <= "~"
            for character in value
        )
    ):
        raise ConfidenceEvaluationError()
    return value


def _lower_hex_32(value: Any) -> str:
    """Validate one canonical lowercase 32-byte hexadecimal value."""
    if type(value) is not str or _LOWER_HEX_32_RE.fullmatch(value) is None:
        raise ConfidenceEvaluationError()
    return value


def _nonzero_lower_hex_32(value: Any) -> str:
    """Validate one nonzero canonical lowercase 32-byte hash."""
    parsed = _lower_hex_32(value)
    if parsed == "0" * 64:
        raise ConfidenceEvaluationError()
    return parsed


def _round_ratio(numerator: int, denominator: int) -> int:
    """Round a non-negative rational to the nearest integer, halves up."""
    if denominator <= 0 or numerator < 0:
        raise ConfidenceEvaluationError()
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
            raise ConfidenceEvaluationError()
        if path.stat().st_size > maximum_bytes:
            raise ConfidenceEvaluationError()
        raw_bytes = path.read_bytes()
    except OSError:
        raise ConfidenceEvaluationError() from None
    if len(raw_bytes) > maximum_bytes:
        raise ConfidenceEvaluationError()
    return raw_bytes


def _main(argv: Sequence[str] | None = None) -> int:
    """Run fixture verification or local-candidate evaluation offline."""
    parser = argparse.ArgumentParser(
        description="Evaluate canonical Guardian confidence evidence offline."
    )
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--predictions", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--expected-report", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument(
        "--candidate",
        action="store_true",
        help="evaluate local_model_candidate predictions without fixture files",
    )
    args = parser.parse_args(argv)
    try:
        corpus_bytes = _read_bounded(args.corpus, MAX_CORPUS_BYTES)
        predictions_bytes = _read_bounded(args.predictions, MAX_PREDICTIONS_BYTES)
        policy_bytes = _read_bounded(args.policy, MAX_POLICY_BYTES)
        if args.candidate:
            if args.expected_report is not None or args.manifest is not None:
                raise ConfidenceEvaluationError()
            report_bytes = evaluate_candidate_set(
                corpus_bytes, predictions_bytes, policy_bytes
            )
        else:
            if args.expected_report is None or args.manifest is None:
                raise ConfidenceEvaluationError()
            report_bytes = verify_fixture_set(
                corpus_bytes,
                predictions_bytes,
                policy_bytes,
                _read_bounded(args.expected_report, MAX_REPORT_BYTES),
                _read_bounded(args.manifest, MAX_MANIFEST_BYTES),
            )
    except ConfidenceEvaluationError:
        print("confidence evaluation failed", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(report_bytes)
    return 0 if json.loads(report_bytes)["gate_pass"] else 1


_IDENTIFIER_RE = re.compile(r"[a-z0-9][a-z0-9._-]*")
_SUBJECT_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*")
_LOWER_HEX_32_RE = re.compile(r"[0-9a-f]{64}")


if __name__ == "__main__":
    raise SystemExit(_main())
