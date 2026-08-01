"""Tests for the deterministic Guardian confidence calibration gate."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from jaeger.confidence_calibration import (
    BenchmarkCase,
    ConfidenceEvaluationError,
    ConfidencePrediction,
    canonical_report_bytes,
    evaluate_confidence,
    parse_corpus,
    parse_integrity_manifest,
    parse_policy,
    parse_predictions,
    verify_fixture_set,
)

VECTOR_ROOT = Path(__file__).parent / "vectors" / "confidence-calibration-v1"


def _read(name: str) -> bytes:
    return (VECTOR_ROOT / name).read_bytes()


def _load_fixture_set() -> tuple[bytes, bytes, bytes, bytes, bytes]:
    return (
        _read("corpus.jsonl"),
        _read("predictions.jsonl"),
        _read("policy.json"),
        _read("expected-report.json"),
        _read("integrity-manifest.json"),
    )


def _jsonl(values: list[dict[str, object]]) -> bytes:
    return b"".join(
        (json.dumps(value, separators=(",", ":"), ensure_ascii=True) + "\n").encode(
            "ascii"
        )
        for value in values
    )


def _decode_jsonl(raw_bytes: bytes) -> list[dict[str, object]]:
    return [json.loads(line) for line in raw_bytes.decode("ascii").splitlines()]


def _parsed_fixture():
    corpus = parse_corpus(_read("corpus.jsonl"))
    predictions = parse_predictions(_read("predictions.jsonl"), corpus)
    policy = parse_policy(_read("policy.json"))
    return corpus, predictions, policy


def _replace_confidences(prediction_set, values: list[int]):
    assert len(values) == len(prediction_set.predictions)
    return replace(
        prediction_set,
        predictions=tuple(
            ConfidencePrediction(prediction.case_id, confidence)
            for prediction, confidence in zip(prediction_set.predictions, values)
        ),
    )


def _write_fixture_set(root: Path, confidence_values: list[int]) -> bytes:
    root.mkdir()
    corpus_bytes = _read("corpus.jsonl")
    policy_bytes = _read("policy.json")
    corpus = parse_corpus(corpus_bytes)
    values = _decode_jsonl(_read("predictions.jsonl"))
    for row, confidence in zip(values[1:], confidence_values):
        row["confidence_bps"] = confidence
    predictions_bytes = _jsonl(values)
    predictions = parse_predictions(predictions_bytes, corpus)
    policy = parse_policy(policy_bytes)
    report_bytes = canonical_report_bytes(
        evaluate_confidence(corpus, predictions, policy)
    )
    manifest = {
        "schema_version": 1,
        "evaluator_version": "guardian-confidence-eval-v1",
        "corpus_sha256": hashlib.sha256(corpus_bytes).hexdigest(),
        "predictions_sha256": hashlib.sha256(predictions_bytes).hexdigest(),
        "policy_sha256": hashlib.sha256(policy_bytes).hexdigest(),
        "expected_report_sha256": hashlib.sha256(report_bytes).hexdigest(),
    }
    files = {
        "corpus.jsonl": corpus_bytes,
        "predictions.jsonl": predictions_bytes,
        "policy.json": policy_bytes,
        "expected-report.json": report_bytes,
        "integrity-manifest.json": (
            json.dumps(manifest, separators=(",", ":")) + "\n"
        ).encode(),
    }
    for name, contents in files.items():
        (root / name).write_bytes(contents)
    return report_bytes


def _run_cli(root: Path) -> subprocess.CompletedProcess[bytes]:
    guardian_root = Path(__file__).parent.parent
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(guardian_root)
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "jaeger.confidence_calibration",
            "--corpus",
            str(root / "corpus.jsonl"),
            "--predictions",
            str(root / "predictions.jsonl"),
            "--policy",
            str(root / "policy.json"),
            "--expected-report",
            str(root / "expected-report.json"),
            "--manifest",
            str(root / "integrity-manifest.json"),
        ],
        cwd=guardian_root,
        env=environment,
        capture_output=True,
        check=False,
    )


def test_committed_fixture_reproduces_exact_report() -> None:
    """All five internally consistent fixtures reproduce one byte-exact report."""
    reproduced = verify_fixture_set(*_load_fixture_set())
    assert reproduced == _read("expected-report.json")
    assert verify_fixture_set(*_load_fixture_set()) == reproduced


def test_cli_returns_one_with_exact_report_when_valid_gate_fails(
    tmp_path: Path,
) -> None:
    """Valid but below-policy evidence emits its report and exits one."""
    root = tmp_path / "failing-fixture"
    expected_report = _write_fixture_set(root, [0] * 24)

    completed = _run_cli(root)

    assert completed.returncode == 1
    assert completed.stdout == expected_report
    assert completed.stderr == b""


def test_cli_returns_two_with_redacted_error_and_no_stdout(
    tmp_path: Path,
) -> None:
    """Invalid evidence exposes no file path, input content, or partial report."""
    root = tmp_path / "invalid-fixture"
    _write_fixture_set(root, [0] * 24)
    (root / "corpus.jsonl").write_bytes(b"sensitive invalid evidence\n")

    completed = _run_cli(root)

    assert completed.returncode == 2
    assert completed.stdout == b""
    assert completed.stderr == b"confidence evaluation failed\n"
    assert b"sensitive" not in completed.stderr
    assert str(root).encode() not in completed.stderr


def test_report_metrics_and_non_authority_are_exact() -> None:
    """The synthetic fixture has hand-checked integer metrics and no authority."""
    corpus, predictions, policy = _parsed_fixture()
    report = evaluate_confidence(corpus, predictions, policy)

    assert report["production_authorized"] is False
    assert report["evidence_class"] == "synthetic_ci_only"
    assert report["threshold_bps"] == 8_500
    assert report["confusion_matrix"] == {
        "true_positive": 11,
        "false_positive": 1,
        "true_negative": 11,
        "false_negative": 1,
    }
    assert report["metrics"] == {
        "precision": {"numerator": 11, "denominator": 12, "bps": 9_167},
        "recall": {"numerator": 11, "denominator": 12, "bps": 9_167},
        "brier_score": {
            "sum_squared_error_bps2": 86_640_000,
            "sample_count": 24,
            "ppm": 36_100,
        },
        "expected_calibration_error": {
            "absolute_gap_sum_bps": 18_000,
            "sample_count": 24,
            "bps": 750,
        },
    }
    assert report["gate_pass"] is True


def test_threshold_uses_8499_8500_boundary() -> None:
    """The unchanged submission policy treats exactly 8500 as positive."""
    corpus, predictions, policy = _parsed_fixture()
    values = [8_500] * 12 + [8_499] * 12
    report = evaluate_confidence(
        corpus, _replace_confidences(predictions, values), policy
    )
    assert report["confusion_matrix"] == {
        "true_positive": 12,
        "false_positive": 0,
        "true_negative": 12,
        "false_negative": 0,
    }


def test_gate_uses_exact_precision_ratio_not_rounded_display() -> None:
    """Policy decisions compare integer cross-products, not display values."""
    corpus, predictions, policy = _parsed_fixture()
    exact_boundary = [8_500] * 9 + [0] * 3 + [8_500] + [0] * 11
    exact_report = evaluate_confidence(
        corpus, _replace_confidences(predictions, exact_boundary), policy
    )
    assert exact_report["metrics"]["precision"] == {
        "numerator": 9,
        "denominator": 10,
        "bps": 9_000,
    }
    assert exact_report["checks"]["minimum_precision"] is True

    below_boundary = [8_500] * 8 + [0] * 4 + [8_500] + [0] * 11
    below_report = evaluate_confidence(
        corpus, _replace_confidences(predictions, below_boundary), policy
    )
    assert below_report["metrics"]["precision"]["bps"] == 8_889
    assert below_report["checks"]["minimum_precision"] is False


def test_undefined_precision_fails_gate() -> None:
    """A result set with no positive decision cannot pass precision policy."""
    corpus, predictions, policy = _parsed_fixture()
    report = evaluate_confidence(
        corpus, _replace_confidences(predictions, [0] * 24), policy
    )
    assert report["metrics"]["precision"] == {
        "numerator": 0,
        "denominator": 0,
        "bps": None,
    }
    assert report["checks"]["minimum_precision"] is False
    assert report["gate_pass"] is False


def test_prompt_injection_text_is_inert_benchmark_data() -> None:
    """Model-facing accessors omit labels and preserve injection text as data."""
    corpus = parse_corpus(_read("corpus.jsonl"))
    injection_case = next(case for case in corpus.cases if case.case_id == "reject-06")
    description, rule = injection_case.assessment_input
    assert "Ignore prior instructions" in description
    assert "filesize >= 0" in rule
    assert injection_case.expected_acceptable is False
    assert len(injection_case.assessment_input) == 2


@pytest.mark.parametrize(
    "mutator",
    [
        lambda raw: raw[:-1],
        lambda raw: b" " + raw,
        lambda raw: raw.replace(
            b'{"schema_version":1,',
            b'{"schema_version":1,"schema_version":1,',
            1,
        ),
        lambda raw: raw.replace(b'"schema_version":1', b'"schema_version":1.0', 1),
        lambda raw: raw.replace(b'"schema_version":1', b'"schema_version":NaN', 1),
        lambda raw: b"\xff" + raw[1:],
    ],
)
def test_corpus_rejects_noncanonical_or_ambiguous_bytes(mutator) -> None:
    """Whitespace, duplicates, floats, constants, and non-ASCII fail closed."""
    with pytest.raises(ConfidenceEvaluationError):
        parse_corpus(mutator(_read("corpus.jsonl")))


def test_corpus_rejects_unsorted_duplicate_and_class_imbalanced_cases() -> None:
    """Case order, identity uniqueness, and both semantic classes are required."""
    values = _decode_jsonl(_read("corpus.jsonl"))
    unsorted_values = [values[0], values[2], values[1], *values[3:]]
    duplicate_values = [*values, dict(values[-1])]
    imbalanced_values = [dict(value) for value in values]
    for value in imbalanced_values[1:]:
        value["expected_acceptable"] = False

    for candidate in (unsorted_values, duplicate_values, imbalanced_values):
        with pytest.raises(ConfidenceEvaluationError):
            parse_corpus(_jsonl(candidate))


@pytest.mark.parametrize(
    "invalid_confidence",
    [True, False, -1, 10_001, 8_500.0, "8500", None, float("nan")],
)
def test_predictions_reject_invalid_confidence_types_and_ranges(
    invalid_confidence: object,
) -> None:
    """Only literal integers from zero through 10000 are accepted."""
    corpus = parse_corpus(_read("corpus.jsonl"))
    values = _decode_jsonl(_read("predictions.jsonl"))
    values[1]["confidence_bps"] = invalid_confidence
    with pytest.raises(ConfidenceEvaluationError):
        parse_predictions(_jsonl(values), corpus)


def test_predictions_reject_missing_unknown_reordered_and_extra_rows() -> None:
    """Every benchmark case must appear exactly once and in canonical order."""
    corpus = parse_corpus(_read("corpus.jsonl"))
    values = _decode_jsonl(_read("predictions.jsonl"))
    missing = values[:-1]
    unknown = [dict(value) for value in values]
    unknown[-1]["case_id"] = "unknown-99"
    reordered = [values[0], values[2], values[1], *values[3:]]
    extra = [*values, dict(values[-1])]

    for candidate in (missing, unknown, reordered, extra):
        with pytest.raises(ConfidenceEvaluationError):
            parse_predictions(_jsonl(candidate), corpus)


def test_predictions_reject_corpus_hash_and_metadata_tampering() -> None:
    """Corpus, subject, prompt, mode, and closed header remain bound."""
    corpus = parse_corpus(_read("corpus.jsonl"))
    values = _decode_jsonl(_read("predictions.jsonl"))
    mutations = [
        ("corpus_sha256", "1" * 64),
        ("subject_sha256", "0" * 64),
        ("prompt_sha256", "0" * 64),
        ("evaluation_mode", "production"),
        ("evaluation_mode", "live_candidate"),
    ]
    for key, replacement in mutations:
        candidate = [dict(value) for value in values]
        candidate[0][key] = replacement
        with pytest.raises(ConfidenceEvaluationError):
            parse_predictions(_jsonl(candidate), corpus)


def test_policy_rejects_weakened_thresholds_and_claims() -> None:
    """The committed policy cannot silently weaken metrics or gain authority."""
    policy = json.loads(_read("policy.json"))
    mutations = {
        "threshold_bps": 8_499,
        "minimum_precision_bps": 0,
        "maximum_brier_score_ppm": 1_000_000,
        "authority": "production",
        "disclaimer": "production calibrated",
    }
    for key, replacement in mutations.items():
        candidate = dict(policy)
        candidate[key] = replacement
        raw = (json.dumps(candidate, separators=(",", ":")) + "\n").encode()
        with pytest.raises(ConfidenceEvaluationError):
            parse_policy(raw)


def test_manifest_and_expected_report_tampering_fail_closed() -> None:
    """No fixture or expected evidence can change without manifest refresh."""
    corpus, predictions, policy, report, manifest = _load_fixture_set()
    parsed_manifest = parse_integrity_manifest(manifest)
    assert parsed_manifest.expected_report_sha256

    tampered_report = report.replace(b'"gate_pass":true', b'"gate_pass":false')
    with pytest.raises(ConfidenceEvaluationError):
        verify_fixture_set(corpus, predictions, policy, tampered_report, manifest)

    manifest_value = json.loads(manifest)
    manifest_value["corpus_sha256"] = "1" * 64
    tampered_manifest = (
        json.dumps(manifest_value, separators=(",", ":")) + "\n"
    ).encode()
    with pytest.raises(ConfidenceEvaluationError):
        verify_fixture_set(corpus, predictions, policy, report, tampered_manifest)


def test_direct_invalid_runtime_objects_fail_closed() -> None:
    """Bypassing parsers cannot inject bool or out-of-range confidence."""
    corpus, predictions, policy = _parsed_fixture()
    invalid = replace(
        predictions,
        predictions=(
            ConfidencePrediction(predictions.predictions[0].case_id, True),
            *predictions.predictions[1:],
        ),
    )
    with pytest.raises(ConfidenceEvaluationError):
        evaluate_confidence(corpus, invalid, policy)

    forged_case = BenchmarkCase(
        corpus.cases[0].case_id,
        corpus.cases[0].category,
        corpus.cases[0].threat_description,
        corpus.cases[0].yara_rule,
        1,  # type: ignore[arg-type]
    )
    with pytest.raises(ConfidenceEvaluationError):
        evaluate_confidence(
            replace(corpus, cases=(forged_case, *corpus.cases[1:])),
            predictions,
            policy,
        )


def test_report_serialization_rejects_non_dict() -> None:
    """Only the exact report object shape enters canonical serialization."""
    with pytest.raises(ConfidenceEvaluationError):
        canonical_report_bytes([])  # type: ignore[arg-type]
