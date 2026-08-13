"""Tests for the GH-177 synthetic YARA semantic-quality gate."""

# Exact-type checks intentionally reject subclasses of bytes/int.
# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

import ast
from dataclasses import replace
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yara_x

from jaeger import yara_semantic_quality as quality
from jaeger.yara_semantic_quality import (
    MAX_CORPUS_BYTES,
    MAX_LINE_BYTES,
    NON_AUTHORITY_DISCLAIMER,
    YaraSemanticQualityError,
    canonical_report_bytes,
    evaluate_quality,
    parse_corpus,
    parse_integrity_manifest,
    parse_policy,
    verify_fixture_set,
)

VECTOR_ROOT = Path(__file__).parent / "vectors" / "yara-semantic-quality-v1"
MODULE_PATH = Path(__file__).parent.parent / "jaeger" / "yara_semantic_quality.py"
STABLE_ERROR = "invalid yara semantic quality evidence"

ALPHA_MARKER = b"PROM-SYNTH-177-ALPHA"
BETA_HEX = "50524f4d2d3137372d42455441001f"


def _read(name: str) -> bytes:
    """Read one committed semantic-quality fixture."""
    return (VECTOR_ROOT / name).read_bytes()


def _jsonl(values: list[dict[str, object]]) -> bytes:
    """Serialize test mappings as compact canonical-style ASCII JSONL."""
    return b"".join(
        (json.dumps(value, separators=(",", ":"), ensure_ascii=True) + "\n").encode(
            "ascii"
        )
        for value in values
    )


def _decode_jsonl(raw_bytes: bytes) -> list[dict[str, object]]:
    """Decode trusted test JSONL for controlled fixture mutation."""
    return [json.loads(line) for line in raw_bytes.decode("ascii").splitlines()]


def _parsed_fixtures():
    """Return the parsed committed corpus and gate policy."""
    return parse_corpus(_read("corpus.jsonl")), parse_policy(_read("policy.json"))


def _corpus_with_cases(cases: list[dict[str, object]]) -> bytes:
    """Build a canonical corpus around replacement case rows."""
    header = {
        "schema_version": 1,
        "evidence_kind": "synthetic_offline",
        "authority": "none",
        "disclaimer": NON_AUTHORITY_DISCLAIMER,
        "corpus_id": "yara-semantic-quality-corpus-v1",
    }
    return _jsonl([header, *cases])


def _case(case_id: str, expected_match: bool, segments: list[dict[str, object]]):
    """Build one canonical case row for synthetic corpus mutation."""
    return {
        "case_id": case_id,
        "expected_match": expected_match,
        "segments": segments,
    }


def _fill(value: int, count: int) -> dict[str, object]:
    """Build one fill segment."""
    return {"kind": "fill", "value": value, "count": count}


def _ascii(text: str) -> dict[str, object]:
    """Build one ascii segment."""
    return {"kind": "ascii", "text": text}


def _expect_stable_error(callable_object, *args) -> None:
    """Require the one stable redacted public validation error."""
    with pytest.raises(YaraSemanticQualityError) as excinfo:
        callable_object(*args)
    assert str(excinfo.value) == STABLE_ERROR


def test_fixture_set_verifies_with_byte_identity() -> None:
    """The committed fixture set reproduces the exact expected report."""
    reproduced = verify_fixture_set(
        _read("corpus.jsonl"),
        _read("policy.json"),
        _read("expected-report.json"),
        _read("integrity-manifest.json"),
    )
    assert reproduced == _read("expected-report.json")


def test_report_matches_expected_exactly() -> None:
    """Direct evaluation is byte-identical to the committed report."""
    corpus, policy = _parsed_fixtures()
    report = evaluate_quality(corpus, policy)
    assert canonical_report_bytes(report) == _read("expected-report.json")


def test_report_binds_corpus_policy_implementation_and_engine() -> None:
    """The report carries exact hashes and the pinned engine version."""
    corpus, policy = _parsed_fixtures()
    report = evaluate_quality(corpus, policy)
    assert report["schema_version"] == 1
    assert report["evaluator_version"] == "guardian-yara-semantic-quality-eval-v1"
    assert report["evidence_kind"] == "synthetic_offline"
    assert report["authority"] == "none"
    assert report["production_authorized"] is False
    assert report["disclaimer"] == NON_AUTHORITY_DISCLAIMER
    assert report["corpus_sha256"] == hashlib.sha256(_read("corpus.jsonl")).hexdigest()
    assert report["policy_sha256"] == hashlib.sha256(_read("policy.json")).hexdigest()
    assert (
        report["implementation_sha256"]
        == hashlib.sha256(MODULE_PATH.read_bytes()).hexdigest()
    )
    assert report["yara_x_version"] == "1.4.0"
    assert report["rule_sha256"] == quality.CANDIDATE_RULE_SHA256
    assert report["gate_pass"] is True
    assert all(report["checks"].values())


def test_committed_metrics_and_confusion_counts() -> None:
    """The committed corpus yields perfect precision, recall, specificity."""
    corpus, policy = _parsed_fixtures()
    report = evaluate_quality(corpus, policy)
    assert report["sample_count"] == 20
    assert report["confusion_matrix"] == {
        "true_positive": 10,
        "false_positive": 0,
        "true_negative": 10,
        "false_negative": 0,
    }
    metrics = report["metrics"]
    assert metrics["precision"] == {"numerator": 10, "denominator": 10, "bps": 10_000}
    assert metrics["recall"] == {"numerator": 10, "denominator": 10, "bps": 10_000}
    assert metrics["specificity"] == {"numerator": 10, "denominator": 10, "bps": 10_000}


def test_false_positive_flips_specificity_and_gate() -> None:
    """A relabeled matching case becomes one false positive and fails."""
    rows = _decode_jsonl(_read("corpus.jsonl"))
    rows[1]["expected_match"] = False  # case-001 payload matches the rule
    corpus = parse_corpus(_jsonl(rows))
    _, policy = _parsed_fixtures()
    report = evaluate_quality(corpus, policy)
    assert report["confusion_matrix"] == {
        "true_positive": 9,
        "false_positive": 1,
        "true_negative": 10,
        "false_negative": 0,
    }
    assert report["metrics"]["precision"]["bps"] == 9_000
    assert report["metrics"]["specificity"]["bps"] == 9_091
    assert report["metrics"]["recall"]["bps"] == 10_000
    assert report["checks"]["minimum_precision"] is False
    assert report["checks"]["minimum_specificity"] is False
    assert report["gate_pass"] is False


def test_false_negative_flips_recall_and_gate() -> None:
    """A relabeled non-matching case becomes one false negative and fails."""
    rows = _decode_jsonl(_read("corpus.jsonl"))
    rows[2]["expected_match"] = True  # case-002 payload never matches
    corpus = parse_corpus(_jsonl(rows))
    _, policy = _parsed_fixtures()
    report = evaluate_quality(corpus, policy)
    assert report["confusion_matrix"] == {
        "true_positive": 10,
        "false_positive": 0,
        "true_negative": 9,
        "false_negative": 1,
    }
    assert report["metrics"]["recall"]["bps"] == 9_091
    assert report["metrics"]["precision"]["bps"] == 10_000
    assert report["checks"]["minimum_recall"] is False
    assert report["gate_pass"] is False


def test_precision_is_null_only_when_undefined() -> None:
    """Precision is null exactly when the rule matches no payload."""
    cases = []
    for index in range(20):
        cases.append(
            _case(
                f"case-{index + 1:03d}",
                index < 10,
                [_ascii(f"harmless filler {index:03d} without any marker")],
            )
        )
    corpus = parse_corpus(_corpus_with_cases(cases))
    _, policy = _parsed_fixtures()
    report = evaluate_quality(corpus, policy)
    assert report["confusion_matrix"]["true_positive"] == 0
    assert report["metrics"]["precision"] == {
        "numerator": 0,
        "denominator": 0,
        "bps": None,
    }
    assert report["metrics"]["recall"]["bps"] == 0
    assert report["metrics"]["specificity"]["bps"] == 10_000
    assert report["gate_pass"] is False


def test_malformed_and_noncanonical_corpus_rejected() -> None:
    """Broken JSON, duplicate keys, and noncanonical bytes fail closed."""
    corpus_bytes = _read("corpus.jsonl")
    _expect_stable_error(parse_corpus, b"not json\n")
    _expect_stable_error(parse_corpus, corpus_bytes.rstrip(b"\n"))
    _expect_stable_error(parse_corpus, b"")
    _expect_stable_error(parse_corpus, corpus_bytes + b" " * MAX_CORPUS_BYTES)
    rows = _decode_jsonl(corpus_bytes)
    _expect_stable_error(
        parse_corpus, json.dumps(rows[0]).encode("ascii") + b"\n" + corpus_bytes
    )
    duplicate = corpus_bytes.replace(
        b'"schema_version":1,', b'"schema_version":1,"schema_version":1,', 1
    )
    _expect_stable_error(parse_corpus, duplicate)
    long_line = dict(rows[1])
    long_line["pad"] = "x" * MAX_LINE_BYTES
    _expect_stable_error(parse_corpus, _jsonl([rows[0], long_line, *rows[2:]]))


def test_corpus_structure_bounds_enforced() -> None:
    """Case count, class coverage, ordering, and uniqueness are enforced."""
    rows = _decode_jsonl(_read("corpus.jsonl"))
    _expect_stable_error(parse_corpus, _jsonl(rows[:19]))  # only 18 cases
    extra = dict(rows[-1])
    extra["case_id"] = "case-021"
    oversized = [dict(row) for row in rows] + [extra]
    while len(oversized) < 66:
        clone = dict(oversized[-1])
        clone["case_id"] = f"case-{len(oversized):03d}"
        oversized.append(clone)
    _expect_stable_error(parse_corpus, _jsonl(oversized))  # 65 cases

    swapped = [rows[0], rows[2], rows[1], *rows[3:]]
    _expect_stable_error(parse_corpus, _jsonl(swapped))  # unsorted ids
    duplicate_id = [rows[0], dict(rows[1]), *rows[2:]]
    duplicate_id[1]["case_id"] = rows[1]["case_id"]
    duplicate_id[2] = dict(rows[2])
    duplicate_id[2]["case_id"] = rows[1]["case_id"]
    _expect_stable_error(parse_corpus, _jsonl(duplicate_id))  # duplicate ids

    few_positives = [dict(row) for row in rows]
    for index in (1, 3, 5):  # rows[1::2] are the expected-match cases
        few_positives[index]["expected_match"] = False
    positives = sum(row["expected_match"] for row in few_positives[1:])
    assert positives == 7
    _expect_stable_error(parse_corpus, _jsonl(few_positives))


def test_segment_schema_and_payload_bounds_enforced() -> None:
    """Unknown kinds, bad keys, magic bytes, and oversize payloads fail."""
    base = [
        _case(f"case-{index + 1:03d}", index < 10, [_fill(32, 8)])
        for index in range(20)
    ]

    def with_segment(index: int, segments: list[dict[str, object]]) -> bytes:
        cases = [dict(case) for case in base]
        cases[index] = _case(f"case-{index + 1:03d}", index < 10, segments)
        return _corpus_with_cases(cases)

    _expect_stable_error(
        parse_corpus, with_segment(0, [{"kind": "blob", "value": "aa"}])
    )
    _expect_stable_error(parse_corpus, with_segment(0, []))
    _expect_stable_error(parse_corpus, with_segment(0, [_fill(32, 8)] * 9))
    _expect_stable_error(
        parse_corpus, with_segment(0, [{"kind": "fill", "count": 8, "value": 32}])
    )
    _expect_stable_error(parse_corpus, with_segment(0, [_fill(256, 8)]))
    _expect_stable_error(parse_corpus, with_segment(0, [_fill(True, 8)]))
    _expect_stable_error(parse_corpus, with_segment(0, [_fill(32, 4097)]))
    _expect_stable_error(parse_corpus, with_segment(0, [_fill(32, 4096), _fill(32, 1)]))
    _expect_stable_error(parse_corpus, with_segment(0, [_ascii("MZ" + "A" * 30)]))
    _expect_stable_error(
        parse_corpus, with_segment(0, [{"kind": "hex", "value": "7f454c46"}])
    )
    _expect_stable_error(
        parse_corpus, with_segment(0, [{"kind": "hex", "value": "cafebabe"}])
    )
    _expect_stable_error(
        parse_corpus, with_segment(0, [{"kind": "hex", "value": "ABC1"}])
    )
    _expect_stable_error(
        parse_corpus, with_segment(0, [{"kind": "digest_walk", "seed": 1, "count": 0}])
    )


def test_version_and_schema_failures() -> None:
    """Wrong schema versions and engine versions fail closed."""
    rows = _decode_jsonl(_read("corpus.jsonl"))
    wrong_schema = [dict(rows[0], schema_version=2), *rows[1:]]
    _expect_stable_error(parse_corpus, _jsonl(wrong_schema))

    policy = json.loads(_read("policy.json"))
    _expect_stable_error(parse_policy, _jsonl([dict(policy, schema_version=0)]))
    _expect_stable_error(parse_policy, b"{}")
    _expect_stable_error(
        parse_policy, _jsonl([dict(policy, minimum_precision_bps=9_999)])
    )
    _expect_stable_error(parse_policy, _jsonl([dict(policy, rule_sha256="1" * 64)]))

    manifest = json.loads(_read("integrity-manifest.json"))
    _expect_stable_error(
        parse_integrity_manifest, _jsonl([dict(manifest, schema_version=2)])
    )

    corpus_obj, policy_obj = _parsed_fixtures()
    original_version = quality.importlib.metadata.version
    quality.importlib.metadata.version = lambda _name: "9.9.9"
    try:
        _expect_stable_error(evaluate_quality, corpus_obj, policy_obj)
    finally:
        quality.importlib.metadata.version = original_version


def test_hash_binding_failures() -> None:
    """Any manifest or report hash drift fails fixture verification."""
    args = [
        _read("corpus.jsonl"),
        _read("policy.json"),
        _read("expected-report.json"),
        _read("integrity-manifest.json"),
    ]
    manifest = json.loads(args[3])
    for key in (
        "corpus_sha256",
        "policy_sha256",
        "implementation_sha256",
        "expected_report_sha256",
    ):
        bad_manifest = _jsonl([dict(manifest, **{key: "2" * 64})])
        _expect_stable_error(verify_fixture_set, *args[:3], bad_manifest)

    drifted_report = args[2].replace(b'"sample_count":20', b'"sample_count":21')
    assert drifted_report != args[2]
    _expect_stable_error(verify_fixture_set, args[0], args[1], drifted_report, args[3])


def test_report_contains_no_rule_source_or_payloads() -> None:
    """The report persists hashes only, never rule source or payload bytes."""
    report_bytes = _read("expected-report.json")
    forbidden = [
        ALPHA_MARKER,
        bytes.fromhex(BETA_HEX),
        BETA_HEX.encode("ascii"),
        quality.CANDIDATE_RULE_SOURCE.encode("ascii"),
        b"rule prometheus_gh177",
        b"strings:",
        b"condition:",
        b"segments",
        b"payload",
    ]
    for token in forbidden:
        assert token not in report_bytes


def test_scan_is_strictly_in_memory() -> None:
    """Every scan call receives transient bytes and nothing else."""
    seen: list[object] = []
    real_scanner = yara_x.Scanner

    class SpyScanner:  # pylint: disable=too-few-public-methods
        """Module-level Scanner wrapper recording every scan argument."""

        def __init__(self, rules: object) -> None:
            self._inner = real_scanner(rules)

        def scan(self, data, *args, **kwargs):
            """Record the scan subject, then delegate to real YARA-X."""
            seen.append(data)
            return self._inner.scan(data, *args, **kwargs)

    yara_x.Scanner = SpyScanner
    try:
        corpus, policy = _parsed_fixtures()
        evaluate_quality(corpus, policy)
    finally:
        yara_x.Scanner = real_scanner
    assert len(seen) == len(corpus.cases)
    assert all(type(item) is bytes and item for item in seen)


def test_direct_object_payload_cannot_bypass_synthetic_recipe() -> None:
    """Evaluation re-derives every payload instead of trusting dataclass bytes."""
    corpus, policy = _parsed_fixtures()
    first = corpus.cases[0]
    forged_case = replace(first, payload=b"arbitrary caller supplied bytes")
    forged_corpus = replace(corpus, cases=(forged_case, *corpus.cases[1:]))
    _expect_stable_error(evaluate_quality, forged_corpus, policy)


def test_direct_object_label_cannot_reuse_old_corpus_hash() -> None:
    """A relabeled direct object must not retain the parsed corpus digest."""
    corpus, policy = _parsed_fixtures()
    forged_case = replace(corpus.cases[0], expected_match=False)
    forged_corpus = replace(corpus, cases=(forged_case, *corpus.cases[1:]))
    _expect_stable_error(evaluate_quality, forged_corpus, policy)


def test_direct_policy_cannot_claim_an_unbound_digest() -> None:
    """Policy objects must reconstruct to the exact canonical policy hash."""
    corpus, policy = _parsed_fixtures()
    forged_policy = replace(policy, sha256="1" * 64)
    _expect_stable_error(evaluate_quality, corpus, forged_policy)


@pytest.mark.parametrize(
    "forged_segment",
    [
        quality.Segment(kind="fill", value=True, count=8),
        quality.Segment(kind="ascii", value="safe", count=3),
        quality.Segment(kind="hex", value="AA", count=1),
        quality.Segment(kind="digest_walk", value=True, count=8),
        quality.Segment(kind="unknown", value=0, count=8),
    ],
)
def test_direct_object_segments_are_fully_revalidated(forged_segment) -> None:
    """Direct Segment construction cannot bypass exact recipe validation."""
    corpus, policy = _parsed_fixtures()
    first = corpus.cases[0]
    forged_case = replace(first, segments=(forged_segment,))
    forged_corpus = replace(corpus, cases=(forged_case, *corpus.cases[1:]))
    _expect_stable_error(evaluate_quality, forged_corpus, policy)


def test_static_import_and_api_boundary() -> None:
    """The module imports only stdlib plus yara_x and no scan-path APIs."""
    source = MODULE_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.module is not None
            imported.add(node.module)
    allowed = {
        "__future__",
        "argparse",
        "hashlib",
        "importlib.metadata",
        "json",
        "re",
        "sys",
        "dataclasses",
        "pathlib",
        "typing",
        "yara_x",
    }
    assert imported <= allowed
    # AST import checks above already forbid every jaeger/production module;
    # the text scan below targets API shapes that prose never contains.
    for forbidden in (
        "scan_file",
        "scan_process",
        "scan_mem",
        "subprocess",
        "socket",
        "import os",
        "open(",
        "yara_validation",
        "yara_generator",
        "from jaeger",
        "from .",
    ):
        assert forbidden not in source


def test_cli_verifies_committed_fixtures() -> None:
    """The CLI prints the exact report and exits zero on gate pass."""
    result = _run_cli(
        "--corpus",
        str(VECTOR_ROOT / "corpus.jsonl"),
        "--policy",
        str(VECTOR_ROOT / "policy.json"),
        "--expected-report",
        str(VECTOR_ROOT / "expected-report.json"),
        "--manifest",
        str(VECTOR_ROOT / "integrity-manifest.json"),
    )
    assert result.returncode == 0
    assert result.stdout == _read("expected-report.json")
    assert result.stderr == b""


def test_cli_fails_closed_on_mismatch(tmp_path: Path) -> None:
    """The CLI exits two with one stable message on any mismatch."""
    bad_manifest = tmp_path / "integrity-manifest.json"
    manifest = json.loads(_read("integrity-manifest.json"))
    manifest["corpus_sha256"] = "3" * 64
    bad_manifest.write_bytes(_jsonl([manifest]))
    result = _run_cli(
        "--corpus",
        str(VECTOR_ROOT / "corpus.jsonl"),
        "--policy",
        str(VECTOR_ROOT / "policy.json"),
        "--expected-report",
        str(VECTOR_ROOT / "expected-report.json"),
        "--manifest",
        str(bad_manifest),
    )
    assert result.returncode == 2
    assert result.stdout == b""
    assert result.stderr == b"yara semantic quality evaluation failed\n"


def test_cli_exit_one_when_gate_fails(tmp_path: Path) -> None:
    """A verified but failing fixture set exits one with the exact report."""
    rows = _decode_jsonl(_read("corpus.jsonl"))
    rows[1]["expected_match"] = False  # introduces one false positive
    corpus_bytes = _jsonl(rows)
    corpus = parse_corpus(corpus_bytes)
    _, policy = _parsed_fixtures()
    report_bytes = canonical_report_bytes(evaluate_quality(corpus, policy))
    assert json.loads(report_bytes)["gate_pass"] is False
    manifest_bytes = _jsonl(
        [
            {
                "schema_version": 1,
                "evaluator_version": "guardian-yara-semantic-quality-eval-v1",
                "corpus_sha256": hashlib.sha256(corpus_bytes).hexdigest(),
                "policy_sha256": hashlib.sha256(_read("policy.json")).hexdigest(),
                "implementation_sha256": hashlib.sha256(
                    MODULE_PATH.read_bytes()
                ).hexdigest(),
                "expected_report_sha256": hashlib.sha256(report_bytes).hexdigest(),
            }
        ]
    )
    paths = {}
    for name, data in (
        ("corpus.jsonl", corpus_bytes),
        ("policy.json", _read("policy.json")),
        ("expected-report.json", report_bytes),
        ("integrity-manifest.json", manifest_bytes),
    ):
        target = tmp_path / name
        target.write_bytes(data)
        paths[name] = target
    result = _run_cli(
        "--corpus",
        str(paths["corpus.jsonl"]),
        "--policy",
        str(paths["policy.json"]),
        "--expected-report",
        str(paths["expected-report.json"]),
        "--manifest",
        str(paths["integrity-manifest.json"]),
    )
    assert result.returncode == 1
    assert result.stdout == report_bytes


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    """Run the evaluator CLI in a clean subprocess."""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(MODULE_PATH.parent.parent)
    return subprocess.run(
        [sys.executable, "-m", "jaeger.yara_semantic_quality", *args],
        capture_output=True,
        text=False,
        env=env,
        check=False,
    )
