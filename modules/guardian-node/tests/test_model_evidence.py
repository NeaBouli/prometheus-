"""Adversarial tests for local model candidate evidence capture."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from jaeger.confidence_calibration import (
    LOCAL_MODEL_EVALUATION_MODE,
    ConfidenceEvaluationError,
    evaluate_confidence,
    parse_corpus,
    parse_policy,
    parse_predictions,
)
from jaeger.llm_server import (
    YARA_CONFIDENCE_PROMPT_SHA256,
    YaraConfidenceAssessment,
)
from jaeger.model_evidence import (
    ModelEvidenceError,
    capture_local_model_predictions,
    write_predictions_atomically,
)

VECTOR_ROOT = Path(__file__).parent / "vectors" / "confidence-calibration-v1"
MODEL_ID = "local-candidate-model-v1"
MODEL_SHA256 = "a1b2c3d4" * 8
CONFIDENCE_VALUES = [8_500 + (index % 5) * 100 for index in range(24)]


def _corpus():
    """Parse the committed canonical benchmark corpus."""
    return parse_corpus((VECTOR_ROOT / "corpus.jsonl").read_bytes())


def _stub_assessor(values, calls=None):
    """Build a deterministic async stub returning the queued assessments."""
    iterator = iter(values)
    recorded = calls if calls is not None else []

    async def assess(threat_description: str, yara_rule: str):
        """Record the untrusted inputs and return the next queued value."""
        recorded.append((threat_description, yara_rule))
        return YaraConfidenceAssessment(next(iterator))

    return assess


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


def _capture(corpus, values, calls=None):
    """Capture predictions with a stub assessor on the default metadata."""
    return capture_local_model_predictions(
        corpus, MODEL_ID, MODEL_SHA256, _stub_assessor(values, calls)
    )


def _run_cli(arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
    """Run the standalone capture CLI in the guardian-node environment."""
    guardian_root = Path(__file__).parent.parent
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(guardian_root)
    return subprocess.run(
        [sys.executable, "-m", "jaeger.model_evidence", *arguments],
        cwd=guardian_root,
        env=environment,
        capture_output=True,
        check=False,
    )


@pytest.mark.asyncio
async def test_capture_returns_canonical_parseable_predictions() -> None:
    """Stub capture output parses against the closed predictions schema."""
    corpus = _corpus()
    raw_bytes = await _capture(corpus, CONFIDENCE_VALUES)

    prediction_set = parse_predictions(raw_bytes, corpus)
    assert prediction_set.evaluation_mode == LOCAL_MODEL_EVALUATION_MODE
    assert prediction_set.corpus_sha256 == corpus.sha256
    assert prediction_set.subject_id == MODEL_ID
    assert prediction_set.subject_sha256 == MODEL_SHA256
    assert prediction_set.prompt_sha256 == YARA_CONFIDENCE_PROMPT_SHA256
    assert prediction_set.sha256 == hashlib.sha256(raw_bytes).hexdigest()
    assert tuple(p.confidence_bps for p in prediction_set.predictions) == tuple(
        CONFIDENCE_VALUES
    )


@pytest.mark.asyncio
async def test_capture_header_and_row_shape_are_exact() -> None:
    """Header key order, mode, and per-case row shape match the schema."""
    corpus = _corpus()
    values = _decode_jsonl(await _capture(corpus, CONFIDENCE_VALUES))

    assert list(values[0]) == [
        "schema_version",
        "evaluation_mode",
        "corpus_sha256",
        "subject_id",
        "subject_sha256",
        "prompt_sha256",
    ]
    assert values[0]["schema_version"] == 1
    assert values[0]["evaluation_mode"] == "local_model_candidate"
    assert values[0]["corpus_sha256"] == corpus.sha256
    assert len(values) == len(corpus.cases) + 1
    for row, case in zip(values[1:], corpus.cases):
        assert list(row) == ["case_id", "confidence_bps"]
        assert row["case_id"] == case.case_id


@pytest.mark.asyncio
async def test_capture_preserves_canonical_corpus_order_and_inputs() -> None:
    """Cases reach the assessor exactly once, in order, without labels."""
    corpus = _corpus()
    calls: list = []
    await _capture(corpus, CONFIDENCE_VALUES, calls)

    assert calls == [case.assessment_input for case in corpus.cases]
    assert all(len(call) == 2 for call in calls)


@pytest.mark.asyncio
async def test_capture_bytes_are_canonical_and_reproducible() -> None:
    """Captured bytes equal a hand-built canonical JSONL byte string."""
    corpus = _corpus()
    raw_bytes = await _capture(corpus, CONFIDENCE_VALUES)
    expected = _jsonl(
        [
            {
                "schema_version": 1,
                "evaluation_mode": "local_model_candidate",
                "corpus_sha256": corpus.sha256,
                "subject_id": MODEL_ID,
                "subject_sha256": MODEL_SHA256,
                "prompt_sha256": YARA_CONFIDENCE_PROMPT_SHA256,
            },
            *[
                {"case_id": case.case_id, "confidence_bps": confidence}
                for case, confidence in zip(corpus.cases, CONFIDENCE_VALUES)
            ],
        ]
    )

    assert raw_bytes == expected
    assert raw_bytes == await _capture(corpus, CONFIDENCE_VALUES)
    raw_bytes.decode("ascii")


@pytest.mark.asyncio
async def test_capture_output_binds_exact_corpus_and_rejects_tampering() -> None:
    """Reordered, missing, or extra rows fail closed against the corpus."""
    corpus = _corpus()
    values = _decode_jsonl(await _capture(corpus, CONFIDENCE_VALUES))
    reordered = [values[0], values[2], values[1], *values[3:]]
    missing = values[:-1]
    extra = [*values, dict(values[-1])]

    for candidate in (reordered, missing, extra):
        with pytest.raises(ConfidenceEvaluationError):
            parse_predictions(_jsonl(candidate), corpus)


@pytest.mark.parametrize(
    "subject_id",
    ["", "../escape", "model//name", "model/../name", "a" * 129, "has space", 8_500],
)
@pytest.mark.asyncio
async def test_capture_rejects_malformed_model_identifiers(subject_id) -> None:
    """Only bounded relative public model identifiers are accepted."""
    with pytest.raises(ModelEvidenceError):
        await capture_local_model_predictions(
            _corpus(), subject_id, MODEL_SHA256, _stub_assessor(CONFIDENCE_VALUES)
        )


@pytest.mark.parametrize(
    "subject_sha256",
    ["0" * 64, "A" * 64, "f" * 63, "g" * 64, "", "f" * 65, 12_345],
)
@pytest.mark.asyncio
async def test_capture_rejects_malformed_artifact_digests(subject_sha256) -> None:
    """Only nonzero lowercase 64-hex artifact digests are accepted."""
    with pytest.raises(ModelEvidenceError):
        await capture_local_model_predictions(
            _corpus(), MODEL_ID, subject_sha256, _stub_assessor(CONFIDENCE_VALUES)
        )


@pytest.mark.asyncio
async def test_capture_accepts_canonical_hugging_face_model_identifier() -> None:
    """A public served-model name is bound without leaking a local path."""
    subject_id = "meta-llama/Meta-Llama-3-8B-Instruct"
    raw_bytes = await capture_local_model_predictions(
        _corpus(), subject_id, MODEL_SHA256, _stub_assessor(CONFIDENCE_VALUES)
    )
    assert _decode_jsonl(raw_bytes)[0]["subject_id"] == subject_id


@pytest.mark.asyncio
async def test_capture_rejects_wrong_corpus_and_assessor_types() -> None:
    """Non-corpus inputs and non-callable assessors fail before model IO."""
    with pytest.raises(ModelEvidenceError):
        await capture_local_model_predictions(
            {"corpus": True},  # type: ignore[arg-type]
            MODEL_ID,
            MODEL_SHA256,
            _stub_assessor(CONFIDENCE_VALUES),
        )
    with pytest.raises(ModelEvidenceError):
        await capture_local_model_predictions(
            _corpus(), MODEL_ID, MODEL_SHA256, None  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "assessment",
    [
        {"confidence_bps": 8_500},
        None,
        8_500,
        '{"confidence_bps":8500}',
        YaraConfidenceAssessment(confidence_bps=True),
        YaraConfidenceAssessment(confidence_bps=-1),
        YaraConfidenceAssessment(confidence_bps=10_001),
    ],
)
@pytest.mark.asyncio
async def test_capture_rejects_wrong_assessment_types_and_ranges(
    assessment,
) -> None:
    """Only exact YaraConfidenceAssessment integers 0..10000 are accepted."""

    async def assess(_threat: str, _rule: str):
        """Return the malformed assessment under test."""
        return assessment

    with pytest.raises(ModelEvidenceError):
        await capture_local_model_predictions(_corpus(), MODEL_ID, MODEL_SHA256, assess)


@pytest.mark.asyncio
async def test_capture_rejects_assessment_subclass_impersonation() -> None:
    """Subclasses of the closed assessment type fail the exact-type check."""

    class ImpersonatingAssessment(YaraConfidenceAssessment):
        """A subclass attempting to widen the closed assessment type."""

    async def assess(_threat: str, _rule: str):
        """Return the impersonating subclass instance."""
        return ImpersonatingAssessment(confidence_bps=8_500)

    with pytest.raises(ModelEvidenceError):
        await capture_local_model_predictions(_corpus(), MODEL_ID, MODEL_SHA256, assess)


@pytest.mark.asyncio
async def test_model_failure_mid_run_fails_closed_redacted_without_output(
    tmp_path: Path,
) -> None:
    """A mid-run model error is redacted and leaves no partial output file."""
    corpus = _corpus()
    calls: list = []

    async def assess(threat_description: str, yara_rule: str):
        """Fail with a sensitive marker after two successful cases."""
        calls.append((threat_description, yara_rule))
        if len(calls) == 3:
            raise RuntimeError("sensitive model internals")
        return YaraConfidenceAssessment(8_500)

    with pytest.raises(ModelEvidenceError) as excinfo:
        await capture_local_model_predictions(corpus, MODEL_ID, MODEL_SHA256, assess)

    assert str(excinfo.value) == "invalid local model evidence capture"
    assert "sensitive" not in str(excinfo.value)
    assert len(calls) == 3
    assert list(tmp_path.iterdir()) == []


@pytest.mark.asyncio
async def test_assessor_shortfall_fails_closed() -> None:
    """An assessor yielding fewer answers than cases never emits output."""
    with pytest.raises(ModelEvidenceError):
        await _capture(_corpus(), [8_500] * 5)


@pytest.mark.asyncio
async def test_prompt_injection_case_is_captured_as_inert_data() -> None:
    """Injection text reaches the assessor verbatim but never the output."""
    corpus = _corpus()
    calls: list = []
    raw_bytes = await _capture(corpus, CONFIDENCE_VALUES, calls)
    injection_index = next(
        index for index, case in enumerate(corpus.cases) if case.case_id == "reject-06"
    )
    description, rule = calls[injection_index]

    assert "Ignore prior instructions" in description
    assert "filesize >= 0" in rule
    assert b"Ignore prior instructions" not in raw_bytes
    assert b"filesize" not in raw_bytes
    parse_predictions(raw_bytes, corpus)


@pytest.mark.asyncio
async def test_prompt_hash_binding_is_stable() -> None:
    """Captures pin the immutable repository prompt specification hash."""
    assert (
        YARA_CONFIDENCE_PROMPT_SHA256
        == "b195c55e0825c73706aac06bd77b346d443aa64416955316574b30aaf526facc"
    )
    values = _decode_jsonl(await _capture(_corpus(), CONFIDENCE_VALUES))
    assert values[0]["prompt_sha256"] == YARA_CONFIDENCE_PROMPT_SHA256


@pytest.mark.asyncio
async def test_captured_evidence_reports_separate_non_authorizing_class() -> None:
    """Local candidate evidence evaluates to its own non-authorizing class."""
    corpus = _corpus()
    raw_bytes = await _capture(corpus, CONFIDENCE_VALUES)
    policy = parse_policy((VECTOR_ROOT / "policy.json").read_bytes())
    report = evaluate_confidence(corpus, parse_predictions(raw_bytes, corpus), policy)

    assert report["evaluation_mode"] == "local_model_candidate"
    assert report["evidence_class"] == "local_model_candidate_only"
    assert report["production_authorized"] is False
    assert report["disclaimer"] == (
        "Local model candidate evaluation only; development metrics are not "
        "production calibration, quality certification, or authorization."
    )
    assert report["evidence_class"] != "synthetic_ci_only"


@pytest.mark.asyncio
async def test_write_creates_owner_only_regular_file(tmp_path: Path) -> None:
    """A fresh output is written exactly once with 0600 permissions."""
    raw_bytes = await _capture(_corpus(), CONFIDENCE_VALUES)
    output = tmp_path / "predictions.jsonl"

    write_predictions_atomically(output, raw_bytes)

    assert output.read_bytes() == raw_bytes
    assert output.is_file() and not output.is_symlink()
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert [entry.name for entry in tmp_path.iterdir()] == ["predictions.jsonl"]
    with pytest.raises(ModelEvidenceError):
        write_predictions_atomically(output, raw_bytes)
    assert output.read_bytes() == raw_bytes


def test_write_rejects_existing_symlink_and_dangling_alias(tmp_path: Path) -> None:
    """Symlink and dangling-alias outputs fail closed without target writes."""
    target = tmp_path / "target.jsonl"
    target.write_bytes(b"original evidence")
    alias = tmp_path / "alias.jsonl"
    alias.symlink_to(target)
    dangling = tmp_path / "dangling.jsonl"
    dangling.symlink_to(tmp_path / "missing.jsonl")

    for candidate in (alias, dangling):
        with pytest.raises(ModelEvidenceError):
            write_predictions_atomically(candidate, b"{}\n")
    assert target.read_bytes() == b"original evidence"
    assert sorted(entry.name for entry in tmp_path.iterdir()) == [
        "alias.jsonl",
        "dangling.jsonl",
        "target.jsonl",
    ]


def test_write_rejects_unsafe_parent_conditions(tmp_path: Path) -> None:
    """Symlinked, missing, and non-directory parents fail before any write."""
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    parent_alias = tmp_path / "parent-alias"
    parent_alias.symlink_to(real_dir, target_is_directory=True)
    file_parent = tmp_path / "file.jsonl"
    file_parent.write_bytes(b"not a directory")

    for candidate in (
        parent_alias / "predictions.jsonl",
        tmp_path / "missing-dir" / "predictions.jsonl",
        file_parent / "predictions.jsonl",
    ):
        with pytest.raises(ModelEvidenceError):
            write_predictions_atomically(candidate, b"{}\n")
    assert list(real_dir.iterdir()) == []
    assert file_parent.read_bytes() == b"not a directory"


def test_write_rejects_invalid_content_and_path_types(tmp_path: Path) -> None:
    """Non-bytes, empty, oversized, and non-Path outputs fail closed."""
    with pytest.raises(ModelEvidenceError):
        write_predictions_atomically(tmp_path / "out.jsonl", b"")
    with pytest.raises(ModelEvidenceError):
        write_predictions_atomically(tmp_path / "out.jsonl", b"x" * 131_073)
    with pytest.raises(ModelEvidenceError):
        write_predictions_atomically(
            tmp_path / "out.jsonl", "{}\n"  # type: ignore[arg-type]
        )
    with pytest.raises(ModelEvidenceError):
        write_predictions_atomically(
            str(tmp_path / "out.jsonl"), b"{}\n"  # type: ignore[arg-type]
        )
    assert list(tmp_path.iterdir()) == []


def test_link_failure_leaves_no_partial_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed final link removes the temporary file and creates nothing."""

    def fail_link(_source: str, _target: Path) -> None:
        """Simulate an atomic no-overwrite link failure."""
        raise FileExistsError("target appeared concurrently")

    monkeypatch.setattr(os, "link", fail_link)
    output = tmp_path / "predictions.jsonl"

    with pytest.raises(ModelEvidenceError):
        write_predictions_atomically(output, b'{"ok":1}\n')
    assert list(tmp_path.iterdir()) == []


def test_temporary_file_creation_failure_is_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Temporary-file failures expose neither paths nor partial evidence."""

    def fail_mkstemp(**_kwargs):
        raise OSError(f"sensitive path: {tmp_path}")

    monkeypatch.setattr("jaeger.model_evidence.tempfile.mkstemp", fail_mkstemp)
    with pytest.raises(ModelEvidenceError) as excinfo:
        write_predictions_atomically(tmp_path / "predictions.jsonl", b"{}\n")

    assert str(excinfo.value) == "invalid local model evidence capture"
    assert str(tmp_path) not in str(excinfo.value)
    assert list(tmp_path.iterdir()) == []


def test_cli_model_failure_is_redacted_and_leaves_no_output(tmp_path: Path) -> None:
    """The CLI exposes no model, corpus, or path content on capture failure."""
    output = tmp_path / "predictions.jsonl"
    completed = _run_cli(
        [
            "--corpus",
            str(VECTOR_ROOT / "corpus.jsonl"),
            "--model",
            MODEL_ID,
            "--model-sha256",
            MODEL_SHA256,
            "--port",
            "59999",
            "--output",
            str(output),
        ]
    )

    assert completed.returncode == 2
    assert completed.stdout == b""
    assert completed.stderr == b"model evidence capture failed\n"
    assert b"alpha_marker_01" not in completed.stderr
    assert MODEL_ID.encode() not in completed.stderr
    assert str(tmp_path).encode() not in completed.stderr
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("port", ["0", "-1", "65536", "70000"])
def test_cli_rejects_out_of_range_ports(tmp_path: Path, port: str) -> None:
    """Only TCP ports 1 through 65535 reach model capture."""
    completed = _run_cli(
        [
            "--corpus",
            str(VECTOR_ROOT / "corpus.jsonl"),
            "--model",
            MODEL_ID,
            "--model-sha256",
            MODEL_SHA256,
            "--port",
            port,
            "--output",
            str(tmp_path / "predictions.jsonl"),
        ]
    )

    assert completed.returncode == 2
    assert completed.stdout == b""
    assert completed.stderr == b"model evidence capture failed\n"


def test_cli_rejects_invalid_metadata_and_existing_output(tmp_path: Path) -> None:
    """Malformed metadata and occupied outputs fail before any model IO."""
    existing = tmp_path / "predictions.jsonl"
    existing.write_bytes(b"occupied")
    base = [
        "--corpus",
        str(VECTOR_ROOT / "corpus.jsonl"),
        "--port",
        "8000",
        "--output",
        str(tmp_path / "fresh.jsonl"),
    ]
    variants = [
        [*base, "--model", "../escape", "--model-sha256", MODEL_SHA256],
        [*base, "--model", MODEL_ID, "--model-sha256", "0" * 64],
        [
            "--corpus",
            str(VECTOR_ROOT / "corpus.jsonl"),
            "--port",
            "8000",
            "--output",
            str(existing),
            "--model",
            MODEL_ID,
            "--model-sha256",
            MODEL_SHA256,
        ],
    ]

    for arguments in variants:
        completed = _run_cli(arguments)
        assert completed.returncode == 2
        assert completed.stdout == b""
        assert completed.stderr == b"model evidence capture failed\n"
    assert existing.read_bytes() == b"occupied"
    assert not (tmp_path / "fresh.jsonl").exists()


def test_cli_rejects_tampered_corpus_without_content_leak(tmp_path: Path) -> None:
    """Corpus validation failures stay redacted and leave no output."""
    tampered = tmp_path / "corpus.jsonl"
    tampered.write_bytes(b"sensitive invalid corpus\n")
    completed = _run_cli(
        [
            "--corpus",
            str(tampered),
            "--model",
            MODEL_ID,
            "--model-sha256",
            MODEL_SHA256,
            "--port",
            "8000",
            "--output",
            str(tmp_path / "predictions.jsonl"),
        ]
    )

    assert completed.returncode == 2
    assert completed.stdout == b""
    assert completed.stderr == b"model evidence capture failed\n"
    assert b"sensitive" not in completed.stderr
    assert [entry.name for entry in tmp_path.iterdir()] == ["corpus.jsonl"]
