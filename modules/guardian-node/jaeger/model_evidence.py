"""Fail-closed local model candidate prediction capture for Guardian evidence.

This module captures confidence predictions for the canonical synthetic
benchmark from one explicitly localhost-only model service. Every capture is
bound to the exact corpus bytes, a nonzero model artifact digest, and the
repository-owned prompt specification hash. The output is candidate evidence
only: it grants no production authority and claims no calibration. On any
model, corpus, metadata, or output failure it fails closed with one redacted
error and leaves no partial final output.
"""

# The assessor is an arbitrary local model adapter; any failure it raises
# must be converted into one redacted capture error. Closed schemas
# intentionally require exact built-in types.
# pylint: disable=broad-exception-caught,unidiomatic-typecheck

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Awaitable, Callable, Sequence

from jaeger.confidence_calibration import (
    LOCAL_MODEL_EVALUATION_MODE,
    MAX_CORPUS_BYTES,
    MAX_PREDICTIONS_BYTES,
    SCHEMA_VERSION,
    BenchmarkCorpus,
    ConfidenceEvaluationError,
    _read_bounded,
    _subject_identifier,
    parse_corpus,
    parse_predictions,
)
from jaeger.llm_server import (
    YARA_CONFIDENCE_PROMPT_SHA256,
    LlmServer,
    YaraConfidenceAssessment,
)

MAX_MODEL_ID_LENGTH = 128
MAX_TCP_PORT = 65_535


class ModelEvidenceError(ValueError):
    """Stable, redacted local model evidence capture failure."""

    def __init__(self) -> None:
        """Create one content-free public capture error."""
        super().__init__("invalid local model evidence capture")


async def capture_local_model_predictions(
    corpus: BenchmarkCorpus,
    subject_id: str,
    subject_sha256: str,
    assessor: Callable[[str, str], Awaitable[YaraConfidenceAssessment]],
) -> bytes:
    """Capture one validated confidence per case in canonical corpus order.

    The assessor receives only the untrusted model-facing case fields, never
    expected labels. Any model, type, range, or corpus failure raises one
    redacted ModelEvidenceError and yields no output bytes. The returned
    canonical JSONL is self-verified against the closed predictions schema
    before it is released.
    """
    if type(corpus) is not BenchmarkCorpus or not callable(assessor):
        raise ModelEvidenceError()
    subject_id = _model_identifier(subject_id)
    subject_sha256 = _model_artifact_sha256(subject_sha256)
    rows: list[dict[str, object]] = [
        {
            "schema_version": SCHEMA_VERSION,
            "evaluation_mode": LOCAL_MODEL_EVALUATION_MODE,
            "corpus_sha256": corpus.sha256,
            "subject_id": subject_id,
            "subject_sha256": subject_sha256,
            "prompt_sha256": YARA_CONFIDENCE_PROMPT_SHA256,
        }
    ]
    for case in corpus.cases:
        try:
            assessment = await assessor(case.threat_description, case.yara_rule)
        except ModelEvidenceError:
            raise
        except Exception:
            raise ModelEvidenceError() from None
        if (
            type(assessment) is not YaraConfidenceAssessment
            or type(assessment.confidence_bps) is not int
            or not 0 <= assessment.confidence_bps <= 10_000
        ):
            raise ModelEvidenceError()
        rows.append(
            {
                "case_id": case.case_id,
                "confidence_bps": assessment.confidence_bps,
            }
        )
    raw_bytes = b"".join(
        (json.dumps(row, separators=(",", ":"), ensure_ascii=True) + "\n").encode(
            "ascii"
        )
        for row in rows
    )
    if len(raw_bytes) > MAX_PREDICTIONS_BYTES:
        raise ModelEvidenceError()
    try:
        parse_predictions(raw_bytes, corpus)
    except ConfidenceEvaluationError:
        raise ModelEvidenceError() from None
    return raw_bytes


def write_predictions_atomically(output_path: Path, content: bytes) -> None:
    """Write predictions to one new owner-only regular file atomically.

    Existing paths, symlinks, unsafe parent directories, and oversized
    content fail closed. A same-directory owner-only temporary file is
    fsynced and hard-linked into place without overwrite, then removed, so
    no partial final output can remain.
    """
    if (
        not isinstance(output_path, Path)
        or type(content) is not bytes
        or not content
        or len(content) > MAX_PREDICTIONS_BYTES
    ):
        raise ModelEvidenceError()
    _validate_output_target(output_path)
    parent = output_path.parent
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=parent, prefix=f".{output_path.name}.", suffix=".tmp"
        )
    except OSError:
        raise ModelEvidenceError() from None
    handle = None
    try:
        os.fchmod(descriptor, 0o600)
        handle = os.fdopen(descriptor, "wb")
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
        handle.close()
        handle = None
        os.link(temporary_name, output_path)
    except OSError:
        raise ModelEvidenceError() from None
    finally:
        if handle is not None:
            try:
                handle.close()
            except OSError:
                pass
        else:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
    _fsync_directory(parent)


def _validate_output_target(output_path: Path) -> None:
    """Reject existing, aliased, or unsafely located output paths."""
    parent = output_path.parent
    try:
        if (
            not output_path.name
            or output_path.name in (".", "..")
            or os.path.lexists(output_path)
            or not parent.is_dir()
            or parent.is_symlink()
        ):
            raise ModelEvidenceError()
    except OSError:
        raise ModelEvidenceError() from None


def _fsync_directory(parent: Path) -> None:
    """Best-effort durability barrier for the linked directory entry."""
    try:
        directory_fd = os.open(parent, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(directory_fd)
    except OSError:
        pass
    finally:
        os.close(directory_fd)


def _model_identifier(value: object) -> str:
    """Require one bounded relative public model identifier."""
    try:
        return _subject_identifier(value, MAX_MODEL_ID_LENGTH)
    except ConfidenceEvaluationError:
        raise ModelEvidenceError() from None


def _model_artifact_sha256(value: object) -> str:
    """Require one nonzero canonical lowercase 32-byte artifact digest."""
    if type(value) is not str or _LOWER_HEX_32_RE.fullmatch(value) is None:
        raise ModelEvidenceError()
    if value == "0" * 64:
        raise ModelEvidenceError()
    return value


def _tcp_port(value: object) -> int:
    """Require one literal integer TCP port in the valid range."""
    if type(value) is not int or not 1 <= value <= MAX_TCP_PORT:
        raise ModelEvidenceError()
    return value


def _main(argv: Sequence[str] | None = None) -> int:
    """Capture local candidate predictions with stable exit semantics."""
    parser = argparse.ArgumentParser(
        description=(
            "Capture Guardian local model candidate confidence evidence "
            "from a localhost-only model service."
        )
    )
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--model", required=True)
    parser.add_argument("--model-sha256", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        subject_id = _model_identifier(args.model)
        subject_sha256 = _model_artifact_sha256(args.model_sha256)
        port = _tcp_port(args.port)
        _validate_output_target(args.output)
        corpus = parse_corpus(_read_bounded(args.corpus, MAX_CORPUS_BYTES))
    except (ModelEvidenceError, ConfidenceEvaluationError):
        print("model evidence capture failed", file=sys.stderr)
        return 2
    server = LlmServer(subject_id, port)
    try:
        predictions = asyncio.run(
            capture_local_model_predictions(
                corpus, subject_id, subject_sha256, server.assess_yara_rule
            )
        )
        write_predictions_atomically(args.output, predictions)
    except ModelEvidenceError:
        print("model evidence capture failed", file=sys.stderr)
        return 2
    return 0


_LOWER_HEX_32_RE = re.compile(r"[0-9a-f]{64}")


if __name__ == "__main__":
    raise SystemExit(_main())
