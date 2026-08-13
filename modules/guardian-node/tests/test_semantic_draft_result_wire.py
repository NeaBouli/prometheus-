"""Adversarial tests for the binding-only semantic-draft result wire."""

# Test names describe the invariant under test.
# pylint: disable=missing-function-docstring,protected-access

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jaeger.observable_analysis_worker import (
    DeterministicSemanticDraftAnalyzer,
    ObservableAnalysisWorker,
    _semantic_draft_binding,
)
from jaeger.observable_approval_consumption import (
    ObservableApprovalOutboxError,
    build_semantic_draft_result_wire,
)
from tests.test_observable_analysis_worker import _claim_result_fixture, _enqueue
from tests.test_threat_hint_v2_outbox import _claim_service
from tests.test_threat_hint_v2_preflight import _Scenario


def _semantic_wire(claim: object, **changes: object) -> bytes:
    values = {
        "analyzer_id": "deterministic_semantic_draft_v2",
        "approval_id": claim.approval_id,
        "input_identity": claim.input_identity,
        "statement_digest": claim.statement_digest,
        "observable_commitment": claim.observable_commitment,
        "file_sha256_count": 1,
        "api_import_count": 0,
        "byte_pattern_count": 0,
        "candidate_binding_sha256": b"\x51" * 32,
        "rule_compile_ok": True,
    }
    values.update(changes)
    return build_semantic_draft_result_wire(**values)


def test_semantic_draft_completes_atomically_and_survives_restart(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    outbox, claim, _ = _claim_result_fixture(scenario)
    wire = _semantic_wire(claim)

    completion = outbox.complete(
        approval_id=claim.approval_id,
        lease_token=claim.lease_token,
        completion_token=b"\x52" * 32,
        input_identity=claim.input_identity,
        result_wire=wire,
        current_time=scenario.current_time,
    )

    restarted = _claim_service(scenario).outbox()
    stored = restarted.result(
        approval_id=claim.approval_id,
        current_time=scenario.current_time + 1,
    )
    assert stored is not None
    assert stored.result_wire == wire
    assert stored.result_digest == completion.result_digest
    decoded = json.loads(wire)
    assert decoded["schema_version"] == 2
    assert decoded["result_kind"] == "semantic_draft_non_actionable_local_v2"
    assert "should_submit" not in decoded
    assert "candidate_rule_source" not in decoded


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", 1),
        ("result_kind", "non_actionable_local_v1"),
        ("observable_count", 2),
        ("candidate_binding_sha256", "0" * 64),
        ("candidate_binding_sha256", "A" * 64),
        ("rule_compile_ok", 1),
    ],
)
def test_semantic_draft_rejects_cross_version_and_malformed_fields(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    scenario = _Scenario(tmp_path)
    outbox, claim, _ = _claim_result_fixture(scenario)
    decoded = json.loads(_semantic_wire(claim))
    decoded[field] = value
    malformed = json.dumps(decoded, separators=(",", ":")).encode("ascii")

    with pytest.raises(ObservableApprovalOutboxError):
        outbox.complete(
            approval_id=claim.approval_id,
            lease_token=claim.lease_token,
            completion_token=b"\x53" * 32,
            input_identity=claim.input_identity,
            result_wire=malformed,
            current_time=scenario.current_time,
        )


def test_semantic_draft_rejects_count_shape_reordering_and_duplicate_keys(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    outbox, claim, _ = _claim_result_fixture(scenario)
    decoded = json.loads(_semantic_wire(claim))
    decoded["observable_kind_counts"] = {
        "api_import": 0,
        "file_sha256": 1,
        "byte_pattern": 0,
    }
    reordered = json.dumps(decoded, separators=(",", ":")).encode("ascii")
    duplicate = _semantic_wire(claim).replace(
        b'"rule_compile_ok":true',
        b'"rule_compile_ok":true,"rule_compile_ok":true',
    )
    nested_duplicate = _semantic_wire(claim).replace(
        b'"file_sha256":1',
        b'"file_sha256":1,"file_sha256":1',
    )
    missing_count = json.loads(_semantic_wire(claim))
    del missing_count["observable_kind_counts"]["api_import"]
    extra_count = json.loads(_semantic_wire(claim))
    extra_count["observable_kind_counts"]["network"] = 0

    for malformed in (
        reordered,
        duplicate,
        nested_duplicate,
        json.dumps(missing_count, separators=(",", ":")).encode("ascii"),
        json.dumps(extra_count, separators=(",", ":")).encode("ascii"),
    ):
        with pytest.raises(ObservableApprovalOutboxError):
            outbox.complete(
                approval_id=claim.approval_id,
                lease_token=claim.lease_token,
                completion_token=b"\x54" * 32,
                input_identity=claim.input_identity,
                result_wire=malformed,
                current_time=scenario.current_time,
            )


def test_semantic_draft_builder_rejects_invalid_counts_digest_and_bool(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    _, claim, _ = _claim_result_fixture(scenario)

    for changes in (
        {"file_sha256_count": 0},
        {"api_import_count": -1},
        {"byte_pattern_count": True},
        {"candidate_binding_sha256": b"\x00" * 32},
        {"rule_compile_ok": 1},
    ):
        with pytest.raises(ObservableApprovalOutboxError):
            _semantic_wire(claim, **changes)


def test_existing_v1_result_remains_readable(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    outbox, claim, v1_wire = _claim_result_fixture(scenario)
    outbox.complete(
        approval_id=claim.approval_id,
        lease_token=claim.lease_token,
        completion_token=b"\x55" * 32,
        input_identity=claim.input_identity,
        result_wire=v1_wire,
        current_time=scenario.current_time,
    )

    stored = outbox.result(
        approval_id=claim.approval_id,
        current_time=scenario.current_time + 1,
    )
    assert stored is not None
    assert stored.result_wire == v1_wire


def test_semantic_draft_exact_retry_is_idempotent_and_mismatch_fails(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    outbox, claim, _ = _claim_result_fixture(scenario)
    wire = _semantic_wire(claim)
    token = b"\x56" * 32
    first = outbox.complete(
        approval_id=claim.approval_id,
        lease_token=claim.lease_token,
        completion_token=token,
        input_identity=claim.input_identity,
        result_wire=wire,
        current_time=scenario.current_time,
    )

    retry = outbox.complete(
        approval_id=claim.approval_id,
        lease_token=claim.lease_token,
        completion_token=token,
        input_identity=claim.input_identity,
        result_wire=wire,
        current_time=scenario.current_time + 1,
    )
    assert retry.result_digest == first.result_digest
    with pytest.raises(ObservableApprovalOutboxError):
        outbox.complete(
            approval_id=claim.approval_id,
            lease_token=claim.lease_token,
            completion_token=token,
            input_identity=claim.input_identity,
            result_wire=_semantic_wire(
                claim,
                candidate_binding_sha256=b"\x57" * 32,
            ),
            current_time=scenario.current_time + 1,
        )


def test_candidate_binding_is_nonce_bound_and_deterministic() -> None:
    candidate_digest = b"\x58" * 32
    first = _semantic_draft_binding(b"\x59" * 32, candidate_digest)
    repeated = _semantic_draft_binding(b"\x59" * 32, candidate_digest)
    changed_nonce = _semantic_draft_binding(b"\x5a" * 32, candidate_digest)
    changed_candidate = _semantic_draft_binding(b"\x59" * 32, b"\x5b" * 32)

    assert first == repeated
    assert first != changed_nonce
    assert first != changed_candidate
    assert (
        first.hex()
        == "97d3da1c5e1cc165851e7279c5307c64c12ef93e2187911f41c20d218a45de6d"
    )
    assert len(first) == 32


@pytest.mark.asyncio
async def test_semantic_draft_worker_claims_and_completes_atomically(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    _enqueue(scenario)
    outbox = _claim_service(scenario).outbox()
    worker = ObservableAnalysisWorker(
        outbox,
        DeterministicSemanticDraftAnalyzer(),
        lease_seconds=60,
        analyzer_timeout_seconds=10,
    )

    completion = await worker.process_next(current_time=scenario.current_time)

    assert completion is not None
    stored = outbox.result(
        approval_id=completion.approval_id,
        current_time=scenario.current_time + 1,
    )
    assert stored is not None
    decoded = json.loads(stored.result_wire)
    assert decoded["analyzer_id"] == "deterministic_semantic_draft_v2"
    assert decoded["observable_count"] == sum(
        decoded["observable_kind_counts"].values()
    )
    assert decoded["rule_compile_ok"] is True
    assert "candidate_rule_source" not in decoded
    assert await worker.process_next(current_time=scenario.current_time + 1) is None
