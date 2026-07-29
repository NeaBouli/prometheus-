"""Adversarial tests for the owner-local v2 analysis completion boundary."""

# Tests intentionally inspect the owner-local SQLite ledger.
# pylint: disable=missing-function-docstring,missing-class-docstring
# pylint: disable=too-many-locals,too-few-public-methods,duplicate-code

from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
from pathlib import Path

import jaeger.observable_analysis_worker as worker_module
import pytest
from jaeger.observable_analysis_worker import (
    DeterministicNonActionableAnalyzer,
    ObservableAnalysisInput,
    ObservableAnalysisWorker,
    ObservableAnalysisWorkerError,
    ObservableAnalysisWorkerTimeoutError,
)
from jaeger.observable_approval_consumption import (
    MAX_CANONICAL_ANALYSIS_RESULT_BYTES,
    ObservableApprovalBusyError,
    ObservableApprovalOutboxError,
    build_analysis_result_wire,
)
from jaeger.threat_observable import ObservableBundle
from tests.test_threat_hint_v2_acceptance import _ledger_path
from tests.test_threat_hint_v2_governed_promotion import _governed_service
from tests.test_threat_hint_v2_outbox import _claim_service, _outbox_rows, _result_rows
from tests.test_threat_hint_v2_preflight import _Scenario
from tests.test_threat_hint_v2_promotion import _promote


def _enqueue(scenario: _Scenario, **changes: object) -> None:
    _promote(_governed_service(scenario, **changes), scenario)


def _claim_result_fixture(
    scenario: _Scenario,
    *,
    lease_seconds: int = 60,
) -> tuple[object, object, bytes]:
    _enqueue(scenario)
    outbox = _claim_service(scenario).outbox()
    claim = outbox.claim(
        current_time=scenario.current_time,
        lease_seconds=lease_seconds,
    )
    assert claim is not None
    bundle = ObservableBundle.parse_canonical(claim.bundle_wire)
    result_wire = build_analysis_result_wire(
        analyzer_id="deterministic_test_v1",
        approval_id=claim.approval_id,
        input_identity=claim.input_identity,
        statement_digest=claim.statement_digest,
        observable_commitment=claim.observable_commitment,
        observable_count=len(bundle.observables),
    )
    return outbox, claim, result_wire


def test_complete_is_atomic_durable_and_restart_readable(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    outbox, claim, result_wire = _claim_result_fixture(scenario)
    completion_token = b"\x41" * 32

    completion = outbox.complete(
        approval_id=claim.approval_id,
        lease_token=claim.lease_token,
        completion_token=completion_token,
        input_identity=claim.input_identity,
        result_wire=result_wire,
        current_time=scenario.current_time,
    )

    ledger = _ledger_path(scenario)
    assert _outbox_rows(ledger) == []
    rows = _result_rows(ledger)
    assert len(rows) == 1
    assert completion.approval_id == claim.approval_id
    assert completion.result_digest == rows[0][2]
    assert completion.input_identity == claim.input_identity
    assert completion.completed_at == scenario.current_time
    assert completion.retention_deadline == scenario.current_time + 86400
    assert rows[0][4] != completion_token

    restarted = _claim_service(scenario).outbox()
    stored = restarted.result(
        approval_id=claim.approval_id,
        current_time=scenario.current_time + 1,
    )
    assert stored is not None
    assert stored.result_wire == result_wire
    assert stored.result_digest == completion.result_digest
    assert stored.input_identity == claim.input_identity


def test_exact_post_commit_retry_is_idempotent_and_mismatch_fails(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    outbox, claim, result_wire = _claim_result_fixture(scenario)
    completion_token = b"\x42" * 32
    first = outbox.complete(
        approval_id=claim.approval_id,
        lease_token=claim.lease_token,
        completion_token=completion_token,
        input_identity=claim.input_identity,
        result_wire=result_wire,
        current_time=scenario.current_time,
    )

    retry = (
        _claim_service(scenario)
        .outbox()
        .complete(
            approval_id=claim.approval_id,
            lease_token=claim.lease_token,
            completion_token=completion_token,
            input_identity=claim.input_identity,
            result_wire=result_wire,
            current_time=scenario.current_time + 1,
        )
    )
    assert retry.result_digest == first.result_digest
    assert retry.completed_at == first.completed_at

    with pytest.raises(ObservableApprovalOutboxError):
        outbox.complete(
            approval_id=claim.approval_id,
            lease_token=claim.lease_token,
            completion_token=b"\x43" * 32,
            input_identity=claim.input_identity,
            result_wire=result_wire,
            current_time=scenario.current_time + 1,
        )
    with pytest.raises(ObservableApprovalOutboxError):
        outbox.complete(
            approval_id=claim.approval_id,
            lease_token=b"\x00" * 32,
            completion_token=completion_token,
            input_identity=claim.input_identity,
            result_wire=result_wire,
            current_time=scenario.current_time + 1,
        )
    assert len(_result_rows(_ledger_path(scenario))) == 1


def test_expired_and_rotated_lease_cannot_complete(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    outbox, first, first_wire = _claim_result_fixture(scenario, lease_seconds=10)

    with pytest.raises(ObservableApprovalOutboxError):
        outbox.complete(
            approval_id=first.approval_id,
            lease_token=first.lease_token,
            completion_token=b"\x44" * 32,
            input_identity=first.input_identity,
            result_wire=first_wire,
            current_time=scenario.current_time + 10,
        )

    second = outbox.claim(
        current_time=scenario.current_time + 10,
        lease_seconds=10,
    )
    assert second is not None
    assert second.lease_token != first.lease_token
    assert second.input_identity != first.input_identity
    with pytest.raises(ObservableApprovalOutboxError):
        outbox.complete(
            approval_id=first.approval_id,
            lease_token=first.lease_token,
            completion_token=b"\x44" * 32,
            input_identity=first.input_identity,
            result_wire=first_wire,
            current_time=scenario.current_time + 10,
        )


def test_complete_revalidates_input_identity_and_leased_row(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    outbox, claim, result_wire = _claim_result_fixture(scenario)
    wrong_identity = b"\x00" * 32
    wrong_result = build_analysis_result_wire(
        analyzer_id="deterministic_test_v1",
        approval_id=claim.approval_id,
        input_identity=wrong_identity,
        statement_digest=claim.statement_digest,
        observable_commitment=claim.observable_commitment,
        observable_count=len(
            ObservableBundle.parse_canonical(claim.bundle_wire).observables
        ),
    )
    with pytest.raises(ObservableApprovalOutboxError):
        outbox.complete(
            approval_id=claim.approval_id,
            lease_token=claim.lease_token,
            completion_token=b"\x44" * 32,
            input_identity=wrong_identity,
            result_wire=wrong_result,
            current_time=scenario.current_time,
        )

    ledger = _ledger_path(scenario)
    with sqlite3.connect(ledger) as connection:
        connection.execute(
            "UPDATE approval_outbox SET retention_deadline = retention_deadline + 1"
        )
    with pytest.raises(ObservableApprovalOutboxError):
        outbox.complete(
            approval_id=claim.approval_id,
            lease_token=claim.lease_token,
            completion_token=b"\x44" * 32,
            input_identity=claim.input_identity,
            result_wire=result_wire,
            current_time=scenario.current_time,
        )

    with sqlite3.connect(ledger) as connection:
        connection.execute(
            "UPDATE approval_outbox SET retention_deadline = ?",
            (scenario.current_time + 86400,),
        )
        connection.execute(
            "UPDATE approval_outbox SET statement_digest = ?",
            (b"\x00" * 32,),
        )
    with pytest.raises(ObservableApprovalOutboxError):
        outbox.complete(
            approval_id=claim.approval_id,
            lease_token=claim.lease_token,
            completion_token=b"\x44" * 32,
            input_identity=claim.input_identity,
            result_wire=result_wire,
            current_time=scenario.current_time,
        )
    assert len(_outbox_rows(ledger)) == 1
    assert _result_rows(ledger) == []


def test_concurrent_completion_has_one_token_winner(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    outbox, claim, result_wire = _claim_result_fixture(scenario)
    barrier = threading.Barrier(2)
    successes: list[bytes] = []
    failures: list[type[BaseException]] = []

    def attempt(token: bytes) -> None:
        barrier.wait(timeout=5)
        try:
            completion = outbox.complete(
                approval_id=claim.approval_id,
                lease_token=claim.lease_token,
                completion_token=token,
                input_identity=claim.input_identity,
                result_wire=result_wire,
                current_time=scenario.current_time,
            )
            successes.append(completion.result_digest)
        except (ObservableApprovalOutboxError, ObservableApprovalBusyError) as error:
            failures.append(type(error))

    workers = [
        threading.Thread(target=attempt, args=(bytes([value]) * 32,))
        for value in (0x45, 0x46)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=15)

    assert all(not worker.is_alive() for worker in workers)
    assert len(successes) == 1
    assert len(failures) == 1
    assert len(_result_rows(_ledger_path(scenario))) == 1
    assert _outbox_rows(_ledger_path(scenario)) == []


def test_complete_lock_is_retryable_and_preserves_lease(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    outbox, claim, result_wire = _claim_result_fixture(scenario)
    ledger = _ledger_path(scenario)
    lock = sqlite3.connect(ledger, isolation_level=None)
    lock.execute("BEGIN EXCLUSIVE")
    try:
        with pytest.raises(ObservableApprovalBusyError):
            outbox.complete(
                approval_id=claim.approval_id,
                lease_token=claim.lease_token,
                completion_token=b"\x46" * 32,
                input_identity=claim.input_identity,
                result_wire=result_wire,
                current_time=scenario.current_time,
            )
    finally:
        lock.rollback()
        lock.close()
    assert len(_outbox_rows(ledger)) == 1
    assert _result_rows(ledger) == []
    outbox.complete(
        approval_id=claim.approval_id,
        lease_token=claim.lease_token,
        completion_token=b"\x46" * 32,
        input_identity=claim.input_identity,
        result_wire=result_wire,
        current_time=scenario.current_time,
    )
    assert _outbox_rows(ledger) == []
    assert len(_result_rows(ledger)) == 1


@pytest.mark.parametrize("trigger_target", ["result", "delete"])
def test_completion_failure_rolls_back_result_and_outbox(
    tmp_path: Path,
    trigger_target: str,
) -> None:
    scenario = _Scenario(tmp_path)
    outbox, claim, result_wire = _claim_result_fixture(scenario)
    ledger = _ledger_path(scenario)
    statement = (
        """
        CREATE TRIGGER reject_completion
        BEFORE INSERT ON observable_analysis_results
        BEGIN
            SELECT RAISE(ABORT, 'injected result failure');
        END
        """
        if trigger_target == "result"
        else """
        CREATE TRIGGER reject_completion
        BEFORE DELETE ON approval_outbox
        BEGIN
            SELECT RAISE(ABORT, 'injected delete failure');
        END
        """
    )
    with sqlite3.connect(ledger) as connection:
        connection.execute(statement)

    with pytest.raises(ObservableApprovalOutboxError):
        outbox.complete(
            approval_id=claim.approval_id,
            lease_token=claim.lease_token,
            completion_token=b"\x47" * 32,
            input_identity=claim.input_identity,
            result_wire=result_wire,
            current_time=scenario.current_time,
        )
    assert len(_outbox_rows(ledger)) == 1
    assert _result_rows(ledger) == []


def test_result_canonicality_size_and_actionable_fields_fail_closed(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    outbox, claim, result_wire = _claim_result_fixture(scenario)
    decoded = json.loads(result_wire)
    noncanonical = json.dumps(decoded, indent=2).encode()
    actionable = dict(decoded)
    actionable["confidence_bps"] = 10_000
    actionable["should_submit"] = True
    wrong_binding = build_analysis_result_wire(
        analyzer_id="deterministic_test_v1",
        approval_id=claim.approval_id,
        input_identity=claim.input_identity,
        statement_digest=b"\x00" * 32,
        observable_commitment=claim.observable_commitment,
        observable_count=decoded["observable_count"],
    )

    for malformed in (
        noncanonical,
        json.dumps(actionable, separators=(",", ":")).encode(),
        wrong_binding,
        b"{" + b"x" * MAX_CANONICAL_ANALYSIS_RESULT_BYTES + b"}",
    ):
        with pytest.raises(ObservableApprovalOutboxError):
            outbox.complete(
                approval_id=claim.approval_id,
                lease_token=claim.lease_token,
                completion_token=b"\x48" * 32,
                input_identity=claim.input_identity,
                result_wire=malformed,
                current_time=scenario.current_time,
            )
    assert len(_outbox_rows(_ledger_path(scenario))) == 1
    assert _result_rows(_ledger_path(scenario)) == []


@pytest.mark.asyncio
async def test_worker_random_failure_is_redacted_and_timeout_cannot_exceed_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _Scenario(tmp_path)
    _enqueue(scenario)
    outbox = _claim_service(scenario).outbox()
    with pytest.raises(ObservableAnalysisWorkerError):
        ObservableAnalysisWorker(
            outbox,
            DeterministicNonActionableAnalyzer(),
            lease_seconds=1,
            analyzer_timeout_seconds=2.0,
        )

    class FailingOs:
        @staticmethod
        def urandom(_: int) -> bytes:
            raise OSError("random source detail")

    monkeypatch.setattr(worker_module, "os", FailingOs)
    worker = ObservableAnalysisWorker(
        outbox,
        DeterministicNonActionableAnalyzer(),
        lease_seconds=60,
        analyzer_timeout_seconds=1.0,
    )
    with pytest.raises(
        ObservableAnalysisWorkerError,
        match=r"^observable analysis worker failure$",
    ) as exc_info:
        await worker.process_next(current_time=scenario.current_time)
    assert "random source detail" not in str(exc_info.value)
    assert len(_outbox_rows(_ledger_path(scenario))) == 1
    assert _result_rows(_ledger_path(scenario)) == []


def test_result_retention_inherits_original_deadline_and_purges(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    _enqueue(scenario, retention_max_retention_seconds=10)
    outbox = _claim_service(scenario).outbox()
    claim = outbox.claim(current_time=scenario.current_time, lease_seconds=10)
    assert claim is not None
    result_wire = build_analysis_result_wire(
        analyzer_id="deterministic_test_v1",
        approval_id=claim.approval_id,
        input_identity=claim.input_identity,
        statement_digest=claim.statement_digest,
        observable_commitment=claim.observable_commitment,
        observable_count=len(
            ObservableBundle.parse_canonical(claim.bundle_wire).observables
        ),
    )
    completion = outbox.complete(
        approval_id=claim.approval_id,
        lease_token=claim.lease_token,
        completion_token=b"\x49" * 32,
        input_identity=claim.input_identity,
        result_wire=result_wire,
        current_time=scenario.current_time,
    )
    assert completion.retention_deadline == scenario.current_time + 10
    assert (
        outbox.result(
            approval_id=claim.approval_id,
            current_time=scenario.current_time + 9,
        )
        is not None
    )
    assert (
        outbox.result(
            approval_id=claim.approval_id,
            current_time=scenario.current_time + 10,
        )
        is None
    )
    assert _result_rows(_ledger_path(scenario)) == []


def test_result_read_revalidates_durable_wire_and_digest(tmp_path: Path) -> None:
    scenario = _Scenario(tmp_path)
    outbox, claim, result_wire = _claim_result_fixture(scenario)
    outbox.complete(
        approval_id=claim.approval_id,
        lease_token=claim.lease_token,
        completion_token=b"\x49" * 32,
        input_identity=claim.input_identity,
        result_wire=result_wire,
        current_time=scenario.current_time,
    )
    ledger = _ledger_path(scenario)
    original = _result_rows(ledger)[0]
    with sqlite3.connect(ledger) as connection:
        connection.execute(
            "UPDATE observable_analysis_results "
            "SET retention_deadline = retention_deadline + 1"
        )
    with pytest.raises(ObservableApprovalOutboxError):
        outbox.result(
            approval_id=claim.approval_id,
            current_time=scenario.current_time,
        )

    with sqlite3.connect(ledger) as connection:
        connection.execute(
            "UPDATE observable_analysis_results "
            "SET retention_deadline = ?, result_digest = ?",
            (original[6], b"\x00" * 32),
        )
    with pytest.raises(ObservableApprovalOutboxError):
        outbox.result(
            approval_id=claim.approval_id,
            current_time=scenario.current_time,
        )

    with sqlite3.connect(ledger) as connection:
        connection.execute(
            "UPDATE observable_analysis_results SET result_digest = ?",
            (original[2],),
        )
    assert (
        outbox.result(
            approval_id=claim.approval_id,
            current_time=scenario.current_time,
        )
        is not None
    )


@pytest.mark.asyncio
async def test_worker_processes_deterministic_non_actionable_result(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    _enqueue(scenario)
    outbox = _claim_service(scenario).outbox()
    worker = ObservableAnalysisWorker(
        outbox,
        DeterministicNonActionableAnalyzer(),
        lease_seconds=60,
        analyzer_timeout_seconds=1.0,
    )

    completion = await worker.process_next(current_time=scenario.current_time)

    assert completion is not None
    stored = outbox.result(
        approval_id=completion.approval_id,
        current_time=scenario.current_time,
    )
    assert stored is not None
    decoded = json.loads(stored.result_wire)
    assert decoded["result_kind"] == "non_actionable_local_v1"
    assert decoded["analyzer_id"] == "deterministic_test_v1"
    assert "confidence_bps" not in decoded
    assert "should_submit" not in decoded
    assert await worker.process_next(current_time=scenario.current_time) is None


@pytest.mark.asyncio
async def test_worker_timeout_cancels_analyzer_and_keeps_lease(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    _enqueue(scenario)
    cancelled = asyncio.Event()

    class SlowAnalyzer:
        async def analyze(self, _: ObservableAnalysisInput) -> bytes:
            try:
                await asyncio.sleep(60)
            finally:
                cancelled.set()
            raise AssertionError("unreachable")

    worker = ObservableAnalysisWorker(
        _claim_service(scenario).outbox(),
        SlowAnalyzer(),
        lease_seconds=60,
        analyzer_timeout_seconds=0.01,
    )
    with pytest.raises(
        ObservableAnalysisWorkerTimeoutError,
        match=r"^observable analysis worker timeout$",
    ):
        await worker.process_next(current_time=scenario.current_time)
    await asyncio.wait_for(cancelled.wait(), timeout=1)
    assert len(_outbox_rows(_ledger_path(scenario))) == 1
    assert _result_rows(_ledger_path(scenario)) == []


@pytest.mark.asyncio
async def test_worker_external_cancellation_propagates_and_never_completes(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    _enqueue(scenario)
    started = asyncio.Event()
    cancelled = asyncio.Event()

    class BlockingAnalyzer:
        async def analyze(self, _: ObservableAnalysisInput) -> bytes:
            started.set()
            try:
                await asyncio.sleep(60)
            finally:
                cancelled.set()
            raise AssertionError("unreachable")

    worker = ObservableAnalysisWorker(
        _claim_service(scenario).outbox(),
        BlockingAnalyzer(),
        lease_seconds=60,
        analyzer_timeout_seconds=30.0,
    )
    task = asyncio.create_task(worker.process_next(current_time=scenario.current_time))
    await asyncio.wait_for(started.wait(), timeout=1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.wait_for(cancelled.wait(), timeout=1)
    assert len(_outbox_rows(_ledger_path(scenario))) == 1
    assert _result_rows(_ledger_path(scenario)) == []


@pytest.mark.asyncio
async def test_worker_redacts_analyzer_failures_and_rejects_malformed_output(
    tmp_path: Path,
) -> None:
    scenario = _Scenario(tmp_path)
    _enqueue(scenario)

    class FailingAnalyzer:
        async def analyze(self, _: ObservableAnalysisInput) -> bytes:
            raise RuntimeError("sensitive observable detail")

    worker = ObservableAnalysisWorker(
        _claim_service(scenario).outbox(),
        FailingAnalyzer(),
        lease_seconds=1,
        analyzer_timeout_seconds=1.0,
    )
    with pytest.raises(
        ObservableAnalysisWorkerError,
        match=r"^observable analysis worker failure$",
    ) as exc_info:
        await worker.process_next(current_time=scenario.current_time)
    assert "sensitive observable detail" not in str(exc_info.value)

    class MalformedAnalyzer:
        async def analyze(self, _: ObservableAnalysisInput) -> bytes:
            return b'{"confidence_bps":10000,"should_submit":true}'

    retry = ObservableAnalysisWorker(
        _claim_service(scenario).outbox(),
        MalformedAnalyzer(),
        lease_seconds=1,
        analyzer_timeout_seconds=1.0,
    )
    with pytest.raises(ObservableApprovalOutboxError):
        await retry.process_next(current_time=scenario.current_time + 1)
    assert len(_outbox_rows(_ledger_path(scenario))) == 1
    assert _result_rows(_ledger_path(scenario)) == []
