"""Tests for the bounded verified ThreatHint analyzer adapter."""

# pylint: disable=missing-class-docstring,missing-function-docstring,too-few-public-methods

from __future__ import annotations

import asyncio
import hashlib
import os
import shutil
import tempfile
import threading
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from jaeger.analyzer import AnalysisResult, Analyzer, VerifiedThreatHint
from jaeger.threat_hint_adapter import (
    MAX_ANALYZER_BATCH_LIMIT,
    ThreatHintAdapterError,
    ThreatHintAnalyzerAdapter,
    ThreatHintDrainFailure,
    ThreatHintDrainReport,
)
from jaeger.threat_hint_ingress import (
    CanonicalThreatHint,
    ThreatHintReplayLedger,
    ThreatProofContext,
    VerifiedThreatHintJob,
)

NOW_SECONDS = 1_800_000_000
CONTEXT = ThreatProofContext("testnet-10")


def owner_only_directory() -> Path:
    path = Path(tempfile.mkdtemp(prefix=".pha-", dir=Path.home())).resolve()
    os.chmod(path, 0o700)
    return path


def make_hint(**changes: object) -> CanonicalThreatHint:
    hint = CanonicalThreatHint(
        schema_version=1,
        threat_hash="11" * 32,
        confidence_bps=8_501,
        indicator_type="behavior",
        proof_system="groth16_kip16_v1",
        proof="aabb",
        report_nonce="22" * 32,
        observed_at=NOW_SECONDS,
    )
    return replace(hint, **changes)


def make_job(**changes: object) -> VerifiedThreatHintJob:
    wire = make_hint().to_wire()
    job = VerifiedThreatHintJob(
        payload_digest=hashlib.sha256(wire).hexdigest(),
        canonical_wire=wire,
        network_id=CONTEXT.network_id,
        admitted_at=NOW_SECONDS,
    )
    return replace(job, **changes)


class SafeAnalyzer:
    def __init__(self) -> None:
        self.hints: list[VerifiedThreatHint] = []

    async def process_verified_threat_hint(
        self, hint: VerifiedThreatHint
    ) -> AnalysisResult:
        self.hints.append(hint)
        return AnalysisResult(hint.threat_hash, None, 0.0, False, "v1 is hash-only")


class BlockingAnalyzer(SafeAnalyzer):
    def __init__(self) -> None:
        super().__init__()
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def process_verified_threat_hint(
        self, hint: VerifiedThreatHint
    ) -> AnalysisResult:
        self.hints.append(hint)
        self.started.set()
        await self.release.wait()
        return AnalysisResult(hint.threat_hash, None, 0.0, False, "v1 is hash-only")


def test_adapter_maps_only_exact_v1_fields() -> None:
    directory = owner_only_directory()
    try:
        ledger = ThreatHintReplayLedger(directory / "replay.sqlite3")
        adapter = ThreatHintAnalyzerAdapter(
            ledger, SafeAnalyzer(), CONTEXT.network_id, now_seconds=lambda: NOW_SECONDS
        )
        mapped = adapter.adapt_job(make_job())
        assert mapped.payload_digest == make_job().payload_digest
        assert mapped.threat_hash == "11" * 32
        assert mapped.confidence_bps == 8_501
        assert mapped.indicator_type == "behavior"
        assert mapped.reporter_zk_proof == bytes.fromhex("aabb")
        assert mapped.report_nonce == "22" * 32
        assert mapped.network_id == "testnet-10"
        assert not hasattr(mapped, "indicators")
    finally:
        shutil.rmtree(directory)


@pytest.mark.parametrize(
    "job,error",
    (
        (make_job(payload_digest="33" * 32), "digest mismatch"),
        (make_job(payload_digest="invalid"), "digest is invalid"),
        (make_job(canonical_wire=b""), "wire is invalid"),
        (make_job(network_id="mainnet"), "network mismatch"),
        (make_job(admitted_at=NOW_SECONDS + 301), "admission window"),
        (make_job(admitted_at=NOW_SECONDS - 31), "admission window"),
    ),
)
def test_adapter_rejects_tampered_job(job: VerifiedThreatHintJob, error: str) -> None:
    directory = owner_only_directory()
    try:
        adapter = ThreatHintAnalyzerAdapter(
            ThreatHintReplayLedger(directory / "replay.sqlite3"),
            SafeAnalyzer(),
            CONTEXT.network_id,
            now_seconds=lambda: NOW_SECONDS,
        )
        with pytest.raises(ThreatHintAdapterError, match=error):
            adapter.adapt_job(job)
    finally:
        shutil.rmtree(directory)


def test_adapter_rejects_stub_and_noncanonical_wire() -> None:
    directory = owner_only_directory()
    try:
        adapter = ThreatHintAnalyzerAdapter(
            ThreatHintReplayLedger(directory / "replay.sqlite3"),
            SafeAnalyzer(),
            CONTEXT.network_id,
            now_seconds=lambda: NOW_SECONDS,
        )
        stub_wire = make_hint(proof_system="development_stub_v1").to_wire()
        stub = make_job(
            canonical_wire=stub_wire,
            payload_digest=hashlib.sha256(stub_wire).hexdigest(),
        )
        with pytest.raises(ThreatHintAdapterError, match="proof system"):
            adapter.adapt_job(stub)
        changed_wire = make_job().canonical_wire + b" "
        changed = make_job(
            canonical_wire=changed_wire,
            payload_digest=hashlib.sha256(changed_wire).hexdigest(),
        )
        with pytest.raises(ThreatHintAdapterError, match="wire is invalid"):
            adapter.adapt_job(changed)
    finally:
        shutil.rmtree(directory)


@pytest.mark.asyncio
async def test_analyzer_never_invokes_llm_or_yara_for_verified_v1() -> None:
    llm = MagicMock()
    llm.analyze_threat = AsyncMock()
    yara = MagicMock()
    yara.generate_rule = AsyncMock()
    analyzer = Analyzer(llm, yara)
    directory = owner_only_directory()
    try:
        adapter = ThreatHintAnalyzerAdapter(
            ThreatHintReplayLedger(directory / "replay.sqlite3"),
            analyzer,
            CONTEXT.network_id,
            now_seconds=lambda: NOW_SECONDS,
        )
        result = await analyzer.process_verified_threat_hint(
            adapter.adapt_job(make_job())
        )
        assert result.confidence == 0.0
        assert result.yara_rule is None
        assert result.should_submit is False
        llm.analyze_threat.assert_not_awaited()
        yara.generate_rule.assert_not_awaited()
    finally:
        shutil.rmtree(directory)


@pytest.mark.asyncio
async def test_drain_marks_only_safe_completed_analysis() -> None:
    directory = owner_only_directory()
    try:
        ledger = ThreatHintReplayLedger(directory / "replay.sqlite3")
        hint = make_hint()
        assert ledger.admit(hint, hint.to_wire(), CONTEXT, NOW_SECONDS) == "accepted"
        analyzer = SafeAnalyzer()
        adapter = ThreatHintAnalyzerAdapter(
            ledger, analyzer, CONTEXT.network_id, now_seconds=lambda: NOW_SECONDS + 1
        )
        result = await adapter.drain_once()
        assert isinstance(result, ThreatHintDrainReport)
        assert len(result.delivered) == 1
        assert result.delivered[0].analysis.should_submit is False
        assert result.delivered[0].delivered_at == NOW_SECONDS + 1
        assert result.delivered[0].batch_index == 0
        assert result.failures == ()
        assert len(analyzer.hints) == 1
        assert ledger.pending_jobs(8) == []
        assert await adapter.drain_once() == ThreatHintDrainReport((), ())
    finally:
        shutil.rmtree(directory)


@pytest.mark.asyncio
async def test_bad_leading_adapt_job_does_not_block_following_safe_job() -> None:
    directory = owner_only_directory()
    try:
        ledger = ThreatHintReplayLedger(directory / "replay.sqlite3")
        first_hint = make_hint(threat_hash="11" * 32, report_nonce="11" * 32)
        second_hint = make_hint(threat_hash="22" * 32, report_nonce="22" * 32)
        assert (
            ledger.admit(first_hint, first_hint.to_wire(), CONTEXT, NOW_SECONDS)
            == "accepted"
        )
        assert (
            ledger.admit(second_hint, second_hint.to_wire(), CONTEXT, NOW_SECONDS + 1)
            == "accepted"
        )
        analyzer = SafeAnalyzer()
        adapter = ThreatHintAnalyzerAdapter(
            ledger,
            analyzer,
            CONTEXT.network_id,
            now_seconds=lambda: NOW_SECONDS + 2,
        )

        call_count = 0
        original_adapt = adapter.adapt_job

        def failing_first(job: VerifiedThreatHintJob) -> VerifiedThreatHint:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ThreatHintAdapterError("adapt failed")
            return original_adapt(job)

        adapter.adapt_job = failing_first

        result = await adapter.drain_once()
        assert len(result.delivered) == 1
        assert result.delivered[0].hint.threat_hash == "22" * 32
        assert len(result.failures) == 1
        assert result.failures[0].batch_index == 0
        assert result.failures[0].category == "adapt"
        first_digest = hashlib.sha256(first_hint.to_wire()).hexdigest()
        assert result.failures[0].payload_digest is None
        pending = ledger.pending_jobs(8)
        assert len(pending) == 1
        assert pending[0].payload_digest == first_digest
    finally:
        shutil.rmtree(directory)


@pytest.mark.asyncio
async def test_malformed_job_has_data_minimal_failure_and_batch_progress() -> None:
    directory = owner_only_directory()
    try:
        ledger = ThreatHintReplayLedger(directory / "replay.sqlite3")
        first_hint = make_hint(threat_hash="11" * 32, report_nonce="11" * 32)
        second_hint = make_hint(threat_hash="22" * 32, report_nonce="22" * 32)
        assert (
            ledger.admit(first_hint, first_hint.to_wire(), CONTEXT, NOW_SECONDS)
            == "accepted"
        )
        assert (
            ledger.admit(second_hint, second_hint.to_wire(), CONTEXT, NOW_SECONDS + 1)
            == "accepted"
        )
        pending = ledger.pending_jobs(2)
        malformed = replace(pending[0], payload_digest="ab" * 32)
        ledger.pending_jobs = MagicMock(return_value=[malformed, pending[1]])
        adapter = ThreatHintAnalyzerAdapter(
            ledger,
            SafeAnalyzer(),
            CONTEXT.network_id,
            now_seconds=lambda: NOW_SECONDS + 2,
        )

        result = await adapter.drain_once()
        assert len(result.delivered) == 1
        assert result.failures == (ThreatHintDrainFailure(0, "adapt", None),)
        assert "ab" * 32 not in repr(result.failures)
    finally:
        shutil.rmtree(directory)


@pytest.mark.asyncio
async def test_analyzer_failure_then_safe_job_still_delivered() -> None:
    directory = owner_only_directory()
    try:
        ledger = ThreatHintReplayLedger(directory / "replay.sqlite3")
        first_hint = make_hint(threat_hash="11" * 32, report_nonce="11" * 32)
        second_hint = make_hint(threat_hash="22" * 32, report_nonce="22" * 32)
        assert (
            ledger.admit(first_hint, first_hint.to_wire(), CONTEXT, NOW_SECONDS)
            == "accepted"
        )
        assert (
            ledger.admit(second_hint, second_hint.to_wire(), CONTEXT, NOW_SECONDS + 1)
            == "accepted"
        )
        analyzer = MagicMock()
        analyzer.process_verified_threat_hint = AsyncMock(
            side_effect=(
                RuntimeError("analyzer unavailable"),
                AnalysisResult(
                    second_hint.threat_hash, None, 0.0, False, "v1 hash only"
                ),
            )
        )
        adapter = ThreatHintAnalyzerAdapter(
            ledger,
            analyzer,
            CONTEXT.network_id,
            now_seconds=lambda: NOW_SECONDS + 2,
        )
        result = await adapter.drain_once()
        assert len(result.delivered) == 1
        assert result.delivered[0].hint.threat_hash == "22" * 32
        assert result.delivered[0].batch_index == 1
        assert len(result.failures) == 1
        assert result.failures[0].batch_index == 0
        assert result.failures[0].category == "analysis"
        first_digest = hashlib.sha256(first_hint.to_wire()).hexdigest()
        assert result.failures[0].payload_digest == first_digest
        pending = ledger.pending_jobs(8)
        assert len(pending) == 1
        assert pending[0].payload_digest == first_digest
    finally:
        shutil.rmtree(directory)


@pytest.mark.asyncio
async def test_delivery_failure_then_safe_job_still_delivered() -> None:
    directory = owner_only_directory()
    try:
        ledger = ThreatHintReplayLedger(directory / "replay.sqlite3")
        first_hint = make_hint(threat_hash="11" * 32, report_nonce="11" * 32)
        second_hint = make_hint(threat_hash="22" * 32, report_nonce="22" * 32)
        assert (
            ledger.admit(first_hint, first_hint.to_wire(), CONTEXT, NOW_SECONDS)
            == "accepted"
        )
        assert (
            ledger.admit(second_hint, second_hint.to_wire(), CONTEXT, NOW_SECONDS + 1)
            == "accepted"
        )
        original_mark_delivered = ledger.mark_delivered
        call_count = 0

        def fail_first_delivery(payload_digest: str, delivered_at: int) -> None:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("private delivery failure")
            original_mark_delivered(payload_digest, delivered_at)

        ledger.mark_delivered = fail_first_delivery
        adapter = ThreatHintAnalyzerAdapter(
            ledger,
            SafeAnalyzer(),
            CONTEXT.network_id,
            now_seconds=lambda: NOW_SECONDS + 2,
        )

        result = await adapter.drain_once()
        first_digest = hashlib.sha256(first_hint.to_wire()).hexdigest()
        assert len(result.delivered) == 1
        assert result.delivered[0].hint.threat_hash == "22" * 32
        assert result.delivered[0].batch_index == 1
        assert result.failures == (ThreatHintDrainFailure(0, "delivery", first_digest),)
        assert "private delivery failure" not in repr(result.failures)
        pending = ledger.pending_jobs(8)
        assert len(pending) == 1
        assert pending[0].payload_digest == first_digest
    finally:
        shutil.rmtree(directory)


@pytest.mark.asyncio
async def test_unsafe_clock_and_delivery_failures_remain_pending() -> None:
    directory = owner_only_directory()
    try:
        ledger = ThreatHintReplayLedger(directory / "replay.sqlite3")
        hint = make_hint()
        assert ledger.admit(hint, hint.to_wire(), CONTEXT, NOW_SECONDS) == "accepted"

        unsafe = MagicMock()
        unsafe.process_verified_threat_hint = AsyncMock(
            return_value=AnalysisResult(hint.threat_hash, None, 0.9, True, "bad")
        )
        adapter = ThreatHintAnalyzerAdapter(
            ledger, unsafe, CONTEXT.network_id, now_seconds=lambda: NOW_SECONDS + 1
        )
        result = await adapter.drain_once()
        assert len(result.failures) == 1
        digest = hashlib.sha256(hint.to_wire()).hexdigest()
        assert result.failures[0] == ThreatHintDrainFailure(0, "analysis", digest)
        assert len(ledger.pending_jobs(8)) == 1

        ledger.mark_delivered = MagicMock(side_effect=RuntimeError("delivery failed"))
        analyzer = SafeAnalyzer()
        adapter = ThreatHintAnalyzerAdapter(
            ledger,
            analyzer,
            CONTEXT.network_id,
            now_seconds=lambda: NOW_SECONDS + 1,
        )
        result = await adapter.drain_once()
        assert len(result.failures) == 1
        assert result.failures[0] == ThreatHintDrainFailure(0, "delivery", digest)
        assert len(ledger.pending_jobs(8)) == 1

        adapter = ThreatHintAnalyzerAdapter(
            ledger,
            SafeAnalyzer(),
            CONTEXT.network_id,
            now_seconds=lambda: NOW_SECONDS - 1,
        )
        result = await adapter.drain_once()
        assert len(result.failures) == 1
        assert result.failures[0] == ThreatHintDrainFailure(0, "clock", digest)
        assert len(ledger.pending_jobs(8)) == 1
    finally:
        shutil.rmtree(directory)


@pytest.mark.asyncio
async def test_analyzer_cancellation_is_not_suppressed() -> None:
    directory = owner_only_directory()
    try:
        ledger = ThreatHintReplayLedger(directory / "replay.sqlite3")
        hint = make_hint()
        assert ledger.admit(hint, hint.to_wire(), CONTEXT, NOW_SECONDS) == "accepted"
        analyzer = MagicMock()
        analyzer.process_verified_threat_hint = AsyncMock(
            side_effect=asyncio.CancelledError
        )
        adapter = ThreatHintAnalyzerAdapter(
            ledger,
            analyzer,
            CONTEXT.network_id,
            now_seconds=lambda: NOW_SECONDS + 1,
        )

        with pytest.raises(asyncio.CancelledError):
            await adapter.drain_once()
        assert len(ledger.pending_jobs(8)) == 1
    finally:
        shutil.rmtree(directory)


@pytest.mark.asyncio
async def test_delivery_cancellation_waits_for_durable_outcome() -> None:
    directory = owner_only_directory()
    release = threading.Event()
    try:
        ledger = ThreatHintReplayLedger(directory / "replay.sqlite3")
        hint = make_hint()
        assert ledger.admit(hint, hint.to_wire(), CONTEXT, NOW_SECONDS) == "accepted"
        original_mark_delivered = ledger.mark_delivered
        started = threading.Event()

        def blocking_delivery(payload_digest: str, delivered_at: int) -> None:
            started.set()
            release.wait()
            original_mark_delivered(payload_digest, delivered_at)

        ledger.mark_delivered = blocking_delivery
        adapter = ThreatHintAnalyzerAdapter(
            ledger,
            SafeAnalyzer(),
            CONTEXT.network_id,
            now_seconds=lambda: NOW_SECONDS + 1,
        )
        drain = asyncio.create_task(adapter.drain_once())
        assert await asyncio.to_thread(started.wait, 1.0)

        drain.cancel()
        await asyncio.sleep(0)
        assert not drain.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await drain
        assert ledger.pending_jobs(8) == []
    finally:
        release.set()
        shutil.rmtree(directory)


@pytest.mark.asyncio
async def test_concurrent_drains_are_serialized_and_at_most_batch_is_loaded() -> None:
    directory = owner_only_directory()
    try:
        ledger = ThreatHintReplayLedger(directory / "replay.sqlite3")
        for index in range(2):
            hint = make_hint(
                threat_hash=f"{index + 10:064x}",
                report_nonce=f"{index + 20:064x}",
            )
            assert (
                ledger.admit(hint, hint.to_wire(), CONTEXT, NOW_SECONDS) == "accepted"
            )
        analyzer = BlockingAnalyzer()
        adapter = ThreatHintAnalyzerAdapter(
            ledger,
            analyzer,
            CONTEXT.network_id,
            now_seconds=lambda: NOW_SECONDS + 1,
            batch_limit=1,
        )
        first = asyncio.create_task(adapter.drain_once())
        await analyzer.started.wait()
        second = asyncio.create_task(adapter.drain_once())
        await asyncio.sleep(0)
        assert len(analyzer.hints) == 1
        analyzer.release.set()
        first_result, second_result = await asyncio.gather(first, second)
        assert len(first_result.delivered) == 1
        assert len(second_result.delivered) == 1
        assert len(analyzer.hints) == 2
        assert ledger.pending_jobs(8) == []
    finally:
        shutil.rmtree(directory)


def test_constructor_bounds_batch_network_and_clock() -> None:
    directory = owner_only_directory()
    try:
        ledger = ThreatHintReplayLedger(directory / "replay.sqlite3")
        with pytest.raises(ThreatHintAdapterError, match="batch"):
            ThreatHintAnalyzerAdapter(
                ledger,
                SafeAnalyzer(),
                CONTEXT.network_id,
                now_seconds=lambda: NOW_SECONDS,
                batch_limit=MAX_ANALYZER_BATCH_LIMIT + 1,
            )
        with pytest.raises(ThreatHintAdapterError, match="network"):
            ThreatHintAnalyzerAdapter(
                ledger, SafeAnalyzer(), "INVALID", now_seconds=lambda: NOW_SECONDS
            )
        with pytest.raises(ThreatHintAdapterError, match="clock"):
            ThreatHintAnalyzerAdapter(
                ledger,
                SafeAnalyzer(),
                CONTEXT.network_id,
                now_seconds=None,  # type: ignore[arg-type]
            )
    finally:
        shutil.rmtree(directory)
