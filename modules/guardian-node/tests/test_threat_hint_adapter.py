"""Tests for the bounded verified ThreatHint analyzer adapter."""

# pylint: disable=missing-class-docstring,missing-function-docstring,too-few-public-methods

from __future__ import annotations

import asyncio
import hashlib
import os
import shutil
import tempfile
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from jaeger.analyzer import AnalysisResult, Analyzer, VerifiedThreatHint
from jaeger.threat_hint_adapter import (
    MAX_ANALYZER_BATCH_LIMIT,
    ThreatHintAdapterError,
    ThreatHintAnalyzerAdapter,
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
        delivered = await adapter.drain_once()
        assert len(delivered) == 1
        assert delivered[0].analysis.should_submit is False
        assert delivered[0].delivered_at == NOW_SECONDS + 1
        assert len(analyzer.hints) == 1
        assert ledger.pending_jobs(8) == []
        assert await adapter.drain_once() == []
    finally:
        shutil.rmtree(directory)


@pytest.mark.asyncio
async def test_analyzer_failure_or_unsafe_result_leaves_job_pending() -> None:
    directory = owner_only_directory()
    try:
        ledger = ThreatHintReplayLedger(directory / "replay.sqlite3")
        hint = make_hint()
        assert ledger.admit(hint, hint.to_wire(), CONTEXT, NOW_SECONDS) == "accepted"
        failed = MagicMock()
        failed.process_verified_threat_hint = AsyncMock(
            side_effect=RuntimeError("analyzer unavailable")
        )
        adapter = ThreatHintAnalyzerAdapter(
            ledger, failed, CONTEXT.network_id, now_seconds=lambda: NOW_SECONDS + 1
        )
        with pytest.raises(RuntimeError, match="unavailable"):
            await adapter.drain_once()
        assert len(ledger.pending_jobs(8)) == 1

        unsafe = MagicMock()
        unsafe.process_verified_threat_hint = AsyncMock(
            return_value=AnalysisResult(
                hint.threat_hash, None, 0.9, True, "invented confidence"
            )
        )
        adapter = ThreatHintAnalyzerAdapter(
            ledger, unsafe, CONTEXT.network_id, now_seconds=lambda: NOW_SECONDS + 1
        )
        with pytest.raises(ThreatHintAdapterError, match="unsafe v1 decision"):
            await adapter.drain_once()
        assert len(ledger.pending_jobs(8)) == 1
    finally:
        shutil.rmtree(directory)


@pytest.mark.asyncio
async def test_clock_rollback_leaves_job_pending() -> None:
    directory = owner_only_directory()
    try:
        ledger = ThreatHintReplayLedger(directory / "replay.sqlite3")
        hint = make_hint()
        assert ledger.admit(hint, hint.to_wire(), CONTEXT, NOW_SECONDS) == "accepted"
        adapter = ThreatHintAnalyzerAdapter(
            ledger,
            SafeAnalyzer(),
            CONTEXT.network_id,
            now_seconds=lambda: NOW_SECONDS - 1,
        )
        with pytest.raises(ThreatHintAdapterError, match="clock rollback"):
            await adapter.drain_once()
        assert len(ledger.pending_jobs(8)) == 1
    finally:
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
        assert len(first_result) == 1
        assert len(second_result) == 1
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
