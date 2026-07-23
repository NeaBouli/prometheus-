"""Bounded adapter from verified ThreatHint outbox jobs to analyzer inputs."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import math
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final, Literal, Protocol

from .analyzer import AnalysisResult, VerifiedThreatHint
from .threat_hint_ingress import (
    MAX_FUTURE_SKEW_SECONDS,
    MAX_HINT_AGE_SECONDS,
    CanonicalThreatHint,
    ThreatHintIngressError,
    ThreatHintReplayLedger,
    ThreatProofContext,
    VerifiedThreatHintJob,
)

DEFAULT_ANALYZER_BATCH_LIMIT: Final[int] = 16
MAX_ANALYZER_BATCH_LIMIT: Final[int] = 32


class ThreatHintAdapterError(ValueError):
    """A verified outbox job cannot safely cross the analyzer boundary."""


class VerifiedThreatAnalyzer(Protocol):  # pylint: disable=too-few-public-methods
    """Analyzer entry point restricted to verified, indicator-free v1 input."""

    async def process_verified_threat_hint(
        self, hint: VerifiedThreatHint
    ) -> AnalysisResult:
        """Return a safe v1 analysis decision without submission side effects."""


@dataclass(frozen=True)
class DeliveredThreatHintAnalysis:
    """One outbox job delivered after an exact fail-closed analyzer result."""

    hint: VerifiedThreatHint
    analysis: AnalysisResult
    delivered_at: int
    batch_index: int


FailureCategory = Literal["adapt", "analysis", "clock", "delivery"]


@dataclass(frozen=True)
class ThreatHintDrainFailure:
    """One bounded job failure with a minimal, non-sensitive envelope."""

    batch_index: int
    category: FailureCategory
    payload_digest: str | None


@dataclass(frozen=True)
class ThreatHintDrainReport:
    """Result of one bounded drain attempt."""

    delivered: tuple[DeliveredThreatHintAnalysis, ...]
    failures: tuple[ThreatHintDrainFailure, ...]


class ThreatHintAnalyzerAdapter:
    """Drain a bounded batch of independent v1 jobs without FIFO acknowledgement."""

    def __init__(
        self,
        ledger: ThreatHintReplayLedger,
        analyzer: VerifiedThreatAnalyzer,
        expected_network_id: str,
        *,
        now_seconds: Callable[[], int],
        batch_limit: int = DEFAULT_ANALYZER_BATCH_LIMIT,
    ) -> None:
        if not isinstance(ledger, ThreatHintReplayLedger):
            raise ThreatHintAdapterError("ThreatHint replay ledger is required")
        if not callable(getattr(analyzer, "process_verified_threat_hint", None)):
            raise ThreatHintAdapterError("verified ThreatHint analyzer is required")
        try:
            ThreatProofContext(expected_network_id)
        except ThreatHintIngressError as exc:
            raise ThreatHintAdapterError(
                "expected analyzer network is invalid"
            ) from exc
        if (
            isinstance(batch_limit, bool)
            or not isinstance(batch_limit, int)
            or not 1 <= batch_limit <= MAX_ANALYZER_BATCH_LIMIT
        ):
            raise ThreatHintAdapterError("analyzer batch limit is invalid")
        if not callable(now_seconds):
            raise ThreatHintAdapterError("analyzer clock is required")
        self._ledger = ledger
        self._analyzer = analyzer
        self._expected_network_id = expected_network_id
        self._now_seconds = now_seconds
        self._batch_limit = batch_limit
        self._drain_lock = asyncio.Lock()

    def adapt_job(self, job: VerifiedThreatHintJob) -> VerifiedThreatHint:
        """Revalidate one durable job and map only fields present in v1."""
        if not isinstance(job, VerifiedThreatHintJob):
            raise ThreatHintAdapterError("verified ThreatHint outbox job is required")
        if job.network_id != self._expected_network_id:
            raise ThreatHintAdapterError("ThreatHint outbox network mismatch")
        if not _is_positive_int(job.admitted_at):
            raise ThreatHintAdapterError("ThreatHint admission time is invalid")
        if not isinstance(job.canonical_wire, bytes) or not job.canonical_wire:
            raise ThreatHintAdapterError("ThreatHint outbox wire is invalid")
        if not _is_lower_hex_32(job.payload_digest):
            raise ThreatHintAdapterError("ThreatHint outbox digest is invalid")

        digest = hashlib.sha256(job.canonical_wire).hexdigest()
        if not hmac.compare_digest(digest, job.payload_digest):
            raise ThreatHintAdapterError("ThreatHint outbox digest mismatch")
        try:
            envelope = CanonicalThreatHint.from_wire(job.canonical_wire)
        except ThreatHintIngressError as exc:
            raise ThreatHintAdapterError("ThreatHint outbox wire is invalid") from exc
        if envelope.proof_system != "groth16_kip16_v1":
            raise ThreatHintAdapterError("ThreatHint outbox proof system is invalid")
        if not (
            envelope.observed_at - MAX_FUTURE_SKEW_SECONDS
            <= job.admitted_at
            <= envelope.observed_at + MAX_HINT_AGE_SECONDS
        ):
            raise ThreatHintAdapterError("ThreatHint admission window is invalid")

        try:
            return VerifiedThreatHint(
                payload_digest=job.payload_digest,
                schema_version=envelope.schema_version,
                threat_hash=envelope.threat_hash,
                confidence_bps=envelope.confidence_bps,
                indicator_type=envelope.indicator_type,
                proof_system=envelope.proof_system,
                reporter_zk_proof=bytes.fromhex(envelope.proof),
                report_nonce=envelope.report_nonce,
                observed_at=envelope.observed_at,
                network_id=job.network_id,
                admitted_at=job.admitted_at,
            )
        except ValueError as exc:
            raise ThreatHintAdapterError(
                "ThreatHint analyzer input is invalid"
            ) from exc

    async def drain_once(self) -> ThreatHintDrainReport:
        """Process one bounded batch while failed jobs remain independently pending."""
        async with self._drain_lock:
            jobs = await asyncio.to_thread(self._ledger.pending_jobs, self._batch_limit)
            delivered: list[DeliveredThreatHintAnalysis] = []
            failures: list[ThreatHintDrainFailure] = []
            if len(jobs) > self._batch_limit:
                raise ThreatHintAdapterError("analyzer batch is unexpectedly unbounded")
            for batch_index, job in enumerate(jobs):
                try:
                    hint = self.adapt_job(job)
                except Exception:  # pylint: disable=broad-exception-caught
                    failures.append(ThreatHintDrainFailure(batch_index, "adapt", None))
                    continue
                digest = hint.payload_digest

                try:
                    analysis = await self._analyzer.process_verified_threat_hint(hint)
                    _validate_v1_analysis(hint, analysis)
                except Exception:  # pylint: disable=broad-exception-caught
                    failures.append(
                        ThreatHintDrainFailure(batch_index, "analysis", digest)
                    )
                    continue

                try:
                    delivered_at = self._now_seconds()
                    if (
                        not _is_positive_int(delivered_at)
                        or delivered_at < hint.admitted_at
                    ):
                        raise ThreatHintAdapterError("analyzer clock rollback detected")
                except Exception:  # pylint: disable=broad-exception-caught
                    failures.append(
                        ThreatHintDrainFailure(batch_index, "clock", digest)
                    )
                    continue

                try:
                    await _mark_delivered_cancellation_safe(
                        self._ledger,
                        hint.payload_digest,
                        delivered_at,
                    )
                except Exception:  # pylint: disable=broad-exception-caught
                    failures.append(
                        ThreatHintDrainFailure(batch_index, "delivery", digest)
                    )
                    continue
                delivered.append(
                    DeliveredThreatHintAnalysis(
                        hint, analysis, delivered_at, batch_index
                    )
                )
            if len(delivered) + len(failures) > MAX_ANALYZER_BATCH_LIMIT:
                raise ThreatHintAdapterError(
                    "analyzer batch result is unexpectedly oversized"
                )
            return ThreatHintDrainReport(tuple(delivered), tuple(failures))


def _validate_v1_analysis(hint: VerifiedThreatHint, analysis: object) -> None:
    if not isinstance(analysis, AnalysisResult):
        raise ThreatHintAdapterError("analyzer returned an invalid result")
    if analysis.threat_hash != hint.threat_hash:
        raise ThreatHintAdapterError("analyzer returned an unsafe v1 decision")
    if (
        isinstance(analysis.confidence, bool)
        or not isinstance(analysis.confidence, (int, float))
        or not math.isfinite(float(analysis.confidence))
        or float(analysis.confidence) != 0.0
    ):
        raise ThreatHintAdapterError("analyzer returned an unsafe v1 decision")
    if analysis.yara_rule is not None or analysis.should_submit is not False:
        raise ThreatHintAdapterError("analyzer returned an unsafe v1 decision")
    if not isinstance(analysis.analysis_notes, str) or not analysis.analysis_notes:
        raise ThreatHintAdapterError("analyzer returned an unsafe v1 decision")


def _is_positive_int(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value > 0


def _is_lower_hex_32(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


async def _mark_delivered_cancellation_safe(
    ledger: ThreatHintReplayLedger,
    payload_digest: str,
    delivered_at: int,
) -> None:
    delivery = asyncio.create_task(
        asyncio.to_thread(ledger.mark_delivered, payload_digest, delivered_at)
    )
    try:
        await asyncio.shield(delivery)
    except asyncio.CancelledError as cancelled:
        while not delivery.done():
            try:
                await asyncio.shield(delivery)
            except asyncio.CancelledError:
                continue
        try:
            delivery.result()
        except Exception:  # pylint: disable=broad-exception-caught
            pass
        raise cancelled
