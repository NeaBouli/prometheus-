"""Bounded owner-local processing for durable ThreatHint-v2 observables.

The worker accepts only claims produced by the governed v4 outbox and stores
only exact non-actionable result contracts enforced by that outbox. It has no
transport, publication, reward, wallet, or chain authority. The legacy analyzer
only counts observables. The semantic-draft analyzer deterministically derives
one memory-only candidate, compile-checks it without scanning, and persists only
its nonce-bound binding, verdict, and kind counts. Neither analyzer calls a
model or grants semantic-quality, submission, disclosure, or production authority.
"""

# Exact built-in types are protocol requirements.
# pylint: disable=unidiomatic-typecheck,too-few-public-methods
# pylint: disable=too-many-boolean-expressions

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Final, Protocol

from jaeger.observable_approval import FIXED_HASH_BYTES, UINT64_MAX
from jaeger.observable_approval_consumption import (
    MAX_CANONICAL_ANALYSIS_RESULT_BYTES,
    MAX_OUTBOX_LEASE_SECONDS,
    ObservableAnalysisCompletion,
    ObservableApprovalOutbox,
    ObservableApprovalOutboxClaim,
    ObservableApprovalOutboxError,
    build_analysis_result_wire,
    build_semantic_draft_result_wire,
)
from jaeger.observable_semantic_draft import (
    ObservableSemanticDraftError,
    derive_semantic_draft,
)
from jaeger.threat_hint_v2_statement import (
    MAX_CANONICAL_V2_STATEMENT_BYTES,
    STATEMENT_DIGEST_DOMAIN,
)
from jaeger.threat_observable import MAX_CANONICAL_BYTES, ObservableBundle

MAX_WORKER_CONCURRENCY: Final[int] = 8
MAX_ANALYZER_TIMEOUT_SECONDS: Final[float] = 300.0
MAX_WORKER_BATCH: Final[int] = 64
DETERMINISTIC_ANALYZER_ID: Final[str] = "deterministic_test_v1"
SEMANTIC_DRAFT_ANALYZER_ID: Final[str] = "deterministic_semantic_draft_v2"
SEMANTIC_DRAFT_BINDING_DOMAIN: Final[bytes] = (
    b"prometheus-observable-semantic-draft-binding-v1\x00"
)


class ObservableAnalysisWorkerError(ValueError):
    """Stable redacted failure for worker configuration or analyzer execution."""

    _MESSAGE = "observable analysis worker failure"

    def __init__(self) -> None:
        super().__init__(self._MESSAGE)


class ObservableAnalysisWorkerTimeoutError(ObservableAnalysisWorkerError):
    """The local analyzer exceeded its configured bounded runtime."""

    _MESSAGE = "observable analysis worker timeout"


@dataclass(frozen=True, repr=False)
class ObservableAnalysisInput:
    """Frozen data-only v2 analyzer input; it grants no downstream authority."""

    approval_id: bytes
    observable_commitment: bytes
    statement_digest: bytes
    report_nonce: bytes
    statement_wire: bytes
    bundle_wire: bytes
    input_identity: bytes

    def __post_init__(self) -> None:
        fixed_values = (
            self.approval_id,
            self.observable_commitment,
            self.statement_digest,
            self.report_nonce,
            self.input_identity,
        )
        if (
            any(
                type(value) is not bytes or len(value) != FIXED_HASH_BYTES
                for value in fixed_values
            )
            or type(self.statement_wire) is not bytes
            or not 1 <= len(self.statement_wire) <= MAX_CANONICAL_V2_STATEMENT_BYTES
            or type(self.bundle_wire) is not bytes
            or not 1 <= len(self.bundle_wire) <= MAX_CANONICAL_BYTES
        ):
            raise ObservableAnalysisWorkerError()


class ObservableAnalysisAnalyzer(Protocol):
    """Typed async analyzer boundary returning one canonical local result wire."""

    async def analyze(self, analysis_input: ObservableAnalysisInput) -> bytes:
        """Return one canonical explicitly non-actionable result wire."""


class DeterministicNonActionableAnalyzer:
    """Deterministic test analyzer that only validates and counts observables."""

    async def analyze(self, analysis_input: ObservableAnalysisInput) -> bytes:
        """Build a fixed-schema result without semantic or actionable output."""
        if type(analysis_input) is not ObservableAnalysisInput:
            raise ObservableAnalysisWorkerError()
        try:
            bundle = ObservableBundle.parse_canonical(analysis_input.bundle_wire)
        except ValueError:
            raise ObservableAnalysisWorkerError() from None
        if not hmac.compare_digest(
            _statement_digest(analysis_input.statement_wire),
            analysis_input.statement_digest,
        ):
            raise ObservableAnalysisWorkerError()
        try:
            return build_analysis_result_wire(
                analyzer_id=DETERMINISTIC_ANALYZER_ID,
                approval_id=analysis_input.approval_id,
                input_identity=analysis_input.input_identity,
                statement_digest=analysis_input.statement_digest,
                observable_commitment=analysis_input.observable_commitment,
                observable_count=len(bundle.observables),
            )
        except ObservableApprovalOutboxError:
            raise ObservableAnalysisWorkerError() from None


class DeterministicSemanticDraftAnalyzer:
    """Derive one binding-only compile-checked draft without external effects."""

    async def analyze(self, analysis_input: ObservableAnalysisInput) -> bytes:
        """Build a canonical v2 semantic draft result from governed input."""
        if type(analysis_input) is not ObservableAnalysisInput:
            raise ObservableAnalysisWorkerError()
        try:
            bundle = ObservableBundle.parse_canonical(analysis_input.bundle_wire)
        except ValueError:
            raise ObservableAnalysisWorkerError() from None
        if not hmac.compare_digest(
            _statement_digest(analysis_input.statement_wire),
            analysis_input.statement_digest,
        ):
            raise ObservableAnalysisWorkerError()
        try:
            draft = derive_semantic_draft(bundle)
            return build_semantic_draft_result_wire(
                analyzer_id=SEMANTIC_DRAFT_ANALYZER_ID,
                approval_id=analysis_input.approval_id,
                input_identity=analysis_input.input_identity,
                statement_digest=analysis_input.statement_digest,
                observable_commitment=analysis_input.observable_commitment,
                file_sha256_count=draft.file_sha256_count,
                api_import_count=draft.api_import_count,
                byte_pattern_count=draft.byte_pattern_count,
                candidate_binding_sha256=_semantic_draft_binding(
                    analysis_input.report_nonce,
                    draft.candidate_rule_sha256,
                ),
                rule_compile_ok=draft.rule_compile_ok,
            )
        except (ObservableSemanticDraftError, ObservableApprovalOutboxError):
            raise ObservableAnalysisWorkerError() from None


class ObservableAnalysisWorker:
    """Claim, analyze, and atomically complete bounded owner-local work."""

    def __init__(
        self,
        outbox: ObservableApprovalOutbox,
        analyzer: ObservableAnalysisAnalyzer,
        *,
        lease_seconds: int,
        analyzer_timeout_seconds: float,
        max_concurrency: int = 1,
    ) -> None:
        analyze = getattr(analyzer, "analyze", None)
        if (
            type(outbox) is not ObservableApprovalOutbox
            or not callable(analyze)
            or type(lease_seconds) is not int
            or not 1 <= lease_seconds <= MAX_OUTBOX_LEASE_SECONDS
            or type(analyzer_timeout_seconds) not in (int, float)
            or not 0 < float(analyzer_timeout_seconds) <= MAX_ANALYZER_TIMEOUT_SECONDS
            or float(analyzer_timeout_seconds) > lease_seconds
            or type(max_concurrency) is not int
            or not 1 <= max_concurrency <= MAX_WORKER_CONCURRENCY
        ):
            raise ObservableAnalysisWorkerError()
        self._outbox = outbox
        self._analyzer = analyzer
        self._lease_seconds = lease_seconds
        self._analyzer_timeout_seconds = float(analyzer_timeout_seconds)
        self._slots = asyncio.Semaphore(max_concurrency)

    async def process_next(
        self, *, current_time: int
    ) -> ObservableAnalysisCompletion | None:
        """Process the oldest eligible record once, leaving failures leased."""
        if type(current_time) is not int or not 1 <= current_time <= UINT64_MAX:
            raise ObservableAnalysisWorkerError()
        async with self._slots:
            claim = self._outbox.claim(
                current_time=current_time,
                lease_seconds=self._lease_seconds,
            )
            if claim is None:
                return None
            analysis_input = _input_from_claim(claim)
            try:
                completion_token = os.urandom(FIXED_HASH_BYTES)
            except OSError:
                raise ObservableAnalysisWorkerError() from None
            try:
                result_wire = await asyncio.wait_for(
                    self._analyzer.analyze(analysis_input),
                    timeout=self._analyzer_timeout_seconds,
                )
            except TimeoutError:
                raise ObservableAnalysisWorkerTimeoutError() from None
            except Exception:
                raise ObservableAnalysisWorkerError() from None
            if (
                type(result_wire) is not bytes
                or not 1 <= len(result_wire) <= MAX_CANONICAL_ANALYSIS_RESULT_BYTES
            ):
                raise ObservableAnalysisWorkerError()
            return self._outbox.complete(
                approval_id=claim.approval_id,
                lease_token=claim.lease_token,
                completion_token=completion_token,
                input_identity=claim.input_identity,
                result_wire=result_wire,
                current_time=current_time,
            )

    async def process_pending(
        self,
        *,
        current_time: int,
        max_records: int,
    ) -> int:
        """Process at most ``max_records`` sequentially and return the count."""
        if type(max_records) is not int or not 1 <= max_records <= MAX_WORKER_BATCH:
            raise ObservableAnalysisWorkerError()
        completed = 0
        while completed < max_records:
            result = await self.process_next(current_time=current_time)
            if result is None:
                break
            completed += 1
        return completed


def _input_from_claim(claim: ObservableApprovalOutboxClaim) -> ObservableAnalysisInput:
    if type(claim) is not ObservableApprovalOutboxClaim:
        raise ObservableAnalysisWorkerError()
    return ObservableAnalysisInput(
        approval_id=claim.approval_id,
        observable_commitment=claim.observable_commitment,
        statement_digest=claim.statement_digest,
        report_nonce=claim.report_nonce,
        statement_wire=claim.statement_wire,
        bundle_wire=claim.bundle_wire,
        input_identity=claim.input_identity,
    )


def _statement_digest(statement_wire: bytes) -> bytes:
    digest = hashlib.sha256()
    digest.update(STATEMENT_DIGEST_DOMAIN)
    digest.update(len(statement_wire).to_bytes(4, byteorder="big", signed=False))
    digest.update(statement_wire)
    return digest.digest()


def _semantic_draft_binding(report_nonce: bytes, candidate_rule_sha256: bytes) -> bytes:
    """Bind one transient candidate digest to its approved report nonce."""
    if (
        type(report_nonce) is not bytes
        or len(report_nonce) != FIXED_HASH_BYTES
        or type(candidate_rule_sha256) is not bytes
        or len(candidate_rule_sha256) != FIXED_HASH_BYTES
    ):
        raise ObservableAnalysisWorkerError()
    digest = hashlib.sha256()
    digest.update(SEMANTIC_DRAFT_BINDING_DOMAIN)
    digest.update(report_nonce)
    digest.update(candidate_rule_sha256)
    return digest.digest()
