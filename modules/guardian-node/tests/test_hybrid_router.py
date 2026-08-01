"""Tests for fail-closed Guardian 8B/70B hybrid routing."""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field

import pytest

from jaeger.analyzer import AnalysisResult, ThreatHint
from jaeger.hybrid_router import ESCALATION_CONFIDENCE, HybridAnalyzer
from jaeger.yara_generator import MIN_CONFIDENCE, YaraRule


def make_hint() -> ThreatHint:
    """Build a deterministic local hint without network or model dependencies."""
    return ThreatHint(
        threat_hash="a" * 64,
        reporter_zk_proof=b"proof",
        indicators=["suspicious process tree"],
        timestamp=1_700_000_000,
    )


def make_analysis(confidence: float, should_submit: bool = False) -> AnalysisResult:
    """Build an analysis with a rule when the decision is submittable."""
    rule = None
    if should_submit:
        rule = YaraRule(
            name="TEST_RULE",
            rule_content='rule TEST_RULE { strings: $a = "x" condition: $a }',
            confidence_bps=round(confidence * 10_000),
            threat_hash="a" * 64,
            generated_at=int(time.time()),
        )
    return AnalysisResult(
        threat_hash="a" * 64,
        yara_rule=rule,
        confidence=confidence,
        should_submit=should_submit,
        analysis_notes="test analysis",
    )


@dataclass
class StubAnalyzer:
    """Dependency-injected analyzer stub with call tracking."""

    result: AnalysisResult | None = None
    error: Exception | None = None
    calls: list[ThreatHint] = field(default_factory=list)

    async def process_threat_hint(self, hint: ThreatHint) -> AnalysisResult:
        """Return the configured result or raise the configured error."""
        self.calls.append(hint)
        if self.error is not None:
            raise self.error
        assert self.result is not None
        return self.result


@dataclass
class MalformedAnalyzer:
    """Analyzer adapter that violates the structural return contract."""

    async def process_threat_hint(self, hint: ThreatHint) -> object:
        """Return a non-analysis object to exercise the total safety envelope."""
        del hint
        return object()


@pytest.mark.asyncio
async def test_keeps_8b_result_above_threshold() -> None:
    """A confident 8B result must not consume the 70B route."""
    primary = StubAnalyzer(result=make_analysis(0.71))
    escalation = StubAnalyzer(result=make_analysis(0.95, should_submit=True))

    routed = await HybridAnalyzer(primary, escalation).process_threat_hint(make_hint())

    assert routed.selected_tier == "8b"
    assert routed.escalated is False
    assert routed.primary_confidence == 0.71
    assert routed.analysis.confidence == 0.71
    assert len(primary.calls) == 1
    assert escalation.calls == []


@pytest.mark.asyncio
async def test_exact_threshold_stays_on_8b() -> None:
    """The 0.70 boundary belongs to the primary route."""
    primary = StubAnalyzer(result=make_analysis(ESCALATION_CONFIDENCE))
    escalation = StubAnalyzer(result=make_analysis(0.90, should_submit=True))

    routed = await HybridAnalyzer(primary, escalation).process_threat_hint(make_hint())

    assert routed.selected_tier == "8b"
    assert routed.escalated is False
    assert escalation.calls == []


@pytest.mark.asyncio
async def test_escalates_below_threshold_and_uses_70b_result() -> None:
    """An uncertain 8B result must be replaced by a valid 70B result."""
    primary = StubAnalyzer(result=make_analysis(0.69))
    escalation = StubAnalyzer(result=make_analysis(0.91, should_submit=True))

    routed = await HybridAnalyzer(primary, escalation).process_threat_hint(make_hint())

    assert routed.selected_tier == "70b"
    assert routed.escalated is True
    assert routed.primary_confidence == 0.69
    assert routed.analysis.confidence == 0.91
    assert routed.analysis.should_submit is True
    assert len(escalation.calls) == 1


@pytest.mark.asyncio
async def test_70b_failure_fails_closed() -> None:
    """A failed escalation must never fall back to an uncertain 8B decision."""
    primary = StubAnalyzer(result=make_analysis(0.50))
    escalation = StubAnalyzer(error=RuntimeError("endpoint unavailable"))

    routed = await HybridAnalyzer(primary, escalation).process_threat_hint(make_hint())

    assert routed.selected_tier == "none"
    assert routed.escalated is True
    assert routed.analysis.confidence == 0.0
    assert routed.analysis.should_submit is False
    assert routed.analysis.yara_rule is None
    assert "endpoint unavailable" not in routed.analysis.analysis_notes


@pytest.mark.asyncio
@pytest.mark.parametrize("confidence", [math.nan, math.inf, -0.01, 1.01, True, False])
async def test_invalid_primary_confidence_escalates(confidence: object) -> None:
    """Malformed primary confidence is uncertainty and requires a valid 70B result."""
    primary = StubAnalyzer(result=make_analysis(confidence))
    escalation = StubAnalyzer(result=make_analysis(0.80))

    routed = await HybridAnalyzer(primary, escalation).process_threat_hint(make_hint())

    assert routed.selected_tier == "70b"
    assert routed.primary_confidence is None
    assert routed.analysis.confidence == 0.80


@pytest.mark.asyncio
async def test_malformed_primary_result_escalates_without_raising() -> None:
    """An adapter contract violation is treated as uncertainty, not an exception."""
    escalation = StubAnalyzer(result=make_analysis(0.80))

    routed = await HybridAnalyzer(  # type: ignore[arg-type]
        MalformedAnalyzer(), escalation
    ).process_threat_hint(make_hint())

    assert routed.selected_tier == "70b"
    assert routed.primary_confidence is None
    assert routed.analysis.confidence == 0.80


@pytest.mark.asyncio
@pytest.mark.parametrize("confidence", [math.nan, math.inf, -0.01, 1.01, True, False])
async def test_invalid_70b_confidence_fails_closed(confidence: object) -> None:
    """Malformed escalation confidence cannot authorize a network submission."""
    primary = StubAnalyzer(result=make_analysis(0.40))
    escalation = StubAnalyzer(result=make_analysis(confidence))

    routed = await HybridAnalyzer(primary, escalation).process_threat_hint(make_hint())

    assert routed.selected_tier == "none"
    assert routed.analysis.confidence == 0.0
    assert routed.analysis.should_submit is False


@pytest.mark.asyncio
async def test_rejects_unsafe_submit_decision() -> None:
    """Submission below MIN_CONFIDENCE is rejected even if an analyzer marks it true."""
    unsafe = make_analysis(MIN_CONFIDENCE - 0.01, should_submit=True)
    primary = StubAnalyzer(result=make_analysis(0.40))
    escalation = StubAnalyzer(result=unsafe)

    routed = await HybridAnalyzer(primary, escalation).process_threat_hint(make_hint())

    assert routed.selected_tier == "none"
    assert routed.analysis.should_submit is False


@pytest.mark.asyncio
async def test_exact_submission_threshold_is_allowed() -> None:
    """The existing MIN_CONFIDENCE boundary remains a valid submit decision."""
    primary = StubAnalyzer(result=make_analysis(0.40))
    escalation = StubAnalyzer(result=make_analysis(MIN_CONFIDENCE, should_submit=True))

    routed = await HybridAnalyzer(primary, escalation).process_threat_hint(make_hint())

    assert routed.selected_tier == "70b"
    assert routed.analysis.should_submit is True


@pytest.mark.asyncio
async def test_primary_hash_mismatch_requires_escalation() -> None:
    """A primary result for another threat cannot bypass the 70B route."""
    mismatched = make_analysis(0.95, should_submit=True)
    mismatched.threat_hash = "b" * 64
    primary = StubAnalyzer(result=mismatched)
    escalation = StubAnalyzer(result=make_analysis(0.80))

    routed = await HybridAnalyzer(primary, escalation).process_threat_hint(make_hint())

    assert routed.selected_tier == "70b"
    assert routed.analysis.threat_hash == make_hint().threat_hash


@pytest.mark.asyncio
async def test_70b_rule_hash_mismatch_fails_closed() -> None:
    """A 70B rule for another threat cannot authorize submission."""
    mismatched = make_analysis(0.95, should_submit=True)
    assert mismatched.yara_rule is not None
    mismatched.yara_rule.threat_hash = "b" * 64
    primary = StubAnalyzer(result=make_analysis(0.40))
    escalation = StubAnalyzer(result=mismatched)

    routed = await HybridAnalyzer(primary, escalation).process_threat_hint(make_hint())

    assert routed.selected_tier == "none"
    assert routed.analysis.should_submit is False


@pytest.mark.asyncio
@pytest.mark.parametrize("unsafe_value", ["false", 1])
async def test_non_boolean_submit_decision_fails_closed(unsafe_value: object) -> None:
    """Only a real bool may carry an analyzer submission decision."""
    malformed = make_analysis(0.95, should_submit=True)
    malformed.should_submit = unsafe_value  # type: ignore[assignment]
    primary = StubAnalyzer(result=make_analysis(0.40))
    escalation = StubAnalyzer(result=malformed)

    routed = await HybridAnalyzer(primary, escalation).process_threat_hint(make_hint())

    assert routed.selected_tier == "none"
    assert routed.analysis.should_submit is False


@pytest.mark.asyncio
async def test_non_yara_rule_fails_closed() -> None:
    """A truthy arbitrary object cannot stand in for a validated YARA rule."""
    malformed = make_analysis(0.95, should_submit=True)
    malformed.yara_rule = "not-a-rule"  # type: ignore[assignment]
    primary = StubAnalyzer(result=make_analysis(0.40))
    escalation = StubAnalyzer(result=malformed)

    routed = await HybridAnalyzer(primary, escalation).process_threat_hint(make_hint())

    assert routed.selected_tier == "none"
    assert routed.analysis.should_submit is False
