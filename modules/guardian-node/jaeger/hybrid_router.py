"""Fail-closed hybrid routing for Guardian threat analyzers.

The router runs an 8B analyzer first and escalates uncertain results to an
independently injected 70B analyzer. It does not own model processes, network
transport, consensus, or submission side effects.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Literal, Protocol

from .analyzer import AnalysisResult, ThreatHint
from .yara_generator import MIN_CONFIDENCE, YaraRule

ESCALATION_CONFIDENCE: float = 0.70

ModelTier = Literal["8b", "70b", "none"]


class ThreatAnalyzer(Protocol):
    """Structural interface implemented by the Guardian analyzer pipeline."""

    async def process_threat_hint(self, hint: ThreatHint) -> AnalysisResult:
        """Analyze a threat hint and return a submission decision."""


@dataclass(frozen=True)
class HybridAnalysisResult:
    """Analysis plus the routing decision that produced it."""

    analysis: AnalysisResult
    selected_tier: ModelTier
    escalated: bool
    primary_confidence: float | None
    routing_reason: str


class HybridAnalyzer:
    """Route threat hints through 8B-first, 70B-on-uncertainty analysis."""

    def __init__(
        self,
        primary_8b: ThreatAnalyzer,
        escalation_70b: ThreatAnalyzer,
    ) -> None:
        """Initialize the router with independently injected analyzers."""
        self.primary_8b = primary_8b
        self.escalation_70b = escalation_70b

    async def process_threat_hint(self, hint: ThreatHint) -> HybridAnalysisResult:
        """Run 8B first and escalate only when its result is uncertain or invalid."""
        primary: AnalysisResult | None = None
        primary_reason = "8B confidence below escalation threshold"

        try:
            primary = await self.primary_8b.process_threat_hint(hint)
        except Exception:  # pylint: disable=broad-except
            primary_reason = "8B analysis failed"
        else:
            if _is_safe_analysis(primary, hint.threat_hash):
                primary_confidence = float(primary.confidence)
                if primary_confidence >= ESCALATION_CONFIDENCE:
                    return HybridAnalysisResult(
                        analysis=primary,
                        selected_tier="8b",
                        escalated=False,
                        primary_confidence=primary_confidence,
                        routing_reason="8B confidence met escalation threshold",
                    )
            else:
                primary_reason = "8B analysis returned an invalid safety decision"

        primary_confidence = (
            float(primary.confidence)
            if isinstance(primary, AnalysisResult)
            and _is_valid_confidence(primary.confidence)
            else None
        )

        try:
            escalation = await self.escalation_70b.process_threat_hint(hint)
        except Exception:  # pylint: disable=broad-except
            return _failed_route(
                hint, primary_confidence, f"{primary_reason}; 70B analysis failed"
            )

        if not _is_safe_analysis(escalation, hint.threat_hash):
            return _failed_route(
                hint,
                primary_confidence,
                f"{primary_reason}; 70B returned an invalid safety decision",
            )

        return HybridAnalysisResult(
            analysis=escalation,
            selected_tier="70b",
            escalated=True,
            primary_confidence=primary_confidence,
            routing_reason=f"{primary_reason}; 70B analysis selected",
        )


def _is_valid_confidence(value: object) -> bool:
    """Return whether a value is a finite numeric confidence within [0, 1]."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    numeric = float(value)
    return math.isfinite(numeric) and 0.0 <= numeric <= 1.0


def _is_safe_analysis(result: object, threat_hash: str) -> bool:
    """Reject malformed or internally unsafe analysis decisions."""
    if not isinstance(result, AnalysisResult) or not _is_valid_confidence(
        result.confidence
    ):
        return False
    if result.threat_hash != threat_hash or not isinstance(result.should_submit, bool):
        return False

    if result.yara_rule is not None:
        if not isinstance(result.yara_rule, YaraRule):
            return False
        if (
            result.yara_rule.threat_hash != threat_hash
            or not _is_valid_confidence(result.yara_rule.confidence)
            or not math.isclose(
                float(result.yara_rule.confidence),
                float(result.confidence),
                rel_tol=0.0,
                abs_tol=1e-9,
            )
        ):
            return False

    if result.should_submit and (
        float(result.confidence) < MIN_CONFIDENCE or result.yara_rule is None
    ):
        return False
    return True


def _failed_route(
    hint: ThreatHint, primary_confidence: float | None, routing_reason: str
) -> HybridAnalysisResult:
    """Build a non-submittable result when no trustworthy route completes."""
    return HybridAnalysisResult(
        analysis=AnalysisResult(
            threat_hash=hint.threat_hash,
            yara_rule=None,
            confidence=0.0,
            should_submit=False,
            analysis_notes="Hybrid Guardian analysis failed closed.",
        ),
        selected_tier="none",
        escalated=True,
        primary_confidence=primary_confidence,
        routing_reason=routing_reason,
    )
