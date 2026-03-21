"""Threat analysis pipeline for Guardian nodes.

Processes incoming threat hints from Light Clients, runs LLaMA 3
analysis, generates YARA rules, and determines submission eligibility.

MIN_CONFIDENCE = 0.85 (from MEMO.md).
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from .llm_server import LlmServer
from .yara_generator import MIN_CONFIDENCE, YaraRule, YaraRuleGenerator


@dataclass
class ThreatHint:
    """Incoming threat hint from a Light Client.

    Attributes:
        threat_hash: SHA-256 hash of the suspicious file.
        reporter_zk_proof: Groth16 ZK proof for anonymous reporting.
        indicators: List of threat indicator descriptions.
        timestamp: Unix timestamp of the report.
    """

    threat_hash: str
    reporter_zk_proof: bytes
    indicators: list[str]
    timestamp: int


@dataclass
class AnalysisResult:
    """Result of threat analysis by the Guardian node.

    Attributes:
        threat_hash: SHA-256 hash of the analyzed threat.
        yara_rule: Generated YARA rule, or None if generation failed.
        confidence: Overall confidence score (0.0 - 1.0).
        should_submit: True if confidence >= 0.85 (MIN_CONFIDENCE).
        analysis_notes: Human-readable analysis summary.
    """

    threat_hash: str
    yara_rule: YaraRule | None
    confidence: float
    should_submit: bool
    analysis_notes: str


class Analyzer:
    """Main threat analysis pipeline for Guardian nodes.

    Combines LLM-based threat analysis with YARA rule generation
    to produce actionable threat intelligence for the network.
    """

    def __init__(self, llm: LlmServer, yara_gen: YaraRuleGenerator) -> None:
        """Initialize the analyzer with LLM and YARA generator.

        Args:
            llm: The vLLM server for threat analysis.
            yara_gen: The YARA rule generator.
        """
        self.llm: LlmServer = llm
        self.yara_gen: YaraRuleGenerator = yara_gen

    async def process_threat_hint(self, hint: ThreatHint) -> AnalysisResult:
        """Process a threat hint through the full analysis pipeline.

        Steps:
        1. Analyze threat data via LLM
        2. Generate YARA rule from indicators
        3. Validate rule and determine submission eligibility

        Args:
            hint: The incoming threat hint to analyze.

        Returns:
            AnalysisResult with YARA rule and submission decision.
        """
        # Step 1: Analyze threat via LLM
        threat_data = {
            "threat_hash": hint.threat_hash,
            "indicators": hint.indicators,
            "timestamp": hint.timestamp,
        }

        try:
            analysis = await self.llm.analyze_threat(threat_data)
            raw_analysis = analysis.get("raw_analysis", "")
        except Exception as exc:  # pylint: disable=broad-except
            return AnalysisResult(
                threat_hash=hint.threat_hash,
                yara_rule=None,
                confidence=0.0,
                should_submit=False,
                analysis_notes=f"LLM analysis failed: {exc}",
            )

        # Step 2: Generate YARA rule
        try:
            yara_rule = await self.yara_gen.generate_rule(
                hint.threat_hash, hint.indicators
            )
        except Exception as exc:  # pylint: disable=broad-except
            return AnalysisResult(
                threat_hash=hint.threat_hash,
                yara_rule=None,
                confidence=0.0,
                should_submit=False,
                analysis_notes=f"YARA generation failed: {exc}",
            )

        # Step 3: Validate and determine submission
        is_valid = self.yara_gen.validate_rule(yara_rule)
        confidence = yara_rule.confidence if is_valid else 0.0
        should_submit = confidence >= MIN_CONFIDENCE

        notes = (
            f"LLM analysis complete. "
            f"YARA rule {'valid' if is_valid else 'invalid'}. "
            f"Confidence: {confidence:.2f}. "
            f"{'Will submit to network.' if should_submit else 'Below threshold.'}"
        )

        return AnalysisResult(
            threat_hash=hint.threat_hash,
            yara_rule=yara_rule if is_valid else None,
            confidence=confidence,
            should_submit=should_submit,
            analysis_notes=notes,
        )
