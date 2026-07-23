"""Threat analysis pipeline for Guardian nodes.

Processes incoming threat hints from Light Clients, runs LLaMA 3
analysis, generates YARA rules, and determines submission eligibility.

MIN_CONFIDENCE = 0.85 (from MEMO.md).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from .llm_server import LlmServer
from .yara_generator import MIN_CONFIDENCE, YaraRule, YaraRuleGenerator

_VERIFIED_INDICATOR_TYPES: Final[set[str]] = {
    "file_hash",
    "behavior",
    "network",
    "api_call",
}
_VERIFIED_PROOF_SYSTEM: Final[str] = "groth16_kip16_v1"
_MAX_VERIFIED_PROOF_BYTES: Final[int] = 1_024


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


@dataclass(frozen=True)
class VerifiedThreatHint:  # pylint: disable=too-many-instance-attributes
    """Post-verification ThreatHint v1 input for the Guardian analyzer.

    The v1 wire format contains a hash commitment and indicator category, but
    no concrete observable strings. This type intentionally has no
    ``indicators`` field so callers cannot silently coerce enum labels into
    analyzer evidence.
    """

    payload_digest: str
    schema_version: int
    threat_hash: str
    confidence_bps: int
    indicator_type: str
    proof_system: str
    reporter_zk_proof: bytes
    report_nonce: str
    observed_at: int
    network_id: str
    admitted_at: int

    def __post_init__(self) -> None:
        if not _is_positive_int(self.schema_version) or self.schema_version != 1:
            raise ValueError("unsupported verified ThreatHint schema")
        if not _is_lower_hex_32(self.payload_digest):
            raise ValueError("verified ThreatHint digest is invalid")
        if not _is_lower_hex_32(self.threat_hash):
            raise ValueError("verified ThreatHint hash is invalid")
        if (
            isinstance(self.confidence_bps, bool)
            or not isinstance(self.confidence_bps, int)
            or not 1 <= self.confidence_bps <= 10_000
        ):
            raise ValueError("verified ThreatHint confidence is invalid")
        if self.indicator_type not in _VERIFIED_INDICATOR_TYPES:
            raise ValueError("verified ThreatHint indicator type is invalid")
        if self.proof_system != _VERIFIED_PROOF_SYSTEM:
            raise ValueError("verified ThreatHint proof system is invalid")
        if (
            not isinstance(self.reporter_zk_proof, bytes)
            or not 0 < len(self.reporter_zk_proof) <= _MAX_VERIFIED_PROOF_BYTES
        ):
            raise ValueError("verified ThreatHint proof is invalid")
        if not _is_lower_hex_32(self.report_nonce):
            raise ValueError("verified ThreatHint nonce is invalid")
        if not _is_positive_int(self.observed_at) or not _is_positive_int(
            self.admitted_at
        ):
            raise ValueError("verified ThreatHint time is invalid")
        if (
            not isinstance(self.network_id, str)
            or not 1 < len(self.network_id) <= 64
            or self.network_id[0] not in "abcdefghijklmnopqrstuvwxyz0123456789"
            or self.network_id[-1] not in "abcdefghijklmnopqrstuvwxyz0123456789"
            or any(
                character not in "abcdefghijklmnopqrstuvwxyz0123456789-"
                for character in self.network_id
            )
        ):
            raise ValueError("verified ThreatHint network is invalid")


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
            await self.llm.analyze_threat(threat_data)
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

    async def process_verified_threat_hint(
        self, hint: VerifiedThreatHint
    ) -> AnalysisResult:
        """Consume a verified v1 claim without fabricating analyzer evidence.

        ThreatHint v1 proves metadata about a hash commitment but transports no
        concrete IOC strings. Running an LLM or YARA generator on that metadata
        would permit hallucinated detection rules, so the only safe v1 result
        is explicit and non-submittable.
        """
        if not isinstance(hint, VerifiedThreatHint):
            raise TypeError("verified ThreatHint input is required")
        return AnalysisResult(
            threat_hash=hint.threat_hash,
            yara_rule=None,
            confidence=0.0,
            should_submit=False,
            analysis_notes=(
                "Verified ThreatHint v1 contains no concrete analyzer indicators; "
                "LLM and YARA generation were not invoked."
            ),
        )


def _is_lower_hex_32(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_positive_int(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value > 0
