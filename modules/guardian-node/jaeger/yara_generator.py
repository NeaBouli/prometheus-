"""YARA rule generator using LLaMA 3 inference.

Generates YARA rules from threat indicators via the LLM server,
validates syntax, and enforces minimum confidence threshold.

MIN_CONFIDENCE = 0.85 (from MEMO.md AUTO-TUNING PARAMETER).
"""

from __future__ import annotations

# Confidence must be an exact integer; bool is not accepted as basis points.
# pylint: disable=unidiomatic-typecheck

import json
import time
from dataclasses import dataclass

from .llm_server import LlmServer
from .yara_validation import validate_candidate_rule_source

MIN_CONFIDENCE_BPS: int = 8_500
MIN_CONFIDENCE: float = MIN_CONFIDENCE_BPS / 10_000


@dataclass
class YaraRule:
    """A generated YARA threat detection rule.

    Attributes:
        name: Rule name, e.g. "PROM_2026_0001".
        rule_content: Full YARA syntax string.
        confidence_bps: Model-provided confidence in integer basis points.
        threat_hash: SHA-256 hash of the original threat.
        generated_at: Unix timestamp of generation.
    """

    name: str
    rule_content: str
    confidence_bps: int
    threat_hash: str
    generated_at: int

    @property
    def confidence(self) -> float:
        """Return the compatibility confidence view in the range 0.0 to 1.0."""
        return self.confidence_bps / 10_000


class YaraRuleGenerator:
    """Generates and validates YARA rules using LLaMA 3 inference.

    The generator uses the LLM to create YARA rules from threat
    indicators, then validates the output for syntactic correctness.
    """

    def __init__(self, llm_server: LlmServer) -> None:
        """Initialize the generator with an LLM server connection.

        Args:
            llm_server: The vLLM server to use for rule generation.
        """
        self.llm: LlmServer = llm_server
        self._rule_counter: int = 0

    async def generate_rule(self, threat_hash: str, indicators: list[str]) -> YaraRule:
        """Generate a YARA rule from threat indicators.

        Args:
            threat_hash: SHA-256 hash of the threat sample.
            indicators: List of threat indicator strings.

        Returns:
            A YaraRule with generated content and metadata.
        """
        description = json.dumps(
            {"indicators": indicators, "threat_hash": threat_hash},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )

        rule_content = await self.llm.generate_yara_rule(description)
        assessment = await self.llm.assess_yara_rule(description, rule_content)
        self._rule_counter += 1
        name = f"PROM_{time.strftime('%Y')}_{self._rule_counter:04d}"

        return YaraRule(
            name=name,
            rule_content=rule_content,
            confidence_bps=assessment.confidence_bps,
            threat_hash=threat_hash,
            generated_at=int(time.time()),
        )

    def validate_rule(self, rule: YaraRule) -> bool:
        """Validate a YARA rule against the bounded YARA-X compile boundary.

        Delegates rule_content to the GH-170 compile-only boundary in
        ``jaeger.yara_validation``: one ASCII, NUL-free, size-bounded rule
        with a bounded name, no import/include directives, and a clean
        pinned YARA-X compile with zero errors and zero warnings. Anything
        else fails closed.

        Args:
            rule: The YaraRule to validate.

        Returns:
            True if the rule passes the bounded compile-only validation.
        """
        if (
            not isinstance(rule, YaraRule)
            or type(rule.confidence_bps) is not int
            or not 0 <= rule.confidence_bps <= 10_000
        ):
            return False
        return validate_candidate_rule_source(rule.rule_content)

    def is_submittable(self, rule: YaraRule) -> bool:
        """Check if a rule meets the minimum confidence for submission.

        Args:
            rule: The YaraRule to check.

        Returns:
            True if confidence >= MIN_CONFIDENCE (0.85) and syntax is valid.
        """
        return self.validate_rule(rule) and rule.confidence_bps >= MIN_CONFIDENCE_BPS
