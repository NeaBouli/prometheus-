"""YARA rule generator using LLaMA 3 inference.

Generates YARA rules from threat indicators via the LLM server,
validates syntax, and enforces minimum confidence threshold.

MIN_CONFIDENCE = 0.85 (from MEMO.md AUTO-TUNING PARAMETER).
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from .llm_server import LlmServer

MIN_CONFIDENCE: float = 0.85


@dataclass
class YaraRule:
    """A generated YARA threat detection rule.

    Attributes:
        name: Rule name, e.g. "PROM_2026_0001".
        rule_content: Full YARA syntax string.
        confidence: Confidence score (0.0 - 1.0).
        threat_hash: SHA-256 hash of the original threat.
        generated_at: Unix timestamp of generation.
    """

    name: str
    rule_content: str
    confidence: float
    threat_hash: str
    generated_at: int


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
        description = f"Threat hash: {threat_hash}\n" f"Indicators:\n" + "\n".join(
            f"  - {ind}" for ind in indicators
        )

        rule_content = await self.llm.generate_yara_rule(description)
        self._rule_counter += 1
        name = f"PROM_{time.strftime('%Y')}_{self._rule_counter:04d}"

        # Estimate confidence based on indicator count and rule quality
        has_strings = "strings:" in rule_content
        has_condition = "condition:" in rule_content
        base_confidence = 0.7 if (has_strings and has_condition) else 0.3
        indicator_bonus = min(len(indicators) * 0.05, 0.3)
        confidence = min(base_confidence + indicator_bonus, 1.0)

        return YaraRule(
            name=name,
            rule_content=rule_content,
            confidence=confidence,
            threat_hash=threat_hash,
            generated_at=int(time.time()),
        )

    def validate_rule(self, rule: YaraRule) -> bool:
        """Validate a YARA rule for basic syntactic correctness.

        Checks that rule_content contains the required YARA sections:
        "rule ", "strings:", and "condition:".

        Args:
            rule: The YaraRule to validate.

        Returns:
            True if the rule passes basic syntax validation.
        """
        content = rule.rule_content
        has_rule_keyword = "rule " in content
        has_strings = "strings:" in content
        has_condition = "condition:" in content
        return has_rule_keyword and has_strings and has_condition

    def is_submittable(self, rule: YaraRule) -> bool:
        """Check if a rule meets the minimum confidence for submission.

        Args:
            rule: The YaraRule to check.

        Returns:
            True if confidence >= MIN_CONFIDENCE (0.85) and syntax is valid.
        """
        return rule.confidence >= MIN_CONFIDENCE and self.validate_rule(rule)
