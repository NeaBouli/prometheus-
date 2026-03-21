"""Tests for jaeger.yara_generator module."""

import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from jaeger.yara_generator import MIN_CONFIDENCE, YaraRule, YaraRuleGenerator


VALID_YARA = """rule TestMalware {
    strings:
        $a = "malicious_payload"
        $b = { 4D 5A 90 00 }
    condition:
        $a or $b
}"""

INVALID_YARA_NO_STRINGS = """rule Broken {
    condition:
        true
}"""

INVALID_YARA_NO_CONDITION = """rule Broken {
    strings:
        $a = "test"
}"""


def make_rule(content: str, confidence: float = 0.9) -> YaraRule:
    """Create a test YaraRule with given content and confidence."""
    return YaraRule(
        name="TEST_0001",
        rule_content=content,
        confidence=confidence,
        threat_hash="a" * 64,
        generated_at=int(time.time()),
    )


class TestYaraRule:
    """Tests for the YaraRule dataclass."""

    def test_create_rule(self) -> None:
        """Test creating a YaraRule instance."""
        rule = make_rule(VALID_YARA)
        assert rule.name == "TEST_0001"
        assert rule.confidence == 0.9

    def test_min_confidence_value(self) -> None:
        """Verify MIN_CONFIDENCE matches MEMO.md."""
        assert abs(MIN_CONFIDENCE - 0.85) < 1e-9


class TestYaraRuleGenerator:
    """Tests for the YaraRuleGenerator class."""

    def _make_generator(self, yara_output: str = VALID_YARA) -> YaraRuleGenerator:
        """Create a generator with a mocked LLM server."""
        mock_llm = MagicMock()
        mock_llm.generate_yara_rule = AsyncMock(return_value=yara_output)
        return YaraRuleGenerator(mock_llm)

    def test_validate_valid_rule(self) -> None:
        """Valid YARA rule passes validation."""
        gen = self._make_generator()
        rule = make_rule(VALID_YARA)
        assert gen.validate_rule(rule) is True

    def test_validate_missing_strings(self) -> None:
        """Rule without strings: section fails validation."""
        gen = self._make_generator()
        rule = make_rule(INVALID_YARA_NO_STRINGS)
        assert gen.validate_rule(rule) is False

    def test_validate_missing_condition(self) -> None:
        """Rule without condition: section fails validation."""
        gen = self._make_generator()
        rule = make_rule(INVALID_YARA_NO_CONDITION)
        assert gen.validate_rule(rule) is False

    def test_is_submittable_high_confidence(self) -> None:
        """Rule with high confidence and valid syntax is submittable."""
        gen = self._make_generator()
        rule = make_rule(VALID_YARA, confidence=0.90)
        assert gen.is_submittable(rule) is True

    def test_is_submittable_low_confidence(self) -> None:
        """Rule below MIN_CONFIDENCE is not submittable."""
        gen = self._make_generator()
        rule = make_rule(VALID_YARA, confidence=0.80)
        assert gen.is_submittable(rule) is False

    def test_is_submittable_invalid_syntax(self) -> None:
        """Rule with invalid syntax is not submittable even with high confidence."""
        gen = self._make_generator()
        rule = make_rule(INVALID_YARA_NO_STRINGS, confidence=0.95)
        assert gen.is_submittable(rule) is False

    @pytest.mark.asyncio
    async def test_generate_rule(self) -> None:
        """Generated rule has correct metadata."""
        gen = self._make_generator(VALID_YARA)
        rule = await gen.generate_rule("abc123" * 10 + "ab", ["indicator1", "indicator2"])
        assert rule.rule_content == VALID_YARA
        assert rule.threat_hash == "abc123" * 10 + "ab"
        assert rule.generated_at > 0
        assert "PROM_" in rule.name

    @pytest.mark.asyncio
    async def test_generate_increments_counter(self) -> None:
        """Rule counter increments with each generation."""
        gen = self._make_generator(VALID_YARA)
        r1 = await gen.generate_rule("hash1", ["ind1"])
        r2 = await gen.generate_rule("hash2", ["ind2"])
        assert r1.name != r2.name
