"""Tests for jaeger.yara_generator module."""

import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from jaeger.llm_server import YaraConfidenceAssessment
from jaeger.yara_generator import (
    MIN_CONFIDENCE,
    MIN_CONFIDENCE_BPS,
    YaraRule,
    YaraRuleGenerator,
)

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


def make_rule(content: str, confidence_bps: int = 9_000) -> YaraRule:
    """Create a test YaraRule with given content and confidence."""
    return YaraRule(
        name="TEST_0001",
        rule_content=content,
        confidence_bps=confidence_bps,
        threat_hash="a" * 64,
        generated_at=int(time.time()),
    )


class TestYaraRule:
    """Tests for the YaraRule dataclass."""

    def test_create_rule(self) -> None:
        """Test creating a YaraRule instance."""
        rule = make_rule(VALID_YARA)
        assert rule.name == "TEST_0001"
        assert rule.confidence_bps == 9_000
        assert rule.confidence == 0.9

    def test_min_confidence_value(self) -> None:
        """Verify MIN_CONFIDENCE matches MEMO.md."""
        assert abs(MIN_CONFIDENCE - 0.85) < 1e-9
        assert MIN_CONFIDENCE_BPS == 8_500


class TestYaraRuleGenerator:
    """Tests for the YaraRuleGenerator class."""

    def _make_generator(
        self, yara_output: str = VALID_YARA, confidence_bps: int = 9_000
    ) -> YaraRuleGenerator:
        """Create a generator with a mocked LLM server."""
        mock_llm = MagicMock()
        mock_llm.generate_yara_rule = AsyncMock(return_value=yara_output)
        mock_llm.assess_yara_rule = AsyncMock(
            return_value=YaraConfidenceAssessment(confidence_bps)
        )
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
        rule = make_rule(VALID_YARA, confidence_bps=9_000)
        assert gen.is_submittable(rule) is True

    def test_is_submittable_low_confidence(self) -> None:
        """Rule below MIN_CONFIDENCE is not submittable."""
        gen = self._make_generator()
        rule = make_rule(VALID_YARA, confidence_bps=8_000)
        assert gen.is_submittable(rule) is False

    def test_is_submittable_invalid_syntax(self) -> None:
        """Rule with invalid syntax is not submittable even with high confidence."""
        gen = self._make_generator()
        rule = make_rule(INVALID_YARA_NO_STRINGS, confidence_bps=9_500)
        assert gen.is_submittable(rule) is False

    @pytest.mark.parametrize("confidence_bps", [None, True, "9000", 9_000.0])
    def test_is_submittable_rejects_invalid_confidence_type(
        self, confidence_bps: object
    ) -> None:
        """Malformed direct callers fail closed instead of raising."""
        gen = self._make_generator()
        rule = make_rule(VALID_YARA, confidence_bps=confidence_bps)  # type: ignore[arg-type]
        assert gen.is_submittable(rule) is False

    @pytest.mark.asyncio
    async def test_generate_rule(self) -> None:
        """Generated rule has correct metadata."""
        gen = self._make_generator(VALID_YARA)
        rule = await gen.generate_rule(
            "abc123" * 10 + "ab", ["indicator1", "indicator2"]
        )
        assert rule.rule_content == VALID_YARA
        assert rule.confidence_bps == 9_000
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

    @pytest.mark.asyncio
    async def test_indicator_count_does_not_change_model_confidence(self) -> None:
        """Indicator cardinality no longer contributes a confidence bonus."""
        gen = self._make_generator(VALID_YARA, confidence_bps=8_501)
        one = await gen.generate_rule("hash1", ["one"])
        many = await gen.generate_rule("hash2", [str(index) for index in range(20)])
        assert one.confidence_bps == many.confidence_bps == 8_501

    @pytest.mark.asyncio
    async def test_assessment_failure_does_not_create_rule(self) -> None:
        """A failed assessment propagates instead of inventing a fallback score."""
        gen = self._make_generator()
        gen.llm.assess_yara_rule = AsyncMock(side_effect=ValueError("invalid"))
        with pytest.raises(ValueError, match="invalid"):
            await gen.generate_rule("hash", ["indicator"])
        assert gen._rule_counter == 0
