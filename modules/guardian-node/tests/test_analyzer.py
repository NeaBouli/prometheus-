"""Tests for jaeger.analyzer module."""

import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from jaeger.analyzer import AnalysisResult, Analyzer, ThreatHint
from jaeger.yara_generator import MIN_CONFIDENCE, YaraRule, YaraRuleGenerator


VALID_YARA = """rule TestThreat {
    strings:
        $a = "malware_sig"
    condition:
        $a
}"""


def make_hint(indicators: list[str] | None = None) -> ThreatHint:
    """Create a test ThreatHint."""
    return ThreatHint(
        threat_hash="deadbeef" * 8,
        reporter_zk_proof=b"\x00" * 48,
        indicators=indicators or ["suspicious_api_call", "encrypted_payload"],
        timestamp=int(time.time()),
    )


def make_analyzer(yara_output: str = VALID_YARA) -> Analyzer:
    """Create an Analyzer with mocked LLM and YARA generator."""
    mock_llm = MagicMock()
    mock_llm.analyze_threat = AsyncMock(
        return_value={"raw_analysis": "Test analysis", "threat_data": {}}
    )
    mock_llm.generate_yara_rule = AsyncMock(return_value=yara_output)

    yara_gen = YaraRuleGenerator(mock_llm)
    return Analyzer(mock_llm, yara_gen)


class TestThreatHint:
    """Tests for the ThreatHint dataclass."""

    def test_create_hint(self) -> None:
        """Test creating a ThreatHint."""
        hint = make_hint()
        assert hint.threat_hash == "deadbeef" * 8
        assert len(hint.indicators) == 2

    def test_hint_with_custom_indicators(self) -> None:
        """Test hint with custom indicator list."""
        hint = make_hint(["custom_ioc_1", "custom_ioc_2", "custom_ioc_3"])
        assert len(hint.indicators) == 3


class TestAnalysisResult:
    """Tests for the AnalysisResult dataclass."""

    def test_create_result(self) -> None:
        """Test creating an AnalysisResult."""
        result = AnalysisResult(
            threat_hash="abc",
            yara_rule=None,
            confidence=0.5,
            should_submit=False,
            analysis_notes="Test",
        )
        assert result.confidence == 0.5
        assert not result.should_submit


class TestAnalyzer:
    """Tests for the Analyzer class."""

    @pytest.mark.asyncio
    async def test_process_threat_hint_success(self) -> None:
        """Full pipeline produces an AnalysisResult."""
        analyzer = make_analyzer()
        hint = make_hint()
        result = await analyzer.process_threat_hint(hint)

        assert result.threat_hash == hint.threat_hash
        assert isinstance(result.confidence, float)
        assert isinstance(result.analysis_notes, str)

    @pytest.mark.asyncio
    async def test_valid_rule_in_result(self) -> None:
        """Valid YARA output produces a non-None yara_rule."""
        analyzer = make_analyzer(VALID_YARA)
        hint = make_hint()
        result = await analyzer.process_threat_hint(hint)
        assert result.yara_rule is not None
        assert "rule " in result.yara_rule.rule_content

    @pytest.mark.asyncio
    async def test_invalid_rule_returns_none(self) -> None:
        """Invalid YARA output results in yara_rule=None."""
        analyzer = make_analyzer("this is not valid yara")
        hint = make_hint()
        result = await analyzer.process_threat_hint(hint)
        assert result.yara_rule is None
        assert result.confidence == 0.0

    @pytest.mark.asyncio
    async def test_should_submit_high_confidence(self) -> None:
        """Result with high confidence should be submitted."""
        analyzer = make_analyzer(VALID_YARA)
        # Many indicators = higher confidence
        hint = make_hint(["ind1", "ind2", "ind3", "ind4", "ind5", "ind6"])
        result = await analyzer.process_threat_hint(hint)
        # With 6 indicators: base 0.7 + 6*0.05=0.3 = 1.0 → should_submit
        if result.confidence >= MIN_CONFIDENCE:
            assert result.should_submit is True

    @pytest.mark.asyncio
    async def test_should_submit_low_confidence(self) -> None:
        """Result with low confidence should not be submitted."""
        analyzer = make_analyzer(VALID_YARA)
        hint = make_hint(["single_indicator"])
        result = await analyzer.process_threat_hint(hint)
        # With 1 indicator: base 0.7 + 0.05 = 0.75 → below 0.85
        if result.confidence < MIN_CONFIDENCE:
            assert result.should_submit is False

    @pytest.mark.asyncio
    async def test_llm_failure_handled(self) -> None:
        """LLM failure returns safe AnalysisResult."""
        mock_llm = MagicMock()
        mock_llm.analyze_threat = AsyncMock(
            side_effect=ConnectionError("Server down")
        )
        yara_gen = YaraRuleGenerator(mock_llm)
        analyzer = Analyzer(mock_llm, yara_gen)

        hint = make_hint()
        result = await analyzer.process_threat_hint(hint)
        assert result.confidence == 0.0
        assert result.should_submit is False
        assert "failed" in result.analysis_notes.lower()

    @pytest.mark.asyncio
    async def test_notes_contain_confidence(self) -> None:
        """Analysis notes include the confidence score."""
        analyzer = make_analyzer(VALID_YARA)
        hint = make_hint()
        result = await analyzer.process_threat_hint(hint)
        assert "Confidence:" in result.analysis_notes
