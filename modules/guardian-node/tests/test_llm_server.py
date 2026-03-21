"""Tests for jaeger.llm_server module."""

import os

import pytest

from jaeger.llm_server import LlmServer

LLM_AVAILABLE = os.environ.get("LLM_AVAILABLE", "").lower() == "true"


class TestLlmServer:
    """Tests for the LlmServer class."""

    def test_init(self) -> None:
        """Test server initialization with model name and port."""
        server = LlmServer("meta-llama/Meta-Llama-3-8B-Instruct", 8000)
        assert server.model_name == "meta-llama/Meta-Llama-3-8B-Instruct"
        assert server.port == 8000
        assert server.base_url == "http://localhost:8000"

    def test_api_url_format(self) -> None:
        """Test that API URL is correctly formed."""
        server = LlmServer("test-model", 9000)
        assert server.api_url == "http://localhost:9000/v1/chat/completions"

    @pytest.mark.asyncio
    async def test_health_check_no_server(self) -> None:
        """Health check returns False when no server is running."""
        server = LlmServer("test-model", 59999)
        result = await server.health_check()
        assert result is False

    @pytest.mark.skipif(not LLM_AVAILABLE, reason="LLM server not available")
    @pytest.mark.asyncio
    async def test_health_check_live(self) -> None:
        """Health check returns True with a live server."""
        server = LlmServer("meta-llama/Meta-Llama-3-8B-Instruct", 8000)
        result = await server.health_check()
        assert result is True

    @pytest.mark.skipif(not LLM_AVAILABLE, reason="LLM server not available")
    @pytest.mark.asyncio
    async def test_analyze_threat_live(self) -> None:
        """Analyze threat data with a live LLM server."""
        server = LlmServer("meta-llama/Meta-Llama-3-8B-Instruct", 8000)
        result = await server.analyze_threat(
            {"hash": "abc123", "indicators": ["suspicious API calls"]}
        )
        assert "raw_analysis" in result

    @pytest.mark.skipif(not LLM_AVAILABLE, reason="LLM server not available")
    @pytest.mark.asyncio
    async def test_generate_yara_rule_live(self) -> None:
        """Generate YARA rule with a live LLM server."""
        server = LlmServer("meta-llama/Meta-Llama-3-8B-Instruct", 8000)
        result = await server.generate_yara_rule("Suspicious PE file with encrypted payload")
        assert isinstance(result, str)
        assert len(result) > 0
