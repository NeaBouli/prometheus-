"""vLLM server wrapper for LLaMA 3 threat analysis.

Connects to a vLLM OpenAI-compatible endpoint for:
- Threat data analysis
- YARA rule generation
- Health monitoring

Architecture Decision #6: LLaMA 3 70B (primary)
Architecture Decision #7: LLaMA 3 8B (fallback)
"""

from __future__ import annotations

import json
from typing import Any

import httpx


class LlmServer:
    """Wrapper for the vLLM OpenAI-compatible inference server.

    Provides async methods for threat analysis and YARA rule generation
    using LLaMA 3 models served via vLLM.
    """

    def __init__(self, model_name: str, port: int) -> None:
        """Initialize the LLM server connection.

        Args:
            model_name: Model identifier (e.g. "meta-llama/Meta-Llama-3-8B-Instruct").
            port: Port number where vLLM is running.
        """
        self.model_name: str = model_name
        self.port: int = port
        self.base_url: str = f"http://localhost:{port}"
        self.api_url: str = f"{self.base_url}/v1/chat/completions"

    async def analyze_threat(self, threat_data: dict[str, Any]) -> dict[str, Any]:
        """Analyze threat data using the LLM.

        Args:
            threat_data: Dictionary containing threat indicators and metadata.

        Returns:
            Analysis result with threat_family, severity, and recommendations.
        """
        prompt = (
            "You are a cybersecurity threat analyst. Analyze the following "
            "threat indicators and provide: threat_family, severity (1-10), "
            "affected_os, cve_references, and recommended YARA patterns.\n\n"
            f"Threat data:\n{json.dumps(threat_data, indent=2)}"
        )

        response = await self._chat_completion(prompt)
        return {"raw_analysis": response, "threat_data": threat_data}

    async def generate_yara_rule(self, threat_description: str) -> str:
        """Generate a YARA rule from a threat description.

        Args:
            threat_description: Human-readable threat description with indicators.

        Returns:
            YARA rule as a string in valid YARA syntax.
        """
        prompt = (
            "Generate a valid YARA rule for the following threat. "
            "The rule MUST contain: rule name, strings section with "
            "at least one pattern, and a condition section.\n\n"
            f"Threat description:\n{threat_description}"
        )

        return await self._chat_completion(prompt)

    async def health_check(self) -> bool:
        """Check if the vLLM server is healthy and responding.

        Returns:
            True if the server is healthy, False otherwise.
        """
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.base_url}/health")
                return resp.status_code == 200
        except (httpx.ConnectError, httpx.TimeoutException):
            return False

    async def _chat_completion(self, prompt: str) -> str:
        """Send a chat completion request to the vLLM endpoint.

        Args:
            prompt: The user prompt to send.

        Returns:
            The model's response text.

        Raises:
            httpx.HTTPStatusError: If the server returns an error status.
        """
        payload: dict[str, Any] = {
            "model": self.model_name,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 2048,
            "temperature": 0.1,
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(self.api_url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]
