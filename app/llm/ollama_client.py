from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Optional

import requests


class OllamaClientError(Exception):
    """Base exception for Ollama client failures."""
    pass


class OllamaConnectionError(OllamaClientError):
    """Raised when the Ollama local daemon is unreachable or offline."""
    pass


class OllamaTimeoutError(OllamaClientError):
    """Raised when the Ollama request exceeds the configured timeout."""
    pass


class OllamaResponseError(OllamaClientError):
    """Raised when Ollama returns an HTTP error or malformed payload."""
    pass


@dataclass(frozen=True)
class OllamaConfig:
    """Configuration for local Ollama connection."""

    base_url: str = "http://localhost:11434"
    model: str = "llama3.2"
    timeout_seconds: float = 120.0

    @classmethod
    def from_env(cls) -> OllamaConfig:
        base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
        model = os.environ.get("OLLAMA_MODEL", "llama3.2")
        timeout_str = os.environ.get("OLLAMA_TIMEOUT", "120.0")
        try:
            timeout_seconds = float(timeout_str)
        except ValueError:
            timeout_seconds = 120.0

        return cls(
            base_url=base_url,
            model=model,
            timeout_seconds=timeout_seconds,
        )


class OllamaClient:
    """
    Lightweight local adapter for interacting with the Ollama API.

    This client strictly sends text prompts and returns text completions.
    It contains no filesystem tools, execution engines, or secret access.
    """

    def __init__(
        self,
        config: Optional[OllamaConfig] = None,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.config = config or OllamaConfig.from_env()
        self.session = session or requests.Session()

    def is_available(self) -> bool:
        """
        Check whether the local Ollama daemon is reachable and responding.
        Uses a short 2.0s timeout to prevent UI freezes.
        """
        try:
            resp = self.session.get(
                f"{self.config.base_url}/api/tags",
                timeout=min(2.0, self.config.timeout_seconds),
            )
            return resp.status_code == 200
        except Exception:
            return False

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
    ) -> str:
        """
        Request a completion from the local Ollama daemon in JSON format.
        """
        endpoint = f"{self.config.base_url}/api/chat"
        payload = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "format": "json",
            "options": {
                "temperature": temperature,
            },
        }

        try:
            response = self.session.post(
                endpoint,
                json=payload,
                timeout=self.config.timeout_seconds,
            )
            response.raise_for_status()
            data = response.json()

            # Extract message content from standard Ollama chat format
            message = data.get("message", {})
            content = message.get("content", "")
            if not content:
                # Fallback check for generate endpoint format if applicable
                content = data.get("response", "")

            if not content:
                raise OllamaResponseError("Ollama returned an empty response content.")

            return content

        except requests.exceptions.Timeout as exc:
            raise OllamaTimeoutError(
                f"Ollama request timed out after {self.config.timeout_seconds}s at {endpoint}."
            ) from exc
        except requests.exceptions.ConnectionError as exc:
            raise OllamaConnectionError(
                f"Could not connect to local Ollama daemon at {self.config.base_url}. "
                "Ensure Ollama is installed and running."
            ) from exc
        except requests.exceptions.HTTPError as exc:
            raise OllamaResponseError(
                f"Ollama returned HTTP error {response.status_code}: {response.text}"
            ) from exc
        except Exception as exc:
            if isinstance(exc, OllamaClientError):
                raise
            raise OllamaResponseError(f"Unexpected error communicating with Ollama: {exc}") from exc
