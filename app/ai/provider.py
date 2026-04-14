"""
app/ai/provider.py -- Pluggable AI provider with auto-detection.

Supported backends:
  - OllamaProvider   -- local Ollama instance (default)
  - OpenAIProvider   -- OpenAI API or any compatible endpoint (e.g. vLLM, LiteLLM)
  - AnthropicProvider -- Anthropic API

Auto-detect logic: try Ollama first; if unreachable, fall back to the
configured remote provider (AI_PROVIDER / AI_API_KEY / AI_API_URL / AI_MODEL).

Usage:
    provider = get_provider()
    text = await provider.generate("Hello", system="You are helpful.")
    async for token in provider.generate_stream("Hello"):
        print(token, end="")
"""
from __future__ import annotations

import abc
import json
import logging
import os
from typing import AsyncIterator, Optional

import httpx

from app.config import Config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration (read once at import time, overridable via env)
# ---------------------------------------------------------------------------

AI_PROVIDER: str = os.getenv("AI_PROVIDER", "auto")  # auto | ollama | openai | anthropic
AI_API_KEY: str = os.getenv("AI_API_KEY", "")
AI_API_URL: str = os.getenv("AI_API_URL", "")
AI_MODEL: str = os.getenv("AI_MODEL", "")


# ---------------------------------------------------------------------------
# Abstract interface
# ---------------------------------------------------------------------------

class AIProvider(abc.ABC):
    """Abstract AI text-generation provider."""

    name: str = "base"

    @abc.abstractmethod
    async def generate(
        self,
        prompt: str,
        *,
        system: str = "",
        temperature: float = 0.7,
        max_tokens: int = 1024,
    ) -> str:
        """Non-streaming text generation. Returns full response string."""

    @abc.abstractmethod
    async def generate_stream(
        self,
        prompt: str,
        *,
        system: str = "",
        temperature: float = 0.7,
        max_tokens: int = 1024,
    ) -> AsyncIterator[str]:
        """Streaming text generation. Yields tokens one by one."""

    @abc.abstractmethod
    async def chat(
        self,
        messages: list[dict],
        *,
        temperature: float = 0.7,
        max_tokens: int = 1024,
    ) -> str:
        """Chat-style generation with messages list."""

    @abc.abstractmethod
    async def chat_stream(
        self,
        messages: list[dict],
        *,
        temperature: float = 0.7,
        max_tokens: int = 1024,
    ) -> AsyncIterator[str]:
        """Chat-style streaming generation."""

    async def is_available(self) -> bool:
        """Check if the provider is reachable."""
        return False


# ---------------------------------------------------------------------------
# Ollama
# ---------------------------------------------------------------------------

class OllamaProvider(AIProvider):
    """Local Ollama backend (http://localhost:11434 by default)."""

    name = "ollama"

    def __init__(self, url: Optional[str] = None, model: Optional[str] = None):
        self.url = (url or getattr(Config, "OLLAMA_URL", None) or "http://localhost:11434").rstrip("/")
        self.model = model or getattr(Config, "OLLAMA_MODEL", None) or "llama3"

    async def is_available(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=3.0) as c:
                r = await c.get(f"{self.url}/api/tags")
                return r.status_code == 200
        except Exception:
            return False

    async def generate(self, prompt, *, system="", temperature=0.7, max_tokens=1024) -> str:
        payload = {
            "model": self.model, "prompt": prompt, "system": system,
            "stream": False, "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        async with httpx.AsyncClient(timeout=60.0) as c:
            r = await c.post(f"{self.url}/api/generate", json=payload)
            r.raise_for_status()
            return r.json().get("response", "")

    async def generate_stream(self, prompt, *, system="", temperature=0.7, max_tokens=1024):
        payload = {
            "model": self.model, "prompt": prompt, "system": system,
            "stream": True, "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        async with httpx.AsyncClient(timeout=60.0) as c:
            async with c.stream("POST", f"{self.url}/api/generate", json=payload) as r:
                r.raise_for_status()
                async for line in r.aiter_lines():
                    if line:
                        chunk = json.loads(line)
                        token = chunk.get("response", "")
                        if token:
                            yield token
                        if chunk.get("done"):
                            break

    async def chat(self, messages, *, temperature=0.7, max_tokens=1024) -> str:
        payload = {
            "model": self.model, "messages": messages, "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        async with httpx.AsyncClient(timeout=60.0) as c:
            r = await c.post(f"{self.url}/api/chat", json=payload)
            r.raise_for_status()
            return r.json().get("message", {}).get("content", "")

    async def chat_stream(self, messages, *, temperature=0.7, max_tokens=1024):
        payload = {
            "model": self.model, "messages": messages, "stream": True,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        async with httpx.AsyncClient(timeout=60.0) as c:
            async with c.stream("POST", f"{self.url}/api/chat", json=payload) as r:
                r.raise_for_status()
                async for line in r.aiter_lines():
                    if line:
                        chunk = json.loads(line)
                        token = chunk.get("message", {}).get("content", "")
                        if token:
                            yield token
                        if chunk.get("done"):
                            break


# ---------------------------------------------------------------------------
# OpenAI-compatible API
# ---------------------------------------------------------------------------

class OpenAIProvider(AIProvider):
    """OpenAI API or any compatible endpoint (vLLM, LiteLLM, Together, etc.)."""

    name = "openai"

    def __init__(
        self,
        api_key: Optional[str] = None,
        api_url: Optional[str] = None,
        model: Optional[str] = None,
    ):
        self.api_key = api_key or AI_API_KEY
        self.api_url = (api_url or AI_API_URL or "https://api.openai.com/v1").rstrip("/")
        self.model = model or AI_MODEL or "gpt-4o-mini"

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    async def is_available(self) -> bool:
        if not self.api_key:
            return False
        try:
            async with httpx.AsyncClient(timeout=5.0) as c:
                r = await c.get(f"{self.api_url}/models", headers=self._headers())
                return r.status_code == 200
        except Exception:
            return False

    def _build_messages(self, prompt: str, system: str) -> list[dict]:
        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.append({"role": "user", "content": prompt})
        return msgs

    async def generate(self, prompt, *, system="", temperature=0.7, max_tokens=1024) -> str:
        return await self.chat(
            self._build_messages(prompt, system),
            temperature=temperature, max_tokens=max_tokens,
        )

    async def generate_stream(self, prompt, *, system="", temperature=0.7, max_tokens=1024):
        async for tok in self.chat_stream(
            self._build_messages(prompt, system),
            temperature=temperature, max_tokens=max_tokens,
        ):
            yield tok

    async def chat(self, messages, *, temperature=0.7, max_tokens=1024) -> str:
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False,
        }
        async with httpx.AsyncClient(timeout=60.0) as c:
            r = await c.post(
                f"{self.api_url}/chat/completions",
                json=payload,
                headers=self._headers(),
            )
            r.raise_for_status()
            data = r.json()
            return data["choices"][0]["message"]["content"]

    async def chat_stream(self, messages, *, temperature=0.7, max_tokens=1024):
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": True,
        }
        async with httpx.AsyncClient(timeout=60.0) as c:
            async with c.stream(
                "POST",
                f"{self.api_url}/chat/completions",
                json=payload,
                headers=self._headers(),
            ) as r:
                r.raise_for_status()
                async for line in r.aiter_lines():
                    if not line or not line.startswith("data: "):
                        continue
                    chunk_str = line[6:]
                    if chunk_str.strip() == "[DONE]":
                        break
                    try:
                        chunk = json.loads(chunk_str)
                        delta = chunk["choices"][0].get("delta", {})
                        token = delta.get("content", "")
                        if token:
                            yield token
                    except (json.JSONDecodeError, KeyError, IndexError):
                        pass


# ---------------------------------------------------------------------------
# Anthropic API
# ---------------------------------------------------------------------------

class AnthropicProvider(AIProvider):
    """Anthropic Messages API (https://api.anthropic.com/v1/messages)."""

    name = "anthropic"

    def __init__(
        self,
        api_key: Optional[str] = None,
        api_url: Optional[str] = None,
        model: Optional[str] = None,
    ):
        self.api_key = api_key or AI_API_KEY
        self.api_url = (api_url or AI_API_URL or "https://api.anthropic.com").rstrip("/")
        self.model = model or AI_MODEL or "claude-sonnet-4-20250514"

    def _headers(self) -> dict:
        return {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }

    async def is_available(self) -> bool:
        return bool(self.api_key)

    def _build_messages(self, prompt: str, system: str) -> tuple[str, list[dict]]:
        return system, [{"role": "user", "content": prompt}]

    async def generate(self, prompt, *, system="", temperature=0.7, max_tokens=1024) -> str:
        sys_text, msgs = self._build_messages(prompt, system)
        return await self.chat(msgs, temperature=temperature, max_tokens=max_tokens, _system=sys_text)

    async def generate_stream(self, prompt, *, system="", temperature=0.7, max_tokens=1024):
        sys_text, msgs = self._build_messages(prompt, system)
        async for tok in self.chat_stream(msgs, temperature=temperature, max_tokens=max_tokens, _system=sys_text):
            yield tok

    async def chat(self, messages, *, temperature=0.7, max_tokens=1024, _system: str = "") -> str:
        payload: dict = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if _system:
            payload["system"] = _system
        async with httpx.AsyncClient(timeout=60.0) as c:
            r = await c.post(
                f"{self.api_url}/v1/messages",
                json=payload,
                headers=self._headers(),
            )
            r.raise_for_status()
            data = r.json()
            # Anthropic returns content as a list of blocks
            blocks = data.get("content", [])
            return "".join(b.get("text", "") for b in blocks if b.get("type") == "text")

    async def chat_stream(self, messages, *, temperature=0.7, max_tokens=1024, _system: str = ""):
        payload: dict = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": True,
        }
        if _system:
            payload["system"] = _system
        async with httpx.AsyncClient(timeout=60.0) as c:
            async with c.stream(
                "POST",
                f"{self.api_url}/v1/messages",
                json=payload,
                headers=self._headers(),
            ) as r:
                r.raise_for_status()
                async for line in r.aiter_lines():
                    if not line or not line.startswith("data: "):
                        continue
                    chunk_str = line[6:]
                    try:
                        chunk = json.loads(chunk_str)
                        if chunk.get("type") == "content_block_delta":
                            token = chunk.get("delta", {}).get("text", "")
                            if token:
                                yield token
                    except (json.JSONDecodeError, KeyError):
                        pass


# ---------------------------------------------------------------------------
# Provider factory with auto-detection
# ---------------------------------------------------------------------------

_cached_provider: Optional[AIProvider] = None


async def _auto_detect() -> AIProvider:
    """Try Ollama first; fall back to configured remote provider."""
    ollama = OllamaProvider()
    if await ollama.is_available():
        logger.info("AI provider auto-detected: Ollama (%s, model=%s)", ollama.url, ollama.model)
        return ollama

    # Determine remote fallback
    provider_name = AI_PROVIDER.lower()
    if provider_name in ("openai", "auto"):
        remote = OpenAIProvider()
        if await remote.is_available():
            logger.info("AI provider fallback: OpenAI-compatible (%s, model=%s)", remote.api_url, remote.model)
            return remote
    if provider_name in ("anthropic", "auto"):
        remote = AnthropicProvider()
        if await remote.is_available():
            logger.info("AI provider fallback: Anthropic (%s, model=%s)", remote.api_url, remote.model)
            return remote

    # No provider available -- return Ollama anyway (calls will fail with connection error)
    logger.warning("No AI provider available. Set AI_PROVIDER/AI_API_KEY or start Ollama.")
    return ollama


def get_provider_sync() -> AIProvider:
    """
    Return a provider instance synchronously (without auto-detection).
    Uses AI_PROVIDER env to pick the right class, defaults to Ollama.
    """
    global _cached_provider
    if _cached_provider is not None:
        return _cached_provider

    name = AI_PROVIDER.lower()
    if name == "openai":
        _cached_provider = OpenAIProvider()
    elif name == "anthropic":
        _cached_provider = AnthropicProvider()
    else:
        _cached_provider = OllamaProvider()
    return _cached_provider


async def get_provider() -> AIProvider:
    """
    Return a cached provider, running auto-detection on first call.
    """
    global _cached_provider
    if _cached_provider is not None:
        return _cached_provider
    _cached_provider = await _auto_detect()
    return _cached_provider


def reset_provider() -> None:
    """Force re-detection on next call (useful after config change)."""
    global _cached_provider
    _cached_provider = None
