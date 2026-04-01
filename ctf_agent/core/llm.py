"""Unified LLM client supporting OpenAI-compatible APIs.

Works with OpenAI, Azure OpenAI, DeepSeek, Moonshot, local servers
(LM Studio, Ollama, vLLM), and any OpenAI-compatible endpoint.

Zero external dependencies — uses only urllib from the stdlib.
"""

import json
import logging
import os
import ssl
import time
from typing import Any, Dict, List, Optional

try:
    from urllib.error import HTTPError, URLError
    from urllib.request import Request, urlopen
except ImportError:  # pragma: no cover
    pass

logger = logging.getLogger(__name__)

_DEFAULT_MODEL = "gpt-4o"
_DEFAULT_BASE_URL = "https://api.openai.com/v1"
_DEFAULT_TEMPERATURE = 0.2
_DEFAULT_MAX_TOKENS = 4096
_DEFAULT_TIMEOUT = 90
_MAX_RETRIES = 3
_RETRY_BASE_DELAY = 1.5


class ToolCall:
    """Parsed tool call from an LLM response."""

    __slots__ = ("id", "name", "arguments")

    def __init__(self, call_id, name, arguments):
        self.id = call_id
        self.name = name
        self.arguments = arguments

    def to_dict(self):
        return {"id": self.id, "name": self.name, "arguments": self.arguments}


class LLMResponse:
    """Wrapper around a single chat-completion response."""

    __slots__ = ("text", "tool_calls", "usage", "model", "finish_reason")

    def __init__(self, text="", tool_calls=None, usage=None, model="", finish_reason=""):
        self.text = text
        self.tool_calls = tool_calls or []
        self.usage = usage or {}
        self.model = model
        self.finish_reason = finish_reason

    def has_tool_calls(self):
        return bool(self.tool_calls)

    def to_dict(self):
        return {
            "text": self.text,
            "tool_calls": [tc.to_dict() for tc in self.tool_calls],
            "usage": self.usage,
            "model": self.model,
            "finish_reason": self.finish_reason,
        }


class LLMClient:
    """
    Unified LLM call abstraction.

    Configuration priority: constructor args > env vars > defaults.

    Env vars:
        CTF_AGENT_LLM_API_KEY   – API key (also reads OPENAI_API_KEY)
        CTF_AGENT_LLM_BASE_URL  – Endpoint base URL
        CTF_AGENT_LLM_MODEL     – Model name
    """

    def __init__(
        self,
        api_key=None,
        base_url=None,
        model=None,
        temperature=None,
        max_tokens=None,
        timeout=None,
        default_system_prompt=None,
    ):
        self.api_key = (
            api_key
            or os.environ.get("CTF_AGENT_LLM_API_KEY")
            or os.environ.get("OPENAI_API_KEY")
            or ""
        )
        self.base_url = (
            base_url
            or os.environ.get("CTF_AGENT_LLM_BASE_URL")
            or _DEFAULT_BASE_URL
        ).rstrip("/")
        self.model = (
            model
            or os.environ.get("CTF_AGENT_LLM_MODEL")
            or _DEFAULT_MODEL
        )
        self.temperature = temperature if temperature is not None else _DEFAULT_TEMPERATURE
        self.max_tokens = max_tokens or _DEFAULT_MAX_TOKENS
        self.timeout = timeout or _DEFAULT_TIMEOUT
        self.default_system_prompt = default_system_prompt or ""
        self._total_tokens_used = 0
        self._total_prompt_tokens = 0
        self._total_completion_tokens = 0
        self._call_count = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def chat(self, messages, tools=None, temperature=None, max_tokens=None, json_mode=False):
        """
        Single chat-completion call, optionally with tool definitions.

        Returns an ``LLMResponse`` with ``.text`` and/or ``.tool_calls``.
        """
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature if temperature is not None else self.temperature,
            "max_tokens": max_tokens or self.max_tokens,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        raw = self._post("/chat/completions", payload)
        return self._parse_response(raw)

    def structured_output(self, messages, schema_hint="", temperature=None):
        """
        Chat completion forcing JSON output.

        *schema_hint* is appended to the system prompt so the model knows
        what shape to return.  Returns a parsed dict (or ``{"raw": text}``
        on parse failure).
        """
        msgs = list(messages)
        if schema_hint:
            injected = False
            for m in msgs:
                if m.get("role") == "system":
                    m["content"] += "\n\nRespond ONLY with valid JSON matching: " + schema_hint
                    injected = True
                    break
            if not injected:
                msgs.insert(0, {
                    "role": "system",
                    "content": "Respond ONLY with valid JSON matching: " + schema_hint,
                })

        resp = self.chat(msgs, temperature=temperature, json_mode=True)
        text = resp.text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return {"raw": resp.text}

    def quick(self, user_prompt, system_prompt=None, temperature=None):
        """Convenience: single user message → text reply."""
        msgs = []
        sys = system_prompt or self.default_system_prompt
        if sys:
            msgs.append({"role": "system", "content": sys})
        msgs.append({"role": "user", "content": user_prompt})
        return self.chat(msgs, temperature=temperature).text

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def is_configured(self):
        return bool(self.api_key)

    @property
    def stats(self):
        return {
            "model": self.model,
            "call_count": self._call_count,
            "total_tokens": self._total_tokens_used,
            "prompt_tokens": self._total_prompt_tokens,
            "completion_tokens": self._total_completion_tokens,
        }

    # ------------------------------------------------------------------
    # Internal HTTP
    # ------------------------------------------------------------------

    def _post(self, endpoint, payload):
        url = self.base_url + endpoint
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = "Bearer " + self.api_key

        last_exc = None
        for attempt in range(_MAX_RETRIES):
            try:
                req = Request(url, data=body, headers=headers, method="POST")
                ctx = ssl.create_default_context()
                with urlopen(req, timeout=self.timeout, context=ctx) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except HTTPError as exc:
                last_exc = exc
                if exc.code == 429 or exc.code >= 500:
                    delay = _RETRY_BASE_DELAY * (2 ** attempt)
                    logger.warning(
                        "LLM API HTTP %d – retry %d/%d in %.1fs",
                        exc.code, attempt + 1, _MAX_RETRIES, delay,
                    )
                    time.sleep(delay)
                    continue
                try:
                    error_body = exc.read().decode("utf-8", errors="replace")
                except Exception:
                    error_body = str(exc)
                raise RuntimeError(
                    "LLM API error {0}: {1}".format(exc.code, error_body[:500])
                )
            except (URLError, OSError) as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES - 1:
                    delay = _RETRY_BASE_DELAY * (2 ** attempt)
                    logger.warning(
                        "LLM network error – retry %d/%d in %.1fs: %s",
                        attempt + 1, _MAX_RETRIES, delay, exc,
                    )
                    time.sleep(delay)
                    continue
                raise RuntimeError(
                    "LLM network error after {0} retries: {1}".format(_MAX_RETRIES, exc)
                )

        raise RuntimeError(
            "LLM API failed after {0} retries: {1}".format(_MAX_RETRIES, last_exc)
        )

    def _parse_response(self, raw):
        self._call_count += 1
        usage = raw.get("usage", {})
        self._total_tokens_used += usage.get("total_tokens", 0)
        self._total_prompt_tokens += usage.get("prompt_tokens", 0)
        self._total_completion_tokens += usage.get("completion_tokens", 0)

        choices = raw.get("choices", [])
        if not choices:
            return LLMResponse(usage=usage, model=raw.get("model", self.model))

        choice = choices[0]
        message = choice.get("message", {})
        text = message.get("content") or ""
        finish_reason = choice.get("finish_reason", "")

        tool_calls = []
        for tc in message.get("tool_calls", []):
            func = tc.get("function", {})
            name = func.get("name", "")
            try:
                arguments = json.loads(func.get("arguments", "{}"))
            except (json.JSONDecodeError, TypeError):
                arguments = {"raw": func.get("arguments", "")}
            tool_calls.append(ToolCall(
                call_id=tc.get("id", ""),
                name=name,
                arguments=arguments,
            ))

        return LLMResponse(
            text=text,
            tool_calls=tool_calls,
            usage=usage,
            model=raw.get("model", self.model),
            finish_reason=finish_reason,
        )
