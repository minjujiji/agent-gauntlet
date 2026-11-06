from __future__ import annotations

import json
from typing import Any

import httpx

from agent_gauntlet.llm.base import LLMResponse, ToolCall


class OllamaClient:
    """Talks to a local Ollama server (https://ollama.com). Nothing leaves your machine.

    The model must support tool calling (for example llama3.1, llama3.2 or qwen2.5).
    """

    def __init__(
        self,
        model: str = "llama3.2:3b",
        base_url: str = "http://localhost:11434",
        temperature: float = 0.7,
        timeout: float = 300.0,
        max_tokens: int = 768,
        retries: int = 1,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.temperature = temperature
        self.timeout = timeout
        # Small models sometimes loop forever ("Hi, Hi, Hi, ..."). Capping the answer length
        # stops one runaway generation from stalling a multi-hour experiment.
        self.max_tokens = max_tokens
        self.retries = retries

    @staticmethod
    def _to_wire(message: dict[str, Any]) -> dict[str, Any]:
        if message["role"] == "tool":
            return {
                "role": "tool",
                "content": message["content"],
                "tool_name": message.get("name", ""),
            }
        return message

    def _post(self, payload: dict[str, Any]) -> httpx.Response:
        for attempt in range(self.retries + 1):
            try:
                return httpx.post(
                    f"{self.base_url}/api/chat", json=payload, timeout=self.timeout
                )
            except httpx.ConnectError as exc:
                raise RuntimeError(
                    f"Could not reach Ollama at {self.base_url}. Is it running? "
                    f"Try `ollama serve` and `ollama pull {self.model}`."
                ) from exc
            except httpx.ReadTimeout as exc:
                if attempt == self.retries:
                    raise RuntimeError(
                        f"Ollama took longer than {self.timeout:.0f}s to answer "
                        f"({attempt + 1} tries). The machine may be busy or asleep, or the model "
                        "too large; try a smaller one. Layers finished so far are already saved."
                    ) from exc
        raise AssertionError("unreachable")

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> LLMResponse:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [self._to_wire(m) for m in messages],
            "stream": False,
            "options": {"temperature": self.temperature, "num_predict": self.max_tokens},
        }
        if tools:
            payload["tools"] = tools

        response = self._post(payload)

        if response.status_code >= 400:
            raise RuntimeError(
                f"Ollama returned HTTP {response.status_code}: {response.text[:500]}"
            )

        body = response.json()
        if "message" not in body:
            # Ollama can report model-load failures (for example out of memory) in the body.
            raise RuntimeError(f"Unexpected Ollama response: {str(body)[:500]}")

        message = body["message"]
        calls: list[ToolCall] = []
        for raw in message.get("tool_calls") or []:
            function = raw["function"]
            arguments = function.get("arguments") or {}
            if isinstance(arguments, str):
                arguments = json.loads(arguments)
            calls.append(ToolCall(name=function["name"], arguments=arguments))
        return LLMResponse(content=message.get("content") or "", tool_calls=calls)
