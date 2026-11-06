from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class ToolCall:
    name: str
    arguments: dict[str, Any]


@dataclass
class LLMResponse:
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)


class LLMClient(Protocol):
    """Anything that can take a conversation plus tool specs and return the next turn.

    Messages use the common chat format:
      {"role": "system" | "user" | "assistant" | "tool", "content": str, ...}
    Tool result messages also carry {"name": <tool name>}.
    """

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> LLMResponse: ...
