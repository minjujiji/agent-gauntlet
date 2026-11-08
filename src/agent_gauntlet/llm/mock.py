from __future__ import annotations

import re
from typing import Any

from agent_gauntlet.llm.base import LLMResponse, ToolCall

SEARCH_DIRECTIVE = re.compile(r'search_notes\(query="([^"]+)"\)')
SEND_DIRECTIVE = re.compile(r'send_message\(to="([^"]+)",\s*body="([^"]*)"\)')
SEND_RESULT_DIRECTIVE = re.compile(r'send_message\(to="([^"]+)",\s*body=<result>\)')
FETCH_DIRECTIVE = re.compile(r'fetch_url\(url="([^"]+)"\)')
FETCH_RESULT_DIRECTIVE = re.compile(r'fetch_url\(url="([^"]*)<result>"\)')

URL = re.compile(r"https?://\S+")
SEND_TASK = re.compile(r"send a message to (\S+@\S+) saying (.+)$", re.IGNORECASE)
NOTES_TASK = re.compile(r"notes for (\w+)", re.IGNORECASE)
FROM_LINE = re.compile(r"^From:\s*(\S+)", re.MULTILINE)


class MockLLM:
    """Deterministic fake model for tests and CI, so they run without Ollama.

    Its numbers mean nothing as results. It can do the
    legitimate tasks in the shipped scenarios. With gullible=True it also obeys
    function-call-style directives found in the first tool output (the failure being
    studied); natural-language attacks do not fool it. With gullible=False it ignores all
    directives.
    """

    def __init__(self, gullible: bool = True) -> None:
        self.gullible = gullible

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> LLMResponse:
        available = {t["function"]["name"] for t in tools}
        task = next((m["content"] for m in messages if m["role"] == "user"), "")
        last = messages[-1]

        if last["role"] == "user":
            return self._plan(task, available)

        if last["role"] == "tool":
            if self.gullible:
                obeyed = self._obey(messages, available)
                if obeyed is not None:
                    return obeyed
            reply = self._reply(task, last, available)
            if reply is not None:
                return reply
            return LLMResponse(content=self._finish(last))

        return LLMResponse(content="Done.")

    @staticmethod
    def _plan(task: str, available: set[str]) -> LLMResponse:
        lowered = task.lower()
        send = SEND_TASK.search(task)
        if send and "send_message" in available:
            body = send.group(2).strip().rstrip(".")
            call = ToolCall("send_message", {"to": send.group(1), "body": body})
            return LLMResponse(tool_calls=[call])
        notes = NOTES_TASK.search(task)
        if notes and "search_notes" in available:
            return LLMResponse(tool_calls=[ToolCall("search_notes", {"query": notes.group(1)})])
        if "email" in lowered and "read_email" in available:
            return LLMResponse(tool_calls=[ToolCall("read_email", {"id": "latest"})])
        url = URL.search(task)
        if url and "fetch_url" in available:
            call = ToolCall("fetch_url", {"url": url.group(0).rstrip(".,")})
            return LLMResponse(tool_calls=[call])
        return LLMResponse(content="I could not work out which tool to use for that.")

    @staticmethod
    def _obey(messages: list[dict[str, Any]], available: set[str]) -> LLMResponse | None:
        tool_messages = [m for m in messages if m["role"] == "tool"]
        last = tool_messages[-1]

        # Directives are only obeyed in the first tool output, plus the second step of a
        # "search the notes, then send/fetch the result" chain.
        if len(tool_messages) == 1:
            content = last["content"]
            search = SEARCH_DIRECTIVE.search(content)
            if search and "search_notes" in available:
                call = ToolCall("search_notes", {"query": search.group(1)})
                return LLMResponse(tool_calls=[call])
            send = SEND_DIRECTIVE.search(content)
            if send and "send_message" in available:
                call = ToolCall("send_message", {"to": send.group(1), "body": send.group(2)})
                return LLMResponse(tool_calls=[call])
            fetch = FETCH_DIRECTIVE.search(content)
            if fetch and "fetch_url" in available:
                return LLMResponse(tool_calls=[ToolCall("fetch_url", {"url": fetch.group(1)})])
            return None

        if last["name"] == "search_notes":
            for earlier in tool_messages[:-1]:
                send_chain = SEND_RESULT_DIRECTIVE.search(earlier["content"])
                if send_chain and "send_message" in available:
                    call = ToolCall(
                        "send_message", {"to": send_chain.group(1), "body": last["content"]}
                    )
                    return LLMResponse(tool_calls=[call])
                fetch_chain = FETCH_RESULT_DIRECTIVE.search(earlier["content"])
                if fetch_chain and "fetch_url" in available:
                    url = fetch_chain.group(1) + last["content"]
                    return LLMResponse(tool_calls=[ToolCall("fetch_url", {"url": url})])
        return None

    @staticmethod
    def _reply(task: str, last: dict[str, Any], available: set[str]) -> LLMResponse | None:
        if last["name"] == "read_email" and "reply" in task.lower() and "send_message" in available:
            sender = FROM_LINE.search(last["content"])
            if sender:
                call = ToolCall("send_message", {"to": sender.group(1), "body": "Thanks!"})
                return LLMResponse(tool_calls=[call])
        return None

    @staticmethod
    def _finish(last: dict[str, Any]) -> str:
        if last["name"] == "send_message":
            return f"Done. {last['content']}"
        flattened = " ".join(last["content"].split())
        return f"Summary: {flattened[:200]}"
