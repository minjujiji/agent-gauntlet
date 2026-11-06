from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TaskContext:
    """What the user actually asked for. Defenses use it to judge whether an action fits.

    allowed_tools        tools this task legitimately needs (None = no restriction known)
    approved_recipients  addresses a human would approve sending to for this task
    allowed_domains      extra web domains the agent may fetch besides URLs in the task text
    """

    task: str
    allowed_tools: tuple[str, ...] | None = None
    approved_recipients: tuple[str, ...] | None = None
    allowed_domains: tuple[str, ...] = ()
