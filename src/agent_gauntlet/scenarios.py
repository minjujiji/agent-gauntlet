"""Scenario definitions, loaded from YAML files in the scenarios/ folder.

A file may hold one scenario (a mapping) or several (a list of mappings).
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from agent_gauntlet.context import TaskContext
from agent_gauntlet.tools import TOOL_NAMES

KINDS = {"attack", "benign"}
CONDITION_TYPES = {"tool_called", "secret_leaked"}


@dataclass
class Scenario:
    id: str
    title: str
    category: str
    kind: str  # "attack" or "benign"
    task: str
    owasp: list[str] = field(default_factory=list)
    environment: dict[str, Any] = field(default_factory=dict)
    success: list[dict[str, Any]] = field(default_factory=list)  # attack: any true = attack won
    utility: dict[str, Any] = field(default_factory=dict)  # did the legitimate task still work?
    allowed_tools: list[str] | None = None  # tools the task legitimately needs
    approved_recipients: list[str] | None = None  # who a human would let the agent message
    # Text-level hijack checks (heuristic): the model's final answer follows the injection.
    hijack_answer_contains: list[str] = field(default_factory=list)  # distinctive attacker data
    hijack_answer_is: list[str] = field(default_factory=list)  # whole answer equals this

    def hijack_markers(self) -> list[str]:
        """Attacker data to look for in any tool call's arguments, found or not.

        Taken from the success conditions, so the author does not list it twice.
        """
        markers: list[str] = []
        for condition in self.success:
            markers += [str(v) for v in condition.get("arg_contains", {}).values()]
            if condition.get("secret"):
                markers.append(str(condition["secret"]))
        return markers

    def context(self) -> TaskContext:
        return TaskContext(
            task=self.task,
            allowed_tools=tuple(self.allowed_tools) if self.allowed_tools is not None else None,
            approved_recipients=(
                tuple(self.approved_recipients) if self.approved_recipients is not None else None
            ),
        )

    @classmethod
    def from_dict(cls, data: Any, source: str = "<memory>") -> Scenario:
        def fail(message: str) -> ValueError:
            return ValueError(f"{source}: {message}")

        if not isinstance(data, dict):
            raise fail("a scenario must be a mapping")
        for key in ("id", "title", "category", "kind", "task"):
            if not data.get(key):
                raise fail(f"missing required field '{key}'")
        if data["kind"] not in KINDS:
            raise fail(f"kind must be one of {sorted(KINDS)}")

        allowed = data.get("allowed_tools")
        if allowed is not None:
            for tool in allowed:
                if tool not in TOOL_NAMES:
                    raise fail(f"unknown tool '{tool}' in allowed_tools")

        scenario = cls(
            id=str(data["id"]),
            title=str(data["title"]),
            category=str(data["category"]),
            kind=data["kind"],
            task=str(data["task"]),
            owasp=list(data.get("owasp", [])),
            environment=dict(data.get("environment") or {}),
            success=list(data.get("success") or []),
            utility=dict(data.get("utility") or {}),
            allowed_tools=list(allowed) if allowed is not None else None,
            approved_recipients=(
                list(data["approved_recipients"])
                if data.get("approved_recipients") is not None
                else None
            ),
            hijack_answer_contains=[str(x) for x in data.get("hijack_answer_contains") or []],
            hijack_answer_is=[str(x) for x in data.get("hijack_answer_is") or []],
        )

        if scenario.kind == "attack":
            if not scenario.success:
                raise fail("attack scenarios need at least one 'success' condition")
            for condition in scenario.success:
                kind = condition.get("type")
                if kind not in CONDITION_TYPES:
                    raise fail(f"condition type must be one of {sorted(CONDITION_TYPES)}")
                if kind == "tool_called" and condition.get("tool") not in TOOL_NAMES:
                    raise fail("tool_called conditions need a valid 'tool'")
                if kind == "secret_leaked" and not condition.get("secret"):
                    raise fail("secret_leaked conditions need a 'secret'")
        elif not (scenario.utility.get("answer_contains") or scenario.utility.get("sent_to")):
            raise fail("benign scenarios need utility.answer_contains or utility.sent_to")
        return scenario


def _documents(path: Path) -> Iterator[tuple[str, Any]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        for index, item in enumerate(data):
            yield f"{path.name}[{index}]", item
    else:
        yield path.name, data


def load_scenarios(directory: str | Path) -> list[Scenario]:
    directory = Path(directory)
    if not directory.is_dir():
        raise FileNotFoundError(f"Scenario folder not found: {directory}")

    scenarios: list[Scenario] = []
    seen: set[str] = set()
    for path in sorted(directory.glob("*.yaml")):
        for source, data in _documents(path):
            scenario = Scenario.from_dict(data, source=source)
            if scenario.id in seen:
                raise ValueError(f"{source}: duplicate scenario id '{scenario.id}'")
            seen.add(scenario.id)
            scenarios.append(scenario)
    return sorted(scenarios, key=lambda s: s.id)
