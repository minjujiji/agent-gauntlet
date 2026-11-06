from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any

from agent_gauntlet.agent import run_agent
from agent_gauntlet.defenses import Defense
from agent_gauntlet.judge import judge
from agent_gauntlet.llm.base import LLMClient
from agent_gauntlet.scenarios import Scenario
from agent_gauntlet.tools import Sandbox


@dataclass
class RunResult:
    scenario_id: str
    kind: str
    defense: str
    run_index: int
    attack_succeeded: bool | None
    utility_ok: bool | None
    steps: int
    reasons: list[str]
    tool_calls: list[dict[str, Any]]
    final_answer: str
    attack_hijacked: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_suite(
    scenarios: list[Scenario],
    llm: LLMClient,
    defense: Defense,
    runs: int = 5,
    max_steps: int = 8,
    on_result: Callable[[RunResult], None] | None = None,
) -> list[RunResult]:
    """Run every scenario `runs` times (models are random, so one run proves little)."""
    results: list[RunResult] = []
    for scenario in scenarios:
        for index in range(runs):
            sandbox = Sandbox.from_environment(scenario.environment)  # fresh state every run
            trace = run_agent(
                scenario.task, llm, sandbox, defense,
                max_steps=max_steps, context=scenario.context(),
            )
            verdict = judge(scenario, trace)
            result = RunResult(
                scenario_id=scenario.id,
                kind=scenario.kind,
                defense=defense.name,
                run_index=index,
                attack_succeeded=verdict.attack_succeeded,
                utility_ok=verdict.utility_ok,
                steps=trace.steps,
                reasons=verdict.reasons,
                tool_calls=[
                    {
                        "name": i.name,
                        "arguments": i.arguments,
                        "blocked": i.blocked,
                        "reason": i.reason,
                    }
                    for i in trace.invocations
                ],
                final_answer=trace.final_answer,
                attack_hijacked=verdict.attack_hijacked,
            )
            results.append(result)
            if on_result is not None:
                on_result(result)
    return results
