from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from agent_gauntlet.runner import RunResult
from agent_gauntlet.scenarios import Scenario


@dataclass
class ScenarioSummary:
    scenario_id: str
    title: str
    kind: str
    runs: int
    attack_success_rate: float | None
    utility_rate: float | None
    hijack_rate: float | None = None


@dataclass
class SuiteSummary:
    scenarios: list[ScenarioSummary]
    overall_attack_success_rate: float | None
    overall_utility_rate: float | None
    overall_hijack_rate: float | None = None


def _rate(values: list[bool]) -> float | None:
    return sum(values) / len(values) if values else None


def summarise(results: list[RunResult], scenarios: list[Scenario]) -> SuiteSummary:
    grouped: dict[str, list[RunResult]] = defaultdict(list)
    for result in results:
        grouped[result.scenario_id].append(result)

    rows: list[ScenarioSummary] = []
    all_attack: list[bool] = []
    all_utility: list[bool] = []
    all_hijack: list[bool] = []
    for scenario in scenarios:
        runs = grouped.get(scenario.id, [])
        attack = [r.attack_succeeded for r in runs if r.attack_succeeded is not None]
        utility = [r.utility_ok for r in runs if r.utility_ok is not None]
        hijack = [r.attack_hijacked for r in runs if r.attack_hijacked is not None]
        all_attack += attack
        all_utility += utility
        all_hijack += hijack
        rows.append(
            ScenarioSummary(
                scenario_id=scenario.id,
                title=scenario.title,
                kind=scenario.kind,
                runs=len(runs),
                attack_success_rate=_rate(attack),
                utility_rate=_rate(utility),
                hijack_rate=_rate(hijack),
            )
        )
    return SuiteSummary(rows, _rate(all_attack), _rate(all_utility), _rate(all_hijack))


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.0f}%"


def to_markdown(summary: SuiteSummary, defense: str, model: str, runs: int) -> str:
    lines = [
        f"## Results: defense {defense}, model {model}, {runs} runs per scenario",
        "",
        "| Scenario | Type | Attack success | Model hijacked | Task still works |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in summary.scenarios:
        lines.append(
            f"| {row.scenario_id} {row.title} | {row.kind} | "
            f"{_pct(row.attack_success_rate)} | {_pct(row.hijack_rate)} | "
            f"{_pct(row.utility_rate)} |"
        )
    lines += [
        "",
        f"**Overall attack success rate:** {_pct(summary.overall_attack_success_rate)}",
        f"**Overall model hijacked rate:** {_pct(summary.overall_hijack_rate)}",
        f"**Overall task success (utility):** {_pct(summary.overall_utility_rate)}",
        "",
    ]
    return "\n".join(lines)


def comparison_markdown(
    summaries: dict[str, SuiteSummary],
    descriptions: dict[str, str],
    scenarios: list[Scenario],
    model: str,
    runs: int,
) -> str:
    """One report comparing every defense layer on the same scenarios."""
    layers = list(summaries)
    by_id = {
        layer: {row.scenario_id: row for row in summary.scenarios}
        for layer, summary in summaries.items()
    }
    attacks = [s for s in scenarios if s.kind == "attack"]
    benign = [s for s in scenarios if s.kind == "benign"]
    last = layers[-1]

    lines = [
        f"## Defense comparison, model {model}, {runs} runs per scenario",
        "",
        f"{len(attacks)} attack scenarios and {len(benign)} benign controls. "
        "Attack success: the attack achieved its goal (strict, from executed tool calls). "
        "Model hijacked: the model was fooled, even if the attack did not land (a malformed or "
        "blocked call, or an answer that follows the injection). Lower is better for both. "
        "Task success: higher is better.",
        "",
        "| Layer | What it adds | Attack success | Model hijacked | Task success |",
        "| --- | --- | --- | --- | --- |",
    ]
    for layer in layers:
        s = summaries[layer]
        lines.append(
            f"| {layer} | {descriptions[layer]} | {_pct(s.overall_attack_success_rate)} "
            f"| {_pct(s.overall_hijack_rate)} | {_pct(s.overall_utility_rate)} |"
        )

    values = [round((summaries[layer].overall_attack_success_rate or 0) * 100) for layer in layers]
    hijacked = [round((summaries[layer].overall_hijack_rate or 0) * 100) for layer in layers]
    lines += [
        "",
        "```mermaid",
        "xychart-beta",
        '    title "Attack success (bars) and model hijacked (line) by defense layer (%)"',
        f"    x-axis [{', '.join(layers)}]",
        '    y-axis "Rate (%)" 0 --> 100',
        f"    bar [{', '.join(str(v) for v in values)}]",
        f"    line [{', '.join(str(v) for v in hijacked)}]",
        "```",
        "",
        "### Attack success by scenario",
        "",
        "| Scenario | Category | " + " | ".join(layers) + " |",
        "| --- | --- | " + " | ".join("---" for _ in layers) + " |",
    ]
    for s in attacks:
        cells = " | ".join(_pct(by_id[layer][s.id].attack_success_rate) for layer in layers)
        lines.append(f"| {s.id} {s.title} | {s.category} | {cells} |")

    lines += ["", "### Model hijacked by scenario", "",
              "| Scenario | Category | " + " | ".join(layers) + " |",
              "| --- | --- | " + " | ".join("---" for _ in layers) + " |"]
    for s in attacks:
        cells = " | ".join(_pct(by_id[layer][s.id].hijack_rate) for layer in layers)
        lines.append(f"| {s.id} {s.title} | {s.category} | {cells} |")

    lines += ["", "### Attack success by category", "",
              "| Category | Scenarios | " + " | ".join(layers) + " |",
              "| --- | --- | " + " | ".join("---" for _ in layers) + " |"]
    categories: dict[str, list[Scenario]] = defaultdict(list)
    for s in attacks:
        categories[s.category].append(s)
    for category, members in sorted(categories.items()):
        cells = []
        for layer in layers:
            rates = [by_id[layer][m.id].attack_success_rate for m in members]
            rates = [r for r in rates if r is not None]
            cells.append(_pct(sum(rates) / len(rates) if rates else None))
        lines.append(f"| {category} | {len(members)} | " + " | ".join(cells) + " |")

    lines += ["", "### Task success by benign control", "",
              "| Scenario | " + " | ".join(layers) + " |",
              "| --- | " + " | ".join("---" for _ in layers) + " |"]
    for s in benign:
        cells = " | ".join(_pct(by_id[layer][s.id].utility_rate) for layer in layers)
        lines.append(f"| {s.id} {s.title} | {cells} |")

    residual = [
        (s, by_id[last][s.id].attack_success_rate)
        for s in attacks
        if (by_id[last][s.id].attack_success_rate or 0) > 0
    ]
    lines += ["", f"### Attacks that still succeed at {last}", ""]
    if residual:
        for s, rate in residual:
            lines.append(f"- {s.id} {s.title}: {_pct(rate)}")
    else:
        lines.append("None in this run. That means these scenarios were all stopped, not that "
                     "the agent is safe against other attacks.")
    lines.append("")
    return "\n".join(lines)
