from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

from agent_gauntlet.defenses import DEFENSES, get_defense
from agent_gauntlet.llm import LLMClient, MockLLM, OllamaClient
from agent_gauntlet.report import comparison_markdown, summarise, to_markdown
from agent_gauntlet.runner import RunResult, run_suite
from agent_gauntlet.scenarios import Scenario, load_scenarios

DEFAULT_SCENARIOS = "scenarios"


def _slug(text: str) -> str:
    """File-name safe text (Windows does not allow ':' in names)."""
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-")


def _build_llm(args: argparse.Namespace) -> tuple[LLMClient, str, str]:
    """Returns the client, a display label and a file-name slug."""
    if args.llm == "mock-gullible":
        return MockLLM(gullible=True), "mock-gullible (test double)", "mock-gullible"
    if args.llm == "mock-robust":
        return MockLLM(gullible=False), "mock-robust (test double)", "mock-robust"
    client = OllamaClient(
        model=args.model, base_url=args.ollama_url, temperature=args.temperature
    )
    return client, f"ollama:{args.model}", f"ollama-{_slug(args.model)}"


def _select(scenarios: list[Scenario], only: str | None) -> list[Scenario]:
    if not only:
        return scenarios
    wanted = {part.strip().upper() for part in only.split(",") if part.strip()}
    unknown = wanted - {s.id for s in scenarios}
    if unknown:
        raise ValueError(f"Unknown scenario id(s): {', '.join(sorted(unknown))}")
    return [s for s in scenarios if s.id in wanted]


def _parse_layers(value: str) -> list[str]:
    if value.strip().lower() == "all":
        return sorted(DEFENSES)
    return [part.strip().upper() for part in value.split(",") if part.strip()]


def _cmd_list(args: argparse.Namespace) -> int:
    scenarios = load_scenarios(args.scenarios)
    if args.markdown:
        print("| ID | Type | Category | OWASP | Title |")
        print("| --- | --- | --- | --- | --- |")
        for s in scenarios:
            print(f"| {s.id} | {s.kind} | {s.category} | {', '.join(s.owasp) or '-'} | {s.title} |")
        return 0
    for s in scenarios:
        print(f"{s.id}  [{s.kind:6}]  {s.category:22}  {s.title}")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    scenarios = _select(load_scenarios(args.scenarios), args.only)
    llm, label, slug = _build_llm(args)
    layers = _parse_layers(args.defense)
    for layer in layers:
        get_defense(layer)  # fail early on a typo, before any slow model calls

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    total = len(scenarios) * args.runs
    print(f"{len(scenarios)} scenarios x {args.runs} runs x {len(layers)} layer(s) "
          f"= {total * len(layers)} agent runs, model {label}")

    summaries = {}
    descriptions = {}
    for layer in layers:
        defense = get_defense(layer)
        descriptions[layer] = defense.description
        done = {"n": 0}

        def progress(result: RunResult, layer: str = layer, done: dict = done) -> None:
            done["n"] += 1
            print(f"\r  {layer}: {done['n']}/{total} (last: {result.scenario_id})   ",
                  end="", flush=True, file=sys.stderr)

        started = time.time()
        results = run_suite(scenarios, llm, defense, runs=args.runs, on_result=progress)
        print(f"\r  {layer}: done in {time.time() - started:.0f}s" + " " * 30, file=sys.stderr)

        summary = summarise(results, scenarios)
        summaries[layer] = summary
        report = to_markdown(summary, layer, label, args.runs)
        (out / f"{layer}-{slug}.json").write_text(
            json.dumps([r.to_dict() for r in results], indent=2), encoding="utf-8"
        )
        (out / f"{layer}-{slug}.md").write_text(report, encoding="utf-8")
        if len(layers) == 1:
            print()
            print(report)

    if len(layers) > 1:
        comparison = comparison_markdown(summaries, descriptions, scenarios, label, args.runs)
        path = out / f"comparison-{slug}.md"
        path.write_text(comparison, encoding="utf-8")
        print()
        print(comparison)
        print(f"Saved {path}")
    print(f"Per-run details (every tool call) are in {out / ('<layer>-' + slug + '.json')}")
    return 0


def _cmd_compare(args: argparse.Namespace) -> int:
    """Build the comparison from layer files already saved by earlier `run` commands."""
    scenarios = load_scenarios(args.scenarios)
    _, label, slug = _build_llm(args)
    out = Path(args.out)
    summaries = {}
    descriptions = {}
    run_counts = set()
    for layer in sorted(DEFENSES):
        path = out / f"{layer}-{slug}.json"
        if not path.exists():
            continue
        results = [RunResult(**row) for row in json.loads(path.read_text(encoding="utf-8"))]
        run_counts.add(max(r.run_index for r in results) + 1)
        summaries[layer] = summarise(results, scenarios)
        descriptions[layer] = get_defense(layer).description
    if len(summaries) < 2:
        raise ValueError(
            f"Need saved results for at least two layers in {out} for model {label}; "
            f"found {sorted(summaries) or 'none'}."
        )
    runs = max(run_counts)
    note = ""
    if len(run_counts) > 1:
        note = f" (layers used different run counts: {sorted(run_counts)}; showing the highest)"
    comparison = comparison_markdown(summaries, descriptions, scenarios, label, runs)
    path = out / f"comparison-{slug}.md"
    path.write_text(comparison, encoding="utf-8")
    print(comparison)
    print(f"Saved {path}, layers {', '.join(summaries)}{note}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-gauntlet",
        description="Attack an LLM agent with prompt injection scenarios and measure defenses.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    list_cmd = sub.add_parser("list", help="List the available scenarios")
    list_cmd.add_argument("--scenarios", default=DEFAULT_SCENARIOS)
    list_cmd.add_argument("--markdown", action="store_true", help="Print as a Markdown table")
    list_cmd.set_defaults(func=_cmd_list)

    run_cmd = sub.add_parser("run", help="Run the scenario suite")
    run_cmd.add_argument("--scenarios", default=DEFAULT_SCENARIOS, help="Folder of YAML scenarios")
    run_cmd.add_argument(
        "--llm", choices=["mock-gullible", "mock-robust", "ollama"], default="mock-gullible"
    )
    run_cmd.add_argument("--model", default="llama3.2:3b", help="Ollama model name")
    run_cmd.add_argument("--ollama-url", default="http://localhost:11434")
    run_cmd.add_argument("--temperature", type=float, default=0.7)
    run_cmd.add_argument(
        "--defense",
        default="L0",
        help=f"One of {', '.join(sorted(DEFENSES))}, a comma list like L3,L4, or 'all'",
    )
    run_cmd.add_argument("--runs", type=int, default=5, help="Runs per scenario")
    run_cmd.add_argument("--only", help="Comma-separated scenario ids, for example S001,S003")
    run_cmd.add_argument("--out", default="results", help="Folder for JSON and Markdown output")
    run_cmd.set_defaults(func=_cmd_run)

    compare_cmd = sub.add_parser(
        "compare", help="Build the layer comparison from results saved by earlier runs"
    )
    compare_cmd.add_argument("--scenarios", default=DEFAULT_SCENARIOS)
    compare_cmd.add_argument(
        "--llm", choices=["mock-gullible", "mock-robust", "ollama"], default="mock-gullible"
    )
    compare_cmd.add_argument("--model", default="llama3.2:3b", help="Ollama model name")
    compare_cmd.add_argument("--ollama-url", default="http://localhost:11434")
    compare_cmd.add_argument("--temperature", type=float, default=0.7)
    compare_cmd.add_argument("--out", default="results", help="Folder holding the layer files")
    compare_cmd.set_defaults(func=_cmd_compare)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, FileNotFoundError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
