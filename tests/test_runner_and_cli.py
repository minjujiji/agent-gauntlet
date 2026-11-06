import json
from pathlib import Path

from agent_gauntlet.cli import _slug, main
from agent_gauntlet.defenses import DEFENSES, get_defense
from agent_gauntlet.llm import MockLLM
from agent_gauntlet.report import comparison_markdown, summarise, to_markdown
from agent_gauntlet.runner import run_suite
from agent_gauntlet.scenarios import load_scenarios

SCENARIO_DIR = Path(__file__).resolve().parents[1] / "scenarios"
SCENARIOS = load_scenarios(SCENARIO_DIR)
N_ATTACKS = sum(s.kind == "attack" for s in SCENARIOS)

# Attacks written in function-call style, which the deterministic mock can be fooled by.
MOCK_FOOLABLE = {"S001", "S002", "S006", "S013"}


def run_layer(layer, llm=None, runs=2):
    results = run_suite(SCENARIOS, llm or MockLLM(gullible=True), get_defense(layer), runs=runs)
    return results, summarise(results, SCENARIOS)


def test_baseline_with_gullible_mock_loses_exactly_the_foolable_attacks():
    results, summary = run_layer("L0")
    lost = {r.scenario_id for r in results if r.attack_succeeded}
    assert lost == MOCK_FOOLABLE
    assert summary.overall_attack_success_rate == len(MOCK_FOOLABLE) / N_ATTACKS
    assert summary.overall_utility_rate == 1.0
    assert len(results) == len(SCENARIOS) * 2


def test_robust_mock_is_never_fooled_at_any_layer():
    for layer in DEFENSES:
        _, summary = run_layer(layer, MockLLM(gullible=False))
        assert summary.overall_attack_success_rate == 0.0, layer


def test_scanner_layer_stops_the_foolable_attacks():
    results, summary = run_layer("L1")
    assert summary.overall_attack_success_rate == 0.0
    assert not {r.scenario_id for r in results if r.attack_succeeded}


def test_scanner_false_positive_costs_utility_on_the_probe():
    results, summary = run_layer("L1")
    failed = {r.scenario_id for r in results if r.utility_ok is False}
    assert failed == {"B005"}
    assert summary.overall_utility_rate < 1.0


def test_least_privilege_and_human_layers_keep_legitimate_tasks_working():
    for layer in ("L3", "L4"):
        results, _ = run_layer(layer)
        failed = {r.scenario_id for r in results if r.utility_ok is False}
        assert failed == {"B005"}, layer  # only the scanner's false positive remains


def test_progress_callback_sees_every_run():
    seen = []
    run_suite(SCENARIOS, MockLLM(), get_defense("L0"), runs=1, on_result=seen.append)
    assert len(seen) == len(SCENARIOS)


def test_markdown_report_has_table_and_totals():
    results, summary = run_layer("L0", runs=1)
    text = to_markdown(summary, "L0", "mock", 1)
    assert "| S001" in text
    assert "Overall attack success rate" in text


def test_comparison_report_covers_every_layer_and_section():
    summaries, descriptions = {}, {}
    for layer in sorted(DEFENSES):
        _, summaries[layer] = run_layer(layer, runs=1)
        descriptions[layer] = get_defense(layer).description
    text = comparison_markdown(summaries, descriptions, SCENARIOS, "mock", 1)
    for heading in (
        "Defense comparison",
        "Attack success by scenario",
        "Attack success by category",
        "Task success by benign control",
        "Attacks that still succeed at L4",
        "xychart-beta",
    ):
        assert heading in text
    assert "bar [20, 0, 0, 0, 0]" in text


def test_comparison_lists_residual_attacks():
    results, summary = run_layer("L0", runs=1)  # L0 is the "strongest" layer here
    text = comparison_markdown({"L0": summary}, {"L0": "baseline"}, SCENARIOS, "mock", 1)
    assert "- S001" in text


def test_slug_is_windows_safe():
    assert _slug("qwen2.5:7b") == "qwen2.5-7b"
    assert _slug("llama3.2:3b") == "llama3.2-3b"


def test_cli_single_layer_writes_outputs(tmp_path, capsys):
    code = main(
        ["run", "--scenarios", str(SCENARIO_DIR), "--runs", "2", "--out", str(tmp_path)]
    )
    assert code == 0
    data = json.loads((tmp_path / "L0-mock-gullible.json").read_text(encoding="utf-8"))
    assert len(data) == len(SCENARIOS) * 2
    assert (tmp_path / "L0-mock-gullible.md").exists()
    assert "Overall attack success rate" in capsys.readouterr().out


def test_cli_all_layers_writes_comparison(tmp_path, capsys):
    code = main(
        ["run", "--defense", "all", "--runs", "1", "--out", str(tmp_path),
         "--scenarios", str(SCENARIO_DIR)]
    )
    assert code == 0
    for layer in DEFENSES:
        assert (tmp_path / f"{layer}-mock-gullible.json").exists()
    assert "Defense comparison" in (tmp_path / "comparison-mock-gullible.md").read_text(
        encoding="utf-8"
    )
    assert "Defense comparison" in capsys.readouterr().out


def test_cli_only_filters_scenarios(tmp_path):
    code = main(
        ["run", "--only", "S001, b001", "--runs", "1", "--out", str(tmp_path),
         "--scenarios", str(SCENARIO_DIR)]
    )
    assert code == 0
    data = json.loads((tmp_path / "L0-mock-gullible.json").read_text(encoding="utf-8"))
    assert {row["scenario_id"] for row in data} == {"S001", "B001"}


def test_cli_list(capsys):
    assert main(["list", "--scenarios", str(SCENARIO_DIR)]) == 0
    assert "S001" in capsys.readouterr().out
    assert main(["list", "--scenarios", str(SCENARIO_DIR), "--markdown"]) == 0
    assert "| ID | Type |" in capsys.readouterr().out


def test_cli_reports_bad_input_without_traceback(capsys):
    assert main(["run", "--scenarios", "nope", "--runs", "1"]) == 1
    assert "error:" in capsys.readouterr().err
    assert main(["run", "--scenarios", str(SCENARIO_DIR), "--defense", "L99"]) == 1
    assert main(["run", "--scenarios", str(SCENARIO_DIR), "--only", "S999"]) == 1
    assert "Unknown scenario" in capsys.readouterr().err


def test_reports_include_the_hijacked_column():
    from agent_gauntlet.report import summarise, to_markdown

    scenarios = [s for s in SCENARIOS if s.id in ("S001", "B001")]
    results = run_suite(scenarios, MockLLM(gullible=True), get_defense("L0"), runs=1)
    summary = summarise(results, scenarios)
    assert summary.overall_hijack_rate == 1.0  # the gullible mock falls for S001
    assert "Model hijacked" in to_markdown(summary, "L0", "mock", 1)
    assert "attack_hijacked" in results[0].to_dict()


def test_layers_can_be_run_separately_then_compared(tmp_path, capsys):
    out = str(tmp_path)
    for layers in ("L0,L1", "L2"):
        code = main(["run", "--llm", "mock-gullible", "--defense", layers, "--runs", "1",
                     "--out", out])
        assert code == 0
    capsys.readouterr()
    assert main(["compare", "--llm", "mock-gullible", "--out", out]) == 0
    text = (tmp_path / "comparison-mock-gullible.md").read_text(encoding="utf-8")
    assert "| L0 |" in text and "| L1 |" in text and "| L2 |" in text
    assert "| L3 |" not in text


def test_compare_needs_two_saved_layers(tmp_path, capsys):
    assert main(["compare", "--llm", "mock-gullible", "--out", str(tmp_path)]) == 1
    assert "at least two layers" in capsys.readouterr().err


def test_ollama_retries_a_timeout_once_and_caps_output(monkeypatch):
    import httpx

    from agent_gauntlet.llm import OllamaClient

    seen = []

    class Reply:
        status_code = 200
        text = ""

        def json(self):
            return {"message": {"content": "ok"}}

    def fake_post(url, json, timeout):
        seen.append(json)
        if len(seen) == 1:
            raise httpx.ReadTimeout("slow")
        return Reply()

    monkeypatch.setattr(httpx, "post", fake_post)
    response = OllamaClient(max_tokens=100).chat([{"role": "user", "content": "hi"}], [])
    assert response.content == "ok"
    assert len(seen) == 2
    assert seen[0]["options"]["num_predict"] == 100


def test_ollama_gives_up_after_the_retry(monkeypatch):
    import httpx
    import pytest

    from agent_gauntlet.llm import OllamaClient

    def always_slow(url, json, timeout):
        raise httpx.ReadTimeout("slow")

    monkeypatch.setattr(httpx, "post", always_slow)
    with pytest.raises(RuntimeError, match="already saved"):
        OllamaClient().chat([{"role": "user", "content": "hi"}], [])
