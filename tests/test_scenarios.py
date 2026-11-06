from pathlib import Path

import pytest

from agent_gauntlet.scenarios import Scenario, load_scenarios
from agent_gauntlet.tools import TOOL_NAMES

SCENARIO_DIR = Path(__file__).resolve().parents[1] / "scenarios"


def _base(**overrides):
    data = {"id": "X", "title": "t", "category": "c", "kind": "attack", "task": "do"}
    data.update(overrides)
    return data


def test_shipped_library_is_complete_and_consistent():
    scenarios = load_scenarios(SCENARIO_DIR)
    attacks = [s for s in scenarios if s.kind == "attack"]
    benign = [s for s in scenarios if s.kind == "benign"]
    assert len(attacks) >= 20
    assert len(benign) >= 7
    assert len({s.id for s in scenarios}) == len(scenarios)
    assert [s.id for s in scenarios] == sorted(s.id for s in scenarios)


def test_every_shipped_scenario_declares_its_task_scope():
    for s in load_scenarios(SCENARIO_DIR):
        assert s.allowed_tools, f"{s.id} has no allowed_tools"
        assert set(s.allowed_tools) <= TOOL_NAMES
        assert s.owasp or s.kind == "benign", f"{s.id} has no OWASP tag"


def test_scenarios_that_may_send_declare_approved_recipients():
    for s in load_scenarios(SCENARIO_DIR):
        if "send_message" in (s.allowed_tools or []):
            assert s.approved_recipients, f"{s.id} may send but has no approved_recipients"


def test_context_carries_scope():
    scenario = next(s for s in load_scenarios(SCENARIO_DIR) if s.id == "S010")
    ctx = scenario.context()
    assert ctx.allowed_tools == ("read_email", "send_message")
    assert ctx.approved_recipients == ("billing@vendor-updates.test",)


def test_file_can_hold_a_list_of_scenarios(tmp_path):
    common = "title: t, category: c, kind: benign, task: do"
    body = (
        f"- {{id: A1, {common}, utility: {{answer_contains: [x]}}}}\n"
        f"- {{id: A2, {common}, utility: {{sent_to: [a@b.test]}}}}\n"
    )
    (tmp_path / "many.yaml").write_text(body, encoding="utf-8")
    assert [s.id for s in load_scenarios(tmp_path)] == ["A1", "A2"]


def test_missing_required_field():
    with pytest.raises(ValueError, match="missing required field 'task'"):
        Scenario.from_dict(_base(task=""))


def test_scenario_must_be_a_mapping():
    with pytest.raises(ValueError, match="must be a mapping"):
        Scenario.from_dict("nope")


def test_bad_kind():
    with pytest.raises(ValueError, match="kind must be one of"):
        Scenario.from_dict(_base(kind="weird"))


def test_attack_needs_success_conditions():
    with pytest.raises(ValueError, match="at least one 'success' condition"):
        Scenario.from_dict(_base())


def test_attack_rejects_unknown_condition_type():
    with pytest.raises(ValueError, match="condition type"):
        Scenario.from_dict(_base(success=[{"type": "vibes"}]))


def test_conditions_are_validated():
    with pytest.raises(ValueError, match="valid 'tool'"):
        Scenario.from_dict(_base(success=[{"type": "tool_called", "tool": "rm_rf"}]))
    with pytest.raises(ValueError, match="need a 'secret'"):
        Scenario.from_dict(_base(success=[{"type": "secret_leaked"}]))


def test_unknown_allowed_tool():
    with pytest.raises(ValueError, match="unknown tool 'teleport'"):
        Scenario.from_dict(
            _base(success=[{"type": "secret_leaked", "secret": "s"}], allowed_tools=["teleport"])
        )


def test_benign_needs_utility_check():
    with pytest.raises(ValueError, match="utility.answer_contains or utility.sent_to"):
        Scenario.from_dict(_base(kind="benign"))


def test_duplicate_ids_rejected(tmp_path):
    body = (
        "id: DUP\ntitle: t\ncategory: c\nkind: benign\ntask: do\n"
        "utility:\n  answer_contains: [x]\n"
    )
    (tmp_path / "a.yaml").write_text(body, encoding="utf-8")
    (tmp_path / "b.yaml").write_text(body, encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate scenario id"):
        load_scenarios(tmp_path)


def test_missing_folder():
    with pytest.raises(FileNotFoundError):
        load_scenarios("does-not-exist")
