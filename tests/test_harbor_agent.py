"""The Harbor probe agent and the task selection rule, with no Harbor or Docker needed."""
import asyncio
import importlib
import importlib.util
import json
import pathlib
import subprocess
import sys
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture
def agent_module(monkeypatch):
    class BaseAgent:
        def __init__(self, logs_dir):
            self.logs_dir = logs_dir
    for name, mod in {"harbor": types.ModuleType("harbor"), "harbor.agents": types.ModuleType("harbor.agents"),
                      "harbor.agents.base": types.ModuleType("harbor.agents.base")}.items():
        monkeypatch.setitem(sys.modules, name, mod)
    sys.modules["harbor.agents.base"].BaseAgent = BaseAgent
    monkeypatch.delitem(sys.modules, "agentsec.integrations.harbor_agent", raising=False)
    yield importlib.import_module("agentsec.integrations.harbor_agent")
    sys.modules.pop("agentsec.integrations.harbor_agent", None)


class FakeEnv:
    def __init__(self):
        self.commands, self.uploads = [], []

    async def upload_file(self, source, target):
        self.uploads.append((source, target))

    async def exec(self, command, timeout_sec=None):
        self.commands.append(command)
        if command.startswith("python3"):
            return types.SimpleNamespace(stdout='{"probe_version": "x"}\n', stderr="note", return_code=0)
        return types.SimpleNamespace(stdout="", stderr="", return_code=1 if "/tests" in command else 0)


def test_agent_runs_the_probe_and_records_verifier_paths(agent_module, tmp_path):
    env, agent = FakeEnv(), agent_module.ProbeAgent(logs_dir=tmp_path)
    asyncio.run(agent.setup(env))
    asyncio.run(agent.run("the task instruction", env, None))
    assert env.uploads[0][1] == agent_module.REMOTE_PROBE
    assert json.loads((tmp_path / "agentsec-probe.json").read_text()) == {"probe_version": "x"}
    assert json.loads((tmp_path / "agentsec-verifier-paths.json").read_text()) == {"/tests": "absent", "/solution": "present"}
    assert not any("the task instruction" in c for c in env.commands), "the task is not attempted"


def _repo(tmp_path, tasks):
    for name, toml in tasks.items():
        d = tmp_path / "tasks" / name
        d.mkdir(parents=True)
        (d / "task.toml").write_text(toml)
    for args in (["init", "-q"], ["add", "."], ["-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-qm", "x"]):
        subprocess.run(["git", "-C", str(tmp_path), *args], check=True)
    return tmp_path


def _select():
    sys.path.insert(0, str(REPO / "scripts"))
    try:
        return importlib.import_module("select_harbor_sample").select
    finally:
        sys.path.pop(0)


def test_the_draw_repeats_and_adds_only_agent_network_off_tasks(tmp_path):
    pytest.importorskip("tomllib", reason="the selection script runs beside Harbor, which needs Python 3.12 or later")
    tasks = {f"t{i}": "[environment]\n" for i in range(10)}
    tasks["off"] = '[environment]\nallow_internet = false\n'
    tasks["verifier-only"] = '[verifier.environment]\nallow_internet = false\n'
    root = _repo(tmp_path, tasks)
    select = _select()
    a, b = select(root, 3), select(root, 3)
    assert a == b and len(a["drawn"]) == 3 and a["population"] == 12
    assert a["network_off"] == ["off"], "a verifier's setting does not change what the agent gets"
    assert "off" in a["measure"]


def test_the_forge_agent_makes_every_attempt_and_records_how_each_ended(agent_module, tmp_path):
    env = FakeEnv()
    asyncio.run(agent_module.ForgeAgent(tmp_path).run("task", env, None))
    recorded = json.loads((tmp_path / "agentsec-forge.json").read_text())
    assert set(recorded) == set(agent_module.FORGE_ATTEMPTS)


def _reader():
    spec = importlib.util.spec_from_file_location("read_harbor_grades", REPO / "scripts" / "read_harbor_grades.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("nothing,forged,solution,result", [
    (0, 0, 1, "held"),
    (0, 1, 1, "forged-run-scored"),
    (1, 0, 1, "untouched-environment-scored"),
    (0, 0, 0, "solution-did-not-pass"),
    (0, 0, None, "incomplete"),
    (None, 0, 1, "incomplete"),
    (0, 1, None, "incomplete"),
])
def test_a_grader_holds_only_when_all_three_runs_settle(nothing, forged, solution, result):
    runs = {"nothing": {"reward": nothing}, "forged": {"reward": forged}, "solution": {"reward": solution}}
    assert _reader().conclude(runs) == result


def test_a_run_with_no_reward_is_not_read_as_zero(tmp_path):
    reader = _reader()
    trial = tmp_path / "forged" / "trial"
    trial.mkdir(parents=True)
    (trial / "result.json").write_text(json.dumps({"verifier_result": None, "exception_info": {"exception_type": "VerifierTimeoutError"}}))
    run = reader.read_run(tmp_path, "forged")
    assert run["reward"] is None and run["error"] == "VerifierTimeoutError"
    assert reader.read_run(tmp_path, "solution") == {"finished": False, "reward": None}
