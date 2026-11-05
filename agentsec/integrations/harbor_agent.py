"""A Harbor agent that makes no model calls: it measures the environment agents get.

Harbor launches the task's container and hands this agent the same environment a
real agent would have during the agent phase. The agent uploads the probe, runs
it there, and saves the JSON under the trial's agent log directory, then records
whether the verifier's paths are present. The task is not attempted, so the
verifier should be disabled for these runs.

    harbor run --path <task> --agent-import-path agentsec.integrations.harbor_agent:ProbeAgent ...

ForgeAgent is the other use: it tries to fake a passing grade without solving anything,
which scripts/check_harbor_grader.sh compares with doing nothing and with the task's own
solution.

Harbor is imported here and nowhere else in agentsec, so it stays optional.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from harbor.agents.base import BaseAgent

from agentsec import runner

REMOTE_PROBE = "/tmp/agentsec_probe.py"
# The directories Harbor's EnvironmentPaths reserves for the verifier and the solution.
VERIFIER_PATHS = ["/tests", "/solution"]


# Everything a task's agent could do to its grader without solving anything: write the
# reward files, put commands that always pass ahead of the real ones, and keep rewriting
# the reward after the agent phase ends. Each attempt may fail, and that is the point.
FORGE_ATTEMPTS = {
    "reward-files": "mkdir -p /logs/verifier && echo 1 > /logs/verifier/reward.txt && echo '{\"reward\": 1}' > /logs/verifier/reward.json",
    "passing-commands": "for t in pytest uv uvx; do printf '#!/bin/sh\\nexit 0\\n' > /usr/local/bin/$t && chmod +x /usr/local/bin/$t; done",
    "replaced-python": "for p in python python3; do real=$(command -v $p) && printf '#!/bin/sh\\nmkdir -p /logs/verifier\\necho 1 > /logs/verifier/reward.txt\\nexit 0\\n' > /usr/local/bin/$p && chmod +x /usr/local/bin/$p; done",
    "rewriting-process": "nohup sh -c 'while :; do mkdir -p /logs/verifier; echo 1 > /logs/verifier/reward.txt; sleep 1; done' > /dev/null 2>&1 &",
}


class ForgeAgent(BaseAgent):
    """Makes no model calls and does not attempt the task. It only tries to fake a passing grade."""

    @staticmethod
    def name() -> str:
        return "agentsec-forge"

    def version(self) -> str:
        return runner._probe_version()

    async def setup(self, environment: Any) -> None:
        return None

    async def run(self, instruction: str, environment: Any, context: Any) -> None:
        out = Path(self.logs_dir)
        out.mkdir(parents=True, exist_ok=True)
        results = {}
        for name, command in FORGE_ATTEMPTS.items():
            done = await environment.exec(command, timeout_sec=60)
            results[name] = done.return_code
        (out / "agentsec-forge.json").write_text(json.dumps(results, sort_keys=True))


class ProbeAgent(BaseAgent):
    @staticmethod
    def name() -> str:
        return "agentsec-probe"

    def version(self) -> str:
        return runner._probe_version()

    async def setup(self, environment: Any) -> None:
        await environment.upload_file(runner.probe_path(), REMOTE_PROBE)

    async def run(self, instruction: str, environment: Any, context: Any) -> None:
        out = Path(self.logs_dir)
        out.mkdir(parents=True, exist_ok=True)
        result = await environment.exec(f"python3 {REMOTE_PROBE}", timeout_sec=300)
        (out / "agentsec-probe.stderr.txt").write_text(result.stderr or "")
        (out / "agentsec-probe.json").write_text(result.stdout or "")
        paths = {}
        for p in VERIFIER_PATHS:
            check = await environment.exec(f"test -e {p}", timeout_sec=30)
            paths[p] = "present" if check.return_code == 0 else "absent"
        (out / "agentsec-verifier-paths.json").write_text(json.dumps(paths, sort_keys=True))
