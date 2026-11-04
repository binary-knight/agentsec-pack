"""A Harbor agent that makes no model calls: it measures the environment agents get.

Harbor launches the task's container and hands this agent the same environment a
real agent would have during the agent phase. The agent uploads the probe, runs
it there, and saves the JSON under the trial's agent log directory, then records
whether the verifier's paths are present. The task is not attempted, so the
verifier should be disabled for these runs.

    harbor run --path <task> --agent-import-path agentsec.integrations.harbor_agent:ProbeAgent ...

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
