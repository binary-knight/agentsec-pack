"""Launch the blast-radius probe under a target and collect its JSON.

Targets:
  * docker  : run the probe inside `docker run <flags> <image>`; the probe is
              bind-mounted read-only, so the image needs only python3.
  * command : run the probe via an arbitrary launcher template, e.g.
              "bwrap --ro-bind / / --dev /dev --unshare-net -- {probe}"
  * local   : run the probe in a plain subprocess (the no-sandbox baseline).

Every result records the exact target so a run can be reproduced.
"""
from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import time
from importlib import resources
from typing import Any

DEFAULT_TIMEOUT = 120


def probe_path() -> str:
    return str(resources.files("agentsec.probe").joinpath("blast_probe.py"))


def _run(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def _parse(stdout: str) -> dict[str, Any]:
    # The probe prints exactly one JSON line; tolerate leading noise from entrypoints.
    for line in reversed(stdout.strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            return json.loads(line)
    raise ValueError("probe produced no JSON (stdout was %r)" % stdout[-500:])


def run_local(timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    rc, out, err = _run([sys.executable, probe_path()], timeout)
    return {"target": {"kind": "local", "python": sys.executable}, "rc": rc, "stderr": err[-2000:], "probe": _parse(out)}


def run_docker(image: str, docker_flags: list[str] | None = None, python: str = "python3",
               timeout: int = DEFAULT_TIMEOUT, docker_bin: str = "docker") -> dict[str, Any]:
    flags = list(docker_flags or [])
    probe = probe_path()
    mount = f"{probe}:/agentsec_probe.py:ro"
    cmd = [docker_bin, "run", "--rm", "-v", mount] + flags + [image, python, "/agentsec_probe.py"]
    rc, out, err = _run(cmd, timeout)
    if rc != 0 and not out.strip():
        raise RuntimeError(f"docker run failed (rc={rc}): {err[-1000:]}")
    return {"target": {"kind": "docker", "image": image, "flags": flags, "python": python, "command": shlex.join(cmd)},
            "rc": rc, "stderr": err[-2000:], "probe": _parse(out)}


def run_command(template: str, timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """`template` must contain {probe}; it is split with shlex after substitution."""
    if "{probe}" not in template:
        raise ValueError("launcher template must contain {probe}")
    cmd = shlex.split(template.format(probe=shlex.quote(probe_path())))
    rc, out, err = _run(cmd, timeout)
    return {"target": {"kind": "command", "template": template, "command": shlex.join(cmd)}, "rc": rc, "stderr": err[-2000:], "probe": _parse(out)}


def result_envelope(run: dict[str, Any], summary: dict[str, Any], label: str | None = None) -> dict[str, Any]:
    return {"tool": "agentsec-pack", "test": "sandbox-blast-radius", "schema_version": 1, "label": label,
            "generated_at": int(time.time()), "target": run["target"], "rc": run["rc"], "summary": summary, "probe": run["probe"],
            "probe_stderr": run.get("stderr", "")}
