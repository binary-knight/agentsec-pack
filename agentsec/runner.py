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

from . import presets

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


def image_digest(image: str, engine: str = "docker") -> str | None:
    """The image's repo digest, so a published score stays reproducible when the tag moves."""
    try:
        p = subprocess.run([engine, "image", "inspect", image, "--format", "{{index .RepoDigests 0}}"],
                           capture_output=True, text=True, timeout=30)
    except Exception:
        return None
    d = p.stdout.strip()
    return d or None


def run_container(image: str, flags: list[str] | None = None, engine: str = "docker",
                  python: str = "python3", timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Run the probe inside `engine run <flags> <image>`. engine is docker or podman."""
    flags = list(flags or [])
    mount = f"{probe_path()}:/agentsec_probe.py:ro"
    cmd = [engine, "run", "--rm", "-v", mount] + flags + [image, python, "/agentsec_probe.py"]
    rc, out, err = _run(cmd, timeout)
    if rc != 0 and not out.strip():
        raise RuntimeError(f"{engine} run failed (rc={rc}): {err[-1000:]}")
    shown = [engine, "run", "--rm", "-v", "<agentsec probe>:/agentsec_probe.py:ro"] + flags + [image, python, "/agentsec_probe.py"]
    return {"target": {"kind": "container", "engine": engine, "image": image, "digest": image_digest(image, engine),
                       "flags": flags, "python": python, "command": shlex.join(shown)},
            "rc": rc, "stderr": err[-2000:], "probe": _parse(out)}


def run_docker(image: str, docker_flags: list[str] | None = None, **kw) -> dict[str, Any]:
    """Backwards-compatible alias for run_container(engine="docker")."""
    return run_container(image, docker_flags, engine="docker", **kw)


def run_preset(name: str, image: str | None = None, timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Run a named preset. Container presets need an image; command presets ignore it."""
    p = presets.get(name)
    if not presets.available(p):
        raise RuntimeError(f"preset {name!r} needs {presets.requirement(p)!r} on PATH")
    if p["kind"] == "container":
        if not image:
            raise ValueError(f"preset {name!r} needs an image")
        run = run_container(image, p.get("flags"), engine=p.get("engine", "docker"), timeout=timeout)
    else:
        run = run_command(p["template"], timeout=timeout)
    run["target"]["preset"] = name
    run["target"]["preset_rationale"] = p.get("rationale", "")
    return run


def run_command(template: str, timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """`template` must contain {probe}; it is split with shlex after substitution."""
    if "{probe}" not in template:
        raise ValueError("launcher template must contain {probe}")
    cmd = shlex.split(template.format(probe=shlex.quote(probe_path())))
    rc, out, err = _run(cmd, timeout)
    return {"target": {"kind": "command", "template": template, "command": template.replace("{probe}", "<agentsec probe>")}, "rc": rc, "stderr": err[-2000:], "probe": _parse(out)}


def result_envelope(run: dict[str, Any], summary: dict[str, Any], label: str | None = None) -> dict[str, Any]:
    return {"tool": "agentsec-pack", "test": "sandbox-blast-radius", "schema_version": 1, "label": label,
            "generated_at": int(time.time()), "target": run["target"], "rc": run["rc"], "summary": summary, "probe": run["probe"],
            "probe_stderr": run.get("stderr", "")}


def _probe_version() -> str:
    for line in open(probe_path()):
        if line.startswith("PROBE_VERSION"):
            return line.split("=")[1].strip().strip('"\'')
    return "unknown"
