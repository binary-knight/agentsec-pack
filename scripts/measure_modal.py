#!/usr/bin/env python3
"""Measure what a process gets inside a Modal Sandbox, through Modal's own client.

    <python with the modal package> scripts/measure_modal.py <scratch dir>

Uses the Modal login already on this machine, in its own app, and terminates each sandbox
when its probe finishes. Each lasts a minute or so. The container holds no personal
credentials, so what it can read says nothing about a person's own account.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import modal

APP = "agentsec-measure"
PYTHON = "3.12"
PROBE_IN_SANDBOX = "/root/agentsec_probe.py"
LIMIT_SECONDS = 300
ALLOWED_DOMAIN = "pypi.org"
ALLOWED_CIDR = "1.1.1.1/32"
REPO = Path(__file__).resolve().parent.parent
CONFIGS = {
    "default": ({}, "no other options"),
    "block-network": ({"block_network": True}, "block_network=True"),
    "domain-allowlist": ({"outbound_domain_allowlist": [ALLOWED_DOMAIN]}, f"outbound_domain_allowlist=[{ALLOWED_DOMAIN}]"),
    "cidr-allowlist": ({"outbound_cidr_allowlist": [ALLOWED_CIDR]}, f"outbound_cidr_allowlist=[{ALLOWED_CIDR}]"),
}


def find_agentsec() -> str:
    local = REPO / ".venv" / "bin" / "agentsec"
    found = str(local) if local.exists() else shutil.which("agentsec")
    if not found:
        sys.exit("agentsec is not installed: run uv venv .venv && uv pip install -e . in this repository")
    return found


def measure(name: str, options: dict, differs: str, app: modal.App, image: modal.Image, scratch: Path, out: Path, agentsec: str) -> bool:
    print(f"== {name}", flush=True)
    sandbox = modal.Sandbox.create(app=app, image=image, timeout=LIMIT_SECONDS, **options)
    try:
        run = sandbox.exec("python3", PROBE_IN_SANDBOX, timeout=LIMIT_SECONDS - 30)
        report = run.stdout.read()
        errors = run.stderr.read()
        if run.wait() != 0:
            print(f"   the probe did not finish:\n{errors[-800:]}", flush=True)
            return False
    finally:
        sandbox.terminate()
    raw = scratch / f"{name}.json"
    raw.write_text(report)
    how = (f"modal client {modal.__version__}, modal.Sandbox.create with Image.debian_slim(python_version={PYTHON}), {differs}. "
           "The probe ran through Sandbox.exec, by scripts/measure_modal.py. No agent was involved, and the container holds no personal credentials. Modal runs this under gVisor, so privilege, capability, seccomp, /proc and resource findings describe gVisor's kernel, not the host's, and escaping gVisor was not tested.")
    return subprocess.run([agentsec, "score", str(raw), "--label", f"modal-sandbox-{name}", "--redact", "--out", str(out), "--how", how]).returncode in (0, 2)


def main() -> int:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    scratch = Path(sys.argv[1]).resolve()
    scratch.mkdir(parents=True, exist_ok=True)
    out = REPO / "examples" / "modal"
    out.mkdir(parents=True, exist_ok=True)
    agentsec = find_agentsec()
    app = modal.App.lookup(APP, create_if_missing=True)
    image = modal.Image.debian_slim(python_version=PYTHON).add_local_file(REPO / "agentsec" / "probe" / "blast_probe.py", PROBE_IN_SANDBOX, copy=True)
    results = {name: measure(name, options, differs, app, image, scratch, out, agentsec) for name, (options, differs) in CONFIGS.items()}
    print(f"reports: {out}")
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
