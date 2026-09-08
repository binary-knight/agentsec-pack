"""Integration: run the real probe in-process and assert it is non-exfiltrating."""
import json
import os
import subprocess
import sys

from agentsec import runner
from agentsec.probe import blast_probe
from agentsec.scoring import summarize


def test_probe_runs_locally_and_emits_json(tmp_path):
    run = runner.run_local(timeout=60)
    p = run["probe"]
    for k in ("identity", "network", "secrets", "filesystem", "process", "resources"):
        assert k in p and "error" not in p[k], p[k]
    summarize(p)  # must not raise


def test_probe_reports_secret_names_not_values(monkeypatch):
    secret_value = "sk-THIS-VALUE-MUST-NEVER-APPEAR-9f8e7d"
    env = dict(os.environ, AGENTSEC_TEST_API_KEY=secret_value)
    out = subprocess.run([sys.executable, runner.probe_path()], capture_output=True, text=True, env=env, timeout=60).stdout
    assert secret_value not in out
    data = json.loads(out.strip().splitlines()[-1])
    names = [e["name"] for e in data["secrets"]["env_secret_names"]]
    assert "AGENTSEC_TEST_API_KEY" in names
    hit = next(e for e in data["secrets"]["env_secret_names"] if e["name"] == "AGENTSEC_TEST_API_KEY")
    assert hit["length"] == len(secret_value)


def test_probe_leaves_no_files_behind(tmp_path):
    before = set(os.listdir("/tmp"))
    subprocess.run([sys.executable, runner.probe_path()], capture_output=True, text=True, timeout=60)
    after = set(os.listdir("/tmp"))
    assert not [f for f in after - before if f.startswith(".agentsec_probe_")]


def test_egress_target_list_is_fixed():
    hosts = {t["host"] for t in blast_probe.EGRESS_TARGETS + blast_probe.METADATA_TARGETS}
    assert hosts == {"dns.google", "pypi.org", "github.com", "1.1.1.1", "169.254.169.254", "metadata.google.internal"}
