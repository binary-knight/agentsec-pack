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
    dirs = [d for d in blast_probe.WRITE_PROBE_DIRS if os.path.isdir(d) and os.access(d, os.W_OK)]
    before = {d: set(os.listdir(d)) for d in dirs}
    subprocess.run([sys.executable, runner.probe_path()], capture_output=True, text=True, timeout=60)
    for d in dirs:
        left = [f for f in set(os.listdir(d)) - before[d] if f.startswith(".agentsec_probe_")]
        assert not left, (d, left)


def test_egress_target_list_is_fixed():
    hosts = {t["host"] for t in blast_probe.EGRESS_TARGETS + blast_probe.METADATA_TARGETS}
    assert hosts == {"dns.google", "pypi.org", "github.com", "1.1.1.1", "169.254.169.254", "metadata.google.internal"}


def test_credential_paths_are_reported_unexpanded():
    """A published report must not carry the operator's home directory."""
    import json as _json
    out = subprocess.run([sys.executable, runner.probe_path()], capture_output=True, text=True, timeout=60).stdout
    data = _json.loads(out.strip().splitlines()[-1])
    home = os.path.expanduser("~")
    for c in data["secrets"]["credential_files"]:
        assert home not in c["path"], c["path"]


def test_socket_finding_proves_reachability_not_just_permissions():
    import json as _json
    out = subprocess.run([sys.executable, runner.probe_path()], capture_output=True, text=True, timeout=60).stdout
    data = _json.loads(out.strip().splitlines()[-1])
    for s in data["secrets"]["container_sockets"]:
        assert "connected" in s, s


def test_control_unix_socket_connects_on_a_normal_host():
    """The control must succeed where nothing is blocking it, or it proves nothing."""
    from agentsec.probe.blast_probe import _control_unix_socket
    r = _control_unix_socket()
    assert r["supported"] is True
    assert r["connected"] is True
    assert r["stage"] == "connect"


def test_control_nopath_reports_connect_permitted_on_a_normal_host():
    from agentsec.probe.blast_probe import _control_unix_connect_nonexistent
    r = _control_unix_connect_nonexistent()
    assert r["verdict"] == "connect permitted"
    assert r["error"] == "FileNotFoundError"


def test_control_leaves_no_directory_behind():
    import glob
    from agentsec.probe.blast_probe import _control_unix_socket
    before = set(glob.glob("/tmp/.agentsec_ctl_*"))
    _control_unix_socket()
    assert set(glob.glob("/tmp/.agentsec_ctl_*")) == before
