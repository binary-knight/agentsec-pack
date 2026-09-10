"""Integration: run the real probe in-process and assert it is non-exfiltrating."""
import json
import os
import re
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


def _matches(name):
    import re
    from agentsec.probe.blast_probe import SECRET_ENV_PATTERNS
    return any(re.search(p, name, re.IGNORECASE) for p in SECRET_ENV_PATTERNS)


def test_secret_env_matcher_flags_real_secret_names():
    for name in ["GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
                 "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "HF_TOKEN", "NPM_TOKEN",
                 "CLAUDE_CODE_MESSAGING_TOKEN", "PGPASSWORD", "MYSQL_PWD",
                 "SSH_KEY", "JWT_SECRET", "GH_PAT"]:
        assert _matches(name), name


def test_secret_env_matcher_ignores_names_that_carry_nothing():
    """A vendor prefix or a substring hit is not a secret. These inflated scores."""
    for name in ["GH_PAGER", "GH_HOST", "AWS_REGION", "AWS_DEFAULT_REGION",
                 "GOOGLE_APPLICATION_NAME", "TOKENIZERS_PARALLELISM", "PATH",
                 "KUBECONFIG_DIR", "DOCKER_HOST", "SESSION_MANAGER",
                 "KEYBOARD_LAYOUT", "OPENAI_BASE_URL", "GPG_KEY"]:
        assert not _matches(name), name


def test_no_file_in_the_repo_carries_an_operator_identity():
    """A path or username in a committed file is how a private repo leaks on the
    day it goes public. This has happened twice here, so it is pinned."""
    import subprocess
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tracked = subprocess.run(["git", "-C", root, "ls-files"],
                             capture_output=True, text=True).stdout.split()
    bad = []
    for rel in tracked:
        path = os.path.join(root, rel)
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except OSError:
            continue
        for m in re.finditer(r"/(?:home|Users)/([A-Za-z0-9_.-]+)", text):
            # the probe's own list of paths to check is not an operator identity
            if m.group(1) in ("<redacted>", "USER", "user"):
                continue
            bad.append(f"{rel}: {m.group(0)}")
    assert not bad, "operator paths in tracked files:\n" + "\n".join(bad[:10])


# --- concealment resistance -------------------------------------------------
# Reported by the supervisor session after a real use test: pointing $HOME at an
# empty directory cleared SEC-003 and dropped the score fifteen points while
# every one of those files stayed readable at its real path. A score that can be
# lowered by hiding rather than fixing is worse than no score.

def _probe_with_home(home):
    env = dict(os.environ, HOME=home)
    out = subprocess.run([sys.executable, blast_probe.__file__],
                         capture_output=True, text=True, env=env).stdout
    return json.loads(out.strip().splitlines()[-1])


def test_redirecting_HOME_does_not_hide_credentials_that_are_still_readable(tmp_path):
    import pwd
    try:
        pw_home = pwd.getpwuid(os.getuid()).pw_dir
    except KeyError:
        import pytest
        pytest.skip("this uid has no passwd entry, so there is no second home to check")

    real = _probe_with_home(pw_home)
    real_creds = [c["path"] for c in real["secrets"]["credential_files"] if c.get("readable")]
    if not real_creds:
        import pytest
        pytest.skip("no readable credential files here, so there is nothing to conceal")

    hidden = _probe_with_home(str(tmp_path))
    hidden_creds = [c["path"] for c in hidden["secrets"]["credential_files"] if c.get("readable")]

    assert set(real_creds) <= set(hidden_creds), (
        "pointing HOME at an empty directory hid credential files that are still readable")
    assert hidden["secrets"]["home_env_matches_passwd"] is False
    assert any(c.get("via") == "passwd" for c in hidden["secrets"]["credential_files"]), (
        "the passwd home must be consulted, because $HOME can be set by anything inside the sandbox")


def test_the_score_does_not_fall_when_HOME_is_redirected(tmp_path):
    import pwd
    try:
        pw_home = pwd.getpwuid(os.getuid()).pw_dir
    except KeyError:
        import pytest
        pytest.skip("no passwd entry for this uid")
    real = summarize(_probe_with_home(pw_home))
    hidden = summarize(_probe_with_home(str(tmp_path)))
    assert hidden["score"] >= real["score"], (
        f"concealment lowered the score from {real['score']} to {hidden['score']}")


def test_a_redirected_HOME_is_reported_but_not_scored_against_the_operator(tmp_path):
    """Redirecting HOME is a real hardening technique. The bug was that it hid
    reachable files, not that anyone does it."""
    from agentsec.scoring import analyze
    hidden = _probe_with_home(str(tmp_path))
    ids = {f.id for f in analyze(hidden)}
    assert not any(i.startswith("SEC-00") and "home" in i.lower() for i in ids), (
        "a redirected HOME must not become a finding of its own")
    sec003 = [f for f in analyze(hidden) if f.id == "SEC-003"]
    if sec003:
        assert sec003[0].evidence.get("home_env_matches_passwd") is False
        assert "not containing them" in sec003[0].remediation


def test_credential_finding_says_it_reports_only_what_it_probed():
    """'Credential files readable' read as an exhaustive claim about reachability
    and was actually a statement about a fixed list."""
    from agentsec.scoring import analyze
    probe = json.loads(json.dumps(_probe_with_home(os.path.expanduser("~"))))
    for f in analyze(probe):
        if f.id == "SEC-003":
            assert "among those probed" in f.title
            assert "readable_of_those_probed" in f.evidence
            assert f.evidence.get("probed"), "say how many paths were tested"
