"""Integration: run the real probe in-process and assert it is non-exfiltrating."""
import json
import os
import re
import subprocess
import sys

import pytest

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


def _unix_sockets_refused():
    """True when this host refuses AF_UNIX socket() itself, as an agent sandbox can.

    The two controls below assert behaviour on an unsandboxed host. Run inside a
    sandbox with that filter, they observe the filter (correctly) and fail; that
    is the environment, not the probe. Skip on the observed capability, the
    same way the bwrap tests skip on whether bwrap can actually sandbox.
    """
    import socket as _s
    try:
        _s.socket(_s.AF_UNIX, _s.SOCK_STREAM).close()
        return False
    except PermissionError:
        return True


needs_unix_sockets = pytest.mark.skipif(_unix_sockets_refused(),
                                        reason="this host refuses AF_UNIX socket(); the control is for an unsandboxed host")


@needs_unix_sockets
def test_control_unix_socket_connects_on_a_normal_host():
    """The control must succeed where nothing is blocking it, or it proves nothing."""
    from agentsec.probe.blast_probe import _control_unix_socket
    r = _control_unix_socket()
    assert r["supported"] is True
    assert r["connected"] is True
    assert r["stage"] == "connect"


@needs_unix_sockets
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


def test_proxy_variables_are_reported_by_name_never_by_value():
    password = "PROXY-PASSWORD-MUST-NEVER-APPEAR-71c2"
    env = {k: v for k, v in os.environ.items() if k.upper() not in blast_probe.PROXY_ENV_NAMES}
    env.update(HTTPS_PROXY="http://u:%s@127.0.0.1:9" % password, http_proxy="http://127.0.0.1:9", ALL_PROXY="")
    out = subprocess.run([sys.executable, runner.probe_path()], capture_output=True, text=True, env=env, timeout=60).stdout
    assert password not in out
    data = json.loads(out.strip().splitlines()[-1])
    assert data["network"]["proxy_env"] == ["HTTPS_PROXY", "http_proxy"]  # empty ALL_PROXY is not a proxy


def test_proxy_names_ignore_unrelated_variables():
    assert blast_probe.proxy_env_names({"NO_PROXY": "localhost", "GRPC_PROXY": "x", "PROXY": "x"}) == []


# --- probe 0.3.0: agent credentials, readability by open, persistence --------

def _run_probe(env_overrides, cwd=None):
    env = dict(os.environ, **env_overrides)
    p = subprocess.run([sys.executable, runner.probe_path()], capture_output=True, text=True,
                       env=env, cwd=cwd, timeout=60)
    return p.stdout, json.loads(p.stdout.strip().splitlines()[-1])


def test_agent_credentials_are_found_and_readability_is_proven_by_opening(tmp_path):
    content = "TOKEN-CONTENT-MUST-NEVER-APPEAR-5b1e"
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "auth.json").write_text(content)
    (tmp_path / ".claude").mkdir()
    locked = tmp_path / ".claude" / ".credentials.json"
    locked.write_text(content)
    locked.chmod(0)
    try:
        out, data = _run_probe({"HOME": str(tmp_path)})
    finally:
        locked.chmod(0o600)
    assert content not in out, "a credential's contents must never reach the output"
    mine = {c["path"]: c for c in data["secrets"]["credential_files"] if c["via"] in ("HOME", "HOME+passwd")}
    assert mine["~/.codex/auth.json"]["readable"] is True
    if os.geteuid() != 0:  # root opens a mode-000 file; the check would prove nothing
        assert mine["~/.claude/.credentials.json"]["readable"] is False
        assert mine["~/.claude/.credentials.json"]["read_error"] == "EACCES"


def test_a_device_standing_in_for_a_file_is_masked_not_readable_or_writable():
    """Sandboxes hide files by bind-mounting /dev/null over them; opening that succeeds."""
    assert blast_probe._masked("/dev/null") is True
    assert blast_probe._masked(blast_probe.__file__) is False


def test_persistence_check_opens_existing_files_and_changes_nothing(tmp_path):
    home, proj = tmp_path / "home", tmp_path / "proj"
    home.mkdir()
    (proj / ".git" / "hooks").mkdir(parents=True)
    rc = home / ".bashrc"
    rc.write_text("# original\n")
    mcp = proj / ".mcp.json"
    mcp.write_text("{}\n")
    before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in (rc, mcp)}
    home_listing, hooks_listing = set(os.listdir(home)), set(os.listdir(proj / ".git" / "hooks"))

    _out, data = _run_probe({"HOME": str(home)}, cwd=str(proj))

    for p, (content, mtime) in before.items():
        assert p.read_bytes() == content and p.stat().st_mtime_ns == mtime, f"{p} was modified"
    assert not (home / ".zshrc").exists(), "a missing file must never be created"
    assert set(os.listdir(home)) == home_listing and set(os.listdir(proj / ".git" / "hooks")) == hooks_listing
    got = {(e["path"], e["via"]): e for e in data["filesystem"]["persistence"]}
    if os.access(str(home), os.W_OK):  # skipped inside a sandbox that already denies this
        assert got[("~/.bashrc", "HOME")]["writable"] is True
        assert got[("~", "HOME")]["writable"] is True
        assert got[("./.mcp.json", "cwd")]["kind"] == "agent-config"
        assert got[("./.git/hooks", "cwd")]["writable"] is True
    for e in data["filesystem"]["persistence"]:
        assert str(tmp_path) not in e["path"], "paths are reported in ~ / ./ form"


def test_mountinfo_resolves_the_longest_mount_and_unescapes_spaces():
    text = ("22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n"
            "40 22 0:5 / /root rw - overlay overlay rw\n"
            "41 22 8:1 /x /srv/a\\040b rw - tmpfs tmpfs rw\n")
    m = blast_probe.parse_mountinfo(text)
    assert ("/srv/a b", "tmpfs") in m
    assert blast_probe.fstype_of("/root/.bashrc", m) == "overlay"
    assert blast_probe.fstype_of("/srv/a b/.zshrc", m) == "tmpfs"
    assert blast_probe.fstype_of("/srv/ab/.zshrc", m) == "ext4", "a prefix that is not a path component must not match"


def test_rootless_and_desktop_sockets_are_looked_for_whatever_the_environment_says(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    shown = {(c[0], c[3]) for c in blast_probe._socket_candidates()}
    assert ("$XDG_RUNTIME_DIR/podman/podman.sock", "XDG_RUNTIME_DIR") in shown
    assert "~/.docker/desktop/docker.sock" in {s for s, _ in shown}
    monkeypatch.delenv("XDG_RUNTIME_DIR")
    if os.path.isdir("/run/user/%d" % os.getuid()):
        shown = {(c[0], c[3]) for c in blast_probe._socket_candidates()}
        assert ("$XDG_RUNTIME_DIR/docker.sock", "uid") in shown, "clearing the variable must not hide the socket"


@needs_unix_sockets
def test_a_forwarded_ssh_agent_is_proven_reachable_and_reported_without_its_path(tmp_path):
    import socket as _s
    import tempfile as _tf
    # macOS caps a unix socket path at 104 bytes, and pytest's tmp_path is longer.
    path = os.path.join(_tf.mkdtemp(prefix="asa", dir="/tmp"), "a.sock")
    srv = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
    srv.bind(path)
    srv.listen(1)
    try:
        out, data = _run_probe({"SSH_AUTH_SOCK": path})
    finally:
        srv.close()
    assert path not in out, "the agent socket's real path can carry a username"
    ssh = [s for s in data["secrets"]["container_sockets"] if s["kind"] == "ssh-agent"]
    assert ssh and ssh[0]["path"] == "$SSH_AUTH_SOCK" and ssh[0]["connected"] is True


# --- probe 0.4.0: egress measured through the configured proxy ---------------

import base64 as _b64
import socket as _socket
import threading as _threading


class _FakeProxy:
    """A loopback HTTP proxy that records every request and answers CONNECT
    with 200 for allowed hosts, 407 when it wants credentials, 403 otherwise."""

    def __init__(self, allowed=(), password=None):
        self.allowed, self.password, self.requests = set(allowed), password, []
        self.sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._t = _threading.Thread(target=self._serve, daemon=True)
        self._t.start()

    def _serve(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            with c:
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = c.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                text = data.decode("latin-1")
                self.requests.append(text)
                host = text.split()[1].rsplit(":", 1)[0] if text.startswith("CONNECT ") else ""
                if self.password is not None:
                    want = "Proxy-Authorization: Basic " + _b64.b64encode(("u:" + self.password).encode()).decode()
                    if want not in text:
                        c.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                        continue
                c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n" if host in self.allowed
                          else b"HTTP/1.1 403 Forbidden\r\n\r\n")

    def close(self):
        self.sock.close()


def _fixed_connects():
    return {"%s:%d" % (t["host"], t["port"]) for t in
            blast_probe.EGRESS_TARGETS + blast_probe.METADATA_TARGETS + [blast_probe.PROXY_CANARY]}


def test_the_canary_is_a_fixed_named_host():
    assert blast_probe.PROXY_CANARY == {"name": "canary-example.com", "host": "example.com", "port": 443}


def test_without_opt_in_the_proxy_gets_connect_lines_and_never_the_password():
    pw = "PROXY-PW-NEVER-SENT-WITHOUT-OPT-IN-3c9a"
    px = _FakeProxy(allowed={"github.com"}, password=pw)
    try:
        r = blast_probe.probe_proxy({"HTTPS_PROXY": "http://u:%s@127.0.0.1:%d" % (pw, px.port)})
    finally:
        px.close()
    assert r["measured"] and r["auth"] == "available, not used"
    assert {t["status"] for t in r["targets"]} == {407}
    for req in px.requests:
        lines = [l for l in req.split("\r\n") if l]
        assert lines[0].startswith("CONNECT ") and lines[0].endswith(" HTTP/1.1"), lines
        assert lines[0].split()[1] in _fixed_connects(), "only the fixed targets and the canary"
        assert [l.split(":", 1)[0] for l in lines[1:]] == ["Host"], "nothing but the request line and Host"
        assert pw not in req


def test_with_opt_in_the_password_goes_to_that_proxy_and_nowhere_in_the_output():
    pw = "PROXY-PW-NEVER-RECORDED-81d4"
    px = _FakeProxy(allowed={"github.com"}, password=pw)
    try:
        r = blast_probe.probe_proxy({"HTTPS_PROXY": "http://u:%s@127.0.0.1:%d" % (pw, px.port),
                                     blast_probe.PROXY_AUTH_OPT_IN: "1"})
    finally:
        px.close()
    dumped = json.dumps(r)
    assert pw not in dumped and "127.0.0.1" not in dumped, "neither the password nor the proxy's address is recorded"
    assert r["auth"] == "used" and r["proxy_loopback"] is True
    status = {t["host"]: t.get("status") for t in r["targets"]}
    assert status["github.com"] == 200 and status["example.com"] == 403


def test_no_proxy_entries_are_left_to_the_direct_test():
    px = _FakeProxy()
    try:
        r = blast_probe.probe_proxy({"HTTPS_PROXY": "http://127.0.0.1:%d" % px.port,
                                     "NO_PROXY": "localhost,169.254.0.0/16,.google.internal"})
    finally:
        px.close()
    bypassed = {t["host"] for t in r["targets"] if t.get("bypassed")}
    assert bypassed == {"169.254.169.254", "metadata.google.internal"}
    assert not any(req.split()[1].startswith(("169.254.", "metadata.")) for req in px.requests)


def test_a_socks_proxy_is_reported_as_not_measured():
    r = blast_probe.probe_proxy({"ALL_PROXY": "socks5h://127.0.0.1:1080"})
    assert r["measured"] is False and "socks5h" in r["reason"]


def test_the_full_probe_never_prints_the_proxy_password(tmp_path):
    pw = "PROXY-PW-FULL-RUN-NEVER-PRINTED-27ee"
    px = _FakeProxy(password=pw)
    try:
        env = {k: v for k, v in os.environ.items() if k.upper() not in blast_probe.PROXY_ENV_NAMES}
        env.update(HTTPS_PROXY="http://u:%s@127.0.0.1:%d" % (pw, px.port), AGENTSEC_PROBE_PROXY_AUTH="1")
        out = subprocess.run([sys.executable, runner.probe_path()], capture_output=True, text=True,
                             env=env, timeout=120).stdout
    finally:
        px.close()
    assert pw not in out
    assert json.loads(out.strip().splitlines()[-1])["network"]["proxy"]["auth"] == "used"


# --- macOS: run on the macos-latest leg of CI ----------------------------------

macos_only = pytest.mark.skipif(sys.platform != "darwin", reason="macOS-specific probe paths")


@macos_only
def test_macos_reports_seatbelt_and_process_visibility_from_the_kernel():
    _out, data = _run_probe({})
    assert data["platform"] == "darwin"
    assert data["identity"]["seatbelt"] == 0, "a plain test process runs under no Seatbelt profile"
    assert data["process"]["method"] == "sysctl(KERN_PROC_ALL)"
    assert data["process"]["visible_pid_count"] > 1
    assert data["filesystem"]["root_rw"] is False, "the macOS system volume is sealed read-only"
    assert data["network"]["interfaces"], "interfaces come from if_nameindex when /sys is absent"


@macos_only
def test_macos_sandbox_exec_is_seen_as_seatbelt():
    import shutil
    if not shutil.which("sandbox-exec"):
        pytest.skip("sandbox-exec not present")
    p = subprocess.run(["sandbox-exec", "-p", "(version 1)(allow default)", sys.executable, runner.probe_path()],
                       capture_output=True, text=True, timeout=120)
    data = json.loads(p.stdout.strip().splitlines()[-1])
    assert data["identity"]["seatbelt"] == 1
