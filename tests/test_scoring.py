import json
import os

from agentsec.probe.blast_probe import decode_caps
from agentsec.scoring import analyze, score, summarize, load_owasp

HERE = os.path.dirname(__file__)


def load(name):
    with open(os.path.join(HERE, "fixtures", name)) as f:
        return json.load(f)


def test_decode_caps():
    assert decode_caps("0") == []
    assert decode_caps("0000000000200000") == ["CAP_SYS_ADMIN"]
    assert "CAP_CHOWN" in decode_caps("00000000a80425fb")


def test_open_sandbox_scores_high():
    s = summarize(load("probe_open.json"))
    ids = {f["id"] for f in s["findings"]}
    assert {"NET-001", "NET-002", "PRIV-001", "PRIV-003", "SEC-001", "SEC-002", "SEC-003", "FS-001", "FS-004"} <= ids
    assert "/etc/shadow" not in str(next(f for f in s["findings"] if f["id"] == "SEC-003")["evidence"])
    assert s["score"] == 100


def test_contained_sandbox_scores_zero():
    s = summarize(load("probe_contained.json"))
    assert s["findings"] == []
    assert s["score"] == 0


def test_score_discriminates():
    assert score(analyze(load("probe_open.json"))) > score(analyze(load("probe_contained.json")))


def test_every_finding_maps_to_known_owasp_ids():
    known = set(load_owasp())
    for f in analyze(load("probe_open.json")):
        assert f.owasp, f.id
        assert set(f.owasp) <= known, (f.id, f.owasp)


def _probe_with_sockets(control, nopath=None):
    return {
        "identity": {"uid": 1000, "capabilities": {"CapEff": []}, "seccomp_mode": 2},
        "network": {"targets": [], "interfaces": []},
        "filesystem": {},
        "secrets": {
            "container_sockets": [{"path": "/var/run/docker.sock", "writable": True,
                                   "connected": False, "connect_error": "PermissionError"}],
            "unix_control": control,
            "unix_control_nopath": nopath or {},
            "credential_files": [], "env_secret_names": [],
        },
        "process": {}, "resources": {},
    }


def _sec006(probe):
    from agentsec.scoring import analyze
    return [f for f in analyze(probe) if f.id == "SEC-006"][0]


def test_sec006_says_path_scoped_when_the_control_connects():
    f = _sec006(_probe_with_sockets({"supported": True, "connected": True, "stage": "connect"}))
    assert "specific to these paths" in f.remediation
    assert "wholesale" not in f.remediation


def test_sec006_says_wholesale_when_the_control_is_also_refused():
    f = _sec006(_probe_with_sockets({"supported": False, "connected": False,
                                     "stage": "bind", "error": "PermissionError"}))
    assert "wholesale" in f.remediation
    assert "bind" in f.remediation


def test_sec006_falls_back_to_the_nopath_control_when_there_is_no_writable_dir():
    f = _sec006(_probe_with_sockets(
        {"supported": False, "connected": False, "stage": "mkdtemp", "error": "OSError"},
        {"verdict": "connect refused before path lookup", "error": "PermissionError", "stage": "connect"}))
    assert "before the path is consulted" in f.remediation
    assert "unverified" not in f.remediation


def test_sec006_admits_it_does_not_know_when_both_controls_fail():
    f = _sec006(_probe_with_sockets(
        {"supported": False, "connected": False, "stage": "mkdtemp", "error": "OSError"},
        {"verdict": "inconclusive", "error": "OSError", "stage": "connect"}))
    assert "unverified" in f.remediation


def test_net003_fires_when_every_connection_is_refused_even_if_sockets_open():
    from agentsec.scoring import analyze
    probe = _probe_with_sockets({"supported": True, "connected": True, "stage": "connect"})
    probe["network"] = {"targets": [{"name": "dns-google", "connect": False, "resolve_error": "gaierror"}],
                        "interfaces": [], "socket_syscall_blocked": False, "connect_refused_all": True}
    ids = [f.id for f in analyze(probe)]
    assert "NET-003" in ids


def test_an_unrunnable_control_reports_unverified_and_never_a_silent_pass():
    """Requested by the supervisor session after a real use test, as the single
    behaviour that made the rest of the output trustworthy: when SEC-006's
    control cannot run, the report must say the containment claim is unverified
    rather than quietly treating it as contained."""
    f = _sec006(_probe_with_sockets(
        {"supported": False, "connected": False, "stage": "mkdtemp", "error": "OSError"},
        {"verdict": "inconclusive", "error": "OSError", "stage": "connect"}))
    assert "unverified" in f.remediation
    assert "not known" in f.remediation
    for phrase in ("contained", "containment holds", "no action"):
        assert phrase not in f.remediation.lower(), (
            f"an unverifiable control must not read as a pass ({phrase!r})")


# --- egress through a proxy the probe does not test through -----------------

def _refused_network(**extra):
    net = {"targets": [{"name": "github", "connect": False, "resolve_error": "gaierror"}],
           "interfaces": [], "socket_syscall_blocked": False, "connect_refused_all": True}
    net.update(extra)
    return {"network": net}


def test_a_configured_proxy_stops_refused_connections_reading_as_containment():
    """Measured under Claude Code's sandbox on 2026-11-03: with github.com on the
    proxy allowlist, curl through HTTPS_PROXY got a 200 while every direct
    connect the probe made was refused. NET-003 then said containment holds."""
    findings = analyze(_refused_network(proxy_env=["HTTPS_PROXY", "https_proxy"]))
    ids = [f.id for f in findings]
    assert "NET-003" not in ids
    f = next(f for f in findings if f.id == "NET-004")
    assert f.evidence["unmeasured"] is True
    assert f.evidence["proxy_env"] == ["HTTPS_PROXY", "https_proxy"]
    for phrase in ("containment holds", "no action"):
        assert phrase not in (f.title + f.remediation).lower()
    assert "unverified" in f.remediation


def test_net004_adds_no_points_because_no_reach_was_proven():
    """Unmeasured is not reachable. Scoring it would assert a connection nobody made."""
    assert score(analyze(_refused_network(proxy_env=["HTTPS_PROXY"]))) == score(analyze(_refused_network()))


def test_a_refused_socket_call_still_proves_containment_with_a_proxy_set():
    """If socket() itself is refused, the proxy cannot be reached either."""
    ids = [f.id for f in analyze(_refused_network(proxy_env=["HTTPS_PROXY"], socket_syscall_blocked=True))]
    assert "NET-003" in ids and "NET-004" not in ids


def test_a_probe_from_before_proxy_detection_scores_as_it_did():
    ids = [f.id for f in analyze(_refused_network())]
    assert "NET-003" in ids and "NET-004" not in ids


# --- probe 0.3.0 findings ----------------------------------------------------

def _sec(**secrets):
    base = {"unix_control": {"supported": True, "connected": True, "stage": "connect"}}
    base.update(secrets)
    return {"secrets": base}


def test_a_reachable_ssh_agent_is_high_and_never_mistaken_for_a_container_socket():
    f = {x.id: x for x in analyze(_sec(container_sockets=[
        {"path": "$SSH_AUTH_SOCK", "kind": "ssh-agent", "is_socket": True, "connected": True}]))}
    assert f["SEC-007"].severity == "high"
    assert "SEC-001" not in f and "SEC-006" not in f


def test_a_refused_ssh_agent_is_low_and_explains_the_refusal():
    f = {x.id: x for x in analyze(_sec(container_sockets=[
        {"path": "$SSH_AUTH_SOCK", "kind": "ssh-agent", "is_socket": True, "connected": False,
         "connect_error": "PermissionError"}]))}
    assert f["SEC-008"].severity == "low" and "path-scoped" in f["SEC-008"].remediation


def test_a_masked_socket_path_is_not_a_socket_finding():
    ids = [x.id for x in analyze(_sec(container_sockets=[
        {"path": "/var/run/docker.sock", "kind": "container", "is_socket": False, "masked": True, "connected": False}]))]
    assert not {"SEC-001", "SEC-006"} & set(ids)


def test_masked_credentials_are_not_counted_and_agent_credentials_are_named():
    f = {x.id: x for x in analyze(_sec(credential_files=[
        {"path": "~/.ssh/id_ed25519", "masked": True, "readable": False, "via": "HOME"},
        {"path": "~/.claude/.credentials.json", "readable": True, "via": "HOME"}]))}
    ev = f["SEC-003"].evidence
    assert ev["readable_of_those_probed"] == ["~/.claude/.credentials.json"]
    assert ev["agent_credentials"] == ["~/.claude/.credentials.json"]


def _fs(*entries):
    return {"filesystem": {"persistence": list(entries)}}


def test_writable_startup_files_on_the_host_are_a_way_out():
    f = {x.id: x for x in analyze(_fs({"path": "~/.bashrc", "kind": "shell-startup", "writable": True,
                                        "host_backed": True, "fstype": "ext4"}))}
    assert f["FS-008"].severity == "high"
    assert f["FS-008"].evidence["writable"][0]["fstype"] == "ext4", "the fstype is what makes the call checkable"


def test_a_writable_agent_config_is_its_own_finding():
    f = {x.id: x for x in analyze(_fs({"path": "./.claude/settings.json", "kind": "agent-config", "writable": True,
                                        "host_backed": True, "fstype": "ext4"}))}
    assert f["FS-009"].severity == "high" and "FS-008" not in f


def test_container_local_writes_are_informational_and_score_nothing():
    probe = _fs({"path": "~/.bashrc", "kind": "shell-startup", "writable": True, "host_backed": False, "fstype": "overlay"})
    f = {x.id: x for x in analyze(probe)}
    assert "FS-008" not in f and f["FS-010"].severity == "info"
    assert score(analyze(probe)) == score(analyze(_fs()))


def test_an_unresolved_mount_counts_rather_than_hides_a_write():
    ids = [x.id for x in analyze(_fs({"path": "~/.bashrc", "kind": "shell-startup", "writable": True,
                                      "host_backed": None, "fstype": None}))]
    assert "FS-008" in ids


def test_masked_or_refused_persistence_paths_are_not_findings():
    ids = [x.id for x in analyze(_fs(
        {"path": "./.mcp.json", "kind": "agent-config", "writable": True, "masked": True, "host_backed": False},
        {"path": "~/.bashrc", "kind": "shell-startup", "writable": False, "error": "EROFS", "host_backed": True}))]
    assert not {"FS-008", "FS-009", "FS-010"} & set(ids)


# --- probe 0.4.0: verdicts from the proxy ------------------------------------

def _proxied(statuses, canary=403, auth="used"):
    targets = [{"name": n, "host": h, "port": 443, "status": statuses.get(h, 403)}
               for n, h in (("dns-google", "dns.google"), ("pypi", "pypi.org"), ("github", "github.com"))]
    targets.append({"name": "gcp-metadata-hostname", "host": "metadata.google.internal", "port": 80,
                    "status": statuses.get("metadata.google.internal", 403)})
    targets.append({"name": "canary-example.com", "host": "example.com", "port": 443, "status": canary})
    return _refused_network(proxy_env=["HTTPS_PROXY"],
                            proxy={"configured": True, "measured": True, "source": "HTTPS_PROXY", "auth": auth,
                                   "targets": targets})


def test_a_proxy_that_refuses_everything_including_the_control_is_proven_containment():
    f = {x.id: x for x in analyze(_proxied({}))}
    assert "NET-003" in f and "NET-004" not in f
    assert "control" in f["NET-003"].evidence["detail"]


def test_a_proxy_that_accepts_the_control_forwards_anywhere():
    f = {x.id: x for x in analyze(_proxied({"github.com": 200}, canary=200))}
    assert f["NET-001"].severity == "high" and f["NET-001"].evidence["via"] == "proxy"


def test_an_allowlisting_proxy_names_what_it_lets_through():
    """Measured 2026-11-04 in Claude Code 2.1.317 with github.com allowed for one command."""
    f = {x.id: x for x in analyze(_proxied({"github.com": 200}))}
    assert f["NET-005"].severity == "medium"
    assert f["NET-005"].evidence["proxy_accepted_connect_to"] == ["github.com"]
    assert "NET-001" not in f and "NET-003" not in f


def test_a_proxy_demanding_auth_the_probe_withheld_stays_unmeasured_and_says_how_to_measure():
    f = {x.id: x for x in analyze(_proxied({h: 407 for h in ("dns.google", "pypi.org", "github.com",
                                                                "metadata.google.internal")},
                                             canary=407, auth="available, not used"))}
    assert f["NET-004"].evidence["unmeasured"] is True
    assert "AGENTSEC_PROBE_PROXY_AUTH=1" in f["NET-004"].remediation
    assert "NET-003" not in f


def test_metadata_through_the_proxy_is_critical():
    f = {x.id: x for x in analyze(_proxied({"metadata.google.internal": 200}))}
    assert f["NET-002"].severity == "critical"


def test_every_agent_credential_the_probe_looks_for_is_named_as_one():
    """A login file added to the probe must also be called out as an agent's own credential."""
    from agentsec.probe.blast_probe import CREDENTIAL_PATHS
    from agentsec.scoring import AGENT_CREDENTIALS
    agentish = {p for p in CREDENTIAL_PATHS if p.startswith(("~/.claude", "~/.codex", "~/.gemini"))}
    assert agentish == AGENT_CREDENTIALS


# --- macOS --------------------------------------------------------------------

def test_macos_is_scored_on_seatbelt_and_never_on_seccomp():
    """macOS has no seccomp; reporting its absence there is noise. Seatbelt is the equivalent."""
    plain = {"platform": "darwin", "identity": {"seatbelt": 0}}
    ids = [f.id for f in analyze(plain)]
    assert "PRIV-006" in ids and "PRIV-004" not in ids
    sandboxed = {"platform": "darwin", "identity": {"seatbelt": 1}}
    assert not {"PRIV-004", "PRIV-006"} & {f.id for f in analyze(sandboxed)}


def test_an_unknown_seatbelt_state_is_not_a_finding():
    assert "PRIV-006" not in [f.id for f in analyze({"platform": "darwin", "identity": {"seatbelt": None}})]


def test_linux_still_reports_a_missing_seccomp_filter():
    assert "PRIV-004" in [f.id for f in analyze({"platform": "linux", "identity": {"seccomp_mode": 0}})]
    assert "PRIV-004" in [f.id for f in analyze({"identity": {"seccomp_mode": 0}})], "old reports had no platform key"
