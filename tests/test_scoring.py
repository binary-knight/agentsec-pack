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
