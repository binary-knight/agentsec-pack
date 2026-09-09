import json
import os
import shutil

import pytest

from agentsec import presets, runner

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
from agentsec.cli import main
from agentsec.scoring import summarize, recommended_flags, analyze


def test_every_preset_is_well_formed():
    for name, p in presets.load_all().items():
        assert p["kind"] in ("container", "command"), name
        assert p.get("rationale") and p.get("source"), name
        if p["kind"] == "container":
            assert p["engine"] in ("docker", "podman"), name
            assert isinstance(p["flags"], list) and all(isinstance(f, str) for f in p["flags"]), name
        else:
            assert "{probe}" in p["template"], name


def test_requirement_and_lookup():
    assert presets.requirement(presets.get("docker-default")) == "docker"
    assert presets.requirement(presets.get("bwrap-ro-root")) == "bwrap"
    with pytest.raises(KeyError):
        presets.get("no-such-preset")


def test_named_presets_cite_a_source_not_a_vendor_claim():
    # A preset named after a third-party agent must cite that agent's own source.
    for name, p in presets.load_all().items():
        if name.split("-")[0] not in ("docker", "podman", "bwrap"):
            assert "http" in p["source"], f"{name} names a third party without a source URL"


@pytest.mark.skipif(not shutil.which("bwrap"), reason="bwrap not installed")
def test_bwrap_preset_runs_and_scores():
    run = runner.run_preset("bwrap-unshare-all")
    s = summarize(run["probe"])
    assert run["target"]["preset"] == "bwrap-unshare-all"
    assert not run["probe"]["network"]["any_egress"], "unshare-all should have no network"
    assert s["score"] >= 0


@pytest.mark.skipif(not shutil.which("docker"), reason="docker not installed")
def test_docker_hardened_preset_is_contained():
    run = runner.run_preset("docker-hardened", image="python:3.12-slim")
    s = summarize(run["probe"])
    assert s["score"] == 0, [f["id"] for f in s["findings"]]
    assert run["target"]["digest"], "digest should be recorded for reproducibility"


def test_max_score_gate_exits_two(tmp_path):
    rc = main(["blast-radius", "local", "--out", str(tmp_path), "--label", "g", "--max-score", "0"])
    assert rc == 2
    rc = main(["blast-radius", "local", "--out", str(tmp_path), "--label", "g", "--max-score", "100"])
    assert rc == 0


def test_recommended_flags_are_deterministic_and_deduped():
    fixture = json.load(open("tests/fixtures/probe_open.json"))
    flags = recommended_flags(analyze(fixture))
    assert flags == recommended_flags(analyze(fixture))
    assert len(flags) == len(set(flags))
    assert "--network none" in flags and "--cap-drop ALL" in flags


def test_contained_fixture_recommends_nothing():
    fixture = json.load(open("tests/fixtures/probe_contained.json"))
    assert recommended_flags(analyze(fixture)) == []


def test_raw_score_separates_capped_sandboxes():
    from agentsec.scoring import raw_score, score
    fixture = json.load(open("tests/fixtures/probe_open.json"))
    f = analyze(fixture)
    assert score(f) == 100
    assert raw_score(f) >= score(f)


@pytest.mark.skipif(not shutil.which("bwrap"), reason="bwrap not installed")
def test_matrix_writes_one_table(tmp_path):
    rc = main(["matrix", "--presets", "bwrap-unshare-all,bwrap-unshare-all-clearenv", "--out", str(tmp_path), "--label", "m"])
    assert rc == 0
    env = json.load(open(tmp_path / "m.json"))
    assert len(env["runs"]) == 2
    md = open(tmp_path / "m.md").read()
    assert "| Configuration |" in md and "bwrap-unshare-all" in md


def test_redaction_removes_identifying_detail_but_keeps_scores():
    import os
    from agentsec.redact import redact
    env = {"summary": {"score": 59, "findings": [{"id": "SEC-002", "evidence": {"names": [{"name": "OPENAI_API_KEY", "length": 51}]}}]},
           "probe": {"identity": {"hostname": "buildbox", "cwd": os.path.expanduser("~") + "/work"},
                     "secrets": {"env_secret_names": [{"name": "AWS_SECRET_ACCESS_KEY", "length": 40}]}},
           "target": {"kind": "container", "flags": ["--network", "none"]}}
    out = redact(env, home=os.path.expanduser("~"), user="someuser")
    assert out["summary"]["score"] == 59
    assert out["target"]["flags"] == ["--network", "none"]
    assert out["probe"]["identity"]["hostname"] == "<redacted>"
    assert out["probe"]["secrets"]["env_secret_names"][0]["name"] == "<redacted>"
    assert out["probe"]["secrets"]["env_secret_names"][0]["length"] == 40
    assert out["summary"]["findings"][0]["evidence"]["names"][0]["name"] == "<redacted>"
    assert "OPENAI_API_KEY" not in json.dumps(out)


def test_measured_profiles_carry_full_provenance():
    """A named agent's sandbox may only be recorded if it was actually measured."""
    import json as _json
    from importlib import resources
    with resources.files("agentsec.data").joinpath("measured_profiles.json").open() as f:
        data = _json.load(f)
    for name, p in data["profiles"].items():
        for key in ("agent", "version", "mode", "measured", "host", "score", "how", "vendor_docs", "result", "report"):
            assert p.get(key), f"{name} is missing {key}"
        assert "http" in p["vendor_docs"], f"{name} must cite the vendor's own documentation"
        assert os.path.exists(os.path.join(REPO, p["report"])), p["report"]


def test_measured_profile_reports_match_their_recorded_score():
    import json as _json
    from importlib import resources
    with resources.files("agentsec.data").joinpath("measured_profiles.json").open() as f:
        data = _json.load(f)
    for name, p in data["profiles"].items():
        report = _json.load(open(os.path.join(REPO, p["report"].replace(".md", ".json"))))
        assert report["summary"]["score"] == p["score"], f"{name}: table says {p['score']}, report says {report['summary']['score']}"


def test_socket_finding_is_critical_only_when_a_connection_succeeded():
    from agentsec.scoring import analyze
    base = json.load(open(os.path.join(HERE, "fixtures", "probe_open.json")))
    ids = {f.id: f for f in analyze(base)}
    assert "SEC-001" in ids and ids["SEC-001"].severity == "critical"
    base["secrets"]["container_sockets"] = [{"path": "/var/run/docker.sock", "writable": True,
                                             "connected": False, "connect_error": "PermissionError"}]
    ids2 = {f.id: f for f in analyze(base)}
    assert "SEC-001" not in ids2, "a refused socket must not be scored as reachable"
    assert ids2["SEC-006"].severity == "low"


def test_codex_bwrap_layer_preset_declares_what_it_does_not_reproduce():
    """A preset named after a product must not be mistaken for the product."""
    p = presets.load_all()["codex-cli-0.153.4-bwrap-layer"]
    assert "seccomp" in p["rationale"].lower()
    assert "not" in p["rationale"].lower()
    assert "cmdline" in p["source"], "the argv must be cited to a live capture, not to source or recall"
    assert "--apply-seccomp-then-exec" not in p["template"], (
        "the template must not claim to apply the vendor's second layer")


@pytest.mark.skipif(not shutil.which("bwrap"), reason="bwrap not installed")
def test_bwrap_layer_alone_leaves_the_socket_reachable_that_codex_closes():
    """The measured gap between the two layers, asserted rather than described."""
    run = runner.run_preset("codex-cli-0.153.4-bwrap-layer")
    probe = run["probe"]
    ids = {f["id"] for f in summarize(probe)["findings"]}
    assert probe["secrets"]["unix_control"]["connected"] is True, (
        "bubblewrap alone does not restrict unix-domain sockets; if this fails the host has an extra layer")
    assert probe["identity"]["seccomp_mode"] == 0
    assert "PRIV-004" in ids


def test_measured_profiles_declare_environment_and_conflicts():
    """A score without its environment is not comparable to another score."""
    import json
    with open(os.path.join(REPO, "agentsec", "data", "measured_profiles.json")) as f:
        profiles = json.load(f)["profiles"]
    for name, p in profiles.items():
        assert p.get("environment"), f"{name} does not say what environment it was measured in"
        assert p.get("how"), f"{name} does not say how it was measured"
        assert p.get("vendor_docs"), f"{name} names a product without citing its documentation"
        if name.startswith("claude-code"):
            assert "Claude Code session measuring Claude Code" in p.get("conflict_of_interest", ""), (
                f"{name} must disclose that the measurer and the measured are the same product")


def test_the_degraded_sandbox_profile_records_the_vendors_own_warning():
    """The finding is the gap between configuration and process, so quote the warning."""
    import json
    with open(os.path.join(REPO, "agentsec", "data", "measured_profiles.json")) as f:
        p = json.load(f)["profiles"]["claude-code-2.1.266-sandbox-enabled-deps-missing"]
    assert "socat" in p["vendor_warning"]
    assert "WITHOUT sandboxing" in p["vendor_warning"]
    assert p["score"] == 100, "a degraded sandbox must score as the unsandboxed run it actually is"


def test_degraded_sandbox_profile_names_the_vendors_own_remedy():
    """Reporting a gap without naming the documented fix is not a fair report."""
    import json
    with open(os.path.join(REPO, "agentsec", "data", "measured_profiles.json")) as f:
        p = json.load(f)["profiles"]["claude-code-2.1.266-sandbox-enabled-deps-missing"]
    assert "failIfUnavailable" in p["fail_closed_verified"]
    assert "Measured, not quoted" in p["fail_closed_verified"]
    assert "documented behaviour" in p["result"]
