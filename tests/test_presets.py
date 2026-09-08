import json
import shutil

import pytest

from agentsec import presets, runner
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
