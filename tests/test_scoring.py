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
