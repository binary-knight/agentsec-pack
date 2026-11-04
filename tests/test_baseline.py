"""The regression gate: fail on anything worse than the accepted baseline, whatever the score."""
import copy
import json
import os

from agentsec import baseline as bl
from agentsec.cli import main
from agentsec.redact import redact
from agentsec.scoring import summarize

HERE = os.path.dirname(__file__)


def _env(probe):
    return {"label": "t", "summary": summarize(probe), "probe": probe, "target": {"kind": "captured"}}


def _probe(name="probe_contained.json"):
    with open(os.path.join(HERE, "fixtures", name)) as f:
        return json.load(f)


def test_an_identical_run_passes():
    r = bl.compare(_env(_probe()), _env(_probe()))
    assert r["regressions"] == [] and r["fixed"] == []


def test_a_new_finding_fails_even_far_under_any_budget():
    """The case --max-score misses: drift that stays under the number."""
    worse = _probe()
    worse["identity"]["no_new_privs"] = 0  # PRIV-005, low, 3 points
    r = bl.compare(_env(_probe()), _env(worse))
    assert [x["id"] for x in r["regressions"]] == ["PRIV-005"]
    assert r["regressions"][0]["kind"] == "new"


def test_wider_evidence_on_an_existing_finding_fails():
    base = _probe("probe_open.json")
    more = copy.deepcopy(base)
    more["secrets"]["credential_files"].append({"path": "~/.aws/credentials", "readable": True, "via": "HOME"})
    r = bl.compare(_env(base), _env(more))
    w = [x for x in r["regressions"] if x["kind"] == "widened"]
    assert w and w[0]["id"] == "SEC-003"
    assert w[0]["gained"]["readable_of_those_probed"] == ["~/.aws/credentials"]


def test_bookkeeping_lists_changing_is_not_a_regression():
    """Which home resolved a credential is provenance, not reach."""
    base = _probe("probe_open.json")
    other = copy.deepcopy(base)
    for c in other["secrets"]["credential_files"]:
        c["via"] = "HOME+passwd"
    assert bl.compare(_env(base), _env(other))["regressions"] == []


def test_a_third_redacted_secret_is_still_a_regression():
    base = _env(_probe("probe_open.json"))
    more_probe = _probe("probe_open.json")
    more_probe["secrets"]["env_secret_names"].append({"name": "ANOTHER_TOKEN", "length": 9})
    r = bl.compare(redact(base), redact(_env(more_probe)))
    assert any(x["id"] == "SEC-002" and x["kind"] == "widened" for x in r["regressions"])


def test_a_fixed_finding_passes_and_asks_for_a_new_baseline():
    r = bl.compare(_env(_probe("probe_open.json")), _env(_probe()))
    assert r["regressions"] == [] and r["fixed"]
    assert "Re-baseline" in bl.render(r)


def test_a_changed_probe_version_is_said_out_loud():
    newer = _probe()
    newer["probe_version"] = "9.9.9"
    out = bl.render(bl.compare(_env(_probe()), _env(newer)))
    assert "probe" in out and "9.9.9" in out


def test_diff_exits_2_on_regression_and_0_otherwise(tmp_path):
    base, worse = tmp_path / "base.json", tmp_path / "worse.json"
    base.write_text(json.dumps(_env(_probe())))
    p = _probe()
    p["identity"]["no_new_privs"] = 0
    worse.write_text(json.dumps(_env(p)))
    assert main(["diff", str(base), str(base)]) == 0
    assert main(["diff", str(base), str(worse)]) == 2


def test_score_with_a_baseline_gates_the_captured_run(tmp_path):
    probe_file = tmp_path / "probe.json"
    probe_file.write_text(json.dumps(_probe("probe_open.json")))
    base = tmp_path / "base.json"
    base.write_text(json.dumps(_env(_probe())))
    rc = main(["score", str(probe_file), "--label", "x", "--how", "test", "--out", str(tmp_path / "r"),
               "--baseline", str(base)])
    assert rc == 2


def test_a_wider_proxy_allowlist_is_a_regression():
    """NET-005 keeps its id when the proxy starts accepting another host; the
    accepted hosts are reach, so the gate must count them."""
    def env(hosts):
        return {"summary": {"score": 49, "findings": [
            {"id": "NET-005", "severity": "medium", "title": "Egress through the proxy is allowlisted",
             "evidence": {"via": "proxy", "proxy_accepted_connect_to": hosts}}]}, "probe": {}}
    r = bl.compare(env(["github.com"]), env(["github.com", "pypi.org"]))
    assert r["regressions"][0]["gained"] == {"proxy_accepted_connect_to": ["pypi.org"]}
