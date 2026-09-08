"""Promptfoo integration.

The eval-output fixture is real: captured from `npx promptfoo@0.122.2 eval` on
2026-09-08. The red-team-shaped fixture is HAND-WRITTEN to the same schema with
plugin ids added, because a live red-team run needs a target and credentials
this repo does not have. Anything that depends on plugin ids is therefore
verified against a fixture, not against promptfoo's red-team output.
"""
import json
import os
import shutil
import subprocess

import pytest

from agentsec.integrations import promptfoo_combine as pc
from agentsec.integrations.promptfoo_assert import grade, get_assert, REPORT_ENV, BUDGET_ENV

HERE = os.path.dirname(__file__)
REAL_EVAL = os.path.join(HERE, "fixtures", "promptfoo_eval_real.json")
REDTEAM_SHAPED = os.path.join(HERE, "fixtures", "promptfoo_redteam_shaped.json")
OPEN_PROBE = os.path.join(HERE, "fixtures", "probe_open.json")


def sandbox_report(score_source=OPEN_PROBE):
    from agentsec.scoring import summarize
    with open(score_source) as f:
        probe = json.load(f)
    return {"summary": summarize(probe), "target": {"kind": "container", "preset": "docker-default", "image": "python:3.12-slim"}}


# --- assertion ---------------------------------------------------------------

def test_grade_shape_matches_promptfoo_grading_result():
    g = grade(sandbox_report())
    assert set(["pass", "score", "reason", "namedScores", "componentResults"]) <= set(g)
    assert isinstance(g["pass"], bool) and 0.0 <= g["score"] <= 1.0
    assert g["namedScores"]["blast_radius"] == 100
    assert g["score"] == 0.0


def test_grade_defaults_to_pass_without_a_budget():
    assert grade(sandbox_report())["pass"] is True


def test_grade_fails_only_when_budget_exceeded():
    assert grade(sandbox_report(), max_score=100)["pass"] is True
    assert grade(sandbox_report(), max_score=10)["pass"] is False
    assert "EXCEEDED" in grade(sandbox_report(), max_score=10)["reason"]


def test_get_assert_reads_the_report_from_the_environment(tmp_path, monkeypatch):
    p = tmp_path / "r.json"
    p.write_text(json.dumps(sandbox_report()))
    monkeypatch.setenv(REPORT_ENV, str(p))
    monkeypatch.setenv(BUDGET_ENV, "10")
    out = get_assert("ignored output", {"vars": {}})
    assert out["pass"] is False and out["namedScores"]["blast_radius"] == 100


# --- plugin -> OWASP join ----------------------------------------------------

def test_asi_is_parsed_from_a_namespaced_plugin_id():
    assert pc.asi_for_plugin("owasp:agentic:asi05") == ["ASI05"]
    assert pc.asi_for_plugin("owasp:agentic:asi10") == ["ASI10"]


def test_asi_is_looked_up_for_a_bare_plugin_id():
    assert "ASI02" in pc.asi_for_plugin("excessive-agency")
    assert "ASI01" in pc.asi_for_plugin("indirect-prompt-injection")
    assert pc.asi_for_plugin("not-a-real-plugin") == []
    assert pc.asi_for_plugin(None) == []


# --- combine -----------------------------------------------------------------

def test_combine_reads_real_promptfoo_eval_output():
    pf = pc.load_promptfoo(REAL_EVAL)
    s = pc.summarize_promptfoo(pf)
    assert s["total"] >= 1
    assert s["has_plugin_ids"] is False, "a plain eval has no plugin ids; the report must say so"


def test_combine_requires_and_prints_the_operator_assumption():
    c = pc.combine(pc.load_promptfoo(REDTEAM_SHAPED), sandbox_report(), "docker-default")
    assert c["assumption"]["deployed_in"] == "docker-default"
    assert c["assumption"]["stated_by"] == "operator"
    md = pc.render_markdown(c)
    assert "Nothing in either input file establishes this" in md
    assert "docker-default" in md


def test_combine_joins_failed_tests_to_sandbox_findings_by_owasp_category():
    c = pc.combine(pc.load_promptfoo(REDTEAM_SHAPED), sandbox_report(), "docker-default")
    cats = {o["asi"] for o in c["overlap"]}
    assert "ASI05" in cats, "a shell-execution failure should meet the privilege findings"
    for o in c["overlap"]:
        assert o["failed_tests"] and o["sandbox_findings"]


def test_combine_says_nothing_is_reachable_when_the_sandbox_is_contained():
    from agentsec.scoring import summarize
    with open(os.path.join(HERE, "fixtures", "probe_contained.json")) as f:
        contained = {"summary": summarize(json.load(f)), "target": {"kind": "container", "preset": "docker-hardened"}}
    c = pc.combine(pc.load_promptfoo(REDTEAM_SHAPED), contained, "docker-hardened")
    md = pc.render_markdown(c)
    assert c["overlap"] == []
    assert "Nothing." in md


# --- end to end through the real promptfoo binary ----------------------------

@pytest.mark.skipif(not shutil.which("npx"), reason="npx not available")
def test_assertion_runs_inside_real_promptfoo(tmp_path):
    report = tmp_path / "report.json"
    report.write_text(json.dumps(sandbox_report()))
    cfg = tmp_path / "promptfooconfig.yaml"
    assert_path = os.path.abspath(os.path.join(HERE, "..", "agentsec", "integrations", "promptfoo_assert.py"))
    cfg.write_text(
        "description: e2e\nproviders: [{id: echo}]\nprompts: ['{{q}}']\n"
        "tests:\n  - vars: {q: check}\n    assert:\n      - type: python\n        value: file://%s\n" % assert_path)
    out = tmp_path / "out.json"
    env = dict(os.environ, AGENTSEC_REPORT=str(report), PROMPTFOO_DISABLE_TELEMETRY="1")
    p = subprocess.run(["npx", "-y", "promptfoo@0.122.2", "eval", "-c", str(cfg), "-o", str(out),
                        "--no-cache", "--no-progress-bar"], capture_output=True, text=True, timeout=600, env=env, cwd=tmp_path)
    assert out.exists(), p.stdout[-2000:] + p.stderr[-2000:]
    row = json.load(open(out))["results"]["results"][0]
    assert row["namedScores"]["blast_radius"] == 100
    assert row["score"] == 0.0
