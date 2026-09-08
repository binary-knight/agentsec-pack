"""Promptfoo custom assertion: gate a run on sandbox containment.

Promptfoo measures what the agent does. This assertion reports what the agent's
sandbox would let a successful attack reach, so both numbers appear in one run.

It READS a report produced earlier by `agentsec blast-radius ...`; it never runs
the probe itself, because promptfoo calls assertions once per test row (four at
a time by default) and launching a container per row would be absurd.

Usage in promptfooconfig.yaml:

    tests:
      - description: sandbox containment
        vars: {q: "(environment check, not a model test)"}
        assert:
          - type: python
            value: file://path/to/promptfoo_assert.py

Environment:
    AGENTSEC_REPORT     path to the JSON written by `agentsec blast-radius`
    AGENTSEC_MAX_SCORE  optional budget; the assertion fails only if set and exceeded

Attach it to ONE dedicated test row rather than `defaultTest`: the sandbox is a
property of the environment, not of any single prompt, and via defaultTest a
single loose sandbox would fail every row in the suite for one cause.
"""
from __future__ import annotations

import json
import os
from typing import Any

REPORT_ENV = "AGENTSEC_REPORT"
BUDGET_ENV = "AGENTSEC_MAX_SCORE"


def load_report(path: str | None = None) -> dict[str, Any]:
    path = path or os.environ.get(REPORT_ENV)
    if not path:
        raise RuntimeError(f"set {REPORT_ENV} to a report written by `agentsec blast-radius`")
    with open(path) as f:
        return json.load(f)


def grade(report: dict[str, Any], max_score: int | None = None) -> dict[str, Any]:
    """Turn a blast-radius report into a promptfoo GradingResult."""
    summary = report.get("summary") or {}
    blast = int(summary.get("score", 0))
    findings = summary.get("findings") or []
    target = report.get("target") or {}
    where = target.get("preset") or target.get("image") or target.get("kind") or "the measured sandbox"

    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    worst = max(findings, key=lambda f: order.get(f.get("severity", "info"), 0), default=None)

    passed = True if max_score is None else blast <= max_score
    if not findings:
        reason = f"Sandbox containment: {where} scored 0/100; the probe reached nothing from inside."
    else:
        reason = (f"Sandbox containment: {where} scored {blast}/100 with {len(findings)} findings; "
                  f"worst is {worst['id']} {worst['title']} ({worst['severity']}).")
    if max_score is not None:
        reason += f" Budget {max_score}: {'within' if passed else 'EXCEEDED'}."

    component = [{"pass": True, "score": 1.0, "reason": f"{f['id']} {f['title']} [{f['severity']}]"} for f in findings]
    return {"pass": passed, "score": max(0.0, 1.0 - blast / 100.0), "reason": reason,
            "namedScores": {"blast_radius": blast}, "componentResults": component}


def get_assert(output: str, context: Any = None) -> dict[str, Any]:
    if os.environ.get("AGENTSEC_DEBUG_CONTEXT") and context is not None:
        import sys
        print("AGENTSEC context type=%s attrs=%s" % (type(context).__name__, dir(context)), file=sys.stderr)
        if isinstance(context, dict):
            print("AGENTSEC context keys=%s" % sorted(context), file=sys.stderr)
    budget = os.environ.get(BUDGET_ENV)
    return grade(load_report(), int(budget) if budget else None)
