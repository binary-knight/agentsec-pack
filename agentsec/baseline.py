"""Compare a measurement with a saved baseline and say what got worse.

`--max-score` fails a build when the blast radius crosses a number. That
misses drift under the number: a sandbox at 41 can lose its seccomp filter and
gain a readable credential and still be under a budget of 45. A baseline gate
fails on any change for the worse, whatever the total:

  * a finding that is new;
  * a finding whose severity rose;
  * a finding whose evidence widened: one more readable credential, one more
    reachable host, one more writable path.

A finding that disappeared is reported as fixed, never as a failure, with a
reminder to re-baseline so the gate keeps the ground that was gained.

Changing the instrument is not the sandbox changing. When the two runs used
different probe versions, a new finding may be a new check rather than a looser
sandbox; the gate still fails, because it cannot tell which, and says so.
"""
from __future__ import annotations

import json
from collections import Counter
from typing import Any

from .scoring import SEVERITY_WEIGHT

# Evidence keys whose lists are things the sandbox let the probe reach. Only
# these can widen a finding; bookkeeping lists (which home resolved a path, the
# error a refusal returned) changing is not the sandbox getting looser.
REACH_KEYS = {"reached", "readable_of_those_probed", "agent_credentials", "names", "connected",
              "paths", "writable", "mounts", "capabilities", "proxy_accepted_connect_to"}


def _key(v: Any) -> str:
    return v if isinstance(v, str) else json.dumps(v, sort_keys=True)


def _widened(old: dict, new: dict) -> dict[str, list]:
    """Reach-evidence entries present now beyond what the baseline had, per key.

    Counted, not set-compared: a redacted report turns every variable name into
    the same placeholder, and a third '<redacted>' is still a third secret.
    """
    out = {}
    for k, v in (new or {}).items():
        if k not in REACH_KEYS or not isinstance(v, list):
            continue
        before = Counter(_key(x) for x in (old or {}).get(k) or [])
        gained = []
        for x in v:
            kx = _key(x)
            if before[kx] > 0:
                before[kx] -= 1
            else:
                gained.append(x)
        if gained:
            out[k] = gained
    return out


def compare(baseline: dict, current: dict) -> dict[str, Any]:
    """Both arguments are result envelopes (what `blast-radius` and `score` write)."""
    if "summary" not in baseline:
        raise ValueError("the baseline is not a single-run report (no summary): pass a report JSON, not a matrix")
    old = {f["id"]: f for f in baseline["summary"]["findings"]}
    new = {f["id"]: f for f in current["summary"]["findings"]}
    regressions, fixed = [], []
    for fid, f in new.items():
        if fid not in old:
            regressions.append({"id": fid, "kind": "new", "severity": f["severity"], "title": f["title"]})
            continue
        was = old[fid]
        if SEVERITY_WEIGHT[f["severity"]] > SEVERITY_WEIGHT[was["severity"]]:
            regressions.append({"id": fid, "kind": "severity", "title": f["title"],
                                "was": was["severity"], "now": f["severity"]})
        gained = _widened(was.get("evidence"), f.get("evidence"))
        if gained:
            regressions.append({"id": fid, "kind": "widened", "title": f["title"], "gained": gained})
    for fid, f in old.items():
        if fid not in new:
            fixed.append({"id": fid, "severity": f["severity"], "title": f["title"]})
    redacted = [((e.get("probe") or {}).get("identity") or {}).get("hostname") == "<redacted>" for e in (baseline, current)]
    pv_old = (baseline.get("probe") or {}).get("probe_version")
    pv_new = (current.get("probe") or {}).get("probe_version")
    return {"regressions": regressions, "fixed": fixed,
            "score": {"baseline": baseline["summary"]["score"], "current": current["summary"]["score"]},
            "probe_versions": {"baseline": pv_old, "current": pv_new},
            "instrument_changed": pv_old != pv_new,
            "redaction_differs": redacted[0] != redacted[1]}


def render(result: dict[str, Any], baseline_label: str = "baseline") -> str:
    lines = []
    s = result["score"]
    lines.append(f"against {baseline_label}: score {s['baseline']} -> {s['current']}")
    for r in result["regressions"]:
        if r["kind"] == "new":
            lines.append(f"  REGRESSION new finding    {r['id']} [{r['severity']}] {r['title']}")
        elif r["kind"] == "severity":
            lines.append(f"  REGRESSION severity rose  {r['id']} {r['was']} -> {r['now']}: {r['title']}")
        else:
            gained = "; ".join(f"{k} + {', '.join(_key(x) for x in v)}" for k, v in r["gained"].items())
            lines.append(f"  REGRESSION widened        {r['id']} {r['title']}: {gained}")
    for f in result["fixed"]:
        lines.append(f"  fixed                     {f['id']} [{f['severity']}] {f['title']}")
    if result["fixed"] and not result["regressions"]:
        lines.append("  Re-baseline with this report, so the gate holds the ground just gained.")
    if result["instrument_changed"]:
        pv = result["probe_versions"]
        lines.append(f"  note: baseline was taken with probe {pv['baseline']}, this run with {pv['current']}. "
                     "A new finding may be a new check rather than a looser sandbox; the gate cannot tell which, "
                     "so it still fails. Re-baseline deliberately once you have read the difference.")
    if result.get("redaction_differs"):
        lines.append("  note: one report is redacted and the other is not, so variable names cannot match. "
                     "Gate a run against a baseline taken with the same --redact setting.")
    if not result["regressions"]:
        lines.append("OK: nothing is worse than the baseline")
    return "\n".join(lines)
