"""Join a promptfoo run with a sandbox measurement.

Promptfoo answers "did the agent do the wrong thing?". agentsec answers "what
could the wrong thing reach?". Neither file says the two describe the same
deployment, so the join is an assumption the operator states with
`--deployed-in`, and every sentence in the output is conditioned on it.

Read defensively: promptfoo's schema was captured from a real `eval` run
(results.results[] with success/score/testCase/gradingResult). Red-team runs
carry a plugin id somewhere in the row's metadata; it is treated as optional.
"""
from __future__ import annotations

import json
import re
from importlib import resources
from typing import Any

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_ASI_IN_ID = re.compile(r"asi(\d{2})", re.IGNORECASE)


def plugin_map() -> dict[str, list[str]]:
    with resources.files("agentsec.data").joinpath("promptfoo_plugin_asi.json").open("r") as f:
        return json.load(f)["plugin_to_asi"]


def asi_for_plugin(plugin_id: str | None) -> list[str]:
    """OWASP categories a promptfoo plugin id covers.

    Ids of the form owasp:agentic:asi02 carry the category themselves; bare ids
    are looked up in promptfoo's published table (agentsec/data/).
    """
    if not plugin_id:
        return []
    m = _ASI_IN_ID.search(plugin_id)
    if m:
        return ["ASI%02d" % int(m.group(1))]
    pid = plugin_id.split(":", 1)[1] if plugin_id.startswith("promptfoo:") else plugin_id
    return plugin_map().get(pid, [])


def load_promptfoo(path: str) -> dict[str, Any]:
    with open(path) as f:
        return json.load(f)


def _rows(pf: dict[str, Any]) -> list[dict[str, Any]]:
    r = pf.get("results")
    if isinstance(r, dict) and isinstance(r.get("results"), list):
        return r["results"]
    if isinstance(r, list):
        return r
    return []


def _plugin_id(row: dict[str, Any]) -> str | None:
    """Red-team rows carry a plugin id; plain eval rows do not."""
    for holder in (row.get("testCase") or {}, row):
        md = holder.get("metadata") or {}
        for key in ("pluginId", "plugin", "pluginid"):
            if md.get(key):
                return str(md[key])
    return None


def _describe(row: dict[str, Any]) -> str:
    tc = row.get("testCase") or {}
    for k in ("description", "name"):
        if tc.get(k):
            return str(tc[k])
    v = row.get("vars") or tc.get("vars") or {}
    if isinstance(v, dict) and v:
        first = next(iter(v.values()))
        return str(first)[:120]
    return f"test {row.get('testIdx', '?')}"


def summarize_promptfoo(pf: dict[str, Any]) -> dict[str, Any]:
    rows = _rows(pf)
    failed = [r for r in rows if not r.get("success")]
    stats = (pf.get("results") or {}).get("stats") or {}
    by_plugin: dict[str, dict[str, int]] = {}
    for r in rows:
        pid = _plugin_id(r) or "(no plugin id: plain eval row)"
        b = by_plugin.setdefault(pid, {"total": 0, "failed": 0})
        b["total"] += 1
        if not r.get("success"):
            b["failed"] += 1
    return {"total": len(rows), "failed": len(failed), "passed": len(rows) - len(failed),
            "errors": stats.get("errors"), "by_plugin": by_plugin,
            "asi_covered": sorted({a for p in by_plugin for a in asi_for_plugin(p if not p.startswith("(") else None)}),
            "failed_rows": [{"description": _describe(r), "plugin": _plugin_id(r), "asi": asi_for_plugin(_plugin_id(r)),
                             "reason": ((r.get("gradingResult") or {}).get("reason") or "")[:300]} for r in failed],
            "has_plugin_ids": any(_plugin_id(r) for r in rows)}


def combine(pf: dict[str, Any], sandbox: dict[str, Any], deployed_in: str) -> dict[str, Any]:
    pfs = summarize_promptfoo(pf)
    summary = sandbox.get("summary") or {}
    findings = summary.get("findings") or []
    target = sandbox.get("target") or {}
    reach = sorted(findings, key=lambda f: -SEVERITY_ORDER.get(f.get("severity", "info"), 0))
    failed_asi = sorted({a for r in pfs["failed_rows"] for a in r.get("asi", [])})
    overlap = []
    for cat in failed_asi:
        hits = [f for f in findings if cat in (f.get("owasp") or [])]
        if hits:
            overlap.append({"asi": cat, "failed_tests": [r["description"] for r in pfs["failed_rows"] if cat in r.get("asi", [])][:5],
                            "sandbox_findings": [{"id": f["id"], "title": f["title"], "severity": f["severity"]} for f in hits]})
    return {"tool": "agentsec-pack", "test": "promptfoo-sandbox-combined", "schema_version": 1,
            "overlap": overlap, "failed_asi": failed_asi,
            "assumption": {"stated_by": "operator", "deployed_in": deployed_in,
                           "text": ("The agent evaluated by promptfoo runs in the sandbox measured here. "
                                    "Nothing in either input file establishes this; it is stated by whoever ran the combine.")},
            "promptfoo": pfs,
            "sandbox": {"score": summary.get("score"), "raw_score": summary.get("raw_score"),
                        "finding_count": len(findings), "target": target,
                        "reachable": [{"id": f["id"], "title": f["title"], "severity": f["severity"], "owasp": f.get("owasp", [])} for f in reach],
                        "recommended_flags": summary.get("recommended_flags", [])}}


def render_markdown(c: dict[str, Any]) -> str:
    pf, sb = c["promptfoo"], c["sandbox"]
    t = sb["target"]
    where = t.get("preset") or t.get("image") or t.get("kind") or c["assumption"]["deployed_in"]
    L: list[str] = []
    L.append("# Agent behaviour and sandbox containment, together")
    L.append("")
    L.append(f"**{pf['failed']} of {pf['total']} promptfoo tests failed.** "
             f"**The sandbox scores {sb['score']}/100** ({sb['finding_count']} findings).")
    L.append("")
    L.append("## The assumption this report rests on")
    L.append("")
    L.append(f"> The agent promptfoo tested is deployed in **{c['assumption']['deployed_in']}**, the configuration measured here.")
    L.append("")
    L.append(c["assumption"]["text"] + " If the agent runs somewhere else in production, the containment column below describes that other place, not this one.")
    L.append("")
    L.append("## If both hold, this is what a failed test could reach")
    L.append("")
    if not sb["reachable"]:
        L.append(f"Nothing. `{where}` scored 0: no network, no secrets, no writable system paths, no extra privileges. "
                 f"A test the agent failed is a correctness or policy problem, not an exfiltration path.")
    elif pf["failed"] == 0:
        L.append(f"No test failed, so nothing is currently demonstrated to reach it. The sandbox nonetheless allows the following, "
                 f"which is what the next failure would get:")
    else:
        L.append(f"{pf['failed']} failed test(s) ran against an agent whose sandbox allows:")
    if sb["reachable"]:
        L.append("")
        L.append("| Severity | Finding | OWASP agentic |")
        L.append("|---|---|---|")
        for f in sb["reachable"]:
            L.append(f"| {f['severity']} | {f['id']} {f['title']} | {', '.join(f['owasp']) or '-'} |")
    L.append("")
    if c.get("overlap"):
        L.append("## Where the two halves meet")
        L.append("")
        L.append("An OWASP agentic category that both a failed test and a sandbox finding touch. The failed test shows the agent can be pushed into that category; the finding shows the sandbox does not stop it there.")
        L.append("")
        for o in c["overlap"]:
            L.append(f"**{o['asi']}**")
            L.append(f"- failed: {'; '.join(o['failed_tests'])}")
            L.append(f"- sandbox allows: {'; '.join(f"{f['id']} {f['title']}" for f in o['sandbox_findings'])}")
            L.append("")
    if pf["failed"]:
        L.append("## The failed tests")
        L.append("")
        for r in pf["failed_rows"][:25]:
            asi = f" [{', '.join(r['asi'])}]" if r.get("asi") else ""
            plugin = f" ({r['plugin']}{asi})" if r["plugin"] else ""
            L.append(f"- **{r['description']}**{plugin}{': ' + r['reason'] if r['reason'] else ''}")
        if len(pf["failed_rows"]) > 25:
            L.append(f"- ... and {len(pf['failed_rows']) - 25} more")
        L.append("")
    if not pf["has_plugin_ids"]:
        L.append("_No red-team plugin ids were present in this promptfoo output, so failures are listed by test description. "
                 "Per-plugin attribution appears automatically when the input comes from a red-team run._")
        L.append("")
    if sb["recommended_flags"]:
        L.append("## Closing the containment half")
        L.append("")
        L.append("```")
        L.extend(sb["recommended_flags"])
        L.append("```")
        L.append("")
    L.append("Reproduce the sandbox half with: `" + (t.get("command") or f"agentsec blast-radius preset {where}") + "`")
    return "\n".join(L) + "\n"
