"""Score and findings for one sandbox over time, so drift shows before it crosses a gate.

A report is written to `reports/<label>.json`, so the next run with that label replaces
it. `agentsec history REPORT --save FILE` keeps a line for each run, and the comparison
between two runs is `baseline.compare`, the same one the `--baseline` gate uses.

A line keeps less than the report. What a finding reached (variable names, paths, mounts)
is kept only as hashes, enough to see that one more thing became reachable, so a history
file can be committed or kept as a build artifact without carrying those names.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any

from .baseline import REACH_KEYS, _key, compare


def _hashed(value: Any) -> str:
    return hashlib.sha256(_key(value).encode()).hexdigest()[:16]


def entry(env: dict[str, Any]) -> dict[str, Any]:
    """The line for one report, in the shape `baseline.compare` reads."""
    findings = []
    for f in env["summary"]["findings"]:
        evidence: dict[str, Any] = {}
        for k, v in (f.get("evidence") or {}).items():
            if k == "unmeasured":
                evidence[k] = v
            elif k in REACH_KEYS and isinstance(v, list):
                evidence[k] = sorted(_hashed(x) for x in v)
        findings.append({"id": f["id"], "severity": f["severity"], "title": f["title"], "evidence": evidence})
    probe = env.get("probe") or {}
    redacted = (probe.get("identity") or {}).get("hostname") == "<redacted>"
    return {"label": env.get("label") or (env.get("target") or {}).get("label"), "generated_at": env.get("generated_at"),
            "summary": {"score": env["summary"]["score"], "findings": findings},
            "probe": {"probe_version": probe.get("probe_version"), "identity": {"hostname": "<redacted>" if redacted else None}}}


def _is_report(data: Any) -> bool:
    return isinstance(data, dict) and data.get("test") == "sandbox-blast-radius" and "summary" in data and data.get("generated_at") is not None


def _is_entry(data: Any) -> bool:
    return isinstance(data, dict) and data.get("generated_at") is not None and isinstance(data.get("summary"), dict) and "probe" in data


def load(paths: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
    """(entries, what was skipped and why) from report files, directories and history files."""
    entries, skipped = [], []
    files = []
    for p in paths:
        files += [os.path.join(p, n) for n in sorted(os.listdir(p)) if n.endswith((".json", ".jsonl"))] if os.path.isdir(p) else [p]
    for path in files:
        with open(path) as f:
            text = f.read()
        if path.endswith(".jsonl"):
            for n, line in enumerate(text.splitlines(), 1):
                if line.strip():
                    try:
                        saved = json.loads(line)
                    except ValueError:
                        saved = None
                    if _is_entry(saved):
                        entries.append(saved)
                    else:
                        skipped.append(f"{path}:{n}: not a history line")
            continue
        try:
            data = json.loads(text)
        except ValueError:
            skipped.append(f"{path}: not JSON")
            continue
        if _is_report(data):
            entries.append(entry(data))
        else:
            skipped.append(f"{path}: not a blast-radius report")
    return entries, skipped


def _identity(e: dict[str, Any]) -> tuple[Any, Any]:
    return e.get("label"), e.get("generated_at")


def save(path: str, entries: list[dict[str, Any]]) -> int:
    """Append the entries the file does not have yet. Returns how many were added."""
    existing: set[tuple[Any, Any]] = set()
    if os.path.exists(path):
        have, _skipped = load([path])
        existing = {_identity(e) for e in have}
    added = 0
    with open(path, "a") as f:
        for e in sorted(entries, key=lambda x: x["generated_at"]):
            if _identity(e) not in existing:
                f.write(json.dumps(e, sort_keys=True) + "\n")
                existing.add(_identity(e))
                added += 1
    return added


def build(entries: list[dict[str, Any]], max_score: int | None = None) -> dict[str, Any]:
    """{label: {runs, change, ...}}, each run compared with the one before it."""
    groups: dict[str, dict[Any, dict[str, Any]]] = {}
    for e in entries:
        groups.setdefault(str(e.get("label")), {})[e.get("generated_at")] = e
    out: dict[str, Any] = {}
    for label, by_time in sorted(groups.items()):
        ordered = [by_time[t] for t in sorted(by_time)]
        runs = []
        for prev, cur in zip([None, *ordered], ordered):
            step = compare(prev, cur) if prev else None
            runs.append({"generated_at": cur["generated_at"], "score": cur["summary"]["score"],
                         "probe_version": cur["probe"].get("probe_version"), "findings": sorted(f["id"] for f in cur["summary"]["findings"]),
                         "change": step and {"regressions": step["regressions"], "fixed": step["fixed"],
                                             "instrument_changed": step["instrument_changed"],
                                             "scorer_changed": step.get("scorer_changed", False),
                                             "redaction_differs": step["redaction_differs"]}})
        scores = [r["score"] for r in runs]
        out[label] = {"runs": runs, "first": scores[0], "last": scores[-1], "highest": max(scores),
                      "worsened_since_first": any(r["change"] and r["change"]["regressions"] for r in runs),
                      "margin": None if max_score is None else max_score - scores[-1]}
    return out


def _describe(change: dict[str, Any] | None) -> str:
    if not change:
        return ""
    parts = []
    for r in change["regressions"]:
        if r["kind"] == "new":
            parts.append(f"new {r['id']} [{r['severity']}]")
        elif r["kind"] == "severity":
            parts.append(f"{r['id']} {r['was']} to {r['now']}")
        else:
            parts.append(f"{r['id']} reaches {sum(len(v) for v in r['gained'].values())} more")
    parts += [f"gone {f['id']}" for f in change["fixed"]]
    if change["instrument_changed"]:
        parts.append("probe changed, so this step may be a new check")
    if change.get("scorer_changed"):
        parts.append("agentsec version changed, so a severity may have been rescored")
    if change["redaction_differs"]:
        parts.append("only one of these runs is redacted")
    return "; ".join(parts)


def _day(ts: Any) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.gmtime(ts))


def render(history: dict[str, Any], max_score: int | None = None) -> str:
    lines: list[str] = []
    for label, h in history.items():
        runs = h["runs"]
        lines += [f"## {label}", "", f"{len(runs)} run{'' if len(runs) == 1 else 's'}, score {h['first']} to {h['last']}, highest {h['highest']}."]
        if max_score is not None:
            lines[-1] += f" Budget {max_score}: " + (f"{h['margin']} left." if h["margin"] >= 0 else f"over by {-h['margin']}.")
        if len(runs) == 1:
            lines[-1] += " One run has no trend yet."
        lines += ["", "| Run (UTC) | Score | Change | Probe | What changed |", "|---|---:|---:|---|---|"]
        for prev, r in zip([None, *runs], runs):
            delta = "" if prev is None else f"{r['score'] - prev['score']:+d}"
            lines.append(f"| {_day(r['generated_at'])} | {r['score']} | {delta} | {r['probe_version']} | {_describe(r['change'])} |")
        lines.append("")
    return "\n".join(lines)
