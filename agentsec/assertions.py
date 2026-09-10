"""Ask a narrow question instead of producing a finding list.

`blast-radius` answers "what can this reach", against a fixed list of things
worth worrying about generally. Some questions are narrower and recur: can this
specific child read this specific file. A grading harness wants to know whether
the process it is about to run can read the answer key; a build wants to know
whether a step can write outside its workspace.

That question does not need a score, it needs a pass or a fail per path, and it
needs to be asked from inside the sandbox rather than from the launcher, for the
same reason everything else here is.
"""
from __future__ import annotations

import json
import os
from typing import Any

KINDS = ("readable", "not-readable", "writable", "not-writable", "exists", "not-exists")


def build_script(expectations: list[tuple[str, str]]) -> str:
    """A stdlib-only script that tests the paths and prints one JSON line.

    Written as source rather than imported so it can run inside a container that
    has nothing but a python3 binary, exactly like the probe.
    """
    return (
        "import json, os\n"
        "E = " + repr(expectations) + "\n"
        "out = []\n"
        "for kind, path in E:\n"
        "    r = {'kind': kind, 'path': path}\n"
        "    try:\n"
        "        r['exists'] = os.path.exists(path)\n"
        "        r['readable'] = os.access(path, os.R_OK)\n"
        "        if os.path.isdir(path):\n"
        "            r['writable'] = os.access(path, os.W_OK | os.X_OK)\n"
        "        else:\n"
        "            parent = os.path.dirname(path) or '.'\n"
        "            r['writable'] = os.access(path, os.W_OK) if os.path.exists(path) \\\n"
        "                else os.access(parent, os.W_OK)\n"
        "    except Exception as exc:\n"
        "        r['error'] = type(exc).__name__\n"
        "    out.append(r)\n"
        "print(json.dumps({'assertions': out}))\n"
    )


def evaluate(kind: str, observed: dict[str, Any]) -> tuple[bool, str]:
    """Did this expectation hold? Returns (ok, what was actually seen)."""
    if "error" in observed:
        return False, f"could not be tested ({observed['error']})"
    exists = observed.get("exists", False)
    readable = observed.get("readable", False)
    writable = observed.get("writable", False)
    if kind == "exists":
        return exists, "present" if exists else "absent"
    if kind == "not-exists":
        return not exists, "present" if exists else "absent"
    if kind == "readable":
        return readable, "readable" if readable else ("absent" if not exists else "not readable")
    if kind == "not-readable":
        # A file that is not there is not reachable. Say which, because "absent"
        # and "present but denied" are different sandbox designs.
        return not readable, "READABLE" if readable else ("absent" if not exists else "present, denied")
    if kind == "writable":
        return writable, "writable" if writable else "not writable"
    if kind == "not-writable":
        return not writable, "WRITABLE" if writable else "not writable"
    raise ValueError(f"unknown expectation: {kind}")


def check(results: list[dict[str, Any]], expectations: list[tuple[str, str]]) -> dict[str, Any]:
    by_key = {(r["kind"], r["path"]): r for r in results}
    rows, failed = [], 0
    for kind, path in expectations:
        observed = by_key.get((kind, path))
        if observed is None:
            rows.append({"kind": kind, "path": path, "ok": False, "observed": "not reported by the probe"})
            failed += 1
            continue
        ok, observed_word = evaluate(kind, observed)
        rows.append({"kind": kind, "path": path, "ok": ok, "observed": observed_word})
        if not ok:
            failed += 1
    return {"rows": rows, "failed": failed, "total": len(expectations)}


def render(outcome: dict[str, Any]) -> str:
    width = max((len(r["kind"]) for r in outcome["rows"]), default=10)
    lines = []
    for r in outcome["rows"]:
        mark = "ok  " if r["ok"] else "FAIL"
        lines.append(f"{mark}  {r['kind']:<{width}}  {r['path']}  ->  {r['observed']}")
    n, total = outcome["failed"], outcome["total"]
    lines.append("")
    lines.append(f"{total - n}/{total} expectations held" if n else f"all {total} expectations held")
    return "\n".join(lines)
