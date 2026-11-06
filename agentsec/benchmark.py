"""Turn opt-in submissions into published figures, without letting one person set them.

Each GitHub account counts once per configuration, whatever it posts. A community
configuration appears only once enough different accounts have submitted it, and what
appears is a median and how many accounts it rests on, never one person's record. Results
reproduced by the maintainer or a known harness are kept apart, with where they came from.

The posted issues stay public, so the threshold protects the published figures from being
moved by one person. It does not make any one issue private.
"""
from __future__ import annotations

import json
import re
import statistics
from collections import Counter
from typing import Any

from .chart import AXES
from .submit import SubmitError, check_record

DEFAULT_MIN_SUBMITTERS = 5
LOWEST_MIN_SUBMITTERS = 3
REJECTED_LABEL = "rejected"

_FENCED = re.compile(r"```json\s*\n(.*?)\n```", re.S)
_KEY_FIELDS = ("agent", "agent_version", "sandbox_mode", "os_family", "probe_version")


class BenchmarkError(Exception):
    """The input could not be read as submissions."""


def configuration(record: dict[str, Any]) -> tuple:
    """What makes two records comparable. The probe version counts, because scoring changes with it."""
    return (*(record[f] for f in _KEY_FIELDS), tuple(sorted(record["settings"])))


def record_from_issue(body: str) -> dict[str, Any]:
    found = _FENCED.search(body or "")
    if not found:
        raise SubmitError("no JSON record in the issue")
    try:
        record = json.loads(found.group(1))
    except ValueError as e:
        raise SubmitError(f"the record is not JSON: {e}") from e
    check_record(record)
    return record


def latest_by_account(issues: list[dict[str, Any]]) -> tuple[dict[tuple, dict[str, dict[str, Any]]], int]:
    """Configuration to account to that account's newest record, and how many issues were refused."""
    groups: dict[tuple, dict[str, dict[str, Any]]] = {}
    refused = 0
    for issue in sorted(issues, key=lambda i: str(i.get("createdAt") or "")):
        author = issue.get("author") or {}
        login = str(author.get("login") or "").lower()
        labels = {str(label.get("name")) for label in issue.get("labels") or []}
        if not login or author.get("is_bot") or REJECTED_LABEL in labels:
            refused += 1
            continue
        try:
            record = record_from_issue(issue.get("body") or "")
        except SubmitError:
            refused += 1
            continue
        groups.setdefault(configuration(record), {})[login] = record
    return groups, refused


def _figure(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Only what no single record can be read back out of: a median and each axis's most common state."""
    first = records[0]
    return {**{f: first[f] for f in _KEY_FIELDS}, "settings": sorted(first["settings"]),
            "median_score": statistics.median(r["score"] for r in records),
            "axes": {a: Counter(r["axes"][a] for r in records).most_common(1)[0][0] for a in AXES}}


def aggregate(issues: list[dict[str, Any]], reproduced: list[dict[str, Any]] | None = None, min_submitters: int = DEFAULT_MIN_SUBMITTERS) -> dict[str, Any]:
    if min_submitters < LOWEST_MIN_SUBMITTERS:
        raise BenchmarkError(f"the threshold cannot go below {LOWEST_MIN_SUBMITTERS}: with fewer, a submitter can work out what another one sent")
    groups, refused = latest_by_account(issues)
    published = [{**_figure(list(by_account.values())), "submitters": len(by_account)}
                 for by_account in groups.values() if len(by_account) >= min_submitters]
    known = []
    for entry in reproduced or []:
        source = entry.get("source") if isinstance(entry, dict) else None
        if not (isinstance(source, str) and source.strip()):
            raise BenchmarkError("every reproduced result must say where it came from")
        try:
            check_record(entry.get("record"))
        except SubmitError as e:
            raise BenchmarkError(f"a reproduced result is not a valid record: {e}") from e
        known.append({**_figure([entry["record"]]), "source": source, "runs": 1})
    order = lambda f: (f["median_score"], f["agent"], f["agent_version"], f["sandbox_mode"])  # noqa: E731
    return {"min_submitters": min_submitters,
            "reproduced": sorted(known, key=order),
            "community": sorted(published, key=order),
            "below_threshold": len(groups) - len(published),
            "refused": refused}


def render_markdown(result: dict[str, Any]) -> str:
    def cell(figure: dict[str, Any]) -> str:
        settings = ", ".join(figure["settings"]) or "defaults"
        return f"{figure['agent']} {figure['agent_version']} | {figure['sandbox_mode']} | {settings} | {figure['os_family']} | {figure['probe_version']} | {figure['median_score']:g}"

    lines = ["# Benchmark", "", "## Reproduced", ""]
    if result["reproduced"]:
        lines += ["Agent | Sandbox | Settings | OS | Probe | Score | Source", "---|---|---|---|---|---:|---"]
        lines += [f"{cell(f)} | {f['source']}" for f in result["reproduced"]]
    else:
        lines.append("None yet.")
    lines += ["", "## Community submissions", "",
              f"A configuration appears once {result['min_submitters']} different accounts have submitted it. Each account counts once.", ""]
    if result["community"]:
        lines += ["Agent | Sandbox | Settings | OS | Probe | Median score | Accounts", "---|---|---|---|---|---:|---:"]
        lines += [f"{cell(f)} | {f['submitters']}" for f in result["community"]]
    else:
        lines.append("None yet.")
    lines += ["", f"{result['below_threshold']} configurations are below the threshold and not shown. {result['refused']} issues were refused.", ""]
    return "\n".join(lines)
