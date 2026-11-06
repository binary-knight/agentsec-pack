"""Prepare one measurement for a public dataset, for a person to send.

Nothing here sends anything. `agentsec submit` builds a record, prints it, asks the person
at the terminal, and opens a pre-filled issue that they then read and post themselves. It
opens nothing without a terminal, so piped input cannot confirm it.

A record is built only from the fields listed in SUBMITTED, and never by copying from a
report and removing what looks private. A report's label and --how are free text and carry
usernames and project names, so the person states the agent and sandbox here instead, and
those words are refused if they look like a path, a variable name or this machine's names.
"""
from __future__ import annotations

import os
import re
import socket
import urllib.parse
from typing import Any

from .chart import AXES, axis_state

SCHEMA = 1
SUBMITTED = {"schema", "agent", "agent_version", "sandbox_mode", "settings", "os_family", "probe_version", "axes", "finding_ids", "score"}
AXIS_STATES = {"sealed", "low", "reachable", "unmeasured"}
OS_FAMILIES = {"linux": "linux", "darwin": "macos", "win32": "windows"}
MAX_URL = 8000

_WORDS = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+= -]{0,79}")
_VARIABLE = re.compile(r"\b[A-Z][A-Z0-9]*_[A-Z0-9_]+\b")
_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+-]{0,31}")
_FINDING_ID = re.compile(r"[A-Z]+-[0-9]{3}")
_REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+")


class SubmitError(Exception):
    """The record could not be built, or holds something it must not."""


def _names_on_this_machine(env: dict[str, Any]) -> set[str]:
    """Words that would identify this machine or person if they reached the record."""
    identity = (env.get("probe") or {}).get("identity") or {}
    names = {os.environ.get("USER", ""), os.environ.get("LOGNAME", ""), os.path.basename(os.path.expanduser("~")),
             socket.gethostname(), str(identity.get("hostname") or "")}
    for item in ((env.get("probe") or {}).get("secrets") or {}).get("env_secret_names") or []:
        names.add(str(item.get("name") if isinstance(item, dict) else item))
    return {n.lower() for n in names if n and n != "<redacted>" and n != "root"}


def _plain_words(what: str, value: str, machine: set[str]) -> str:
    if not _WORDS.fullmatch(value):
        raise SubmitError(f"{what} may only hold letters, digits, spaces and . _ + = -, so it cannot hold a path: {value!r}")
    if _VARIABLE.search(value):
        raise SubmitError(f"{what} looks like it names an environment variable: {value!r}")
    words = set(re.split(r"[^a-z0-9]+", value.lower()))
    for name in machine:
        if name in words or (len(name) > 3 and name in value.lower()):
            raise SubmitError(f"{what} holds a name from this machine: {value!r}")
    return value


def build_record(env: dict[str, Any], agent: str, agent_version: str, sandbox_mode: str, settings: list[str]) -> dict[str, Any]:
    if env.get("test") != "sandbox-blast-radius" or "summary" not in env:
        raise SubmitError("this is not a single-run blast-radius report")
    machine = _names_on_this_machine(env)
    probe = env.get("probe") or {}
    findings = env["summary"].get("findings") or []
    record = {"schema": SCHEMA,
              "agent": _plain_words("--agent", agent, machine),
              "agent_version": _plain_words("--agent-version", agent_version, machine),
              "sandbox_mode": _plain_words("--sandbox", sandbox_mode, machine),
              "settings": [_plain_words("--setting", s, machine) for s in settings],
              "os_family": OS_FAMILIES.get(str(probe.get("platform")), "other"),
              "probe_version": probe.get("probe_version"),
              "axes": {a: axis_state(findings, a)[0] for a in AXES},
              "finding_ids": sorted(f["id"] for f in findings),
              "score": env["summary"].get("score")}
    check_record(record)
    return record


def check_record(record: Any) -> None:
    """Raise unless this is a record of the allowed shape. A dataset can run this on what it receives."""
    if not isinstance(record, dict) or set(record) != SUBMITTED:
        raise SubmitError("the record does not have exactly the allowed fields")
    if record["schema"] != SCHEMA:
        raise SubmitError(f"unknown record schema: {record['schema']!r}")
    for key in ("agent", "agent_version", "sandbox_mode"):
        if not (isinstance(record[key], str) and _WORDS.fullmatch(record[key]) and not _VARIABLE.search(record[key])):
            raise SubmitError(f"{key} is not plain words")
    settings = record["settings"]
    if not (isinstance(settings, list) and all(isinstance(s, str) and _WORDS.fullmatch(s) and not _VARIABLE.search(s) for s in settings)):
        raise SubmitError("settings are not plain words")
    if record["os_family"] not in {*OS_FAMILIES.values(), "other"}:
        raise SubmitError("unknown OS family")
    if not (isinstance(record["probe_version"], str) and _VERSION.fullmatch(record["probe_version"])):
        raise SubmitError("the report has no usable probe version")
    axes = record["axes"]
    if not (isinstance(axes, dict) and set(axes) == set(AXES) and all(v in AXIS_STATES for v in axes.values())):
        raise SubmitError("the axes are not the five known axes and states")
    ids = record["finding_ids"]
    if not (isinstance(ids, list) and all(isinstance(i, str) and _FINDING_ID.fullmatch(i) for i in ids)):
        raise SubmitError("a finding id has an unexpected form")
    score = record["score"]
    if not (isinstance(score, int) and not isinstance(score, bool) and 0 <= score <= 100):
        raise SubmitError("the score is not a number from 0 to 100")


def issue_url(repo: str, record_text: str, record: dict[str, Any]) -> str:
    if not _REPO.fullmatch(repo):
        raise SubmitError(f"--to must be owner/repository: {repo!r}")
    title = f"{record['agent']} {record['agent_version']}, {record['sandbox_mode']}: {record['score']}"
    body = f"A measurement submitted with `agentsec submit`.\n\n```json\n{record_text}\n```\n"
    url = f"https://github.com/{repo}/issues/new?" + urllib.parse.urlencode({"title": title, "body": body}, quote_via=urllib.parse.quote)
    if len(url) > MAX_URL:
        raise SubmitError("the record is too long to pre-fill an issue, so shorten --setting")
    return url
