"""Markdown rendering of a blast-radius result envelope."""
from __future__ import annotations

from typing import Any

from .scoring import load_owasp


def render_markdown(env: dict[str, Any]) -> str:
    s = env["summary"]
    t = env["target"]
    owasp = load_owasp()
    lines = []
    lines.append(f"# Sandbox blast radius: {env.get('label') or t.get('image') or t.get('kind')}")
    lines.append("")
    lines.append(f"**Score: {s['score']} / 100** (0 = fully contained; higher = larger blast radius)  ")
    lines.append(f"Findings: {s['finding_count']} "
                 f"(critical {s['by_severity']['critical']}, high {s['by_severity']['high']}, medium {s['by_severity']['medium']}, low {s['by_severity']['low']})")
    lines.append("")
    lines.append("## Target (reproduce with this)")
    for k, v in t.items():
        lines.append(f"- {k}: `{v}`")
    p = env["probe"]
    ident = p.get("identity", {})
    lines.append(f"- probe version: `{p.get('probe_version')}`, python `{p.get('python')}`, uid `{ident.get('uid')}`, seccomp `{ident.get('seccomp_mode')}`, user namespace `{ident.get('in_user_namespace')}`")
    lines.append("")
    lines.append("## Findings")
    if not s["findings"]:
        lines.append("None. The probe could not reach the network, secrets, host filesystem or extra privileges from inside this sandbox.")
    for f in s["findings"]:
        tags = ", ".join(f"{o} {owasp.get(o, '')}".strip() for o in f.get("owasp", []))
        lines.append(f"### {f['id']} · {f['severity'].upper()} · {f['title']}")
        if f.get("evidence"):
            lines.append(f"- evidence: `{f['evidence']}`")
        if tags:
            lines.append(f"- OWASP agentic: {tags}")
        if f.get("remediation"):
            lines.append(f"- fix: {f['remediation']}")
        lines.append("")
    lines.append("## What the probe does not do")
    lines.append("It never reads secret values, sends no data to the egress targets, and writes only a zero-byte temp marker that it removes. Read `agentsec/probe/blast_probe.py` before running it in an environment you care about.")
    return "\n".join(lines) + "\n"
