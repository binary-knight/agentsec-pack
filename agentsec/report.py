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
    capped = " (capped; raw %d)" % s["raw_score"] if s.get("raw_score", 0) > 100 else ""
    lines.append(f"**Score: {s['score']} / 100**{capped} (0 = fully contained; higher = larger blast radius)  ")
    lines.append(f"Findings: {s['finding_count']} "
                 f"(critical {s['by_severity']['critical']}, high {s['by_severity']['high']}, medium {s['by_severity']['medium']}, low {s['by_severity']['low']})")
    lines.append("")
    lines.append("## Target (reproduce with this)")
    if t.get("preset_rationale"):
        lines.append(f"> {t['preset_rationale']}")
        lines.append("")
    for k, v in t.items():
        if k == "preset_rationale" or v in (None, [], ""):
            continue
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
    flags = s.get("recommended_flags") or []
    if flags:
        is_container = t.get("kind") == "container"
        engine = t.get("engine", "the container engine")
        lines.append("## Minimum flag set that closes the findings above" if is_container
                     else f"## Equivalent controls (written as {engine} flags; translate for your launcher)")
        lines.append("")
        if not is_container:
            lines.append("This target is not a container, so the flags below are the docker/podman spelling of each control. Bubblewrap and other launchers express the same controls differently (`--unshare-net` for the network, `--seccomp` with a compiled filter, and so on).")
            lines.append("")
        lines.append("A starting point, not a policy: each entry closes at least one finding observed here. Anything in parentheses is a change to how the sandbox is composed rather than a flag. A workload that genuinely needs the network or a dropped capability will break under these, and that is the operator's call to make deliberately.")
        lines.append("")
        lines.append("```")
        for f in flags:
            lines.append(f)
        lines.append("```")
        lines.append("")
    lines.append("## What the probe does not do")
    lines.append("It never reads secret values, sends no data to the egress targets, and writes only a zero-byte temp marker that it removes. Read `agentsec/probe/blast_probe.py` before running it in an environment you care about.")
    return "\n".join(lines) + "\n"


def render_matrix_markdown(env: dict) -> str:
    """One paste-ready table comparing presets against a single image."""
    lines = [f"# Sandbox blast radius across {len(env['runs'])} configurations", ""]
    if env.get("image"):
        lines.append(f"Image: `{env['image']}`")
        if env.get("digest"):
            lines.append(f"Digest: `{env['digest']}`")
    lines.append(f"Probe version `{env.get('probe_version')}`, measured {env.get('generated_at_iso')}.")
    lines.append("")
    capped_any = any(r.get("raw_score", r["score"]) > 100 for r in env["runs"])
    head = "| Configuration | Score | Raw | Findings | Worst finding |" if capped_any else "| Configuration | Score | Findings | Worst finding |"
    rule = "|---|---:|---:|---:|---|" if capped_any else "|---|---:|---:|---|"
    lines.append(head)
    lines.append(rule)
    for r in sorted(env["runs"], key=lambda r: (-r.get("raw_score", r["score"]), -r["score"])):
        worst = r.get("worst") or "none"
        if capped_any:
            lines.append(f"| `{r['preset']}` | {r['score']} | {r.get('raw_score', r['score'])} | {r['findings']} | {worst} |")
        else:
            lines.append(f"| `{r['preset']}` | {r['score']} | {r['findings']} | {worst} |")
    lines.append("")
    if capped_any:
        lines.append("Score is capped at 100 for budgeting; the raw column is the uncapped weight sum and is what separates the worst configurations from each other.")
        lines.append("")
    if any(rr["preset"].startswith("bwrap") for rr in env["runs"]):
        lines.append("Sandboxes that bind the host filesystem (the bwrap rows) are scored against **this host**: what they expose depends on what the machine has. A host with no container socket and no credentials in the home directory scores lower on the same configuration. Container rows are properties of the image and flags, and travel.")
        lines.append("")
    lines.append("0 means the probe could reach nothing from inside: no network, no secrets, no writable system paths, no extra privileges. Higher is a larger blast radius. Scores are the sum of fixed per-finding weights, capped at 100.")
    if env.get("skipped"):
        lines.append("")
        lines.append("Not run here: " + ", ".join(f"`{k}` ({v})" for k, v in env["skipped"].items()) + ".")
    lines.append("")
    lines.append("## What each configuration is")
    for r in sorted(env["runs"], key=lambda r: -r["score"]):
        lines.append(f"- **{r['preset']}** — {r.get('rationale', '')}")
    return "\n".join(lines) + "\n"
