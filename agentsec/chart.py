"""A quick-look chart of many measurements: one row per run, one cell per axis.

Each cell is the state of one of the probe's five axes, worked out the same way
as the HTML report's band (`axisState` in ui/template.html):

  sealed        nothing above informational was found on that axis
  low           only low-severity findings: visible but refused, or a minor gap
  reachable     a medium, high or critical finding: the probe got through
  unmeasured    the probe could not settle the axis (an egress proxy it may not
                authenticate to, for example)

Colors are the fixed status scale from the dataviz guidance (good, warning,
critical, plus a neutral). Medium and high share "reachable" because the
warning and serious steps are too close to tell apart even with full color
vision; the exact severity is in the text table. Every cell also carries a
glyph, so no state depends on color alone, and the same rows render as a
Markdown table for agents and screen readers.
"""
from __future__ import annotations

import html
from typing import Any

AXES = ["privilege", "network", "secrets", "filesystem", "process"]
AXIS_LABEL = {"privilege": "Privilege", "network": "Network", "secrets": "Secrets",
              "filesystem": "Filesystem", "process": "Processes"}
ORDER = ["critical", "high", "medium", "low", "info"]

STATES = {
    "sealed": {"glyph": "✓", "word": "sealed"},
    "low": {"glyph": "○", "word": "low"},
    "reachable": {"glyph": "✕", "word": "reachable"},
    "unmeasured": {"glyph": "?", "word": "not measured"},
}

THEMES = {
    "light": {"surface": "#fcfcfb", "text": "#0b0b0b", "text2": "#52514e", "grid": "#e1e0d9",
              "border": "#c3c2b7", "bar": "#2a78d6",
              "sealed": "#0ca30c", "low": "#fab219", "reachable": "#d03b3b", "unmeasured": "none",
              "on_sealed": "#ffffff", "on_low": "#0b0b0b", "on_reachable": "#ffffff", "on_unmeasured": "#52514e"},
    "dark": {"surface": "#1a1a19", "text": "#f0efec", "text2": "#c3c2b7", "grid": "#2c2c2a",
             "border": "#383835", "bar": "#3987e5",
             "sealed": "#0ca30c", "low": "#fab219", "reachable": "#d03b3b", "unmeasured": "none",
             "on_sealed": "#ffffff", "on_low": "#0b0b0b", "on_reachable": "#ffffff", "on_unmeasured": "#c3c2b7"},
}


def axis_state(findings: list[dict], axis: str) -> tuple[str, str | None]:
    """(state, worst severity) for one axis of one run."""
    f = [x for x in findings if x.get("category") == axis]
    if not f:
        return "sealed", None
    worst = next((s for s in ORDER if any(x.get("severity") == s for x in f)), "info")
    if worst in ("info", "low") and any((x.get("evidence") or {}).get("unmeasured") for x in f):
        return "unmeasured", worst
    if worst == "info":
        return "sealed", worst
    if worst == "low":
        return "low", worst
    return "reachable", worst


def row_from_envelope(env: dict[str, Any], label: str | None = None) -> dict[str, Any]:
    s = env.get("summary") or {}
    findings = s.get("findings") or []
    return {"label": label or env.get("label") or "unnamed run",
            "score": s.get("score", 0),
            "probe": (env.get("probe") or {}).get("probe_version"),
            "cells": {a: axis_state(findings, a) for a in AXES}}


def rows_from_matrix(env: dict[str, Any]) -> list[dict[str, Any]]:
    pv = env.get("probe_version")
    out = []
    for r in env.get("runs", []):
        row = row_from_envelope({"summary": r["summary"], "label": r["preset"]})
        row["probe"] = pv
        out.append(row)
    return out


def render_markdown(groups: list[tuple[str, list[dict]]]) -> str:
    head = "| Configuration | Score | " + " | ".join(AXIS_LABEL[a] for a in AXES) + " | Probe |"
    rule = "|---|---:|" + "|".join(":-:" for _ in AXES) + "|---|"
    lines = []
    for title, rows in groups:
        if title:
            lines += [f"**{title}**", ""]
        lines += [head, rule]
        for r in rows:
            cells = []
            for a in AXES:
                st, sev = r["cells"][a]
                g = STATES[st]
                cells.append(f"{g['glyph']} {g['word']}" + (f" ({sev})" if st == "reachable" else ""))
            lines.append(f"| {r['label']} | {r['score']} | " + " | ".join(cells) + f" | {r['probe'] or ''} |")
        lines.append("")
    return "\n".join(lines)


def render_svg(groups: list[tuple[str, list[dict]]], title: str, subtitle: str = "", theme: str = "light") -> str:
    t = THEMES[theme]
    esc = html.escape
    pad, label_w, cell_w, cell_h, gap, row_h = 20, 330, 72, 22, 4, 30
    score_x = pad + label_w + len(AXES) * (cell_w + gap) + 16
    bar_w = 110
    probe_x = score_x + bar_w + 46
    width = probe_x + 70
    y = pad
    out = []

    def text(x, y, s, size=13, fill=None, weight=400, anchor="start", extra=""):
        out.append(f'<text x="{x}" y="{y}" font-size="{size}" font-weight="{weight}" fill="{fill or t["text"]}" '
                   f'text-anchor="{anchor}"{extra}>{esc(s)}</text>')

    y += 18
    text(pad, y, title, size=17, weight=600)
    if subtitle:
        y += 20
        text(pad, y, subtitle, size=12.5, fill=t["text2"])
    y += 30
    for i, a in enumerate(AXES):
        cx = pad + label_w + i * (cell_w + gap) + cell_w / 2
        text(cx, y, AXIS_LABEL[a], size=12, fill=t["text2"], anchor="middle")
    text(score_x, y, "Score (0–100)", size=12, fill=t["text2"])
    text(probe_x, y, "Probe", size=12, fill=t["text2"])
    y += 10
    for gi, (gtitle, rows) in enumerate(groups):
        if gtitle:
            y += 26 if gi else 18
            text(pad, y, gtitle, size=13, weight=600)
            y += 8
        for r in rows:
            out.append(f'<line x1="{pad}" x2="{width - pad}" y1="{y + 4}" y2="{y + 4}" stroke="{t["grid"]}" stroke-width="1"/>')
            y += row_h
            mid = y - row_h / 2 + 4
            text(pad, mid + 4.5, r["label"], size=13)
            for i, a in enumerate(AXES):
                st, sev = r["cells"][a]
                x = pad + label_w + i * (cell_w + gap)
                tip = f'{r["label"]}: {AXIS_LABEL[a]} {STATES[st]["word"]}' + (f" ({sev})" if sev and st != "sealed" else "")
                fill = t[st]
                stroke = f' stroke="{t["text2"]}" stroke-dasharray="3 2" stroke-width="1"' if st == "unmeasured" else ""
                out.append(f'<g><title>{esc(tip)}</title>'
                           f'<rect x="{x}" y="{mid - cell_h / 2}" width="{cell_w}" height="{cell_h}" rx="4" fill="{fill}"{stroke}/>'
                           f'<text x="{x + cell_w / 2}" y="{mid + 4.5}" font-size="13" font-weight="600" fill="{t["on_" + st]}" '
                           f'text-anchor="middle">{STATES[st]["glyph"]}</text></g>')
            score = max(0, min(100, int(r["score"])))
            out.append(f'<rect x="{score_x}" y="{mid - 5}" width="{bar_w}" height="10" rx="4" fill="{t["grid"]}"/>')
            if score:
                out.append(f'<rect x="{score_x}" y="{mid - 5}" width="{bar_w * score / 100:.1f}" height="10" rx="4" fill="{t["bar"]}"/>')
            text(score_x + bar_w + 8, mid + 4.5, str(r["score"]), size=13, weight=600)
            text(probe_x, mid + 4.5, r["probe"] or "", size=12, fill=t["text2"])
    y += 34
    x = pad
    for k, st in enumerate(("sealed", "low", "reachable", "unmeasured")):
        if k == 2:  # two entries per line keeps the legend inside the chart at any width
            x, y = pad, y + 26
        stroke = f' stroke="{t["text2"]}" stroke-dasharray="3 2" stroke-width="1"' if st == "unmeasured" else ""
        out.append(f'<rect x="{x}" y="{y - 14}" width="22" height="18" rx="4" fill="{t[st]}"{stroke}/>'
                   f'<text x="{x + 11}" y="{y}" font-size="12" font-weight="600" fill="{t["on_" + st]}" text-anchor="middle">{STATES[st]["glyph"]}</text>')
        word = {"sealed": "Sealed: nothing above informational", "low": "Low: visible but refused, or a minor gap",
                "reachable": "Reachable: medium, high or critical", "unmeasured": "Not measured"}[st]
        text(x + 30, y, word, size=12, fill=t["text2"])
        x += 30 + 330
    height = y + pad
    desc = esc(title + (". " + subtitle if subtitle else "") + ". One row per measured configuration, one cell per axis.")
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0f}" height="{height:.0f}" viewBox="0 0 {width:.0f} {height:.0f}" '
            f'role="img" aria-label="{esc(title)}" font-family="system-ui, -apple-system, Segoe UI, Helvetica, Arial, sans-serif">'
            f'<title>{esc(title)}</title><desc>{desc}</desc>'
            f'<rect width="100%" height="100%" rx="8" fill="{t["surface"]}"/>' + "".join(out) + "</svg>\n")
