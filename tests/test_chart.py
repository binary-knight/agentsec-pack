"""The quick-look chart: axis states, the CLI command, and the README charts staying current."""
import json
import os
import subprocess
import sys

from agentsec import chart
from agentsec.cli import main
from agentsec.scoring import summarize

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


def _f(cat, sev, **ev):
    return {"id": "X", "category": cat, "severity": sev, "evidence": ev}


def test_axis_states_match_the_html_report():
    assert chart.axis_state([], "network") == ("sealed", None)
    assert chart.axis_state([_f("network", "info")], "network")[0] == "sealed"
    assert chart.axis_state([_f("secrets", "low")], "secrets")[0] == "low"
    assert chart.axis_state([_f("secrets", "medium")], "secrets") == ("reachable", "medium")
    assert chart.axis_state([_f("secrets", "low"), _f("secrets", "critical")], "secrets") == ("reachable", "critical")
    assert chart.axis_state([_f("network", "info", unmeasured=True)], "network")[0] == "unmeasured"


def test_every_state_has_a_glyph_so_color_never_carries_it_alone():
    glyphs = [s["glyph"] for s in chart.STATES.values()]
    assert len(set(glyphs)) == len(glyphs)
    svg = chart.render_svg([("", [chart.row_from_envelope({"summary": {"score": 0, "findings": []}, "label": "x"})])], "t")
    assert "✓" in svg and "<title>" in svg and 'role="img"' in svg


def test_chart_command_draws_svg_and_markdown(tmp_path):
    with open(os.path.join(HERE, "fixtures", "probe_open.json")) as f:
        probe = json.load(f)
    rep = tmp_path / "r.json"
    rep.write_text(json.dumps({"label": "open", "summary": summarize(probe), "probe": probe}))
    assert main(["chart", str(tmp_path), "--out", str(tmp_path / "c.svg")]) == 0
    assert (tmp_path / "c.svg").read_text().startswith("<svg")
    assert main(["chart", str(rep), "--out", str(tmp_path / "c.md")]) == 0
    assert "| open |" in (tmp_path / "c.md").read_text()


def test_the_readme_charts_are_current_with_the_reports():
    """Change a report without regenerating and this fails: the chart cannot drift from the data."""
    p = subprocess.run([sys.executable, os.path.join(REPO, "scripts", "readme_charts.py"), "--check"],
                       capture_output=True, text=True)
    assert p.returncode == 0, p.stdout + p.stderr
