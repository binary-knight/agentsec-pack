"""The promises in docs/COMPATIBILITY.md, each as a test that fails if it breaks."""
import copy
import json
import re
from pathlib import Path

import jsonschema
import pytest

from agentsec import __version__
from agentsec import baseline as bl
from agentsec import scoring
from agentsec.cli import main

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "agentsec" / "data"
SCORING_SRC = (ROOT / "agentsec" / "scoring.py").read_text()


def _schema(name):
    schema = json.loads((DATA / name).read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    return schema


def _example_reports():
    out = []
    for p in sorted((ROOT / "examples").rglob("*.json")):
        d = json.loads(p.read_text())
        if isinstance(d, dict) and d.get("test") == "sandbox-blast-radius":
            out.append(p)
    return out


REPORTS = _example_reports()


def test_examples_exist():
    assert len(REPORTS) >= 50


@pytest.mark.parametrize("path", REPORTS, ids=lambda p: str(p.relative_to(ROOT)))
def test_every_example_report_matches_the_schema(path):
    jsonschema.validate(json.loads(path.read_text()), _schema("blast-radius-report.schema.json"))


def test_the_schema_declares_every_field_the_examples_use():
    """additionalProperties stays open for readers, so this is what catches an undocumented field."""
    schema = _schema("blast-radius-report.schema.json")
    declared = {
        "envelope": set(schema["properties"]),
        "target": set(schema["$defs"]["target"]["properties"]),
        "summary": set(schema["$defs"]["summary"]["properties"]),
        "finding": set(schema["$defs"]["finding"]["properties"]),
    }
    seen = {k: set() for k in declared}
    for p in REPORTS:
        d = json.loads(p.read_text())
        seen["envelope"] |= set(d)
        seen["target"] |= set(d["target"])
        seen["summary"] |= set(d["summary"])
        for f in d["summary"]["findings"]:
            seen["finding"] |= set(f)
    for part in declared:
        assert seen[part] <= declared[part], f"{part}: undeclared {sorted(seen[part] - declared[part])}"


def test_a_fresh_report_matches_the_schema_and_records_the_version(tmp_path):
    src = REPORTS[0]
    probe = json.loads(src.read_text())["probe"]
    pf = tmp_path / "probe.json"
    pf.write_text(json.dumps(probe))
    out = tmp_path / "r"
    main(["score", str(pf), "--label", "fresh", "--how", "test", "--out", str(out)])
    report = json.loads((out / "fresh.json").read_text())
    jsonschema.validate(report, _schema("blast-radius-report.schema.json"))
    assert report["agentsec_version"] == __version__


def test_an_assert_result_matches_its_schema(tmp_path):
    readable = tmp_path / "f.txt"
    readable.write_text("x")
    out = tmp_path / "assert.json"
    main(["assert", "--readable", str(readable), "--not-readable", str(tmp_path / "absent"), "--out", str(out)])
    result = json.loads(out.read_text())
    jsonschema.validate(result, _schema("path-assertions.schema.json"))
    assert result["agentsec_version"] == __version__


def test_the_weights_are_the_documented_ones():
    assert scoring.SEVERITY_WEIGHT == {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}


def test_the_score_is_the_raw_score_capped_at_100():
    f = scoring.Finding("NET-001", "t", "critical", "network")
    assert scoring.score([f] * 5) == 100
    assert scoring.raw_score([f] * 5) == 125


def _constructed():
    """Each finding id the scorer can emit, with the severity argument as written."""
    found = {}
    for m in re.finditer(r'_f\(\s*"([A-Z]+-\d{3})",\s*(?:\(?\s*f?"(?:[^"\\]|\\.)*"\s*)+\)?,\s*([^,]+),', SCORING_SRC):
        found.setdefault(m.group(1), set()).add(m.group(2).strip())
    return found


def test_every_finding_id_fits_the_schema():
    schema = _schema("blast-radius-report.schema.json")
    pattern = re.compile(schema["$defs"]["finding"]["properties"]["id"]["pattern"])
    ids = set(re.findall(r'_f\(\s*"([A-Z]+-\d{3})"', SCORING_SRC))
    assert ids and all(pattern.match(i) for i in ids)
    assert set(_constructed()) == ids


def test_only_the_documented_findings_take_their_severity_from_evidence():
    variable = sorted(i for i, sev in _constructed().items()
                      if len(sev) > 1 or not re.fullmatch(r'"(critical|high|medium|low|info)"', next(iter(sev))))
    assert variable == ["FS-001", "PRIV-003"], "update docs/COMPATIBILITY.md if this list changes"


def test_a_version_difference_alone_passes_the_baseline_gate_with_a_note():
    base = json.loads((ROOT / "examples" / "slim_hardened_online.json").read_text())
    cur = copy.deepcopy(base)
    cur["probe"]["probe_version"] = "9.9.9"
    base["agentsec_version"], cur["agentsec_version"] = "0.4.0", "9.9.9"
    result = bl.compare(base, cur)
    assert result["regressions"] == []
    assert result["instrument_changed"] and result["scorer_changed"]
    text = bl.render(result)
    assert "probe 0.4.0" in text and "agentsec 0.4.0" in text and text.endswith("OK: nothing is worse than the baseline")


def test_a_rescored_severity_still_fails_the_baseline_gate():
    base = json.loads((ROOT / "examples" / "slim_hardened_online.json").read_text())
    cur = copy.deepcopy(base)
    f = next(f for f in cur["summary"]["findings"] if f["severity"] != "critical")
    f["severity"] = "critical"
    base["agentsec_version"], cur["agentsec_version"] = "0.4.0", "9.9.9"
    result = bl.compare(base, cur)
    assert [r["kind"] for r in result["regressions"]] == ["severity"]


def test_a_report_without_agentsec_version_is_not_a_change():
    base = json.loads((ROOT / "examples" / "slim_hardened_online.json").read_text())
    cur = copy.deepcopy(base)
    cur["agentsec_version"] = __version__
    assert bl.compare(base, cur)["scorer_changed"] is False


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
    out = capsys.readouterr().out
    assert out.startswith(f"agentsec-pack {__version__}, probe ")


def test_experimental_commands_say_so(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    help_text = capsys.readouterr().out
    for cmd in ("verify", "submit", "benchmark"):
        line = next(l for l in help_text.splitlines() if l.strip().startswith(cmd + " ") or l.strip() == cmd)
        idx = help_text.splitlines().index(line)
        assert "(experimental)" in " ".join(help_text.splitlines()[idx:idx + 2]), cmd


STABLE = ["presets", "probe", "blast-radius", "matrix", "score", "assert", "diff", "history", "report", "chart", "ui",
          "combine", "compare"]


def _flags(cmd):
    import contextlib
    import io
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.suppress(SystemExit):
        main([cmd, "--help"])
    assert f"usage: agentsec {cmd}" in buf.getvalue(), f"agentsec {cmd} is gone"
    return sorted(set(re.findall(r"(?<![\w-])(--[a-z][a-z0-9-]*)", buf.getvalue())) - {"--help"})


def test_the_stable_commands_are_the_documented_ones():
    doc = (ROOT / "docs" / "COMPATIBILITY.md").read_text()
    line = next(l for l in doc.splitlines() if l.startswith("**Commands and flags.**"))
    assert re.findall(r"`([a-z-]+)`", line) == STABLE


@pytest.mark.parametrize("cmd", STABLE)
def test_no_stable_flag_disappears(cmd):
    """A new flag is fine: add it to tests/fixtures/cli_surface.json. A missing one breaks a promise."""
    recorded = json.loads((ROOT / "tests" / "fixtures" / "cli_surface.json").read_text())[cmd]
    now = _flags(cmd)
    assert set(recorded) <= set(now), f"removed: {sorted(set(recorded) - set(now))}"
    assert set(now) <= set(recorded), f"new flags, record them: {sorted(set(now) - set(recorded))}"


def test_exit_codes(tmp_path):
    probe = json.loads((ROOT / "examples" / "slim_default.json").read_text())["probe"]
    pf = tmp_path / "probe.json"
    pf.write_text(json.dumps(probe))
    common = ["score", str(pf), "--label", "x", "--how", "test", "--out", str(tmp_path / "r")]
    assert main(common + ["--max-score", "100"]) == 0
    assert main(common + ["--max-score", "10"]) == 2
    assert main(["assert"]) == 1


def test_the_action_keeps_its_inputs_and_outputs():
    text = (ROOT / "action.yml").read_text()
    inputs = text.split("\ninputs:\n", 1)[1].split("\noutputs:\n", 1)[0]
    outputs = text.split("\noutputs:\n", 1)[1].split("\nruns:\n", 1)[0]
    names = lambda block: re.findall(r"^  ([a-z][a-z-]*):", block, re.M)
    assert names(inputs) == ["image", "preset", "engine", "flags", "max-score", "baseline", "label", "redact", "out",
                             "upload"]
    assert names(outputs) == ["score", "report"]
