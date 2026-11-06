"""`agentsec history`: the comparison, the saved file, and what the file must not hold."""
import copy
import glob
import json
import os

import pytest

from agentsec import baseline, history as hs
from agentsec.cli import main

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def report(score, findings, at, label="box", version="0.6.0", hostname="host-name"):
    return {"tool": "agentsec-pack", "test": "sandbox-blast-radius", "label": label, "generated_at": at, "target": {"kind": "docker", "label": label},
            "summary": {"score": score, "findings": findings}, "probe": {"probe_version": version, "identity": {"hostname": hostname}}}


def f(fid, severity="medium", **evidence):
    return {"id": fid, "severity": severity, "title": f"title of {fid}", "category": "secrets", "evidence": evidence}


def saved(tmp_path, *reports):
    paths = []
    for i, r in enumerate(reports):
        p = tmp_path / f"r{i}.json"
        p.write_text(json.dumps(r))
        paths.append(str(p))
    return paths


def test_a_new_finding_is_shown_at_the_run_it_appeared():
    h = hs.build([hs.entry(report(15, [], 100)), hs.entry(report(23, [f("FS-003")], 200))])["box"]
    assert [r["score"] for r in h["runs"]] == [15, 23]
    assert h["runs"][0]["change"] is None
    assert h["runs"][1]["change"]["regressions"][0]["id"] == "FS-003"
    assert "new FS-003 [medium]" in hs.render({"box": h})


def test_runs_are_put_in_order_whatever_order_they_are_read_in():
    h = hs.build([hs.entry(report(23, [f("FS-003")], 200)), hs.entry(report(15, [], 100))])["box"]
    assert [r["generated_at"] for r in h["runs"]] == [100, 200]
    assert (h["first"], h["last"]) == (15, 23)


def test_drift_under_a_steady_score_is_still_shown():
    """One finding fixed and another of the same weight gained: the total hides it."""
    h = hs.build([hs.entry(report(8, [f("FS-003")], 100)), hs.entry(report(8, [f("SEC-001")], 200))])["box"]
    assert h["first"] == h["last"]
    text = hs.render({"box": h})
    assert "new SEC-001" in text and "gone FS-003" in text
    assert h["worsened_since_first"]


def test_one_more_reachable_thing_is_widening_even_with_the_names_hashed():
    one = report(8, [f("SEC-001", names=["A_TOKEN"])], 100)
    two = report(8, [f("SEC-001", names=["A_TOKEN", "B_TOKEN"])], 200)
    h = hs.build([hs.entry(one), hs.entry(two)])["box"]
    assert h["runs"][1]["change"]["regressions"][0]["kind"] == "widened"
    assert "SEC-001 reaches 1 more" in hs.render({"box": h})


def test_a_swapped_reachable_thing_is_noticed_with_the_same_count():
    one = report(8, [f("SEC-001", names=["A_TOKEN"])], 100)
    two = report(8, [f("SEC-001", names=["B_TOKEN"])], 200)
    assert hs.build([hs.entry(one), hs.entry(two)])["box"]["worsened_since_first"]


def test_a_changed_probe_is_called_out_on_that_step():
    h = hs.build([hs.entry(report(0, [], 100, version="0.5.0")), hs.entry(report(8, [f("FS-003")], 200))])["box"]
    assert "probe changed" in hs.render({"box": h})


def test_labels_do_not_mix():
    h = hs.build([hs.entry(report(0, [], 100, label="a")), hs.entry(report(8, [], 200, label="b"))])
    assert sorted(h) == ["a", "b"]
    assert h["a"]["runs"][0]["change"] is None and h["b"]["runs"][0]["change"] is None


def test_the_budget_margin_is_shown_either_way():
    es = [hs.entry(report(40, [], 100))]
    assert "Budget 45: 5 left." in hs.render(hs.build(es, 45), 45)
    assert "Budget 30: over by 10." in hs.render(hs.build(es, 30), 30)


def test_the_saved_line_holds_no_name_a_report_holds():
    env = report(8, [f("SEC-001", names=["SECRET_NAME_A"], paths=["/srv/someone/secret-path"], other="/srv/someone/other-evidence")], 100)
    env["target"]["how"] = "run from /srv/someone/project"
    env["probe_stderr"] = "/srv/someone/stderr"
    line = json.dumps(hs.entry(env))
    for name in ("SECRET_NAME_A", "someone", "host-name", "secret-path", "other-evidence"):
        assert name not in line


def test_the_saved_line_is_compared_exactly_as_the_gate_compares_the_full_reports():
    """Every pair of real reports here: history and the gate have to agree on what got worse."""
    envs = []
    for path in sorted(glob.glob(os.path.join(REPO, "examples", "agents", "*.json"))):
        with open(path) as fh:
            data = json.load(fh)
        if "summary" in data and data.get("probe"):
            envs.append(data)
    assert len(envs) >= 4
    for a, b in zip(envs, envs[1:]):
        full, short = baseline.compare(a, b), baseline.compare(hs.entry(a), hs.entry(b))
        pick = lambda rs: sorted((r["id"], r["kind"]) for r in rs)  # noqa: E731
        assert pick(full["regressions"]) == pick(short["regressions"])
        assert sorted(x["id"] for x in full["fixed"]) == sorted(x["id"] for x in short["fixed"])


def test_saving_twice_adds_nothing_the_second_time(tmp_path):
    paths = saved(tmp_path, report(0, [], 100), report(8, [f("FS-003")], 200))
    out = tmp_path / "history.jsonl"
    assert hs.save(str(out), [hs.entry(json.loads(open(p).read())) for p in paths]) == 2
    assert hs.save(str(out), [hs.entry(json.loads(open(p).read())) for p in paths]) == 0
    assert len(out.read_text().splitlines()) == 2


def test_a_replaced_report_survives_in_the_history_file(tmp_path, capsys):
    out, rep = tmp_path / "history.jsonl", tmp_path / "box.json"
    rep.write_text(json.dumps(report(15, [], 100)))
    assert main(["history", str(rep), "--save", str(out)]) == 0
    rep.write_text(json.dumps(report(23, [f("FS-003")], 200)))
    assert main(["history", str(rep), "--save", str(out), "--max-score", "45"]) == 0
    text = capsys.readouterr().out
    assert "2 runs, score 15 to 23" in text and "new FS-003" in text and "22 left" in text


def test_the_cli_reads_a_directory_and_prints_json(tmp_path, capsys):
    saved(tmp_path, report(0, [], 100), report(8, [f("FS-003")], 200))
    assert main(["history", str(tmp_path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["box"]["last"] == 8


def test_real_reports_in_this_repository_are_read(capsys):
    assert main(["history", os.path.join(REPO, "examples", "agents")]) == 0
    captured = capsys.readouterr()
    assert "## aider-0.86.2-default" in captured.out
    assert "not a blast-radius report" not in captured.err


def test_other_kinds_of_report_are_skipped_and_said_to_be(tmp_path, capsys):
    paths = saved(tmp_path, {"test": "verifier-integrity", "summary": {}}, report(0, [], 100))
    (tmp_path / "broken.json").write_text("{")
    assert main(["history", str(tmp_path)]) == 0
    err = capsys.readouterr().err
    assert paths[0] in err and "broken.json" in err


def test_a_damaged_history_file_is_reported_and_the_rest_still_read(tmp_path, capsys):
    p = tmp_path / "h.jsonl"
    good = json.dumps(hs.entry(report(0, [], 100)))
    p.write_text("{\n" + '{"label": "box"}\n' + good + "\n")
    assert main(["history", str(p)]) == 0
    captured = capsys.readouterr()
    assert "h.jsonl:1" in captured.err and "h.jsonl:2" in captured.err
    assert "1 run," in captured.out


def test_nothing_to_read_is_an_error_and_not_an_empty_table(tmp_path, capsys):
    assert main(["history", str(tmp_path)]) == 1
    assert main(["history", str(tmp_path / "missing.json")]) == 1


def test_label_narrows_what_is_shown_and_saved(tmp_path, capsys):
    saved(tmp_path, report(0, [], 100, label="a"), report(8, [], 200, label="b"))
    out = tmp_path / "keep.jsonl"
    assert main(["history", str(tmp_path), "--label", "a", "--save", str(out)]) == 0
    assert "## a" in capsys.readouterr().out
    assert [json.loads(x)["label"] for x in out.read_text().splitlines()] == ["a"]


def test_a_history_line_is_not_changed_by_reading_it_back(tmp_path):
    p = tmp_path / "h.jsonl"
    e = hs.entry(report(8, [f("FS-003", paths=["/srv/someone"])], 100))
    hs.save(str(p), [copy.deepcopy(e)])
    assert hs.load([str(p)])[0] == [e]
