"""Published figures from submissions: no single person sets them or can be read out of them."""
import json

import pytest

from agentsec import benchmark as bm
from agentsec.chart import AXES
from agentsec.cli import main
from agentsec.submit import DATASET


def record(score=50, **changed):
    return {"schema": 1, "agent": "some agent", "agent_version": "1.0", "sandbox_mode": "on", "settings": [], "os_family": "linux",
            "probe_version": "0.6.0", "axes": {a: "sealed" for a in AXES}, "finding_ids": ["NET-001"], "score": score, **changed}


def issue(login, rec, created="2026-11-01", **extra):
    return {"author": {"login": login}, "createdAt": created, "labels": [], "body": f"text\n\n```json\n{json.dumps(rec)}\n```\n", **extra}


def many(n, **changed):
    return [issue(f"person{i}", record(score=10 * (i + 1), **changed)) for i in range(n)]


def test_a_configuration_appears_only_at_the_threshold_of_different_accounts():
    assert bm.aggregate(many(4))["community"] == []
    assert bm.aggregate(many(4))["below_threshold"] == 1
    figures = bm.aggregate(many(5))["community"]
    assert [(f["submitters"], f["median_score"]) for f in figures] == [(5, 30)]


def test_one_account_counts_once_however_many_it_posts():
    flood = [issue("Mallory", record(score=100), created=f"2026-11-0{i}") for i in range(1, 9)]
    result = bm.aggregate(flood + many(3), min_submitters=5)
    assert result["community"] == [] and result["below_threshold"] == 1


def test_an_accounts_name_in_another_case_is_the_same_account():
    posts = [issue("Mallory", record(score=100)), issue("mallory", record(score=100), created="2026-11-02")]
    assert bm.aggregate(posts + many(3), min_submitters=5)["community"] == []


def test_an_accounts_newest_record_is_the_one_that_counts_whatever_order_they_arrive_in():
    posts = [issue("a", record(score=90), created="2026-11-09"), issue("a", record(score=10), created="2026-11-01")] + many(2)
    figure = bm.aggregate(posts, min_submitters=3)["community"][0]
    assert figure["median_score"] == 20  # 10 and 20 from the others, and a's newest, 90


def test_a_figure_holds_nothing_one_record_can_be_read_back_from():
    figure = bm.aggregate(many(5))["community"][0]
    assert not {"finding_ids", "score", "login", "records", "min", "max"} & set(figure)
    assert "person" not in json.dumps(figure)


def test_different_settings_and_probe_versions_are_not_mixed():
    posts = many(3) + many(3, settings=["a"]) + many(3, probe_version="0.7.0")
    result = bm.aggregate(posts, min_submitters=3)
    assert len(result["community"]) == 3


def test_setting_order_does_not_split_a_configuration():
    assert bm.configuration(record(settings=["a", "b"])) == bm.configuration(record(settings=["b", "a"]))


@pytest.mark.parametrize("bad", [
    {"author": {"login": "x"}, "body": "no record here"},
    {"author": {"login": "x"}, "body": "```json\nnot json\n```"},
    issue("x", {**record(), "hostname": "laptop"}),
    issue("x", record(score=101)),
    issue("x", record(), labels=[{"name": "rejected"}]),
    {"author": {"login": "app", "is_bot": True}, "body": issue("a", record())["body"]},
    {"author": None, "body": issue("a", record())["body"]},
])
def test_what_cannot_be_trusted_is_refused_and_counted(bad):
    result = bm.aggregate([bad])
    assert result["refused"] == 1 and result["community"] == [] and result["below_threshold"] == 0


def test_the_threshold_cannot_be_set_low_enough_to_expose_someone():
    with pytest.raises(bm.BenchmarkError):
        bm.aggregate(many(5), min_submitters=2)


def test_reproduced_results_are_shown_apart_and_say_where_they_came_from():
    result = bm.aggregate(many(1), [{"record": record(score=7), "source": "maintainer run 123"}])
    assert result["community"] == []
    assert [(f["source"], f["median_score"], f["runs"]) for f in result["reproduced"]] == [("maintainer run 123", 7, 1)]
    with pytest.raises(bm.BenchmarkError):
        bm.aggregate([], [{"record": record()}])
    with pytest.raises(bm.BenchmarkError):
        bm.aggregate([], [{"record": {"score": 1}, "source": "x"}])


def test_the_command_prints_markdown_and_json(tmp_path, capsys):
    path = tmp_path / "issues.json"
    path.write_text(json.dumps(many(5)))
    assert main(["benchmark", "--issues", str(path)]) == 0
    out = capsys.readouterr().out
    assert "some agent 1.0" in out and "| 30 | 5" in out and "person" not in out
    assert main(["benchmark", "--issues", str(path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["community"][0]["submitters"] == 5
    assert main(["benchmark", "--issues", str(path), "--min-submitters", "1"]) == 1


def test_a_file_that_is_not_a_list_of_issues_is_an_error_not_an_empty_benchmark(tmp_path):
    path = tmp_path / "issues.json"
    path.write_text("{}")
    assert main(["benchmark", "--issues", str(path)]) == 1


def test_submit_goes_to_the_dataset_by_default_and_says_what_posting_means():
    from agentsec import submit
    assert DATASET == "binary-knight/agentsec-benchmark"
    assert "CC0-1.0" in submit.urllib.parse.unquote(submit.issue_url(DATASET, "{}", record()))


def test_an_axis_shows_the_state_most_accounts_saw():
    states = {a: "sealed" for a in AXES}
    axis = AXES[0]
    posts = many(3, axes={**states, axis: "reachable"}) + [issue("other", record(axes=states))]
    assert bm.aggregate(posts, min_submitters=3)["community"][0]["axes"][axis] == "reachable"
