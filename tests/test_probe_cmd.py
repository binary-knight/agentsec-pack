"""`agentsec probe`: measure the sandbox you are standing in, in one step."""
import json
import os

import pytest

from agentsec import runner
from agentsec.cli import main


def test_probe_writes_a_scored_report_that_records_how(tmp_path, capsys):
    rc = main(["probe", "--label", "here", "--how", "pytest, in-process", "--out", str(tmp_path)])
    assert rc == 0
    env = json.load(open(tmp_path / "here.json"))
    assert env["target"]["kind"] == "self"
    assert env["target"]["how"] == "pytest, in-process"
    assert env["target"]["proxy_auth"] is False
    assert "score" in env["summary"] and env["probe"]["probe_version"]


@pytest.mark.parametrize("missing", ["--label", "--how"])
def test_probe_refuses_to_measure_without_provenance(missing, tmp_path):
    argv = ["probe", "--label", "x", "--how", "y", "--out", str(tmp_path)]
    i = argv.index(missing)
    del argv[i:i + 2]
    with pytest.raises(SystemExit) as e:
        main(argv)
    assert e.value.code == 2


def test_proxy_auth_is_off_unless_asked_and_recorded_when_asked(monkeypatch):
    # Clear every proxy variable first: with the opt-in on, the probe would
    # otherwise send whatever proxy this test runs behind its real password.
    for k in list(os.environ):
        if k.upper() in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"):
            monkeypatch.delenv(k)
    monkeypatch.delenv(runner.PROXY_AUTH_ENV, raising=False)
    assert runner.run_self()["target"]["proxy_auth"] is False
    assert runner.run_self(proxy_auth=True)["target"]["proxy_auth"] is True
    assert runner.PROXY_AUTH_ENV not in os.environ, "the flag must not leak into this process's environment"


def test_an_unwritable_out_dir_hands_the_report_back_on_stdout(capsys):
    rc = main(["probe", "--label", "ro", "--how", "read-only", "--out", "/dev/null/reports"])
    out = capsys.readouterr()
    assert rc == 0
    env = json.loads(out.out.strip().splitlines()[-1])
    assert env["label"] == "ro" and env["summary"]["findings"] is not None
    assert "could not write" in out.err


def test_probe_gates_like_the_other_commands(tmp_path):
    assert main(["probe", "--label", "g", "--how", "t", "--out", str(tmp_path), "--max-score", "-1"]) == 2
