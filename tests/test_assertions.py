"""`agentsec assert` answers a narrow question: can this sandbox reach these
specific paths? Requested by a reviewer whose recurring need was not a finding
list. Four grading tasks in one week had each hand-rolled a probe asking whether
a graded subprocess could read the sealed answer key, and the same bug was live
in two of them. A generic credential list would not catch that, because the file
that matters is a task artifact.
"""
import json
import os
import shutil
import subprocess
import sys

import pytest

from agentsec import assertions, runner
from agentsec.cli import main

HERE = os.path.dirname(os.path.abspath(__file__))


def _run_local(expectations):
    src = assertions.build_script(expectations)
    out = subprocess.run([sys.executable, "-c", src], capture_output=True, text=True).stdout
    return json.loads(out)["assertions"]


def test_a_readable_file_satisfies_readable_and_fails_not_readable(tmp_path):
    f = tmp_path / "key.txt"
    f.write_text("answer=42")
    exp = [("readable", str(f)), ("not-readable", str(f))]
    outcome = assertions.check(_run_local(exp), exp)
    rows = {r["kind"]: r for r in outcome["rows"]}
    assert rows["readable"]["ok"] is True
    assert rows["not-readable"]["ok"] is False
    assert rows["not-readable"]["observed"] == "READABLE"
    assert outcome["failed"] == 1


def test_absent_and_denied_are_reported_differently():
    """'Not there' and 'there but denied' are different sandbox designs, and a
    reader deciding whether containment holds needs to know which."""
    exp = [("not-readable", "/etc/shadow"), ("not-readable", "/no/such/path/at/all")]
    rows = assertions.check(_run_local(exp), exp)["rows"]
    observed = {r["path"]: r["observed"] for r in rows}
    assert observed["/no/such/path/at/all"] == "absent"
    if os.geteuid() != 0:
        assert observed["/etc/shadow"] == "present, denied"


def test_a_missing_file_counts_as_not_reachable(tmp_path):
    exp = [("not-readable", str(tmp_path / "nope"))]
    assert assertions.check(_run_local(exp), exp)["failed"] == 0


def test_writability_of_a_directory_is_tested_not_guessed(tmp_path):
    exp = [("writable", str(tmp_path)), ("not-writable", "/proc/sys/kernel")]
    rows = {r["kind"]: r for r in assertions.check(_run_local(exp), exp)["rows"]}
    assert rows["writable"]["ok"] is True
    if os.geteuid() != 0:
        assert rows["not-writable"]["ok"] is True


def test_an_untestable_path_fails_rather_than_passing_quietly():
    """Never let an error read as a satisfied expectation."""
    ok, observed = assertions.evaluate("not-readable", {"kind": "not-readable", "path": "/x",
                                                        "error": "PermissionError"})
    assert ok is False
    assert "could not be tested" in observed


def test_a_result_the_probe_never_reported_fails():
    outcome = assertions.check([], [("readable", "/etc/hostname")])
    assert outcome["failed"] == 1
    assert "not reported" in outcome["rows"][0]["observed"]


def test_cli_exits_two_when_an_expectation_is_violated(tmp_path):
    f = tmp_path / "key.txt"
    f.write_text("secret")
    assert main(["assert", "--not-readable", str(f)]) == 2
    assert main(["assert", "--readable", str(f)]) == 0


def test_cli_refuses_to_run_with_no_expectations():
    assert main(["assert"]) == 1


def test_cli_writes_a_machine_readable_result(tmp_path):
    out = tmp_path / "r.json"
    main(["assert", "--readable", "/etc/hostname", "--out", str(out)])
    d = json.loads(out.read_text())
    assert d["test"] == "path-assertions"
    assert d["target"]["kind"] == "local"
    assert d["rows"][0]["ok"] is True


@pytest.mark.skipif(not runner.sandbox_available("docker"), reason="no working docker daemon here")
def test_the_grading_case_end_to_end(tmp_path):
    """A mounted answer key is reachable; without the mount it is not."""
    key = tmp_path / "key.txt"
    key.write_text("answer=42")
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    mounted = main(["assert", "--kind", "docker", "--image", "python:3.12-slim",
                    "--not-readable", "/agentsec_key.txt", "--out", str(a),
                    "--", "-v", f"{key}:/agentsec_key.txt:ro"])
    assert mounted == 2, "a mounted key must be reported as reachable"
    got = json.loads(a.read_text())
    assert got["rows"][0]["observed"] == "READABLE"
    assert got["target"]["kind"] == "docker", "the check must have run inside the container"

    unmounted = main(["assert", "--kind", "docker", "--image", "python:3.12-slim",
                      "--not-readable", "/agentsec_key.txt", "--out", str(b)])
    assert unmounted == 0
    assert json.loads(b.read_text())["rows"][0]["observed"] == "absent"
