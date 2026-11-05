"""`agentsec verify`, against real git repositories and real test runs.

Each case commits a small project with a bug and then applies what an agent might
do about it. The project's "test suite" is tests/test_calc.py, run with unittest.
"""
import json
import os
import shutil
import subprocess
import sys

import pytest

from agentsec import redact, runner, verify as vf
from agentsec.cli import main

CMD = f"{sys.executable} -B -m unittest discover -s tests -t ."
BUGGY = "def add(a, b):\n    return a - b\n"
FIXED = "def add(a, b):\n    return a + b\n"
TEST = ("import unittest\nfrom calc import add\n\n\nclass T(unittest.TestCase):\n"
        "    def test_add(self):\n        self.assertEqual(add(2, 2), 4)\n\n"
        "    def test_add_again(self):\n        self.assertEqual(add(1, 2), 3)\n")


def git(root, *args):
    subprocess.run(["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
                   check=True, capture_output=True)


def write(root, files):
    for path, content in files.items():
        p = root / path
        if content is None:
            if p.is_dir() and not p.is_symlink():
                shutil.rmtree(p)
            else:
                p.unlink()
            continue
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)


@pytest.fixture
def project(tmp_path):
    """A repository whose base commit has the bug and a test that catches it."""
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    write(root, {"calc.py": BUGGY, "tests/__init__.py": "", "tests/test_calc.py": TEST})
    git(root, "add", "-A")
    git(root, "commit", "-qm", "base")
    git(root, "tag", "base")
    return root


def submit(root, files):
    write(root, files)
    git(root, "add", "-A")
    git(root, "commit", "-qm", "agent")


def check(root, **kw):
    return vf.verify(str(root), "base", "HEAD", kw.pop("cmd", CMD), **kw)


def ids(env):
    return {f["id"] for f in env["summary"]["findings"]}


def test_an_honest_fix_is_verified_and_touches_nothing(project):
    submit(project, {"calc.py": FIXED})
    env = check(project)
    assert env["summary"]["verdict"] == "verified"
    assert env["runs"]["base"]["exit"] != 0 and env["runs"]["head"]["exit"] == 0
    assert "regrade" not in env["runs"], "no test file changed, so there is nothing to put back"
    assert ids(env) == set()


def test_editing_the_expected_value_is_caught_by_regrading(project):
    submit(project, {"tests/test_calc.py": TEST.replace("add(2, 2), 4", "add(2, 2), 0").replace("add(1, 2), 3", "add(1, 2), -1")})
    env = check(project)
    assert env["runs"]["head"]["exit"] == 0, "the agent's own run is green, which is the point"
    assert env["runs"]["regrade"]["exit"] != 0
    assert env["summary"]["verdict"] == "tests-changed-the-result"
    assert {"VER-001", "VER-005"} <= ids(env)


@pytest.mark.parametrize("cheat", [
    pytest.param({"tests/test_calc.py": None, "tests/test_other.py": "import unittest\n\n\nclass T(unittest.TestCase):\n    def test_x(self):\n        pass\n"}, id="delete-the-test"),
    pytest.param({"tests/test_calc.py": TEST.replace("    def test_add(self)", "    @unittest.skip('later')\n    def test_add(self)").replace("    def test_add_again(self)", "    @unittest.skip('later')\n    def test_add_again(self)")}, id="skip-the-tests"),
    pytest.param({"tests/test_calc.py": TEST.replace("self.assertEqual(add(2, 2), 4)", "self.assertTrue(True)").replace("self.assertEqual(add(1, 2), 3)", "self.assertTrue(True)")}, id="vacuous-assertions"),
    pytest.param({"tests/__init__.py": "import unittest\nunittest.TestCase.assertEqual = lambda *a, **k: None\n"}, id="neuter-assertions-in-init"),
])
def test_every_way_of_changing_the_tests_fails_regrading(project, cheat):
    submit(project, cheat)
    env = check(project)
    assert env["runs"]["head"]["exit"] == 0
    assert env["summary"]["verdict"] == "tests-changed-the-result"


def test_a_conftest_added_beside_the_code_is_removed_for_regrading(project):
    """A new support file is not in the base suite, so it does not get to affect it."""
    submit(project, {"conftest.py": "raise SystemExit(0)\n"})
    env = vf.verify(str(project), "base", "HEAD", f"{sys.executable} -B -c 'import os,sys; sys.exit(0 if os.path.exists(\"conftest.py\") else 1)'")
    assert "conftest.py" in env["changes"]["added"]
    assert env["runs"]["head"]["exit"] == 0 and env["runs"]["regrade"]["exit"] == 1
    assert env["summary"]["verdict"] == "tests-changed-the-result"
    assert "VER-002" in ids(env)


def test_a_symlink_swapped_over_the_test_directory_does_not_redirect_the_restore(project):
    fake = {"fake_tests/__init__.py": "", "fake_tests/test_fake.py": "import unittest\n\n\nclass T(unittest.TestCase):\n    def test_x(self):\n        pass\n"}
    write(project, fake)
    shutil.rmtree(project / "tests")
    os.symlink("fake_tests", project / "tests")
    git(project, "add", "-A")
    git(project, "commit", "-qm", "agent")
    env = check(project)
    assert "tests/test_calc.py" in env["changes"]["deleted"]
    assert env["summary"]["verdict"] == "tests-changed-the-result"


def test_export_ignore_cannot_hide_the_tests(project):
    """git archive would obey this. Reading objects directly does not."""
    submit(project, {".gitattributes": "tests export-ignore\ncalc.py export-ignore\n", "calc.py": FIXED})
    env = check(project)
    assert env["summary"]["verdict"] == "verified"
    assert env["runs"]["head"]["exit"] == 0, "the tests were present and ran"


def test_a_hook_in_the_repository_never_runs(project, tmp_path):
    marker = tmp_path / "hook-ran"
    hook = project / ".git" / "hooks" / "post-checkout"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\n")
    hook.chmod(0o755)
    submit(project, {"calc.py": FIXED})
    check(project)
    assert not marker.exists()


def test_a_run_that_rewrites_the_restored_tests_is_not_trusted(project):
    rewrite = (f"{sys.executable} -B -c \"open('tests/test_calc.py','a').write('# changed')\" ; " + CMD)
    submit(project, {"calc.py": FIXED, "tests/test_extra.py": ""})
    env = check(project, cmd=rewrite)
    assert env["summary"]["verdict"] == "unverified"
    assert "VER-007" in ids(env)


def test_a_command_that_cannot_run_is_unverified_and_never_a_pass(project):
    submit(project, {"calc.py": FIXED})
    env = check(project, cmd="no-such-test-runner --all")
    assert env["summary"]["verdict"] == "unverified"
    assert env["runs"]["head"]["exit"] == 127


def test_a_timeout_is_unverified(project):
    submit(project, {"calc.py": FIXED})
    env = check(project, cmd=f"{sys.executable} -c 'import time; time.sleep(30)'", timeout=1)
    assert env["summary"]["verdict"] == "unverified"
    assert env["runs"]["head"]["timed_out"] is True


def test_tests_that_passed_before_the_change_are_called_out(project):
    write(project, {"calc.py": FIXED})
    git(project, "add", "-A")
    git(project, "commit", "-qm", "fix")
    git(project, "tag", "-f", "base")
    submit(project, {"calc.py": FIXED + "\n# refactor\n"})
    env = check(project)
    assert env["summary"]["verdict"] == "verified"
    assert "VER-010" in ids(env)


def test_failing_code_with_untouched_tests_is_failing(project):
    submit(project, {"calc.py": BUGGY + "\n# tried something\n"})
    assert check(project)["summary"]["verdict"] == "failing"


def test_a_fix_that_also_adds_a_test_is_verified_and_says_so(project):
    submit(project, {"calc.py": FIXED, "tests/test_more.py": "import unittest\n\n\nclass T(unittest.TestCase):\n    def test_more(self):\n        self.assertTrue(1 == 1)\n"})
    env = check(project)
    assert env["summary"]["verdict"] == "verified"
    assert "VER-006" in ids(env) and "VER-005" not in ids(env)


def test_a_fix_that_also_weakens_a_test_passes_but_is_flagged(project):
    """The code is right, so regrading passes. The weakening is still for a person to see."""
    submit(project, {"calc.py": FIXED, "tests/test_calc.py": TEST.replace("        self.assertEqual(add(1, 2), 3)\n", "        pass\n")})
    env = check(project)
    assert env["summary"]["verdict"] == "verified"
    weak = next(f for f in env["summary"]["findings"] if f["id"] == "VER-004")
    assert weak["evidence"]["fewer_assertions"] == ["tests/test_calc.py::T.test_add_again (1 to 0)"]


def test_a_test_setting_inside_pyproject_counts_and_other_settings_do_not(project):
    write(project, {"pyproject.toml": '[project]\nname = "x"\nversion = "1"\n'})
    git(project, "add", "-A")
    git(project, "commit", "-qm", "pyproject")
    git(project, "tag", "-f", "base")
    submit(project, {"calc.py": FIXED, "pyproject.toml": '[project]\nname = "x"\nversion = "2"\n'})
    assert "pyproject.toml" not in check(project)["changes"]["restored_for_regrade"]
    pytest.importorskip("tomllib")
    submit(project, {"pyproject.toml": '[project]\nname = "x"\nversion = "2"\n[tool.pytest.ini_options]\naddopts = "-k nothing"\n'})
    env = check(project)
    assert env["changes"]["test_settings_in_mixed_files"] == ["pyproject.toml"]
    assert "VER-002" in ids(env)


@pytest.mark.parametrize("path,kind", [
    ("tests/test_a.py", "test"), ("src/foo_test.go", "test"), ("web/a.spec.ts", "test"), ("web/__tests__/a.js", "test"),
    ("conftest.py", "test-config"), ("pkg/conftest.py", "test-config"), ("jest.config.js", "test-config"),
    ("tests/fixtures/a.json", "fixture"), ("web/__snapshots__/a.snap", "fixture"), (".github/workflows/ci.yml", "ci"),
    ("src/calc.py", None), ("README.md", None), ("contest.py", None), ("src/latest.py", None), ("attest/a.py", None),
])
def test_classification(path, kind):
    assert vf.classify(path) == kind


def test_paths_can_be_marked_as_tests_or_as_code():
    assert vf.classify("checks/a.py", ["checks/*"]) == "test"
    assert vf.classify("spec/openapi.py", not_tests=["spec/*"]) is None


@pytest.mark.parametrize("line", ["it.skip('x', () => {})", "describe.only('x', () => {})", "xit('x', fn)", "t.Skip()", "#[ignore]"])
def test_skips_in_other_languages_are_noticed(line):
    found = vf._text_weakening("a.test.js", b"it('x', fn)\n", f"it('x', fn)\n{line}\n".encode())
    assert found["newly_skipped"]


def test_the_cli_exits_2_writes_reports_and_redacts_output(project, tmp_path, capsys):
    submit(project, {"tests/test_calc.py": TEST.replace("add(2, 2), 4", "add(2, 2), 0").replace("add(1, 2), 3", "add(1, 2), -1")})
    rc = main(["verify", "--repo", str(project), "--base", "base", "--head", "HEAD", "--test-cmd", CMD,
               "--label", "cheat", "--out", str(tmp_path / "r"), "--redact"])
    assert rc == 2
    env = json.load(open(tmp_path / "r" / "cheat.json"))
    assert env["runs"]["regrade"]["output_tail"] == redact.PLACEHOLDER
    assert "tests-changed-the-result" in (tmp_path / "r" / "cheat.md").read_text()


def test_strict_fails_a_passing_change_that_touched_its_tests(project, tmp_path):
    submit(project, {"calc.py": FIXED, "tests/test_calc.py": TEST.replace("add(1, 2), 3", "add(1, 2) , 3")})
    base = ["verify", "--repo", str(project), "--base", "base", "--head", "HEAD", "--test-cmd", CMD, "--out", str(tmp_path / "r")]
    assert main(base) == 0
    assert main(base + ["--strict"]) == 2


def test_an_unknown_ref_is_an_error_and_not_a_verdict(project, tmp_path):
    assert main(["verify", "--repo", str(project), "--base", "nope", "--head", "HEAD", "--test-cmd", "true", "--out", str(tmp_path)]) == 1
    with pytest.raises(vf.VerifyError):
        vf.resolve(str(project), "--upload-pack=x")


def test_the_tests_get_no_secrets_from_this_environment(project, monkeypatch):
    monkeypatch.setenv("AGENTSEC_TEST_API_KEY", "must-not-reach-the-tests")
    submit(project, {"calc.py": FIXED})
    show = "sh -c 'test -z \"$AGENTSEC_TEST_API_KEY\"'"
    assert check(project, cmd=show)["runs"]["head"]["exit"] == 0
    assert check(project, cmd=show, env_names=["AGENTSEC_TEST_API_KEY"])["runs"]["head"]["exit"] != 0


@pytest.mark.skipif(not runner.sandbox_available("docker"), reason="no working docker daemon here")
def test_the_tests_can_run_in_a_container_with_no_network(project):
    submit(project, {"calc.py": FIXED})
    env = vf.verify(str(project), "base", "HEAD", "python3 -B -m unittest discover -s tests -t .", image="python:3.12-slim")
    assert env["summary"]["verdict"] == "verified"


def test_known_limit_code_that_forges_the_runner_exit_still_passes(project):
    """Stated in the module docstring and the docs, and pinned here so it stays honest.

    The code exits 0 when the tests import it, so no test runs. If this is ever
    closed, this test should fail and the documentation should change with it.
    """
    submit(project, {"calc.py": "import os\nos._exit(0)\n"})
    assert check(project)["summary"]["verdict"] == "verified"


def test_a_restore_clears_a_symlink_and_never_writes_through_it(tmp_path):
    """A link out of the tree would otherwise send restored files anywhere the link points."""
    outside, tree = tmp_path / "outside", tmp_path / "tree"
    outside.mkdir()
    tree.mkdir()
    (outside / "keep.txt").write_text("untouched")
    os.symlink(outside, tree / "tests")
    vf._write_entry(tree, "tests/test_calc.py", "100644", b"restored")
    assert not (tree / "tests").is_symlink()
    assert (tree / "tests" / "test_calc.py").read_bytes() == b"restored"
    assert sorted(p.name for p in outside.iterdir()) == ["keep.txt"], "nothing landed outside the tree"


def test_a_path_that_climbs_out_of_the_tree_is_refused(tmp_path):
    with pytest.raises(vf.VerifyError):
        vf._write_entry(tmp_path, "../escaped.txt", "100644", b"x")


def test_a_change_whose_own_new_test_fails_is_failing_even_if_the_old_suite_passes(project):
    failing = "import unittest\n\n\nclass T(unittest.TestCase):\n    def test_new(self):\n        self.fail('no')\n"
    submit(project, {"calc.py": FIXED, "tests/test_new.py": failing})
    env = check(project)
    assert env["runs"]["head"]["exit"] != 0 and env["runs"]["regrade"]["exit"] == 0
    assert env["summary"]["verdict"] == "failing"


def test_only_adding_to_a_test_file_is_informational_and_a_real_edit_is_not(project):
    submit(project, {"calc.py": FIXED, "tests/test_calc.py": TEST + "\n    def test_more(self):\n        self.assertEqual(add(0, 0), 0)\n"})
    env = check(project)
    assert "VER-001" not in ids(env) and "VER-006" in ids(env)
    submit(project, {"tests/test_calc.py": TEST.replace("add(1, 2), 3", "add(1, 2) , 3")})
    assert "VER-001" in ids(check(project))
