"""`agentsec submit`: what a record may hold, and that only a person can send one."""
import io
import json
import os
import socket
import urllib.parse

import pytest

from agentsec import submit as sb
from agentsec.cli import main

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PRIVATE = ["box-of-someone", "/home/someone", "/srv/mount-point", "MY_SECRET_TOKEN", "secret-project", "pid1-command"]


def poisoned():
    """A report with something private in every place a report can hold it."""
    return {"tool": "agentsec-pack", "test": "sandbox-blast-radius", "label": "secret-project on box-of-someone", "generated_at": 1,
            "target": {"how": "ran from /home/someone/secret-project", "note": "MY_SECRET_TOKEN", "image": "secret-project:latest"},
            "probe_stderr": "/home/someone", "rc": 0,
            "probe": {"probe_version": "0.6.0", "platform": "linux", "identity": {"hostname": "box-of-someone", "cwd": "/home/someone"},
                      "process": {"pid1_cmdline": "pid1-command"},
                      "secrets": {"env_secret_names": [{"name": "MY_SECRET_TOKEN", "length": 8}]},
                      "filesystem": {"mounts": ["/srv/mount-point"]}},
            "summary": {"score": 33, "recommended_flags": ["/home/someone"],
                        "findings": [{"id": "SEC-001", "severity": "high", "category": "secrets", "title": "title with /home/someone",
                                      "evidence": {"names": ["MY_SECRET_TOKEN"], "paths": ["/srv/mount-point"]}, "remediation": "secret-project"},
                                     {"id": "NET-004", "severity": "info", "category": "network", "title": "not measured", "evidence": {"unmeasured": True}}]}}


def good_record(**over):
    return sb.build_record(poisoned(), over.get("agent", "vendor-agent"), over.get("version", "1.2.3"), over.get("mode", "workspace-write"), over.get("settings", ["network=off"]))


def test_a_record_holds_exactly_the_listed_fields_and_nothing_private():
    record = good_record()
    assert set(record) == sb.SUBMITTED
    assert record["finding_ids"] == ["NET-004", "SEC-001"]
    assert record["axes"] == {"privilege": "sealed", "network": "unmeasured", "secrets": "reachable", "filesystem": "sealed", "process": "sealed"}
    assert (record["score"], record["os_family"], record["probe_version"]) == (33, "linux", "0.6.0")
    text = json.dumps(record)
    for private in PRIVATE:
        assert private not in text


@pytest.mark.parametrize("field", ["agent", "version", "mode"])
@pytest.mark.parametrize("bad", ["/home/x/agent", "..\\agent", "~/.config", "user@host", "MY_API_KEY", "a:b", "$HOME", "x\ny", "box-of-someone", "BOX-OF-SOMEONE build", "my_secret_token"])
def test_words_that_look_private_are_refused(field, bad):
    with pytest.raises(sb.SubmitError):
        good_record(**{field: bad})


@pytest.mark.parametrize("bad", ["denyRead=~/", "/etc/passwd", "ANTHROPIC_API_KEY=x", "allow=box-of-someone"])
def test_a_setting_that_looks_private_is_refused(bad):
    with pytest.raises(sb.SubmitError):
        good_record(settings=[bad])


def test_this_machines_names_are_refused(monkeypatch):
    monkeypatch.setenv("USER", "someuser")
    monkeypatch.setattr(socket, "gethostname", lambda: "myworkstation")
    for bad in ("someuser", "agent on myworkstation"):
        with pytest.raises(sb.SubmitError):
            good_record(mode=bad)


def test_a_short_username_does_not_refuse_ordinary_words(monkeypatch):
    monkeypatch.setenv("USER", "al")
    assert good_record(mode="always-allow network")["sandbox_mode"] == "always-allow network"


def test_a_redacted_report_is_accepted():
    env = poisoned()
    env["probe"]["identity"]["hostname"] = "<redacted>"
    env["probe"]["secrets"]["env_secret_names"] = [{"name": "<redacted>", "length": 8}]
    assert sb.build_record(env, "agent", "1", "default", [])["score"] == 33


def test_a_report_with_no_probe_version_builds_no_record():
    env = poisoned()
    del env["probe"]["probe_version"]
    with pytest.raises(sb.SubmitError):
        sb.build_record(env, "agent", "1", "default", [])


def test_real_reports_in_this_repository_build_a_record():
    for name in ("aider-0.86.2-default", "claude-code-2.1.266-default-no-sandbox"):
        with open(os.path.join(REPO, "examples", "agents", name + ".json")) as f:
            env = json.load(f)
        record = sb.build_record(env, "agent", "1.0", "default", [])
        sb.check_record(record)
        assert record["score"] == env["summary"]["score"]


@pytest.mark.parametrize("env", [{"test": "verifier-integrity", "summary": {}}, {"test": "sandbox-blast-radius-matrix", "runs": []}, {"test": "sandbox-blast-radius"}])
def test_other_kinds_of_file_are_refused(env):
    with pytest.raises(sb.SubmitError):
        sb.build_record(env, "agent", "1", "default", [])


@pytest.mark.parametrize("change", [
    {"hostname": "x"},
    {"agent": "/home/x"},
    {"settings": ["MY_API_KEY"]},
    {"settings": "plain"},
    {"os_family": "someone's laptop"},
    {"probe_version": "/x"},
    {"probe_version": None},
    {"axes": {"privilege": "sealed"}},
    {"axes": {"privilege": "/x", "network": "sealed", "secrets": "sealed", "filesystem": "sealed", "process": "sealed"}},
    {"finding_ids": ["/home/x"]},
    {"finding_ids": ["SEC-001", "MY_SECRET"]},
    {"score": 101},
    {"score": True},
    {"schema": 2},
])
def test_a_dataset_can_check_what_it_receives(change):
    record = dict(good_record(), **change)
    with pytest.raises(sb.SubmitError):
        sb.check_record(record)


def test_the_issue_holds_the_record_exactly_as_it_was_shown():
    record = good_record()
    text = json.dumps(record, indent=2, sort_keys=True)
    url = sb.issue_url("owner/dataset", text, record)
    assert url.startswith("https://github.com/owner/dataset/issues/new?")
    q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert text in q["body"][0]
    assert q["title"] == ["vendor-agent 1.2.3, workspace-write: 33"]


@pytest.mark.parametrize("repo", ["owner", "https://evil.example/x", "owner/repo/extra", "../x/y", "owner/repo?a=b"])
def test_only_a_github_repository_is_accepted(repo):
    record = good_record()
    with pytest.raises(sb.SubmitError):
        sb.issue_url(repo, "{}", record)


def test_a_record_too_long_for_an_address_is_refused():
    record = good_record()
    with pytest.raises(sb.SubmitError):
        sb.issue_url("owner/dataset", "x" * sb.MAX_URL, record)


class Terminal(io.StringIO):
    def isatty(self):
        return True


@pytest.fixture
def run(tmp_path, monkeypatch):
    """Run the command with no way to reach the network, recording what it tries to open."""
    report = tmp_path / "report.json"
    report.write_text(json.dumps(poisoned()))
    opened = []

    def no_network(*_a, **_k):
        raise AssertionError("submit must not open a connection")

    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr("webbrowser.open", lambda url: opened.append(url) or True)

    def go(typed=None, *extra):
        monkeypatch.setattr("sys.stdin", Terminal(typed) if typed is not None else io.StringIO())
        code = main(["submit", str(report), "--to", "owner/dataset", "--agent", "vendor-agent", "--agent-version", "1.2.3", "--sandbox", "default", *extra])
        return code, opened

    return go


def test_without_a_terminal_it_shows_the_record_and_opens_nothing(run, capsys):
    code, opened = run()
    assert code == 1 and opened == []
    captured = capsys.readouterr()
    assert '"score": 33' in captured.out
    assert "person at a terminal" in captured.err


@pytest.mark.parametrize("typed", ["\n", "n\n", "y\n", "YES\n", "no\n"])
def test_anything_but_yes_opens_nothing(run, capsys, typed):
    code, opened = run(typed)
    assert code == 0 and opened == []
    assert "Nothing was opened or sent" in capsys.readouterr().out


def test_yes_opens_the_issue_and_says_nothing_is_posted_yet(run, capsys):
    code, opened = run("yes\n")
    assert code == 0 and len(opened) == 1
    out = capsys.readouterr().out
    assert out.index('"score": 33') < out.index("Nothing is posted until")
    for private in PRIVATE:
        assert private not in out and private not in urllib.parse.unquote(opened[0])


def test_no_browser_prints_the_address(run, capsys):
    code, opened = run("yes\n", "--no-browser")
    assert code == 0 and opened == []
    assert "https://github.com/owner/dataset/issues/new?" in capsys.readouterr().out


def test_there_is_no_default_dataset_and_no_flag_that_skips_the_question():
    with pytest.raises(SystemExit):
        main(["submit", "x.json", "--agent", "a", "--agent-version", "1", "--sandbox", "d"])
    with open(os.path.join(REPO, "agentsec", "cli.py")) as f:
        source = f.read()
    start = source.index('sub.add_parser("submit"')
    block = source[start:source.index("sb.set_defaults", start)]
    for flag in ("--yes", "--force", "--non-interactive"):
        assert flag not in block


def test_a_bad_report_path_is_an_error(tmp_path, capsys):
    assert main(["submit", str(tmp_path / "none.json"), "--to", "o/r", "--agent", "a", "--agent-version", "1", "--sandbox", "d"]) == 1
