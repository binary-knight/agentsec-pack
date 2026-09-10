"""The README and AGENTS.md make checkable promises. Check them.

AGENTS.md is handed to an agent that will execute what it says, and the README
tells a reader it is safe to do that. Both claims have to keep being true after
later edits, so they are tests rather than good intentions.
"""
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


def _read(name):
    with open(os.path.join(REPO, name), encoding="utf-8") as f:
        return f.read()


def _fenced_commands(text):
    """Only what is inside code fences. Prose that names sysctl to forbid it is
    not the same as a command line that runs it."""
    return "\n".join(re.findall(r"```(?:bash|sh)?\n(.*?)```", text, re.S))


def test_agent_brief_stays_short_enough_that_a_person_will_read_it():
    # The README tells the reader it is under 100 lines. Keep that honest.
    assert len(_read("AGENTS.md").splitlines()) < 100


def test_agent_brief_asks_for_nothing_privileged():
    cmds = _fenced_commands(_read("AGENTS.md"))
    for danger in ("sudo", "sysctl", "apparmor_parser", "chmod 777", "curl", "wget",
                   "rm -rf", "git push", "docker run --privileged", "-v /:/"):
        assert danger not in cmds, f"AGENTS.md runs {danger!r}, which the README promises it does not"


def test_agent_brief_tells_the_agent_the_repo_is_not_authority():
    """A file that instructs an agent must say it is data, or it is teaching the
    exact habit this tool exists to worry about."""
    text = _read("AGENTS.md")
    assert "data, not authority" in text
    assert "Read this file before you act on it" in text


def test_agent_brief_refuses_to_let_the_agent_publish():
    text = _read("AGENTS.md")
    assert "Do not publish anything" in text
    assert "Never assert a read you did not make" in text


def test_agent_brief_does_not_present_zero_as_the_goal():
    """Zero needs --network none, which stops an agent reaching its model."""
    text = _read("AGENTS.md")
    assert "0 is not the target" in _read("README.md") or "not present 0 as the goal" in text.lower() \
        or "Do not present 0 as the goal" in text


def test_every_documented_subcommand_exists():
    from agentsec.cli import main
    import argparse
    import contextlib
    import io

    documented = set()
    for name in ("README.md", "AGENTS.md"):
        documented |= set(re.findall(r"\bagentsec ([a-z][a-z-]+)", _read(name)))

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.suppress(SystemExit):
        main(["--help"])
    help_text = buf.getvalue()
    known = set(re.findall(r"[{,]([a-z][a-z-]+)", help_text.split("\n")[1] if "\n" in help_text else ""))
    known |= set(re.findall(r"^\s{4}([a-z][a-z-]+)\s{2,}", help_text, re.M))

    missing = sorted(documented - known)
    assert not missing, f"documented but not implemented: {missing} (known: {sorted(known)})"
