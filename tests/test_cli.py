import json
import os

from agentsec.cli import main


def test_cli_local_writes_json_and_markdown(tmp_path, capsys):
    rc = main(["blast-radius", "local", "--out", str(tmp_path), "--label", "t"])
    assert rc == 0
    env = json.load(open(tmp_path / "t.json"))
    assert env["test"] == "sandbox-blast-radius" and env["target"]["kind"] == "local"
    md = open(tmp_path / "t.md").read()
    assert "Score:" in md and "Target (reproduce with this)" in md
    rc = main(["compare", str(tmp_path / "t.json")])
    assert rc == 0
    assert "score" in capsys.readouterr().out


def test_every_module_parses_on_the_oldest_python_we_claim_to_support():
    """pyproject said >=3.10 while the code used 3.12-only f-string nesting, and
    only CI on an older runner caught it. This makes the claim testable here."""
    import ast
    import re as _re

    # Read the claim with a regex rather than tomllib, which is itself 3.11+.
    # A test that checks version support must run on the version it checks.
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "pyproject.toml"), encoding="utf-8") as f:
        pyproject = f.read()
    m = _re.search(r'^requires-python\s*=\s*["\']([^"\']+)["\']', pyproject, _re.M)
    assert m, "pyproject.toml does not state requires-python"
    claim = m.group(1)
    major, minor = (int(x) for x in _re.search(r"(\d+)\.(\d+)", claim).groups())

    bad = []
    for dirpath, _dirs, files in os.walk(os.path.join(root, "agentsec")):
        for name in files:
            if not name.endswith(".py"):
                continue
            path = os.path.join(dirpath, name)
            with open(path, encoding="utf-8") as f:
                src = f.read()
            try:
                ast.parse(src, filename=path, feature_version=(major, minor))
            except SyntaxError as exc:
                bad.append(f"{os.path.relpath(path, root)}: {exc}")
            # feature_version does not catch f-string quote reuse, which the
            # 3.12 tokenizer accepts and 3.11 rejects. Catch it by pattern.
            for i, line in enumerate(src.splitlines(), 1):
                if (major, minor) < (3, 12) and _re.search(r'f"[^"]*\{[^}]*"', line) and line.count('"') > 2:
                    bad.append(f"{os.path.relpath(path, root)}:{i}: reuses \" inside an f-string "
                               f"(needs Python 3.12; this project claims {claim})")
    assert not bad, "\n".join(bad)


# --- accepting what an agent actually hands back ----------------------------
# A read-only sandbox cannot write a file, so the JSON comes back inside a reply:
# wrapped in prose, fenced, and clipped, often all three. The supervisor session
# hand-wrote an extractor for this before it existed.

def _probe_text():
    import json as _json
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "probe_open.json")
    with open(path) as f:
        return _json.dumps(_json.load(f))


def test_score_reads_a_clean_json_file_unchanged():
    from agentsec.cli import _probe_from_text
    obj, note = _probe_from_text(_probe_text())
    assert obj and note == ""


def test_score_finds_the_object_inside_prose():
    from agentsec.cli import _probe_from_text
    obj, note = _probe_from_text("Sure! Here is the output:\n\n" + _probe_text() + "\n\nAnything else?")
    assert obj["identity"]
    assert "skipped" in note or "trailing" in note


def test_score_finds_the_object_inside_a_code_fence():
    from agentsec.cli import _probe_from_text
    obj, note = _probe_from_text("I ran it:\n\n```json\n" + _probe_text() + "\n```\n")
    assert obj["identity"]
    assert "fenced" in note


def test_score_repairs_a_transcript_that_was_fenced_and_clipped():
    """The real shape: read-only mode, reply truncated mid-object."""
    from agentsec.cli import _probe_from_text
    text = "Here is the probe output:\n\n```json\n" + _probe_text()[:-2] + "\n"
    obj, note = _probe_from_text(text)
    assert obj["identity"]
    assert "repaired" in note, "a repair must be reported, never silent"


def test_score_refuses_text_with_no_object_rather_than_guessing():
    from agentsec.cli import _probe_from_text
    import pytest
    with pytest.raises(ValueError):
        _probe_from_text("Sorry, I was not able to run that command.")


def test_score_accepts_print_findings_for_symmetry_with_blast_radius(tmp_path):
    """It always prints them; the flag existing stops the muscle memory failing."""
    src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "probe_open.json")
    rc = main(["score", src, "--label", "s", "--how", "h", "--print-findings", "--out", str(tmp_path)])
    assert rc == 0
