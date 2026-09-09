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
    import tomllib

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "pyproject.toml"), "rb") as f:
        claim = tomllib.load(f)["project"]["requires-python"]
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
