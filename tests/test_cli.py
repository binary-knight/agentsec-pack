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
