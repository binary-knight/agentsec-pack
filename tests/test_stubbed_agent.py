"""The stand-in model behind scripts/measure_stubbed_agent.py."""
import importlib.util
import json
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("measure_stubbed_agent", ROOT / "scripts" / "measure_stubbed_agent.py")
stub = importlib.util.module_from_spec(spec)
sys.modules["measure_stubbed_agent"] = stub
spec.loader.exec_module(stub)

GEMINI_TOOLS = [{"functionDeclarations": [
    {"name": "read_file", "parameters": {"properties": {"path": {"type": "string"}}}},
    {"name": "run_shell_command", "parametersJsonSchema": {"properties": {"command": {"type": "string"}}, "required": ["command"]}},
]}]


def part_of(answer):
    return answer["candidates"][0]["content"]["parts"][0]


def test_asks_for_the_command_through_the_shell_tool_the_agent_declared():
    answer, kind = stub.reply({"tools": GEMINI_TOOLS, "contents": []}, "python3 probe.py", "/p", 0)
    assert kind == "shell-call"
    assert part_of(answer)["functionCall"] == {"name": "run_shell_command", "args": {"command": "python3 probe.py"}}


def test_fills_other_required_arguments_from_the_declared_schema():
    tools = [{"functionDeclarations": [{"name": "run_command", "parameters": {
        "properties": {"CommandLine": {"type": "STRING"}, "Cwd": {"type": "STRING"}, "Wait": {"type": "BOOLEAN"}, "WaitMs": {"type": "integer"}, "BypassSandbox": {"type": "boolean"}},
        "required": ["CommandLine", "Cwd", "Wait", "WaitMs", "BypassSandbox"]}}]}]
    answer, _ = stub.reply({"tools": tools}, "x", "/p", 0)
    assert part_of(answer)["functionCall"]["args"] == {"CommandLine": "x", "Cwd": "/p", "Wait": False, "WaitMs": 0, "BypassSandbox": False}


def test_keeps_antigravitys_wait_within_its_limit():
    tools = [{"functionDeclarations": [{"name": "run_command", "parameters": {
        "properties": {"CommandLine": {"type": "string"}, "WaitMsBeforeAsync": {"type": "integer"}}, "required": ["CommandLine", "WaitMsBeforeAsync"]}}]}]
    assert part_of(stub.reply({"tools": tools}, "x", "/p", 0)[0])["functionCall"]["args"]["WaitMsBeforeAsync"] == 10000


def test_never_asks_to_leave_the_sandbox_when_the_option_is_not_required():
    tools = [{"functionDeclarations": [{"name": "run_command", "parameters": {
        "properties": {"CommandLine": {"type": "string"}, "BypassSandbox": {"type": "boolean"}}, "required": ["CommandLine"]}}]}]
    assert "BypassSandbox" not in part_of(stub.reply({"tools": tools}, "x", "/p", 0)[0])["functionCall"]["args"]


def test_stops_once_the_command_has_been_answered():
    body = {"tools": GEMINI_TOOLS, "contents": [{"parts": [{"functionResponse": {"name": "run_shell_command"}}]}]}
    answer, kind = stub.reply(body, "x", "/p", 1)
    assert (kind, part_of(answer)) == ("text", {"text": "DONE"})


def test_does_not_ask_forever_when_the_agent_never_reports_back():
    assert stub.reply({"tools": GEMINI_TOOLS}, "x", "/p", stub.MAX_CALLS)[1] == "text"


def test_answers_a_side_request_with_no_tools_in_the_form_it_asked_for():
    assert stub.reply({}, "x", "/p", 0)[1] == "text"
    assert stub.reply({"generationConfig": {"responseMimeType": "application/json"}}, "x", "/p", 0)[1] == "json"


def test_scores_a_report_when_a_fake_agent_runs_what_the_stub_asks(tmp_path, monkeypatch):
    """The whole path, with a small agent that follows the stub over real HTTP."""
    agent = tmp_path / "fake_agent.py"
    agent.write_text(f"""#!{sys.executable}
import json, os, subprocess, urllib.request
base = os.environ["GOOGLE_GEMINI_BASE_URL"]
assert "SECRET_ONLY_OUTSIDE" not in os.environ
def ask(body):
    r = urllib.request.Request(base + "/v1beta/models/m:streamGenerateContent?alt=sse", json.dumps(body).encode())
    return json.loads(urllib.request.urlopen(r).read().decode().removeprefix("data: "))
tools = {json.dumps(GEMINI_TOOLS)}
part = ask({{"tools": tools, "contents": []}})["candidates"][0]["content"]["parts"][0]
subprocess.run(part["functionCall"]["args"]["command"], shell=True, check=True)
done = ask({{"tools": tools, "contents": [{{"parts": [{{"functionResponse": {{"name": "x"}}}}]}}]}})
assert done["candidates"][0]["content"]["parts"][0] == {{"text": "DONE"}}
""")
    agent.chmod(agent.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("SECRET_ONLY_OUTSIDE", "1")
    monkeypatch.setenv("PATH", str(Path(sys.executable).parent), prepend=":")
    out = tmp_path / "reports"
    code = stub.main(["--name", "fake", "--label", "fake-agent", "--how", "a test.", "--project", str(tmp_path / "p"), "--out", str(out),
                      "--logs", str(tmp_path / "logs"), "--python", sys.executable, "--timeout", "120", "--", str(agent)])
    assert code in (0, 2)
    report = json.loads(next(out.glob("*.json")).read_text())
    assert "The model was a local stub" in json.dumps(report)
    requests = [json.loads(line) for line in (tmp_path / "logs" / "fake.stub.jsonl").read_text().splitlines()]
    assert [r["reply"] for r in requests] == ["shell-call", "text"]


def printed_report(text):
    import base64
    import gzip
    return stub.BEGIN + base64.b64encode(gzip.compress(text.encode())).decode() + stub.END


def response_body(output):
    return {"contents": [{"parts": [{"functionResponse": {"name": "run_command", "response": {"output": output}}}]}]}


def test_reads_a_report_the_command_printed_even_when_a_terminal_wrapped_it():
    printed = printed_report('{"a": 1}')
    assert stub.report_in(response_body(f"Command output:\n{printed}\r\n")) == '{"a": 1}'
    middle = len(printed) // 2
    assert stub.report_in(response_body(printed[:middle] + "\r\n" + printed[middle:])) == '{"a": 1}'


def test_a_cut_off_report_or_the_echoed_command_is_not_a_report():
    assert stub.report_in(response_body(printed_report("{}")[:-5])) is None
    assert stub.report_in(response_body(stub.ENCODE)) is None
    assert stub.report_in({}) is None


def test_a_script_runs_in_place_of_the_probe_and_its_output_is_kept_unscored(tmp_path, monkeypatch):
    agent = tmp_path / "fake-agent"
    agent.write_text(f"""#!{sys.executable}
import json, os, subprocess, urllib.request
def ask(body):
    request = urllib.request.Request(os.environ["GOOGLE_GEMINI_BASE_URL"] + "/v1beta/models/m:generateContent", json.dumps(body).encode())
    return json.load(urllib.request.urlopen(request))
tools = {json.dumps(GEMINI_TOOLS)}
part = ask({{"tools": tools, "contents": []}})["candidates"][0]["content"]["parts"][0]
subprocess.run(part["functionCall"]["args"]["command"], shell=True, check=True)
""")
    agent.chmod(agent.stat().st_mode | stat.S_IEXEC)
    script = tmp_path / "script.py"
    script.write_text('import json\nprint(json.dumps({"from": "script"}))\n')
    monkeypatch.setenv("PATH", str(Path(sys.executable).parent), prepend=":")
    out = tmp_path / "reports"
    code = stub.main(["--name", "fake", "--label", "fake-check", "--how", "a test.", "--project", str(tmp_path / "p"), "--out", str(out), "--logs", str(tmp_path / "logs"),
                      "--python", sys.executable, "--timeout", "120", "--script", str(script), "--", str(agent)])
    assert code == 0
    kept = json.loads((out / "fake-check.json").read_text())
    assert kept["check"] == {"from": "script"}
    assert "The model was a local stub" in kept["how"]
    assert not list(out.glob("*.md"))
