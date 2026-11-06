#!/usr/bin/env python3
"""Measure an agent's own sandbox on a disposable machine, with a stand-in for the model.

Gemini CLI and Antigravity CLI both document GOOGLE_GEMINI_BASE_URL for a custom endpoint.
This serves that endpoint: it asks for one shell command, the probe, and then stops. The
agent's own sandbox runs as shipped and only the model is replaced, so no account or key is
needed, and what the command can reach does not depend on which model asked for it.

    measure_stubbed_agent.py --name NAME --label LABEL --how HOW --project DIR --out DIR -- agent args...
"""
from __future__ import annotations

import argparse
import http.server
import json
import os
import re
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

SHELL_TOOL = re.compile(r"shell|bash|run_command|terminal", re.I)
COMMAND_ARGS = ("command", "CommandLine", "commandLine", "cmd")
NOT_A_KEY = "stub-endpoint-takes-no-key"  # pragma: allowlist secret
MAX_CALLS = 3
KNOWN_ARGS = {"WaitMsBeforeAsync": 10000}  # Antigravity's limit, so the probe stays in the foreground


def _declarations(body: dict[str, Any]) -> list[dict[str, Any]]:
    return [d for tool in body.get("tools") or [] for d in tool.get("functionDeclarations") or []]


def _schema(declaration: dict[str, Any]) -> dict[str, Any]:
    return declaration.get("parameters") or declaration.get("parametersJsonSchema") or {}


def shell_call(body: dict[str, Any], command: str, cwd: str) -> dict[str, Any] | None:
    """A functionCall part that runs the command, built from the tool the agent declared."""
    for declaration in _declarations(body):
        if not SHELL_TOOL.search(declaration.get("name", "")):
            continue
        schema = _schema(declaration)
        properties = schema.get("properties") or {}
        key = next((k for k in COMMAND_ARGS if k in properties), None)
        if key is None:
            continue
        args: dict[str, Any] = {key: command}
        for name in schema.get("required") or []:
            if name == key:
                continue
            kind = str((properties.get(name) or {}).get("type", "")).lower()
            if name in KNOWN_ARGS:
                args[name] = KNOWN_ARGS[name]
            elif kind == "string":
                args[name] = cwd if "dir" in name.lower() or name.lower() == "cwd" else "probe"
            else:
                args[name] = 0 if kind in ("integer", "number") else False
        return {"functionCall": {"name": declaration["name"], "args": args}}
    return None


def _responses(body: dict[str, Any]) -> list[Any]:
    """What the agent reported back from its tools, cut short for the log."""
    return [json.dumps(part["functionResponse"])[:1500] for content in (body.get("contents") or [])[-1:] for part in content.get("parts") or [] if "functionResponse" in part]


def _answered(body: dict[str, Any]) -> bool:
    return any("functionResponse" in part for content in body.get("contents") or [] for part in content.get("parts") or [])


def reply(body: dict[str, Any], command: str, cwd: str, calls_made: int) -> tuple[dict[str, Any], str]:
    """What the model says to this request, and a short name for it."""
    part = None if _answered(body) or calls_made >= MAX_CALLS else shell_call(body, command, cwd)
    kind = "shell-call"
    if part is None:
        wants_json = (body.get("generationConfig") or {}).get("responseMimeType") == "application/json"
        part, kind = ({"text": "{}"}, "json") if wants_json else ({"text": "DONE"}, "text")
    return ({"candidates": [{"index": 0, "finishReason": "STOP", "content": {"role": "model", "parts": [part]}}],
             "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1, "totalTokenCount": 2}}, kind)


def part_sent(answer: dict[str, Any]) -> Any:
    return answer["candidates"][0]["content"]["parts"][0]


def serve(host: str, command: str, cwd: str, log_path: Path) -> http.server.ThreadingHTTPServer:
    calls = {"made": 0}
    lock = threading.Lock()

    class Handler(http.server.BaseHTTPRequestHandler):
        def _send(self, data: bytes, content_type: str = "application/json") -> None:
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _note(self, **fields: Any) -> None:
            with lock, log_path.open("a") as f:
                f.write(json.dumps({"method": self.command, "path": self.path, **fields}, sort_keys=True) + "\n")

        def do_GET(self) -> None:  # noqa: N802
            self._note()
            self._send(b'{"models": []}')

        def do_POST(self) -> None:  # noqa: N802
            raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            try:
                body = json.loads(raw or b"{}")
            except ValueError:
                body = {}
            if ":countTokens" in self.path:
                self._note()
                self._send(b'{"totalTokens": 1}')
                return
            with lock:
                answer, kind = reply(body, command, cwd, calls["made"])
                calls["made"] += kind == "shell-call"
            shells = [{"name": d.get("name"), "schema": _schema(d)} for d in _declarations(body) if SHELL_TOOL.search(d.get("name", ""))]
            self._note(tools=[d.get("name") for d in _declarations(body)], shell_tools=shells, answered=_answered(body), reply=kind, sent=part_sent(answer), responses=_responses(body))
            data = json.dumps(answer)
            if "alt=sse" in self.path:
                self._send(f"data: {data}\n\n".encode(), "text/event-stream")
            elif ":streamGenerateContent" in self.path:
                self._send(f"[{data}]".encode())
            else:
                self._send(data.encode())

        def log_message(self, *args: Any) -> None:
            pass

    server = http.server.ThreadingHTTPServer((host, 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--name", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--how", required=True)
    ap.add_argument("--project", required=True, type=Path, help="a throwaway project directory, created here")
    ap.add_argument("--out", required=True, type=Path, help="where reports go")
    ap.add_argument("--logs", required=True, type=Path, help="where the agent's output and the stub's request log go")
    ap.add_argument("--python", default="/usr/bin/python3", help="the interpreter the agent is asked to use")
    ap.add_argument("--url-host", default="127.0.0.1", help="the address the agent reaches the stub at")
    ap.add_argument("--env", action="append", default=[], metavar="NAME=VALUE", help="also set this for the agent")
    ap.add_argument("--copy-to-project", action="append", default=[], metavar="FILE=RELATIVE", help="also place this file in the project")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("agent", nargs=argparse.REMAINDER, help="-- then the agent's command")
    args = ap.parse_args(argv)
    agent = args.agent[1:] if args.agent[:1] == ["--"] else args.agent
    if not agent:
        ap.error("give the agent's command after --")

    project = args.project.resolve()
    for name in (".codex", ".agents", ".claude", ".gemini"):
        (project / name).mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(project)], check=True)
    shutil.copy(Path(__file__).resolve().parent.parent / "agentsec" / "probe" / "blast_probe.py", project / "probe.py")
    for item in args.copy_to_project:
        source, relative = item.split("=", 1)
        shutil.copy(source, project / relative)
    args.logs.mkdir(parents=True, exist_ok=True)
    args.out.mkdir(parents=True, exist_ok=True)

    result = project / f"out-{args.name}.json"
    command = f"{args.python} probe.py > {result.name}"
    server = serve("0.0.0.0" if args.url_host != "127.0.0.1" else "127.0.0.1", command, str(project), args.logs / f"{args.name}.stub.jsonl")
    # Named one at a time, so nothing else on this machine reaches the agent or the probe.
    env = {k: os.environ[k] for k in ("HOME", "PATH", "USER", "TMPDIR") if k in os.environ}
    env.update(TERM="xterm", SHELL="/bin/bash", LANG="C.UTF-8", GEMINI_API_KEY=NOT_A_KEY,
               GOOGLE_GEMINI_BASE_URL=f"http://{args.url_host}:{server.server_address[1]}")
    env.update(item.split("=", 1) for item in args.env)

    print(f"== {args.name}: {' '.join(agent)}", flush=True)
    with (args.logs / f"{args.name}.agent.log").open("w") as log:
        try:
            done = subprocess.run(agent, cwd=project, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, timeout=args.timeout)
            print(f"   exit {done.returncode}", flush=True)
        except subprocess.TimeoutExpired:
            print(f"   stopped after {args.timeout}s", flush=True)
    server.shutdown()

    try:
        json.loads(result.read_text())
    except (OSError, ValueError) as e:
        print(f"   no probe report, so nothing was measured: {e}", flush=True)
        print("   " + "\n   ".join((args.logs / f"{args.name}.agent.log").read_text(errors="replace").splitlines()[-15:]), flush=True)
        return 1
    how = (f"{args.how} The model was a local stub reached through GOOGLE_GEMINI_BASE_URL, which asked for one shell command, "
           f"{command}, and then stopped, so no real model or account was involved. Launched with only HOME, PATH, USER, TMPDIR, "
           "TERM, SHELL, LANG, the stub's address and a placeholder GEMINI_API_KEY, from a throwaway git repository holding empty "
           "project config directories, by scripts/measure_stubbed_agent.py on a disposable GitHub-hosted machine, whose home "
           "holds no personal credentials.")
    return subprocess.run(["agentsec", "score", str(result), "--label", args.label, "--redact", "--out", str(args.out), "--how", how]).returncode


if __name__ == "__main__":
    sys.exit(main())
