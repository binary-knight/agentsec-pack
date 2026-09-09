"""A localhost console for agentsec.

Threat model, because a browser UI for a sandbox tool deserves one written down:

* The server binds 127.0.0.1 by default. `--bind` can widen that, because
  people do run this on a box they reach from another machine, but a console
  bound to a non-loopback address refuses to launch anything unless the
  operator also passes `--allow-remote-runs`. Viewing is safe to expose;
  handing a LAN the ability to start containers is not, so that stays a
  separate, deliberate decision.
* Every /api/ call must carry a random token minted at startup and printed in
  the URL. That stops another local process, or a page in another tab, from
  driving it.
* The Host header is checked, so a name that resolves to 127.0.0.1 cannot be
  used to reach it from a hostile page (DNS rebinding).
* No CORS header is ever sent, and a Content-Security-Policy keeps the page
  from loading anything off-box.
* The run surface accepts a preset name that exists in the shipped data file,
  or an engine/image/flag triple where every flag is a key in FINDING_FLAGS.
  It does NOT accept a command template. The browser cannot ask this server to
  run an arbitrary command, and a test asserts that.
"""
from __future__ import annotations

import json
import re
import secrets
import threading
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .. import presets as presets_mod
import time

from ..runner import run_container, run_preset
from ..scoring import FINDING_FLAGS, summarize
from . import render_html

# A docker/podman reference: registry, path and tag or digest. Deliberately
# strict; an image name is the one string here that reaches a subprocess.
IMAGE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._\-]*(:[0-9]+)?(/[a-zA-Z0-9._\-]+)*"
                      r"(:[a-zA-Z0-9._\-]+)?(@sha256:[a-f0-9]{64})?$")
MAX_BODY = 4 * 1024 * 1024

# Flags the browser may ask for, derived from the remediation map rather than
# typed in. Anything outside this set is refused.
ALLOWED_FLAGS = sorted({f for flags in FINDING_FLAGS.values() for f in flags
                        if f.startswith("--")})


def is_loopback(addr: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return addr in ("localhost",)


class Console:
    def __init__(self, results: list[dict[str, Any]] | None = None, allow_runs: bool = True):
        self.allow_runs = allow_runs
        self.token = secrets.token_urlsafe(24)
        self.results: list[dict[str, Any]] = list(results or [])
        self.jobs: dict[str, dict[str, Any]] = {}
        self.lock = threading.Lock()

    # -- the two things the browser may ask us to do ----------------------
    def start_run(self, spec: dict[str, Any]) -> str:
        job = uuid.uuid4().hex
        with self.lock:
            self.jobs[job] = {"state": "running"}
        threading.Thread(target=self._run, args=(job, spec), daemon=True).start()
        return job

    def _run(self, job: str, spec: dict[str, Any]) -> None:
        try:
            if "preset" in spec:
                env = run_preset(spec["preset"], image=spec.get("image") or None)
            else:
                env = run_container(spec["image"], spec["flags"], engine=spec["engine"])
            with self.lock:
                self.results.insert(0, env)
                self.jobs[job] = {"state": "done", "result": env}
        except Exception as exc:  # a failed run is a result, not a crash
            with self.lock:
                self.jobs[job] = {"state": "error", "error": f"{type(exc).__name__}: {exc}"}

    def score(self, label: str, how: str, raw: str) -> dict[str, Any]:
        if not label or not how:
            raise ValueError("a capture needs a label and a record of how it was run")
        probe, repaired = _parse_probe(raw)
        env = {"tool": "agentsec-pack", "test": "sandbox-blast-radius", "schema_version": 1,
               "label": label, "generated_at": int(time.time()),
               "target": {"kind": "captured", "label": label, "how": how,
                          "note": "Captured externally: the probe was run inside the target by the means "
                                  "described in `how`, not launched by agentsec."},
               "rc": 0, "summary": summarize(probe), "probe": probe, "probe_stderr": ""}
        with self.lock:
            self.results.insert(0, env)
        return {"result": env, "repaired": repaired}


def _parse_probe(raw: str) -> tuple[dict[str, Any], bool]:
    """Accept probe JSON, repairing a transcript that lost its closing braces.

    Read-only agents cannot write a file, so their output arrives pasted from a
    reply and is often clipped. Repairing is fine; doing it silently is not, so
    the caller is told.
    """
    text = raw.strip()
    start = text.find("{")
    if start < 0:
        raise ValueError("no JSON object found in that text")
    text = text[start:]
    try:
        return json.loads(text), False
    except json.JSONDecodeError:
        pass
    for extra in range(1, 6):
        try:
            return json.loads(text + "}" * extra), True
        except json.JSONDecodeError:
            continue
    raise ValueError("that is not parseable probe JSON, even allowing for a truncated tail")


def validate_run(spec: Any) -> dict[str, Any]:
    """Return a safe run spec, or raise. This is the whole trust boundary."""
    if not isinstance(spec, dict):
        raise ValueError("expected an object")
    if "command" in spec or "template" in spec or "kind" in spec:
        raise ValueError("this console does not run command templates; use the CLI for that")
    if "preset" in spec:
        name = spec["preset"]
        known = presets_mod.load_all()
        if not isinstance(name, str) or name not in known:
            raise ValueError("unknown configuration")
        image = spec.get("image")
        if image not in (None, "") and not (isinstance(image, str) and IMAGE_RE.match(image)):
            raise ValueError("that is not a valid image reference")
        return {"preset": name, "image": image or None}
    engine = spec.get("engine")
    if engine not in ("docker", "podman"):
        raise ValueError("engine must be docker or podman")
    image = spec.get("image")
    if not isinstance(image, str) or not IMAGE_RE.match(image):
        raise ValueError("that is not a valid image reference")
    flags = spec.get("flags") or []
    if not isinstance(flags, list) or any(f not in ALLOWED_FLAGS for f in flags):
        raise ValueError("flags must come from the recommended set")
    return {"engine": engine, "image": image, "flags": flags}


def make_handler(console: Console, port: int, bind: str = "127.0.0.1"):
    # The Host check still applies; it just has to know every name this server
    # legitimately answers to.
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}", f"{bind}:{port}",
                     f"[{bind}]:{port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = "agentsec"
        sys_version = ""

        def log_message(self, fmt, *args):  # keep the terminal readable
            pass

        # -- helpers ----------------------------------------------------
        def _send(self, code: int, body: bytes, ctype: str):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                             "script-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                             "connect-src 'self'; base-uri 'none'; form-action 'none'; "
                             "frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, obj: Any):
            self._send(code, json.dumps(obj).encode(), "application/json")

        def _host_ok(self) -> bool:
            return (self.headers.get("Host") or "") in allowed_hosts

        def _auth_ok(self) -> bool:
            return secrets.compare_digest(self.headers.get("X-Agentsec-Token") or "", console.token)

        def _guard(self) -> bool:
            if not self._host_ok():
                self._json(400, {"error": "unexpected Host header"})
                return False
            if not self._auth_ok():
                self._json(401, {"error": "missing or wrong token"})
                return False
            return True

        # -- routes -----------------------------------------------------
        def do_GET(self):
            if not self._host_ok():
                self._send(400, b"unexpected Host header", "text/plain")
                return
            path = self.path.split("?")[0]
            if path == "/":
                with console.lock:
                    results = list(console.results)
                html = render_html(results, mode="server", token=console.token,
                                   presets=presets_mod.load_all() if console.allow_runs else {})
                self._send(200, html.encode(), "text/html; charset=utf-8")
                return
            if path == "/api/results":
                if not self._guard():
                    return
                with console.lock:
                    self._json(200, {"results": list(console.results)})
                return
            if path.startswith("/api/job/"):
                if not self._guard():
                    return
                with console.lock:
                    job = console.jobs.get(path.rsplit("/", 1)[-1])
                self._json(200, job) if job else self._json(404, {"error": "no such job"})
                return
            self._json(404, {"error": "not found"})

        def do_POST(self):
            if not self._guard():
                return
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                self._json(413, {"error": "body too large"})
                return
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                self._json(400, {"error": "body was not JSON"})
                return
            path = self.path.split("?")[0]
            if path == "/api/run":
                if not console.allow_runs:
                    self._json(403, {"error": "This console is reachable from outside this machine, "
                                              "so running configurations is switched off. Restart with "
                                              "--allow-remote-runs if that is what you want."})
                    return
                try:
                    spec = validate_run(body)
                except ValueError as exc:
                    self._json(400, {"error": str(exc)})
                    return
                self._json(200, {"job": console.start_run(spec)})
                return
            if path == "/api/score":
                try:
                    out = console.score(str(body.get("label", "")).strip(),
                                        str(body.get("how", "")).strip(),
                                        str(body.get("probe", "")))
                except ValueError as exc:
                    self._json(400, {"error": str(exc)})
                    return
                self._json(200, out)
                return
            self._json(404, {"error": "not found"})

    return Handler


def serve(port: int = 8787, results: list[dict[str, Any]] | None = None,
          open_browser: bool = False, forever: bool = True, bind: str = "127.0.0.1",
          allow_remote_runs: bool = False):
    local = is_loopback(bind)
    console = Console(results, allow_runs=local or allow_remote_runs)
    httpd = ThreadingHTTPServer((bind, port), make_handler(console, port, bind))
    actual = httpd.server_address[1]
    if actual != port:  # port 0 was asked for
        httpd.RequestHandlerClass = make_handler(console, actual, bind)
    url = f"http://{bind}:{actual}/?t={console.token}"
    if forever:
        print(f"agentsec console on {url}")
        if local:
            print("Bound to localhost. The token in that URL is required for every action; "
                  "share the link with nobody. Ctrl-C to stop.")
        else:
            print(f"WARNING: bound to {bind}, so anyone who can reach this address and holds "
                  "the token can use it.")
            print("Running configurations is " + ("ENABLED by --allow-remote-runs."
                  if console.allow_runs else "switched off; this console is read-only."))
            print("Ctrl-C to stop.")
        if open_browser:
            webbrowser.open(url)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped")
        finally:
            httpd.server_close()
        return None
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, console, actual
