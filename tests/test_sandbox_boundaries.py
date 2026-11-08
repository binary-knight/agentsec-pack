"""scripts/check_sandbox_boundaries.py, which tests writes and proxy traffic for real."""
import importlib.util
import json
import socketserver
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("check_sandbox_boundaries", ROOT / "scripts" / "check_sandbox_boundaries.py")
check = importlib.util.module_from_spec(spec)
sys.modules["check_sandbox_boundaries"] = check
spec.loader.exec_module(check)


def machine(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".cargo" / "bin").mkdir(parents=True)
    project = tmp_path / "project"
    (project / ".git" / "hooks").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(check, "WRITE_TARGETS", tuple(t for t in check.WRITE_TARGETS if t != "/tmp"))
    for name in ("HTTPS_PROXY", "https_proxy"):
        monkeypatch.delenv(name, raising=False)
    return home, project


def by_path(entries):
    return {entry["path"]: entry for entry in entries}


def test_inside_it_writes_where_it_can_and_says_why_where_it_cannot(tmp_path, monkeypatch):
    home, project = machine(tmp_path, monkeypatch)
    writes = by_path(check.try_writes(project))
    assert writes["."]["written"] and writes["~/.cargo/bin"]["written"]
    assert writes["~/.rustup"] == {"path": "~/.rustup", "exists": False, "written": False, "error": "FileNotFoundError", "errno": 2}
    assert (project / check.MARK).read_text() == ""


def test_on_the_host_it_reports_markers_runs_the_planted_one_and_removes_them(tmp_path, monkeypatch):
    home, project = machine(tmp_path, monkeypatch)
    check.try_writes(project)
    report = check.check_host(project)
    assert report["markers_visible_on_host"]["~/.cargo/bin"] is True
    assert report["markers_visible_on_host"]["~/.rustup"] is False
    assert report["planted_ran_on_host"] is True
    assert not (home / check.RAN).exists()
    assert not (project / check.MARK).exists()
    assert not (home / ".cargo" / "bin" / check.MARK).exists()


def test_a_marker_that_did_not_persist_is_not_run(tmp_path, monkeypatch):
    home, project = machine(tmp_path, monkeypatch)
    assert check.check_host(project)["planted_ran_on_host"] is False


def test_opening_an_existing_tool_changes_nothing(tmp_path, monkeypatch):
    home, _ = machine(tmp_path, monkeypatch)
    tool = home / ".cargo" / "bin" / "cargo"
    tool.write_text("contents")
    assert by_path(check.try_existing_tools())["~/.cargo/bin/cargo"] == {"path": "~/.cargo/bin/cargo", "exists": True, "open_for_append": True}
    assert tool.read_text() == "contents"


class FakeProxy(socketserver.StreamRequestHandler):
    def handle(self):
        target = self.rfile.readline().split()[1].decode()
        while self.rfile.readline().strip():
            pass
        if target.startswith("refused"):
            self.wfile.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            return
        self.wfile.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        while self.rfile.readline().strip():
            pass
        self.wfile.write(f"HTTP/1.1 204 None\r\n\r\n{check.LOOPBACK_MARK}".encode())


def fake_proxy():
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), FakeProxy)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def test_through_a_proxy_it_tells_a_tunnel_from_what_came_back_down_it():
    server, proxy = fake_proxy()
    with server:
        reached = check.through_proxy(proxy, "open.example", 80, False)
        refused = check.through_proxy(proxy, "refused.example", 80, False)
        server.shutdown()
    assert reached == {"host": "open.example", "port": 80, "connect_status": 200, "http_status": 204, "loopback_marker_seen": True}
    assert refused == {"host": "refused.example", "port": 80, "connect_status": 403}


def test_no_proxy_means_no_proxy_requests(tmp_path, monkeypatch):
    _, project = machine(tmp_path, monkeypatch)
    monkeypatch.setattr(check, "direct", lambda host, port: {"host": host})
    report = check.check_inside(project)
    assert report["proxy"] == {"configured": False}
    json.dumps(report)


def test_a_bad_proxy_is_reported_rather_than_raised():
    assert "proxy_error" in check.through_proxy("http://127.0.0.1:1", "example.com", 443, True)
