#!/usr/bin/env python3
"""Test what a sandbox's mount table and a proxy's status line only suggest.

Run inside the sandbox, this tries a write in each directory and leaves a marker there, opens
existing tools for append without writing, and sends real requests through a configured proxy.
Run again on the host with --host-check, it reports which markers are visible outside, runs the
one left in ~/.cargo/bin, and removes them all. For a disposable machine only: unlike the probe,
it leaves files behind and makes requests that go through to their destination.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

MARK = "agentsec-boundary-test"
RAN = "agentsec-boundary-ran"
LOOPBACK_MARK = "agentsec-loopback-marker"
LOOPBACK_PORT = 8765
WRITE_TARGETS = (".", ".git/hooks", ".agents", "~", "~/.config", "~/.cache", "~/.cargo", "~/.cargo/bin", "~/.dotnet", "~/.nvm", "~/.rustup", "/tmp")
EXISTING_TOOLS = ("~/.cargo/bin/cargo", "~/.cargo/bin/rustup", "~/.dotnet/dotnet", "~/.nvm/nvm.sh")
PLANTED = "~/.cargo/bin"
# (host, port, tls, why it is here)
THROUGH_PROXY = (
    ("example.com", 443, True, "a host no allowlist has a reason to contain"),
    ("pypi.org", 443, True, "a common package host"),
    ("nonexistent.invalid", 443, True, "cannot resolve, so a 200 here does not mean reached"),
    ("metadata.google.internal", 80, False, "resolves only on Google Cloud; no Metadata-Flavor header is sent"),
    ("1.1.1.1", 443, True, "an IP address on an ordinary port"),
    ("localhost", LOOPBACK_PORT, False, "a service bound to the host's loopback, by name"),
    ("127.0.0.1", LOOPBACK_PORT, False, "a service bound to the host's loopback, by address"),
)


def _path(target: str, project: Path) -> Path:
    expanded = Path(os.path.expanduser(target))
    return expanded if expanded.is_absolute() else project / expanded


def try_writes(project: Path) -> list[dict[str, object]]:
    results = []
    for target in WRITE_TARGETS:
        directory = _path(target, project)
        entry: dict[str, object] = {"path": target, "exists": directory.is_dir()}
        try:
            marker = directory / MARK
            marker.write_text(f'#!/bin/sh\n: > "$HOME/{RAN}"\n' if target == PLANTED else "")
            marker.chmod(0o755)
            entry["written"] = True
        except OSError as e:
            entry.update(written=False, error=type(e).__name__, errno=e.errno)
        results.append(entry)
    return results


def try_existing_tools() -> list[dict[str, object]]:
    results = []
    for target in EXISTING_TOOLS:
        path = _path(target, Path.cwd())
        entry: dict[str, object] = {"path": target, "exists": path.is_file()}
        if path.is_file():
            try:
                with path.open("ab"):  # opened for append and closed, so nothing in it changes
                    entry["open_for_append"] = True
            except OSError as e:
                entry.update(open_for_append=False, error=type(e).__name__)
        results.append(entry)
    return results


def _first_line(sock: socket.socket, host: str) -> dict[str, object]:
    sock.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: agentsec-boundary-check\r\n\r\n".encode())
    data = b""
    while len(data) < 65536:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    fields = data.split(b"\r\n", 1)[0].split()
    return {"http_status": int(fields[1]) if len(fields) > 1 and fields[1].isdigit() else None,
            "loopback_marker_seen": LOOPBACK_MARK.encode() in data}


def _issuer(cert: dict) -> str:
    return ", ".join(value for rdn in cert.get("issuer", ()) for key, value in rdn if key in ("organizationName", "commonName"))


def request(sock: socket.socket, host: str, tls: bool) -> dict[str, object]:
    """Send one request down an open connection, and say what came back. Nothing of the body is kept."""
    if not tls:
        return _first_line(sock, host)
    try:
        with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as wrapped:
            return {"tls": "verified", "issuer": _issuer(wrapped.getpeercert()), **_first_line(wrapped, host)}
    except ssl.SSLCertVerificationError as e:
        return {"tls": "certificate not verified", "error": e.verify_message}
    except (OSError, ssl.SSLError) as e:
        return {"tls": "failed", "error": type(e).__name__}


def through_proxy(proxy: str, host: str, port: int, tls: bool) -> dict[str, object]:
    parts = urlsplit(proxy)
    out: dict[str, object] = {"host": host, "port": port}
    try:
        sock = socket.create_connection((parts.hostname, parts.port or 80), timeout=20)
    except OSError as e:
        out["proxy_error"] = type(e).__name__
        return out
    with sock:
        try:
            sock.settimeout(20)
            sock.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
            head = b""
            while b"\r\n\r\n" not in head and len(head) < 8192:
                chunk = sock.recv(1)
                if not chunk:
                    break
                head += chunk
            fields = head.split(b"\r\n", 1)[0].split()
            status = int(fields[1]) if len(fields) > 1 and fields[1].isdigit() else None
            out["connect_status"] = status
            if status == 200:
                out.update(request(sock, host, tls))
        except OSError as e:
            out["error"] = type(e).__name__
    return out


def direct(host: str, port: int) -> dict[str, object]:
    try:
        with socket.create_connection((host, port), timeout=5):
            return {"host": host, "port": port, "connected": True}
    except OSError as e:
        return {"host": host, "port": port, "connected": False, "error": type(e).__name__}


def check_inside(project: Path) -> dict[str, object]:
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    report: dict[str, object] = {
        "writes": try_writes(project),
        "existing_tools": try_existing_tools(),
        "direct": [direct("example.com", 443), direct("127.0.0.1", LOOPBACK_PORT)],
        "proxy": {"configured": bool(proxy)},
    }
    if proxy:
        report["proxy"] = {"configured": True, "loopback": urlsplit(proxy).hostname in ("127.0.0.1", "localhost", "::1"),
                           "targets": [{**through_proxy(proxy, h, p, tls), "why": why} for h, p, tls, why in THROUGH_PROXY]}
    return report


def check_host(project: Path) -> dict[str, object]:
    """From outside the sandbox: which markers persisted, whether the planted one runs, then clean up."""
    home = Path.home()
    seen = {target: (_path(target, project) / MARK).is_file() for target in WRITE_TARGETS}
    ran = False
    planted = _path(PLANTED, project) / MARK
    if planted.is_file():
        subprocess.run([str(planted)], env={"HOME": str(home)}, check=False)
        ran = (home / RAN).exists()
    for leftover in [_path(target, project) / MARK for target in WRITE_TARGETS] + [home / RAN]:
        try:
            leftover.unlink(missing_ok=True)
        except OSError:
            pass  # a directory nothing could be written to has nothing to remove
    return {"markers_visible_on_host": seen, "planted_ran_on_host": ran}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host-check", action="store_true", help="run outside the sandbox, after the run inside it")
    ap.add_argument("--project", type=Path, default=Path("."), help="the directory the run inside used")
    ap.add_argument("--out", type=Path, help="write here rather than to stdout")
    args = ap.parse_args(argv)
    project = args.project.resolve()
    report = check_host(project) if args.host_check else check_inside(project)
    text = json.dumps(report, indent=1, sort_keys=True)
    if args.out:
        args.out.write_text(text + "\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
