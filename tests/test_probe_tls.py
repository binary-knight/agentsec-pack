"""A connection that opens and is then refused at TLS is not egress."""
import socket
import ssl
import threading

from agentsec.probe import blast_probe as probe
from agentsec.scoring import analyze


def pair_with_server(behavior):
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)

    def run():
        conn, _ = server.accept()
        behavior(conn)

    threading.Thread(target=run, daemon=True).start()
    client = socket.create_connection(server.getsockname(), timeout=2)
    client.settimeout(0.5)
    return client


def test_a_connection_closed_during_the_handshake_is_refused():
    client = pair_with_server(lambda conn: (conn.recv(1), conn.close()))
    refused, what = probe._refused_at_tls(client, "example.com")
    assert refused is True and what


def test_a_stalled_handshake_gives_no_clear_answer_so_it_stays_reached():
    held = []
    client = pair_with_server(held.append)
    assert probe._refused_at_tls(client, "example.com") == (False, "stalled")


def test_a_certificate_that_does_not_verify_means_something_answered(monkeypatch):
    class Context:
        def wrap_socket(self, sock, server_hostname):
            raise ssl.SSLCertVerificationError("self signed")

    monkeypatch.setattr(ssl, "create_default_context", Context)
    client = pair_with_server(lambda conn: None)
    assert probe._refused_at_tls(client, "example.com") == (False, "certificate did not verify")


def test_only_hostnames_can_be_checked_by_tls_name():
    assert probe._is_hostname("pypi.org") and not probe._is_hostname("1.1.1.1")


def network(*reached, control=None):
    targets = [{"name": n, "host": n, "port": 443, "connect": True} for n in reached]
    return {"targets": targets, "any_egress": bool(targets), "connect_refused_all": not targets, "direct_control": control}


def ids(net, identity=None):
    env = {"network": net, "identity": identity or {"uid": 1000, "euid": 1000}, "secrets": {}, "filesystem": {}, "process": {}, "resources": {}, "platform": "linux"}
    return {f.id: f for f in analyze(env)}


def test_reached_hosts_with_the_control_refused_are_an_allowlist_not_open_internet():
    found = ids(network("pypi", control={"name": "c", "reached": False, "detail": "ConnectionResetError"}))
    assert "NET-005" in found and "NET-001" not in found


def test_reached_hosts_with_the_control_reached_are_open_internet():
    found = ids(network("pypi", control={"name": "c", "reached": True, "detail": "ok"}))
    assert "NET-001" in found and "NET-005" not in found


def test_a_report_from_before_the_control_existed_scores_as_it_did():
    found = ids(network("pypi"))
    assert "NET-001" in found and "NET-005" not in found


def test_a_user_space_kernel_is_flagged_and_root_inside_it_counts_as_info():
    plain = ids(network(), {"uid": 0, "euid": 0})
    flagged = ids(network(), {"uid": 0, "euid": 0, "user_space_kernel": "gvisor"})
    assert "PRIV-007" in flagged and "PRIV-007" not in plain
    assert flagged["PRIV-007"].weight == 0
    assert plain["PRIV-001"].severity == "high"
    assert flagged["PRIV-001"].severity == "info"
    assert flagged["PRIV-001"].evidence["severity_on_shared_kernel"] == "high"
