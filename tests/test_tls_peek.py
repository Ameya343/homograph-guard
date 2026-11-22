import socket
import ssl
import threading

from homograph_guard import tls_peek as tp


def _serve_once(ctx, port_holder, ready):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port_holder.append(srv.getsockname()[1])
    ready.set()
    for _ in range(2):
        try:
            conn, _ = srv.accept()
            with ctx.wrap_socket(conn, server_side=True) as tls:
                tls.recv(1)  # we never expect application data
        except (OSError, ssl.SSLError):
            pass
    srv.close()


def test_refuses_private_targets():
    assert "refused" in tp.tls_peek("127.0.0.1", "x.example")["error"]
    assert "refused" in tp.tls_peek("192.168.1.1", "x.example")["error"]


def test_peek_reads_certificate_without_http(lab, monkeypatch):
    monkeypatch.setattr(tp, "_target_allowed", lambda addr: True)
    ports, ready = [], threading.Event()
    threading.Thread(target=_serve_once, args=(lab.server_ctx, ports, ready), daemon=True).start()
    ready.wait(5)
    res = tp.tls_peek("127.0.0.1", "google.dns.test", port=ports[0], timeout=3, cafile=str(lab.ca))
    assert res["verified"] is True and "google.dns.test" in res["san"]
    assert res["issuer"].startswith("homograph-guard test lab") and len(res["sha256"]) == 64


def test_peek_reports_untrusted_certificate(lab, monkeypatch):
    monkeypatch.setattr(tp, "_target_allowed", lambda addr: True)
    ports, ready = [], threading.Event()
    threading.Thread(target=_serve_once, args=(lab.server_ctx, ports, ready), daemon=True).start()
    ready.wait(5)
    res = tp.tls_peek("127.0.0.1", "google.dns.test", port=ports[0], timeout=3)  # test CA not trusted
    assert res["verified"] is False and res["verify_error"] and len(res["sha256"]) == 64
    assert "google.dns.test" in res.get("san", [])  # parsed with cryptography
