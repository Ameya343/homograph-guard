"""Feed updates against a local HTTPS server with a throw-away CA (no internet needed)."""

import http.server
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from homograph_guard import feeds
from homograph_guard.settings import Settings
from homograph_guard.threatdb import ThreatDB

ROOT = Path(__file__).resolve().parent.parent
ENTRY = ROOT / "src" / "homograph_guard" / "_entry.py"
GOOD = {
    "openphish.txt": "https://paypa1-login.com/x/y\nhttps://docs.google.com/forms/d/e/abc/viewform\n",
    "phishing-filter.txt": "# list\nphish-one.top\nphish-two.xyz\npaypal.com\n",
    "urlhaus-filter.txt": "203.0.113.50\nmalware-host.com\n",
    "cert-pl.txt": "\n".join(f"cert-phish-{i}.pl" for i in range(50)),
    "phishing-army.txt": "army-phish.com\n",
    "hagezi-tif.txt": "threat-one.com\nthreat-two.com\n",
}


class FeedServer:
    def __init__(self, tmp: Path):
        from dnslab import make_pki

        self.ca, cert, key = make_pki(tmp, ["localhost"])
        self.files = dict(GOOD)
        self.redirects: dict[str, str] = {}
        self.failures: dict[str, int] = {}  # answer 503 this many times first
        self.delays: dict[str, float] = {}  # wait this long before answering (a download in progress)
        self.requests: list[str] = []
        server = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                name = self.path.lstrip("/")
                server.requests.append(name)
                if server.delays.get(name):
                    time.sleep(server.delays[name])
                if server.failures.get(name):
                    server.failures[name] -= 1
                    self.send_error(503)
                    return
                if name in server.redirects:
                    self.send_response(302)
                    self.send_header("Location", server.redirects[name])
                    self.end_headers()
                    return
                body = server.files.get(name)
                if body is None:
                    self.send_error(404)
                    return
                data = body.encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        class Server(http.server.ThreadingHTTPServer):
            address_family = socket.AF_INET6  # "localhost" resolves to ::1 first; no slow fallback on Windows

        self.httpd = Server(("::1", 0), Handler)
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(cert, key)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    @property
    def mirror(self) -> str:
        return f"https://localhost:{self.port}/"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server(tmp_path):
    s = FeedServer(tmp_path)
    yield s
    s.close()


@pytest.fixture
def db(tmp_path):
    d = ThreatDB(tmp_path / "threats.db")
    yield d
    d.close()


def status(results):
    return {r.name: r.status for r in results}


def test_update_unchanged_shrink_and_failure(server, db):
    s = Settings(feed_mirror=server.mirror, cafile=str(server.ca))
    first = feeds.update(db, s)
    assert status(first) == {**{n: "updated" for n in (f.name for f in feeds.FEEDS) if n != "adguard-dns"},
                             "adguard-dns": "disabled"}
    st = db.status()
    assert st["urls"] == 2 and "paypal.com" not in {r for r in []}  # protected brand refused
    assert db.lookup("x.phish-one.top", None).feeds and not db.lookup("www.paypal.com", None).feeds
    assert status(feeds.update(db, s))["cert-pl"] == "unchanged"

    server.files["cert-pl.txt"] = "only-one.pl\n"  # a feed that suddenly loses 98% of its entries
    server.files.pop("phishing-army.txt")  # and one that disappears
    again = {r.name: r for r in feeds.update(db, s)}
    assert again["cert-pl"].status == "kept" and db.feed_count("cert-pl") == 50
    assert again["phishing-army"].status == "failed" and again["phishing-army"].detail == "HTTP 404"
    assert db.lookup("army-phish.com", None).feeds  # the previous list is still used
    assert again["hagezi-tif"].status == "unchanged"


def test_redirects_tls_and_size_limits(server, db, monkeypatch):
    s = Settings(feed_mirror=server.mirror, cafile=str(server.ca))
    server.redirects["openphish.txt"] = "https://evil.example/feed.txt"
    server.redirects["cert-pl.txt"] = f"http://localhost:{server.port}/cert-pl.txt"
    r = {x.name: x for x in feeds.update(db, s, only=["openphish", "cert-pl"])}
    assert r["openphish"].status == "failed" and "refused redirect" in r["openphish"].detail
    assert r["cert-pl"].status == "failed" and "refused redirect" in r["cert-pl"].detail

    untrusted = Settings(feed_mirror=server.mirror)  # the server's CA is not trusted
    r = feeds.update(db, untrusted, only=["hagezi-tif"])[0]
    assert r.status == "failed" and "not trusted" in r.detail

    monkeypatch.setattr(feeds, "MAX_FEED_BYTES", 10)
    r = feeds.update(db, s, only=["phishing-filter"])[0]
    assert r.status == "failed" and "larger than" in r.detail


def test_fetch_refuses_other_hosts_and_plain_http():
    s = Settings()
    with pytest.raises(ValueError):
        feeds.fetch("https://attacker.example/x", s, feeds.allowed_hosts(s))
    with pytest.raises(ValueError):
        feeds.fetch("http://phishing.army/download/phishing_army_blocklist.txt", s, feeds.allowed_hosts(s))


def test_cli_update_through_the_guard(server, tmp_path):
    """The real command with the sandbox guard on: it may reach only the feed server."""
    home = tmp_path / "home"
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"feed_mirror": server.mirror, "feeds": {"adguard-dns": False}}))
    env = {**os.environ, "HGUARD_HOME": str(home), "HGUARD_POLICY": str(policy)}

    def run(*args):
        return subprocess.run([sys.executable, "-I", str(ENTRY), *args], capture_output=True, text=True,
                              encoding="utf-8", timeout=120, env=env)

    proc = run("update", "--cafile", str(server.ca))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "sandbox" not in proc.stderr
    st = json.loads(run("db", "status", "--json").stdout)
    assert st["domains"] >= 50 and st["urls"] == 2
    rep = json.loads(run("--no-dns", "--json", "https://login.phish-one.top/").stdout)[0]
    assert rep["verdict"] == "high_risk" and any(f["code"] == "FEED_LISTED" for f in rep["findings"])
    assert run("block", "add", "evil-corp-login.com").returncode == 0
    rep = json.loads(run("--no-dns", "--json", "https://evil-corp-login.com/").stdout)[0]
    assert rep["summary"] == "On your blocklist"
    assert "No such" not in run("settings", "set", "dns_mode", "suspicious").stderr
