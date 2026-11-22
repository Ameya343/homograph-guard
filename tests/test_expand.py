"""Short links: the shortening service is asked where a link leads; the destination is never contacted.

A fake HTTPS "shortening service" on 127.0.0.1 answers for bit.ly, tinyurl.com and shorturl.at with a
certificate from a throwaway test CA. Nothing leaves the machine.
"""

import http.server
import ssl
import threading

import pytest

from dnslab import make_pki
from homograph_guard import expand as ex
from homograph_guard.analyzer import Analyzer, Options
from homograph_guard.cli import build_parser
from homograph_guard.dns_check import DnsInvestigator
from homograph_guard.dns_transport import DnsClient

ALL = ["google", "cloudflare", "cloudflare-security", "adguard-unfiltered", "adguard"]
SHORT_HOSTS = ["bit.ly", "tinyurl.com", "shorturl.at"]
CHALLENGE = b"<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>challenge-platform</body></html>"


class FakeShortener:
    def __init__(self, directory):
        self.ca, cert, key = make_pki(directory, SHORT_HOSTS)
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(cert, key)
        self.requests: list[tuple[str, str, str, dict]] = []
        self.routes = {
            ("bit.ly", "/abc"): (301, {"Location": "https://tinyurl.com/xyz"}, b""),
            ("tinyurl.com", "/xyz"): (302, {"Location": "https://paypa1.com/signin"}, b""),
            ("bit.ly", "/rel"): (301, {"Location": "/abc"}, b""),
            ("bit.ly", "/meta"): (200, {"Content-Type": "text/html"},
                                  b'<html><head><meta http-equiv="refresh" content="0; url=https://evil.example/x">'),
            ("bit.ly", "/page"): (200, {"Content-Type": "text/html"}, b"<html><body>Bitly</body></html>"),
            ("bit.ly", "/gone"): (404, {}, b"not found"),
            ("bit.ly", "/js"): (301, {"Location": "javascript:alert(1)"}, b""),
            ("bit.ly", "/news"): (301, {"Location": "https://www.wikipedia.org/wiki/Phishing"}, b""),
            ("shorturl.at", "/zNYEi"): (403, {"cf-mitigated": "challenge", "Content-Type": "text/html"}, CHALLENGE),
        }
        for i in range(1, 6):
            self.routes[("bit.ly", f"/l{i}")] = (301, {"Location": f"https://bit.ly/l{i + 1}"}, b"")
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):  # noqa: N802 - http.server API
                host = self.headers.get("Host", "")
                outer.requests.append((self.command, host, self.path, dict(self.headers)))
                status, headers, body = outer.routes.get((host, self.path), (404, {}, b""))
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        class Server(http.server.ThreadingHTTPServer):
            daemon_threads = True

            def handle_error(self, request, client_address):
                pass  # a client that rejects the certificate is part of a test

        self.httpd = Server(("127.0.0.1", 0), Handler)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def hosts(self) -> list[str]:
        return [r[1] for r in self.requests]


@pytest.fixture(scope="module")
def shortener(tmp_path_factory):
    srv = FakeShortener(tmp_path_factory.mktemp("short-pki"))
    yield srv
    srv.httpd.shutdown()


@pytest.fixture
def local(shortener, monkeypatch):
    """Let the expander talk to the fake service on loopback (public addresses only, normally)."""
    monkeypatch.setattr(ex, "_target_allowed", lambda addr: True)
    monkeypatch.setattr(ex, "HTTPS_PORT", shortener.port)
    shortener.requests.clear()
    asked: list[str] = []

    def resolve(host):
        asked.append(host)
        return ["127.0.0.1"] if host in SHORT_HOSTS else []

    return shortener, resolve, asked


def run(local, url, **kw):
    srv, resolve, _ = local
    return ex.expand(url, resolve, timeout=3, cafile=str(srv.ca), **kw)


def test_only_known_shorteners_are_asked():
    assert ex.expand("https://example.com/abc", lambda h: ["127.0.0.1"]) is None
    assert ex.short_link("https://example.com/") is None and ex.short_link("mailto:x@bit.ly") is None
    assert ex.short_link("shorturl.at/zNYEi") == ("https://shorturl.at/zNYEi", "shorturl.at")
    assert ex.short_link("http://BIT.ly/AbC?x=1#frag") == ("https://bit.ly/AbC?x=1", "bit.ly")
    assert ex.short_link("https://bit.ly:8443/x") is None


def test_chain_of_short_links_is_read_but_the_destination_is_never_contacted(local):
    exp = run(local, "https://bit.ly/abc")
    srv, _, asked = local
    assert exp.destination == "https://paypa1.com/signin" and exp.reason is None
    assert exp.steps == ["https://bit.ly/abc", "https://tinyurl.com/xyz"]
    assert asked == ["bit.ly", "tinyurl.com"]  # paypa1.com was not even looked up
    assert srv.hosts() == ["bit.ly", "tinyurl.com"]
    for method, _host, _path, headers in srv.requests:
        assert method == "GET" and headers["User-Agent"].startswith("homograph-guard/")
        assert "does not follow the link" in headers["User-Agent"]
        assert "Cookie" not in headers and headers.get("Connection") == "close"


def test_relative_redirect_and_meta_refresh(local):
    assert run(local, "https://bit.ly/rel").steps == ["https://bit.ly/rel", "https://bit.ly/abc", "https://tinyurl.com/xyz"]
    assert run(local, "https://bit.ly/meta").destination == "https://evil.example/x"
    page = run(local, "https://bit.ly/page")
    assert page.destination is None and "answered 200" in page.reason


def test_browser_check_is_reported_never_bypassed(local):
    exp = run(local, "https://shorturl.at/zNYEi")
    srv, _, _ = local
    assert exp.destination is None and exp.browser_needed is True
    assert "only to a web browser" in exp.reason and "Show where this short link leads" in exp.reason
    assert len(srv.requests) == 1  # asked once, honestly; no second try pretending to be a browser


def test_unknown_link_loops_and_odd_targets(local):
    gone = run(local, "https://bit.ly/gone")
    assert "does not know this short link" in gone.reason and gone.final
    loop = run(local, "https://bit.ly/l1")
    assert loop.destination is None and loop.reason == "too many short links in a row" and len(loop.steps) == ex.MAX_STEPS
    assert run(local, "https://bit.ly/js").destination == "javascript:alert(1)"  # analysed as it is, never run


def test_private_addresses_are_never_contacted(shortener, monkeypatch):
    monkeypatch.setattr(ex, "HTTPS_PORT", shortener.port)
    shortener.requests.clear()
    exp = ex.expand("https://bit.ly/abc", lambda h: ["10.1.2.3", "127.0.0.1", "::1"], timeout=3, cafile=str(shortener.ca))
    assert exp.destination is None and "private or local address" in exp.reason
    assert shortener.requests == []
    assert "could not be looked up" in ex.expand("https://bit.ly/abc", lambda h: [], timeout=3).reason


def test_untrusted_certificate_is_refused(local):
    srv, resolve, _ = local
    exp = ex.expand("https://bit.ly/abc", resolve, timeout=3)  # the test CA is not trusted
    assert exp.destination is None and "valid certificate" in exp.reason


# ---------------------------------------------------------------------------- in the analyzer
@pytest.fixture
def online(lab, brands, cmap, local):
    lab.set_all(ALL, "bit.ly", "A", values=["127.0.0.1"])
    lab.set_all(ALL, "tinyurl.com", "A", values=["127.0.0.1"])
    lab.set_all(ALL, "shorturl.at", "A", values=["127.0.0.1"])
    srv = local[0]

    def make(**opts):
        return Analyzer(brands, cmap, DnsInvestigator(DnsClient("udp", timeout=3), lab.resolvers, asn=False),
                        Options(cafile=str(srv.ca), **opts))

    return make


def test_expanded_short_link_is_judged_by_its_destination(online, local):
    rep = online().analyze("https://bit.ly/abc")
    codes = {f["code"] for f in rep["findings"]}
    assert rep["verdict"] == "high_risk" and {"URL_SHORTENER_EXPANDED", "BRAND_LOOKALIKE"} <= codes
    assert "URL_SHORTENER" not in codes
    assert rep["short_link"]["destination"] == "https://paypa1.com/signin" and rep["short_link"]["by"] == "app"
    assert [h["kind"] for h in rep["wrapped"]["hops"]] == ["shortener", "shortener"]
    assert rep["url"]["host_ascii"] == "paypa1.com" and "behind a bit.ly short link" in rep["summary"]
    assert "paypa1.com" not in local[0].hosts()
    clean = online().analyze("bit.ly/news")  # typed without https://
    assert clean["verdict"] == "no_indicators" and clean["summary"].startswith("Short link to www.wikipedia.org")


def test_short_link_that_cannot_be_expanded_is_caution(online, offline):
    rep = online().analyze("https://shorturl.at/zNYEi")
    f = next(f for f in rep["findings"] if f["code"] == "URL_SHORTENER")
    assert rep["verdict"] == "caution" and f["weight"] == 15 and f["evidence"]["browser_needed"] is True
    assert "only to a web browser" in f["detail"]
    off = offline.analyze("https://shorturl.at/zNYEi")
    assert off["verdict"] == "caution" and "network checks are off" in off["short_link"]["reason"]


def test_links_in_messages_are_not_expanded_unless_asked(online, local):
    ctx = {"source": "anchor", "text": "https://bit.ly/abc", "medium": "email"}
    rep = online().analyze("https://bit.ly/abc", ctx)
    assert rep["verdict"] == "caution" and "counts as a click" in rep["short_link"]["reason"]
    assert local[0].requests == []  # the person who made the link learns nothing
    rep = online(expand_in_messages=True).analyze("https://bit.ly/abc", ctx)
    codes = {f["code"] for f in rep["findings"]}
    assert rep["verdict"] == "high_risk" and "LINK_TEXT_MISMATCH" not in codes  # the text is the short link itself
    off = online(expand=False).analyze("https://bit.ly/abc")
    assert "switched off" in off["short_link"]["reason"]


def test_text_showing_a_brand_over_a_short_link_to_elsewhere(online):
    rep = online(expand_in_messages=True).analyze(
        "https://bit.ly/abc", {"source": "anchor", "text": "www.paypal.com", "medium": "email"})
    mismatch = next(f for f in rep["findings"] if f["code"] == "LINK_TEXT_MISMATCH")
    assert mismatch["title"] == "Link text shows paypal.com but opens paypa1.com"


def test_destination_found_by_the_browser(offline):
    exp = ex.Expansion(url="https://shorturl.at/zNYEi", service="shorturl.at", destination="https://paypa1.com/signin",
                       steps=["https://shorturl.at/zNYEi"], by="browser")
    rep = offline.analyze("https://shorturl.at/zNYEi", expansion=exp)
    assert rep["verdict"] == "high_risk" and rep["short_link"]["by"] == "browser"
    assert rep["wrapped"]["hops"][0]["wrapper_url"] == "https://shorturl.at/zNYEi"


def test_cli_flags():
    args = build_parser().parse_args(["--no-expand", "--expand-in-messages", "bit.ly/x"])
    assert args.no_expand and args.expand_in_messages
