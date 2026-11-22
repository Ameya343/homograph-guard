"""The native messaging host, driven over its real stdin/stdout protocol."""

import getpass
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from homograph_guard.native_host import CHROME_EXTENSION_IDS, caller_allowed, encode_message

ENTRY = Path(__file__).resolve().parent.parent / "src" / "homograph_guard" / "_native_entry.py"
ORIGIN = f"chrome-extension://{CHROME_EXTENSION_IDS[0]}/"


class HostProc:
    def __init__(self, home: Path, *args: str):
        env = {**os.environ, "HGUARD_HOME": str(home), "HGUARD_POLICY": str(home / "none.json")}
        self.home = home
        self.p = subprocess.Popen([sys.executable, "-I", str(ENTRY), *args], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        self.raw: list[bytes] = []

    def send(self, obj) -> None:
        self.send_raw(encode_message(obj))

    def send_raw(self, data: bytes) -> None:
        self.p.stdin.write(data)
        self.p.stdin.flush()

    def recv(self) -> dict:
        header = self.p.stdout.read(4)
        assert len(header) == 4, self.p.stderr.read().decode(errors="replace")
        (n,) = struct.unpack("=I", header)
        data = self.p.stdout.read(n)
        self.raw.append(data)
        return json.loads(data)

    def ask(self, obj) -> dict:
        self.send(obj)
        return self.recv()

    def close(self) -> int:
        self.p.stdin.close()
        code = self.p.wait(timeout=30)
        self.p.stdout.close()
        self.p.stderr.close()
        return code


@pytest.fixture
def host(tmp_path):
    h = HostProc(tmp_path, ORIGIN, "--parent-window=0")
    yield h
    if h.p.poll() is None:
        h.close()


def test_hello_lists_reports_and_checks(host):
    hello = host.ask({"type": "hello", "req": "r1"})
    assert hello["type"] == "hello" and hello["req"] == "r1" and hello["settings"]["dns_mode"] == "off"
    ok = host.ask({"type": "list_add", "req": "r2", "list": "block", "entry": "https://evil-corp-login.com/sso", "note": "phish"})
    assert ok == {"type": "ok", "entry": {"match": "url", "value": "https://evil-corp-login.com/sso"}, "req": "r2"}
    assert host.ask({"type": "report", "req": "r3", "url": "https://reported-phish.com/x", "note": ""})["type"] == "ok"
    assert host.ask({"type": "list_add", "list": "allow", "entry": "partner-site.com", "note": ""})["type"] == "ok"
    host.send({"type": "check", "req": "r4", "links": [
        {"id": "a", "url": "https://evil-corp-login.com/sso?x=1", "ctx": {"source": "anchor", "text": "Sign in"}},
        {"id": "b", "url": "https://reported-phish.com/x"},
        {"id": "c", "url": "https://p\u0430ypal.com/"},
        {"id": "d", "url": "https://example.org/", "ctx": {"evil": "x" * 9999, "text": 5}},
        {"id": "../../x", "url": "https://skipped.example/"},
    ]})
    results = {}
    for _ in range(4):
        r = host.recv()
        results[r["id"]] = r["report"]
    assert results["a"]["summary"] == "On your blocklist" and results["a"]["checked_on"] == "device"
    assert results["b"]["summary"] == "You reported this link as phishing"
    assert results["c"]["verdict"] == "high_risk"
    assert results["d"]["verdict"] == "no_indicators" and "evil" not in (results["d"]["context"] or {})
    lists = host.ask({"type": "lists", "req": "r5"})
    assert lists["block"][0]["value"] == "https://evil-corp-login.com/sso" and lists["reported"][0]["url"] == "https://reported-phish.com/x"
    assert host.ask({"type": "list_remove", "req": "r6", "list": "block", "entry": "https://evil-corp-login.com/sso"})["removed"]
    assert host.ask({"type": "settings_set", "req": "r7", "dns_mode": "suspicious"})["settings"]["dns_mode"] == "suspicious"
    assert host.close() == 0


def test_short_links(host):
    """Links on pages are never expanded by themselves; a destination found in the browser is checked here."""
    host.send({"type": "check", "req": "c1", "links": [{"id": "s", "url": "https://bit.ly/abc"}]})
    rep = host.recv()["report"]
    assert rep["verdict"] == "caution" and rep["short_link"]["destination"] is None
    reply = host.ask({"type": "expand", "req": "s1", "url": "https://shorturl.at/zNYEi",
                      "destination": "https://paypa1.com/signin"})
    assert reply["type"] == "expanded" and reply["req"] == "s1"
    rep = reply["report"]
    assert rep["verdict"] == "high_risk" and rep["wrapped"]["hops"][0]["kind"] == "shortener"
    assert rep["short_link"] == {"service": "shorturl.at", "destination": "https://paypa1.com/signin", "reason": None,
                                 "browser_needed": False, "final": False, "by": "browser"}
    chain = host.ask({"type": "expand", "url": "https://bit.ly/a", "steps": ["https://bit.ly/a", "tinyurl.com/b"],
                      "destination": "https://example.org/"})["report"]
    assert [h["host"] for h in chain["wrapped"]["hops"]] == ["bit.ly", "tinyurl.com"]
    bad = host.ask({"type": "expand", "url": "https://bit.ly/a", "steps": ["https://evil.example/"], "destination": "https://x.example/"})
    assert bad["error"] == "steps must be 1 to 4 short links"
    assert host.ask({"type": "expand", "url": "https://bit.ly/x", "destination": ["x"]})["error"] == "invalid destination"
    assert host.close() == 0


@pytest.mark.parametrize("msg,error", [
    ({"type": "rm -rf /"}, "unknown command"),
    ({"type": "expand", "url": "https://example.com/abc"}, "not a link from a known link-shortening service"),
    ({"type": "expand"}, "url"),
    ({"type": "list_add", "list": "../../etc/passwd", "entry": "x.com"}, "list must be"),
    ({"type": "list_add", "list": "block", "entry": "co.uk"}, "public suffix"),
    ({"type": "list_add", "list": "block", "entry": "x" * 5000}, "at most"),
    ({"type": "list_add", "list": "block", "entry": ["a"]}, "must be text"),
    ({"type": "report", "url": "javascript:alert(1)"}, "only web links"),
    ({"type": "settings_set", "dns_mode": "everything"}, "dns_mode must be"),
    ({"type": "check", "links": [{"id": "x", "url": "https://a.com"}] * 501}, "at most 500"),
])
def test_bad_messages_are_rejected(host, msg, error):
    reply = host.ask({**msg, "req": "bad"})
    assert reply["type"] == "error" and error in reply["error"], reply


@pytest.mark.parametrize("frame", [
    struct.pack("=I", 0xFFFFFFFF),  # 4 GB announced
    struct.pack("=I", 5) + b"nope!",  # not JSON
    struct.pack("=I", 2) + b"[]",  # not an object
    b"\x01\x00",  # truncated header
])
def test_protocol_errors_end_the_session_safely(tmp_path, frame):
    h = HostProc(tmp_path, ORIGIN)
    h.send_raw(frame)
    if frame != b"\x01\x00":
        assert h.recv()["error"].startswith("protocol error")
    assert h.close() == 0


def test_replies_reveal_nothing_about_the_device(host):
    host.ask({"type": "hello"})
    host.ask({"type": "status"})
    host.ask({"type": "lists"})
    host.ask({"type": "list_add", "list": "allow", "entry": "\\\\server\\share"})
    host.send({"type": "check", "links": [{"id": "z", "url": "file://attacker.example/share/x.lnk"}]})
    host.recv()
    blob = b"".join(host.raw).decode()
    for secret in (str(host.home), str(host.home).replace("\\", "\\\\"), getpass.getuser(), os.environ.get("COMPUTERNAME", "@@"),
                   sys.executable.replace("\\", "\\\\")):
        assert secret.lower() not in blob.lower(), secret


def test_only_our_extension_may_start_it(tmp_path):
    assert caller_allowed(["host", ORIGIN, "--parent-window=1"])
    assert caller_allowed(["host", "C:\\x\\manifest.json", "{b8a89689-dc16-48f4-936e-100f254404d8}"])
    assert not caller_allowed(["host", "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"])
    assert not caller_allowed(["host"])
    p = HostProc(tmp_path, "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/")
    assert p.close() == 2


def test_short_link_setting(tmp_path):
    """short_links = browser: the app never asks the service itself; off (e.g. by policy): nobody asks."""
    (tmp_path / "settings.json").write_text('{"short_links": "browser"}')
    h = HostProc(tmp_path, ORIGIN)
    rep = h.ask({"type": "expand", "url": "https://bit.ly/abc"})["report"]
    assert rep["short_link"]["browser_needed"] is True and rep["verdict"] == "caution"
    assert h.ask({"type": "expand", "url": "https://bit.ly/abc", "destination": "https://example.org/"})["type"] == "expanded"
    assert h.close() == 0
    (tmp_path / "none.json").write_text('{"short_links": "off"}')  # the organisation's policy
    h = HostProc(tmp_path, ORIGIN)
    err = h.ask({"type": "expand", "url": "https://bit.ly/abc", "destination": "https://example.org/"})
    assert err["type"] == "error" and err["locked"] is True and "organisation" in err["error"]
    assert h.close() == 0
