"""End-to-end test of the browser extension in Playwright's Chromium (Windows, Linux, macOS).

    pip install playwright && python -m playwright install chromium
    python extension/tests/e2e.py [screenshot-dir]
    HG_NATIVE=1 python extension/tests/e2e.py     # also through the app on this device (native messaging)

Fixture pages are served on the real hostnames (mail.google.com, discord.com, web.whatsapp.com,
example.com) through request interception, so the site-specific "focus" logic is exercised.
With the default privacy setting no DNS query is made; nothing leaves the machine. Without HG_NATIVE, an app
installed on this computer is hidden from the test browser, so the extension really runs on its own.
"""

from __future__ import annotations

import datetime as dt
import http.server
import json
import threading
import os
import sys
import tempfile
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

EXT = Path(__file__).resolve().parent.parent
NATIVE = os.environ.get("HG_NATIVE") == "1"
SHOTS = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(tempfile.mkdtemp(prefix="hg-e2e-"))
now = dt.datetime.now().astimezone()
recent = (now - dt.timedelta(hours=1)).isoformat()
old = (now - dt.timedelta(days=3)).isoformat()
wa_recent = f"[{now:%H}:{now:%M}, {now.month}/{now.day}/{now.year}] Bank: "

PAGES = {
    "https://mail.google.com/mail/u/0/#inbox/FMfcgz": """<!doctype html><title>Inbox</title>
<nav><a id="outside" href="https://paypa1.com/other">https://www.paypal.com/ (not the open email)</a></nav>
<div role="main"><div class="adn"><h3><span class="gD" email="service@paypa1.com" name="PayPal">PayPal</span></h3>
<div class="a3s">
 <p>Your account is limited. <a id="masked" href="https://paypa1.com/signin">https://www.paypal.com/signin</a></p>
 <p><a id="safe" href="https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fp%D0%B0ypal.com%2Flogin&amp;data=x">Review activity</a></p>
 <p><a id="ok" href="https://www.paypal.com/help">Help center</a></p>
 <p><a id="jsmail" href="javascript:alert(document.cookie)">View invoice</a></p>
 <p><a id="devonly" href="https://device-only-block.com/statement">Your statement</a></p>
 <div style="display:none"><a id="hidden" href="https://micros0ft-login.top/verify">x</a></div>
 <p id="plain">Or paste hxxps://sbi-kyc-update[.]in/verify into your browser.</p>
</div></div></div>""",
    "https://discord.com/channels/1/2": f"""<!doctype html><title>Discord</title><main>
<ol data-list-id="chat-messages">
 <li id="chat-messages-2-1"><time datetime="{old}">3 days ago</time><div><a id="old" href="https://paypa1.com/old">https://www.paypal.com/old</a></div></li>
 <li id="chat-messages-2-2"><time datetime="{recent}">1 hour ago</time><div><a id="steam" href="https://steamcommunity.com/linkfilter/?u=https%3A%2F%2Fsteamcommunlty.com%2Ftrade">https://steamcommunity.com/tradeoffer/new</a></div></li>
 <li id="chat-messages-2-3"><time datetime="{recent}">1 hour ago</time><div><a id="fine" href="https://github.com/">https://github.com/</a></div></li>
</ol></main>""",
    "https://web.whatsapp.com/": f"""<!doctype html><title>WhatsApp</title><div id="main">
<div role="row"><div data-pre-plain-text="[09:00, 1/2/2020] Old: "><span>see paypa1.com/login</span></div></div>
<div role="row"><div data-pre-plain-text="{wa_recent}"><span>Your KYC expires today, update at sbi-kyc-update.in/verify now</span></div></div>
</div>""",
    "https://example.com/page": """<!doctype html><title>A page</title>
<p><a id="g1" href="https://www.paypal.com@evil.example/login">Log in to PayPal</a></p>
<p><span style="font-size:0">https://аррӏе.com/</span></p>
<form id="f" action="https://xn--pypal-4ve.com/collect"><input name="p"></form>
<p><a id="rel" href="/about">About</a> <a id="js" href="javascript:alert(1)">Click</a></p>""",
}

# Short links ("Show where this short link leads"): fake shortening services and their destinations.
REDIRECTS = {
    "https://bit.ly/hg-e2e": (301, "https://paypa1.com/short-dest"),
    "https://shorturl.at/hg-e2e?passed=1": (302, "https://www.wikipedia.org/wiki/Phishing"),
    "https://is.gd/hg-e2e?ok=1": (302, "https://paypa1.com/verified-dest"),
    "https://tinyurl.com/hg-guard": (301, "https://xn--pypal-4ve.com/login"),  # clicked in a normal tab
}
SPECIAL = {
    # a "checking your browser" page that passes by itself, and loads something from elsewhere
    "https://shorturl.at/hg-e2e": (403, """<!doctype html><title>Just a moment...</title><p>Checking your browser</p>
<img src="https://tracker.example/pixel.gif"><script>setTimeout(() => location.replace("https://shorturl.at/hg-e2e?passed=1"), 800);</script>"""),
    # a check that needs a person
    "https://is.gd/hg-e2e": (200, """<!doctype html><title>Verify</title>
<button id="verify" onclick="location.href='https://is.gd/hg-e2e?ok=1'">Verify you are human</button>"""),
    "https://xn--pypal-4ve.com/login": (200, "<!doctype html><title>Log in</title><form><input name=p></form>"),
    "https://example.com/short": (200, """<!doctype html><title>Short links</title>
<p><a id="s1" href="https://bit.ly/hg-e2e">https://bit.ly/hg-e2e</a> <a id="s2" href="https://shorturl.at/hg-e2e">shorturl.at/hg-e2e</a></p>"""),
}
# Never to be requested: the destinations of the short links, and what their pages load from elsewhere.
NEVER = ("https://paypa1.com/short-dest", "https://www.wikipedia.org/", "https://paypa1.com/verified-dest",
         "https://tracker.example/")
requested: list[str] = []
failures: list[str] = []
served: list[str] = []  # what the local server saw (short.test, dest.test and tracker.test all point at it)


class LocalShortener(http.server.BaseHTTPRequestHandler):
    """A real server playing a shortening service: its log proves the destination is never contacted."""

    def do_GET(self):  # noqa: N802 - http.server API
        host = self.headers.get("Host", "").split(":")[0]
        served.append(f"{host}{self.path}")
        port = self.server.server_address[1]
        if host == "short.test" and self.path == "/hg":
            self.send_response(301)
            self.send_header("Location", f"http://dest.test:{port}/landing")
            body = b""
        elif host == "short.test" and self.path == "/check":
            self.send_response(403)
            body = (f'<!doctype html><title>Just a moment...</title><img src="http://tracker.test:{port}/p.gif">'
                    f'<script>setTimeout(() => location.replace("http://dest.test:{port}/after-check"), 600);</script>').encode()
        else:
            self.send_response(200)
            body = b"<!doctype html><title>reached</title>"
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def check(cond: bool, what: str) -> None:
    print(("PASS " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def status(sw, tab_id: int | None = None) -> dict:
    return sw.evaluate("""async (id) => {
        const [t] = id ? [{ id }] : await chrome.tabs.query({ active: true, lastFocusedWindow: true });
        return await chrome.tabs.sendMessage(t.id, { type: "status" });
    }""", tab_id)


def wait_status(sw, pred, timeout=40.0, tab_id: int | None = None) -> dict:
    end = time.time() + timeout
    s = {}
    while time.time() < end:
        try:
            s = status(sw, tab_id) or {}
        except Exception:  # noqa: BLE001 - content script not ready yet
            s = {}
        if s and pred(s):
            return s
        time.sleep(0.4)
    return s


def verdict(page, sel: str):
    return page.get_attribute(sel, "data-hg-verdict")


def register_native_host(profile: str):
    """Connect the test browser to the app, with its own data folder; returns a function that undoes it.

    A domain that is only on the device blocklist proves the answers came from the app.
    """
    os.environ["HGUARD_HOME"] = tempfile.mkdtemp(prefix="hg-e2e-home-")
    os.environ["HGUARD_POLICY"] = os.path.join(os.environ["HGUARD_HOME"], "no-policy.json")
    from homograph_guard import native_install, paths
    from homograph_guard.native_host import HOST_NAME
    from homograph_guard.threatdb import ThreatDB

    paths.ensure_data_dir()
    # This network lets only the browser reach shortening services (and the tests reach no real one).
    paths.settings_path().write_text(json.dumps({"short_links": "browser"}))
    db = ThreatDB(paths.db_path())
    db.add_entry("block", "device-only-block.com", "end-to-end test")
    db.close()
    command = native_install.host_command(Path(os.environ["HGUARD_HOME"]) / "native-messaging")
    if sys.platform != "win32":  # Linux and macOS: Chromium reads <user-data-dir>/NativeMessagingHosts
        folder = Path(profile) / "NativeMessagingHosts"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / f"{HOST_NAME}.json").write_text(json.dumps(native_install.manifest("chromium", command)))
        return lambda: None
    # Windows has only the per-user registry key (Chromium shares Chrome's). Put back what was
    # registered before, so an installed copy of the app keeps working in Chrome afterwards.
    import winreg

    key_path = rf"{native_install._WIN_KEYS['chromium']}\{HOST_NAME}"
    previous = native_install.registered().get("chromium")
    native_install.register(["chromium"], host_path=command)

    def undo() -> None:
        native_install.unregister(["chromium"])
        if previous:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, previous)

    return undo


def hide_installed_app():
    """Without HG_NATIVE the extension must run without the app. On Windows, Chromium reads Chrome's registry key,
    so an installed copy of the app would answer instead (and ask real shortening services). Its registration is
    hidden for the run and put back afterwards; only the registry value is touched, never the app's files."""
    if NATIVE or sys.platform != "win32":
        return lambda: None
    import winreg

    from homograph_guard import native_install
    from homograph_guard.native_host import HOST_NAME

    key_path = rf"{native_install._WIN_KEYS['chromium']}\{HOST_NAME}"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            previous = winreg.QueryValueEx(key, "")[0]
    except OSError:
        return lambda: None  # no app installed
    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
    print("note: the installed app is hidden from the test browser for this run")

    def undo() -> None:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, previous)

    return undo


def main() -> int:
    SHOTS.mkdir(parents=True, exist_ok=True)
    fixtures = {url.split("#")[0]: html for url, html in PAGES.items()}

    def serve(route):
        url = route.request.url
        requested.append(url)
        if url.startswith(NEVER):
            route.abort()  # recorded above; must not happen
            return
        if url in REDIRECTS:
            status, location = REDIRECTS[url]
            route.fulfill(status=status, headers={"Location": location}, body="")
            return
        if url in SPECIAL:
            status, body = SPECIAL[url]
            route.fulfill(status=status, content_type="text/html; charset=utf-8", body=body)
            return
        html = fixtures.get(url.split("#")[0])
        if html is None:
            route.continue_()
        else:
            route.fulfill(status=200, content_type="text/html; charset=utf-8", body=html)

    local = http.server.ThreadingHTTPServer(("127.0.0.1", 0), LocalShortener)
    threading.Thread(target=local.serve_forever, daemon=True).start()
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as profile:
        undo = register_native_host(profile) if NATIVE else hide_installed_app()
        try:
            with sync_playwright() as pw:
                run(pw, profile, serve, local.server_address[1])
        finally:
            undo()
            local.shutdown()
    print(f"\nscreenshots: {SHOTS}")
    print("all end-to-end checks passed" if not failures else f"{len(failures)} check(s) failed")
    return 1 if failures else 0


def run(pw, profile: str, serve, port: int) -> None:
    ctx = pw.chromium.launch_persistent_context(
        profile, channel="chromium", headless=True, viewport={"width": 1280, "height": 800},
        env=dict(os.environ),  # the app started by the browser must see HGUARD_HOME
        args=[f"--disable-extensions-except={EXT}", f"--load-extension={EXT}",
              "--host-resolver-rules=MAP short.test 127.0.0.1, MAP dest.test 127.0.0.1, MAP tracker.test 127.0.0.1"])
    ctx.route("**/*", serve)
    sw = ctx.service_workers[0] if ctx.service_workers else ctx.wait_for_event("serviceworker")
    ext_id = sw.url.split("/")[2]
    page = ctx.pages[0] if ctx.pages else ctx.new_page()

    # ---- Gmail: only the open message, every kind of link
    page.goto("https://mail.google.com/mail/u/0/#inbox/FMfcgz")
    page.wait_for_selector("#masked[data-hg-verdict]", timeout=15000)
    expected = 7 if NATIVE else 6
    s = wait_status(sw, lambda s: s.get("risky", 0) >= expected and s.get("pending", 1) == 0)
    if NATIVE:
        check(verdict(page, "#devonly") == "high_risk", "App: a domain only on the device blocklist is flagged")
        check(s.get("checked_on") == ["device"], f"App: every link was checked on the device ({s.get('checked_on')})")
        s["risky"] -= 1
    else:
        print(f"note: links were checked on: {s.get('checked_on')} (device = an installed copy of the app answered)")
        check(verdict(page, "#devonly") is None, "A domain only in the test database is not flagged without it")
    check(verdict(page, "#safe") == "high_risk", "Gmail: Safe Links wrapper decoded to a Cyrillic homograph")
    check(verdict(page, "#hidden") in ("high_risk", "suspicious"), "Gmail: hidden link (display:none) flagged")
    check(verdict(page, "#jsmail") == "high_risk", "Gmail: javascript: link in an email flagged")
    check(verdict(page, "#ok") is None, "Gmail: real paypal.com link left alone")
    check(verdict(page, "#outside") is None, "Gmail: link outside the open email is not scanned")
    check(s.get("risky") == 6, f"Gmail: 6 risky (masked, wrapped, javascript:, hidden, sender, plain-text address) - got {s}")
    check(s.get("pending") == 0, "Gmail: every check finished")
    has_hl = page.evaluate("CSS.highlights.has('hg-suspicious') || CSS.highlights.has('hg-high_risk')")
    check(has_hl, "Gmail: plain-text address highlighted without changing the DOM")
    page.screenshot(path=str(SHOTS / "gmail.png"))
    before = page.url
    page.click("#masked")
    page.wait_for_timeout(500)
    check(page.url == before and len(ctx.pages) == 1, "Gmail: click on the phishing link was blocked")
    page.screenshot(path=str(SHOTS / "gmail-blocked.png"))
    page.keyboard.press("Escape")

    # ---- Discord: only the last 24 hours
    page.goto("https://discord.com/channels/1/2")
    page.wait_for_selector("#steam[data-hg-verdict]", timeout=15000)
    s = wait_status(sw, lambda s: s.get("pending", 1) == 0)
    check(verdict(page, "#steam") == "high_risk", "Discord: Steam redirect to steamcommunlty.com flagged")
    check(verdict(page, "#old") is None, "Discord: message older than 24 h ignored")
    check(verdict(page, "#fine") is None, "Discord: github.com left alone")
    check(s.get("links") == 2, f"Discord: only the 2 recent links were checked - got {s}")
    page.screenshot(path=str(SHOTS / "discord.png"))

    # ---- WhatsApp: plain-text address in today's message
    page.goto("https://web.whatsapp.com/")
    s = wait_status(sw, lambda s: s.get("risky", 0) >= 1 and s.get("pending", 1) == 0)
    check(s.get("risky") == 1 and s.get("links") == 1, f"WhatsApp: today's KYC lure flagged, 2020 message ignored - got {s}")
    page.screenshot(path=str(SHOTS / "whatsapp.png"))

    # ---- Ordinary website: the whole page, hidden text, forms, javascript:
    page.goto("https://example.com/page")
    page.wait_for_selector("#g1[data-hg-verdict]", timeout=15000)
    s = wait_status(sw, lambda s: s.get("risky", 0) >= 3 and s.get("pending", 1) == 0)
    check(verdict(page, "#g1") == "high_risk", "Page: fake paypal.com before '@' flagged")
    check(verdict(page, "#f") == "high_risk", "Page: form posting to a homograph flagged")
    check(verdict(page, "#js") is None, "Page: a website's own javascript: button is not flagged")
    check(verdict(page, "#rel") is None, "Page: relative same-site link ignored")
    check(s.get("risky") == 3, f"Page: 3 risky incl. hidden homograph text - got {s}")
    page.screenshot(path=str(SHOTS / "page.png"))

    # ---- Short links: right-click > "Show where this short link leads"
    page.goto("https://example.com/short")
    page.wait_for_timeout(500)
    tab_id = sw.evaluate("async () => (await chrome.tabs.query({ active: true, lastFocusedWindow: true }))[0].id")
    reveal = "async ([url, id]) => homographGuard.revealShortLink(url, await chrome.tabs.get(id))"
    res = sw.evaluate(reveal, ["https://bit.ly/hg-e2e", tab_id])
    check(res.get("state") == "done" and res.get("destination") == "https://paypa1.com/short-dest",
          f"Short link: bit.ly redirect read in a locked-down background tab ({res.get('state')}, {res.get('error')})")
    rep = res.get("report") or {}
    check(rep.get("verdict") in ("suspicious", "high_risk") and (rep.get("short_link") or {}).get("by") == "browser",
          f"Short link: the destination paypa1.com is flagged ({rep.get('verdict')}: {rep.get('summary')})")
    if NATIVE:
        check(rep.get("checked_on") == "device", "Short link: the destination was checked by the app on this device")
    check(len(ctx.pages) == 1, "Short link: the background tab was closed")
    s = status(sw, tab_id)
    check((s.get("short") or {}).get("destination") == "https://paypa1.com/short-dest", "Short link: the answer is shown on the page")
    page.wait_for_timeout(600)  # the card fades in
    page.screenshot(path=str(SHOTS / "short-link.png"))
    res = sw.evaluate(reveal, ["https://shorturl.at/hg-e2e", tab_id])
    check(res.get("state") == "done" and res.get("destination") == "https://www.wikipedia.org/wiki/Phishing",
          f"Short link: a 'checking your browser' page that passes by itself ({res.get('state')}, {res.get('error')})")
    check((res.get("report") or {}).get("verdict") == "no_indicators", "Short link: a harmless destination is not flagged")
    sw.evaluate("([url, id]) => { globalThis.__hgReveal = chrome.tabs.get(id).then((t) => homographGuard.revealShortLink(url, t)); }",
                ["https://is.gd/hg-e2e", tab_id])
    shown = wait_status(sw, lambda s: (s.get("short") or {}).get("state") == "needs-you", timeout=20, tab_id=tab_id)
    check((shown.get("short") or {}).get("state") == "needs-you", "Short link: a check that needs a person is shown to you")
    check_page = next((p for p in ctx.pages if p.url.startswith("https://is.gd/")), None)
    if check_page:
        check_page.screenshot(path=str(SHOTS / "short-link-check.png"))
        check_page.click("#verify")
    res = sw.evaluate("globalThis.__hgReveal")
    check(res.get("state") == "done" and res.get("destination") == "https://paypa1.com/verified-dest",
          f"Short link: after you confirm, the destination is read, not opened ({res.get('state')}, {res.get('error')})")
    leaked = [u for u in requested if u.startswith(NEVER)]
    check(not leaked, f"Short link: no destination (and nothing from another site) was requested - {leaked}")
    find = """async (url) => homographGuard.findInBrowser({ url, host: "short.test", service: "short.test" }, null, () => {})"""
    for path, dest in (("/hg", "/landing"), ("/check", "/after-check")):
        got = sw.evaluate(find, f"http://short.test:{port}{path}")
        check(got.get("destination") == f"http://dest.test:{port}{dest}", f"Short link, real server: {path} read ({got})")
    down = sw.evaluate(find, "http://short.test:1/unreachable")  # nothing listens on port 1
    check("could not be reached" in (down.get("reason") or ""), f"Short link: an unreachable service is reported at once ({down})")
    others = [u for u in served if not u.startswith("short.test/")]
    check(served and not others, f"Short link, real server: only the shortening service was contacted - {served}")
    page.bring_to_front()
    try:
        page.goto("https://tinyurl.com/hg-guard")
    except Exception:  # noqa: BLE001 - the guard replaces the page while it loads
        pass
    end = time.time() + 20
    while time.time() < end and "/warning/warning.html" not in page.url:
        page.wait_for_timeout(300)
    check("/warning/warning.html" in page.url, f"Redirect guard: a short link clicked in a normal tab that redirects to a homograph is stopped ({page.url[:80]})")
    check(not any(u.startswith("https://xn--pypal-4ve.com/") for u in requested), "Redirect guard: the homograph page itself was never requested")
    page.wait_for_timeout(500)
    page.screenshot(path=str(SHOTS / "redirect-guard.png"))
    page.goto("https://example.com/page")

    # ---- Toggle off and on
    sw.evaluate("chrome.storage.local.set({ enabled: false })")
    page.wait_for_function("!document.querySelector('[data-hg-verdict]')", timeout=5000)
    check(page.query_selector("hg-guard-ui") is None, "Off: marks and panel removed")
    sw.evaluate("chrome.storage.local.set({ enabled: true })")
    page.wait_for_selector("#g1[data-hg-verdict]", timeout=15000)
    check(True, "On again: page rescanned")

    # ---- Popup: the slide switch
    popup = ctx.new_page()
    popup.set_viewport_size({"width": 300, "height": 200})
    popup.goto(f"chrome-extension://{ext_id}/popup/popup.html")
    popup.wait_for_selector("#toggle[aria-checked='true']")
    popup.screenshot(path=str(SHOTS / "popup-on.png"))
    popup.click("#toggle")
    popup.wait_for_selector("#toggle[aria-checked='false']")
    popup.wait_for_timeout(400)
    popup.screenshot(path=str(SHOTS / "popup-off.png"))
    check(sw.evaluate("chrome.storage.local.get('enabled').then(v => v.enabled)") is False, "Popup: switch turns protection off")
    popup.click("#toggle")
    popup.wait_for_selector("#toggle[aria-checked='true']")
    check(sw.evaluate("chrome.storage.local.get('enabled').then(v => v.enabled)") is True, "Popup: switch turns protection on")
    if NATIVE:
        opts = ctx.new_page()
        opts.goto(f"chrome-extension://{ext_id}/options/options.html")
        opts.wait_for_function("/Connected|not installed/.test(document.getElementById('status-text').textContent)", timeout=20000)
        check("Connected" in opts.inner_text("#status-text"), "Options page: connected to the app on this device")
        opts.screenshot(path=str(SHOTS / "options-native.png"), full_page=True)
    ctx.close()


if __name__ == "__main__":
    raise SystemExit(main())
