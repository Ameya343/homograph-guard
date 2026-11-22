"""Does the extension leave web apps working? Playwright's Chromium with the extension loaded.

    python extension/tests/compat.py [screenshot-dir]            # stand-in pages
    python extension/tests/compat.py [screenshot-dir] --live     # also the real public pages

Stand-in pages, served on the real host names so the site adapters apply, do what Gmail-,
Outlook- and chat-style apps do: their own click handlers and keyboard shortcuts, a reply editor
holding the quoted phishing link, constant React-style re-rendering, thousands of links, and a
strict Content-Security-Policy with Trusted Types. Each check is about the site still working:
the site's handlers still run, the user's draft is never touched, a clean page is not modified at
all, the page is not blocked, and the extension logs no errors.

--live also opens the sign-in or QR pages of Gmail, Outlook, Yahoo Mail, WhatsApp, Telegram,
Discord, Slack, Teams and Messenger (no account) with and without the extension and compares them.
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

EXT = Path(__file__).resolve().parent.parent
ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
LIVE = "--live" in sys.argv
SHOTS = Path(ARGS[0]) if ARGS else Path(tempfile.mkdtemp(prefix="hg-compat-"))
PHISH = '<a id="phish" href="https://paypa1.com/signin">https://www.paypal.com/signin</a>'
QUOTED = '<p>On Monday PayPal wrote:</p><blockquote><a id="quoted" href="https://paypa1.com/signin">https://www.paypal.com/signin</a></blockquote>'

# What every stand-in page records about itself: clicks that reached its own handlers, keys,
# and every DOM change made after load (so a change by the extension is visible).
RECORDER = """
window.__site = {clicks: [], keys: [], mutations: [], renders: 0, csp: []};
document.addEventListener("click", (e) => { const a = e.target.closest("a"); window.__site.clicks.push(a ? a.id : e.target.id);
  if (a && a.dataset.spa) e.preventDefault(); });
document.addEventListener("keydown", (e) => window.__site.keys.push(e.key));
document.addEventListener("securitypolicyviolation", (e) => window.__site.csp.push(e.violatedDirective + " " + e.blockedURI));
window.addEventListener("load", () => new MutationObserver((ms) => { for (const m of ms) {
  if (m.target.closest && m.target.closest("[data-live]")) continue;  // the page's own re-rendering
  window.__site.mutations.push(m.type + ":" + (m.attributeName || [...m.addedNodes].map((n) => n.nodeName).join(",")));
}}).observe(document.documentElement, {subtree: true, childList: true, attributes: true, characterData: true}));
"""

GMAIL = f"""<!doctype html><title>Inbox - Gmail</title><script>{RECORDER}</script>
<div role="main"><div class="adn"><h3><span class="gD" email="service@paypal.com" name="PayPal">PayPal</span></h3>
<div class="a3s"><p>Your receipt. {PHISH}</p><p><a id="help" data-spa="1" href="https://www.paypal.com/help">Help center</a></p></div></div>
<div class="M9"><div id="reply" contenteditable="true" role="textbox" aria-label="Message Body">{QUOTED}</div></div></div>"""

OUTLOOK = f"""<!doctype html><title>Mail - Outlook</title><script>{RECORDER}
let n = 0; setInterval(() => {{ const l = document.getElementById("list"); l.innerHTML = "";
  for (let i = 0; i < 30; i++) {{ const d = document.createElement("div"); d.textContent = "Message " + i + " - " + (++n);
  l.append(d); }} window.__site.renders++; }}, 250);
setTimeout(() => {{ const p = document.createElement("p"); p.innerHTML = 'Reminder: <a id="late" href="https://paypa1.com/verify">verify now</a>';
  document.getElementById("body").append(p); window.__lateAt = performance.now(); }}, 2500);</script>
<div id="list" data-live="1" role="list"></div>
<div role="main"><div id="body" aria-label="Message body" class="allowTextSelection"><p>Your account is on hold. {PHISH}</p>
<p><a id="help" data-spa="1" href="https://support.microsoft.com/">Support</a></p></div>
<div id="reply" contenteditable="true" role="textbox" aria-label="Message body">{QUOTED}</div></div>"""

STRICT_CSP = ("default-src 'self'; script-src 'nonce-hg'; style-src 'self'; img-src 'self'; "
              "require-trusted-types-for 'script'; trusted-types app")
STRICT = f"""<!doctype html><title>Strict</title><script nonce="hg">{RECORDER}</script>
<p>Sign in again: {PHISH}</p><p><a id="help" data-spa="1" href="/help">Help</a></p>"""

BIG = ("<!doctype html><title>Big</title><script>" + RECORDER + """
let frames = 0; (function tick() { frames++; window.__frames = frames; requestAnimationFrame(tick); })();
window.__long = []; new PerformanceObserver((l) => { for (const e of l.getEntries()) window.__long.push(Math.round(e.duration)); })
  .observe({type: "longtask", buffered: true});</script><h1>Archive</h1>"""
       + "".join(f'<p>Item {i}: <a href="https://news.example.org/story/{i}">story {i}</a> and docs.example.org/page{i} '
                 f'mentioned in text.</p>' for i in range(5000))
       + f"<p>{PHISH}</p>")

CLEAN = f"""<!doctype html><title>Clean</title><script>{RECORDER}</script>
<p><a id="a1" href="https://www.wikipedia.org/">Wikipedia</a> <a id="a2" href="https://github.com/">GitHub</a>
docs.python.org is mentioned as text.</p><form action="https://www.google.com/search"><input name="q"></form>"""

PAGES = {
    "https://mail.google.com/mail/u/0/#inbox/compat": (GMAIL, {}),
    "https://outlook.live.com/mail/0/inbox/id/compat": (OUTLOOK, {}),
    "https://secure.example.com/strict": (STRICT, {"Content-Security-Policy": STRICT_CSP}),
    "https://news.example.com/big": (BIG, {}),
    "https://docs.example.com/clean": (CLEAN, {}),
}
LIVE_SITES = [
    "https://mail.google.com/", "https://outlook.live.com/mail/", "https://mail.yahoo.com/", "https://web.whatsapp.com/",
    "https://web.telegram.org/a/", "https://discord.com/login", "https://app.slack.com/", "https://teams.microsoft.com/",
    "https://www.messenger.com/",
]

failures: list[str] = []


def check(cond: bool, what: str) -> None:
    print(("PASS " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def status(sw) -> dict:
    return sw.evaluate("""async () => {
        const [t] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
        return await chrome.tabs.sendMessage(t.id, { type: "status" });
    }""")


def settled(sw, pred=lambda s: True, timeout=30.0) -> dict:
    end, s = time.time() + timeout, {}
    while time.time() < end:
        try:
            s = status(sw) or {}
        except Exception:  # noqa: BLE001 - content script not ready yet
            s = {}
        if s and s.get("pending", 1) == 0 and pred(s):
            return s
        time.sleep(0.3)
    return s


def site(page) -> dict:
    return page.evaluate("window.__site")


def main() -> int:
    SHOTS.mkdir(parents=True, exist_ok=True)
    fixtures = {url.split("#")[0]: v for url, v in PAGES.items()}

    def serve(route):
        hit = fixtures.get(route.request.url.split("#")[0])
        if hit is None:
            route.continue_()
        else:
            html, headers = hit
            route.fulfill(status=200, headers={"Content-Type": "text/html; charset=utf-8", **headers}, body=html)

    with sync_playwright() as pw, tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as profile:
        ctx = pw.chromium.launch_persistent_context(
            profile, channel="chromium", headless=True, viewport={"width": 1280, "height": 800},
            args=[f"--disable-extensions-except={EXT}", f"--load-extension={EXT}"])
        ctx.route("**/*", serve)
        sw = ctx.service_workers[0] if ctx.service_workers else ctx.wait_for_event("serviceworker")
        page = ctx.pages[0] if ctx.pages else ctx.new_page()
        ext_errors: list[str] = []
        page.on("console", lambda m: ext_errors.append(m.text) if m.type == "error" and (
            "chrome-extension://" in (m.location or {}).get("url", "") or "content.js" in m.text) else None)
        page.on("pageerror", lambda e: ext_errors.append(f"page error: {e}"))

        for name, url in (("Gmail", "https://mail.google.com/mail/u/0/#inbox/compat"),
                          ("Outlook", "https://outlook.live.com/mail/0/inbox/id/compat")):
            page.goto(url)
            draft_before = page.inner_html("#reply")
            started = time.time()
            page.wait_for_selector("#phish[data-hg-verdict]", timeout=20000)
            took = time.time() - started
            settled(sw)
            check(page.get_attribute("#phish", "data-hg-verdict") == "high_risk", f"{name}: the phishing link in the open email is flagged")
            if name == "Outlook":  # a new email arrives while the page re-renders every 250 ms
                page.wait_for_selector("#late[data-hg-verdict]", timeout=15000)
                late = page.evaluate("(performance.now() - window.__lateAt) / 1000")
                check(late < 5 and site(page)["renders"] > 10,
                      f"Outlook: a link added while the page re-renders every 250 ms is flagged within {late:.1f} s")
            check(page.get_attribute("#quoted", "data-hg-verdict") is None, f"{name}: the link quoted in the reply editor is not marked")
            check(page.inner_html("#reply") == draft_before, f"{name}: the draft's HTML is exactly as before (nothing would be sent along)")
            page.click("#quoted")
            check(site(page)["clicks"][-1:] == ["quoted"], f"{name}: clicking inside the draft reaches the editor (no warning popup)")
            page.click("#reply")
            page.keyboard.press("End")
            page.keyboard.type(" Thanks!")
            check("Thanks!" in page.inner_text("#reply"), f"{name}: typing in the draft works")
            page.click("#help")
            check(site(page)["clicks"][-1:] == ["help"], f"{name}: the site's own click handler runs for a normal link")
            page.click("body", position={"x": 5, "y": 5})
            for k in ("j", "k", "c", "Escape"):
                page.keyboard.press(k)
            check(site(page)["keys"][-4:] == ["j", "k", "c", "Escape"], f"{name}: keyboard shortcuts reach the site")
            page.click("#phish")
            check(site(page)["clicks"][-1:] != ["phish"], f"{name}: only the phishing link's click is intercepted")
            page.keyboard.press("Escape")
            page.screenshot(path=str(SHOTS / f"compat-{name.lower()}.png"))

        page.goto("https://secure.example.com/strict")
        page.wait_for_selector("#phish[data-hg-verdict]", timeout=20000)
        settled(sw)
        page.wait_for_timeout(500)
        violations = site(page)["csp"]
        check(not violations, f"strict CSP + Trusted Types: no policy violations by the extension {violations}")
        page.click("#help")
        check(site(page)["clicks"][-1:] == ["help"], "strict CSP: the site still works")
        page.screenshot(path=str(SHOTS / "compat-strict-csp.png"))

        page.goto("https://news.example.com/big")
        started = time.time()
        s = settled(sw, lambda s: s.get("links", 0) >= 400, timeout=60)
        took = time.time() - started
        check(s.get("links") == 400 and s.get("risky") == 0,
              f"5,000 links: the 400 nearest the screen checked in {took:.1f} s (the phishing link at the end is not on screen yet)")
        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        started = time.time()
        s = settled(sw, lambda s: s.get("risky", 0) >= 1, timeout=30)
        check(s.get("risky") == 1, f"5,000 links: the phishing link at the very end is found {time.time() - started:.1f} s after scrolling to it")
        frames_before = page.evaluate("window.__frames")
        page.wait_for_timeout(1000)
        frames_after = page.evaluate("window.__frames")
        long_tasks = page.evaluate("window.__long")
        check(frames_after - frames_before > 20, f"5,000 links: the page keeps drawing ({frames_after - frames_before} frames in 1 s)")
        check(max(long_tasks or [0]) < 300, f"5,000 links: no long freeze (longest main-thread task {max(long_tasks or [0])} ms)")

        page.goto("https://docs.example.com/clean")
        settled(sw, lambda s: s.get("links", 0) >= 3)
        page.wait_for_timeout(1500)
        check(site(page)["mutations"] == [], f"clean page: the extension changed nothing in it {site(page)['mutations'][:5]}")

        check(not ext_errors, f"no errors from the extension in the page consoles {ext_errors[:3]}")

        if LIVE:
            live_pages(pw, ctx, sw, page)
        ctx.close()
    print(f"\nscreenshots: {SHOTS}")
    print("all compatibility checks passed" if not failures else f"{len(failures)} check(s) failed")
    return 1 if failures else 0


def live_pages(pw, ctx, sw, page) -> None:
    """The real public pages: same title and no extra errors with the extension; nothing flagged or changed."""
    ctx.unroute("**/*")
    plain = pw.chromium.launch(channel="chromium", headless=True)
    for url in LIVE_SITES:
        host = url.split("/")[2]
        base = plain.new_page(viewport={"width": 1280, "height": 800})
        base_errors: list[str] = []
        base.on("pageerror", lambda e, errs=base_errors: errs.append(str(e)))
        sources: dict[str, str] = {}
        with_errors: list[str] = []
        def handler(e, errs=with_errors, where=sources) -> None:
            errs.append(str(e))
            frames = (e.stack or "").splitlines()[1:2]
            where[str(e)] = frames[0].strip()[:160] if frames else "?"  # whose code threw it
        page.on("pageerror", handler)
        try:
            base.goto(url, wait_until="load", timeout=45000)
            page.goto(url, wait_until="load", timeout=45000)
            page.wait_for_timeout(6000)
            for loaded in (base, page):  # some apps (WhatsApp) set their title only after a slow start
                end = time.time() + 25
                while time.time() < end and not loaded.title():
                    loaded.wait_for_timeout(500)
            s = settled(sw, timeout=20)
            marked = page.evaluate("document.querySelectorAll('[data-hg-verdict]').length")
            same = page.title() == base.title()
            extra = sorted(set(with_errors) - set(base_errors))  # errors seen only with the extension
            ours = [x for x in extra if "chrome-extension://" in sources.get(x, "")]
            for x in extra:
                print(f"     note: seen only with the extension this time: {x[:90]} ({sources.get(x, '?')})")
            # Some sites (WhatsApp) now and then answer a headless test browser with an "update your
            # browser" page, with or without the extension. The test browser is not disguised to avoid
            # that: the comparison is then not possible, but errors from the extension still fail.
            refused = [label for label, loaded in (("without", base), ("with", page)) if loaded.evaluate(
                "/works with Google Chrome|update your browser|browser is not supported/i.test(document.body?.innerText || '')")]
            if refused:
                check(not ours and marked == 0,
                      f"live {host}: the site showed its unsupported-browser page to the headless test browser "
                      f"({' and '.join(refused)} the extension), so titles were not compared; errors from the "
                      f"extension: {ours[:2] or 'none'}")
                page.screenshot(path=str(SHOTS / f"live-{host}.png"))
                continue
            # Errors thrown by the site's own code that come and go between loads are the site's;
            # only an error from the extension's code, or a changed page, fails the check.
            check(same and not ours and s.get("risky", 0) == 0 and marked == 0,
                  f"live {host}: loads like without the extension ('{page.title()[:40]}'), {s.get('links', 0)} links "
                  f"checked, {s.get('risky', 0)} flagged, errors from the extension: {ours[:2] or 'none'}")
            page.screenshot(path=str(SHOTS / f"live-{host}.png"))
        except Exception as exc:  # noqa: BLE001 - a site that does not load is reported, not fatal
            check(False, f"live {host}: could not compare ({str(exc)[:120]})")
        finally:
            page.remove_listener("pageerror", handler)
            base.close()
    plain.close()


if __name__ == "__main__":
    raise SystemExit(main())
