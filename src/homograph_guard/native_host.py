"""Native messaging host: how the browser extension uses this device.

The browser starts this program when the Homograph Guard extension connects and
talks to it over stdin/stdout (4-byte length + JSON, the native messaging
protocol). There is no network listener: nothing else on the network or on the
web can reach it, and the browser only lets the extension IDs listed in the host
manifest connect.

What it does for the extension, all on this device:

* checks links against the threat database (daily feeds, your lists, your reports)
  and the full analysis of the desktop app;
* optionally asks the DNS resolvers about suspicious links (privacy setting,
  off by default), over pinned resolver addresses;
* lets you manage your allowlist / blocklist and report phishing links;
* finds out where a short link leads - only when you ask for that link (right-click >
  "Show where this short link leads"): the shortening service is asked, the destination
  is never contacted.

Hardening: every message is size-limited and validated against a fixed set of
commands; responses never contain file paths, user names or other details about
the device; the sandbox guard blocks processes, native code, file writes other
than the database and settings, and any network traffic other than the pinned
DNS resolvers.
"""

from __future__ import annotations

import json
import re
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import __version__, guard, paths, settings as settings_mod
from .analyzer import Analyzer, Options
from .brands import BrandIndex, default_domains
from .expand import Expansion, expand as expand_short_link, short_link
from .threatdb import ThreatDB, backup_files, ensure_healthy, side_files
from .unicode_tools import ConfusableMap

HOST_NAME = "com.homograph_guard.host"
CHROME_EXTENSION_IDS = ("lfcmpmjjgdljkicfeikalojnocghgibe",)
FIREFOX_EXTENSION_IDS = ("{b8a89689-dc16-48f4-936e-100f254404d8}",)
MAX_MESSAGE = 1024 * 1024
MAX_REPLY = 1000 * 1000
MAX_LINKS = 500
CACHE_TTL = 30 * 60
_ID = re.compile(r"^[A-Za-z0-9_\-]{1,40}$")
_CTX_KEYS = ("source", "text", "hidden", "where", "medium")
_COMMANDS = ("hello", "check", "expand", "lists", "list_add", "list_remove", "report", "settings", "settings_set",
             "status")


class ProtocolError(Exception):
    pass


def read_message(stream) -> dict | None:
    header = stream.read(4)
    if not header:
        return None  # the browser closed the connection
    if len(header) < 4:
        raise ProtocolError("truncated header")
    (size,) = struct.unpack("=I", header)
    if size == 0 or size > MAX_MESSAGE:
        raise ProtocolError("message size out of range")
    data = stream.read(size)
    if len(data) < size:
        raise ProtocolError("truncated message")
    try:
        msg = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ProtocolError("not JSON") from exc
    if not isinstance(msg, dict):
        raise ProtocolError("not a JSON object")
    return msg


def encode_message(obj: dict) -> bytes:
    data = json.dumps(obj, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    if len(data) > MAX_REPLY:
        data = json.dumps({"type": "error", "req": obj.get("req"), "error": "reply too large"}).encode("ascii")
    return struct.pack("=I", len(data)) + data


def slim(rep: dict) -> dict:
    """The parts of a report the extension shows. Never includes anything about the device."""
    findings = sorted(rep.get("findings") or [], key=lambda f: -abs(f.get("weight", 0)))[:12]
    d = rep.get("dns") or {}
    url = rep.get("url") or {}
    wrapped = rep.get("wrapped")
    return {
        "input": rep.get("input"), "verdict": rep.get("verdict"), "verdict_label": rep.get("verdict_label"),
        "score": rep.get("score"), "summary": rep.get("summary"), "defanged": rep.get("defanged"),
        "kind": rep.get("kind"), "error": rep.get("error"),
        "url": {"host_unicode": url.get("host_unicode"), "host_ascii": url.get("host_ascii"),
                "registrable": url.get("registrable")} if url else None,
        "wrapped": {"destination": wrapped["destination"],
                    "hops": [{k: h.get(k) for k in ("service", "host", "trusted", "kind")} for h in wrapped["hops"]],
                    "embedded": ({"url": wrapped["embedded"]["url"], "param": wrapped["embedded"]["param"]}
                                 if wrapped.get("embedded") else None)} if wrapped else None,
        "context": rep.get("context"),
        "lists": rep.get("lists"),
        "short_link": {k: rep["short_link"].get(k)
                       for k in ("service", "destination", "reason", "browser_needed", "final", "by")}
        if rep.get("short_link") else None,
        "findings": [{k: f.get(k) for k in ("code", "severity", "weight", "title", "detail")} for f in findings],
        "dns": {"consensus": d.get("consensus"),
                "brand": {"domain": d["brand"]["domain"], "relation": d["brand"]["relation"]} if d.get("brand") else None,
                "resolvers": [{"name": r["name"], "filtering": r["filtering"], "blocked": r["blocked"],
                               "block_reason": r["block_reason"], "rcode": r["a"].get("rcode"),
                               "addresses": (r["a"].get("addresses") or [])[:3], "error": r["a"].get("error")}
                              for r in d.get("resolvers") or []]} if d.get("resolvers") else None,
        "checked_on": "device",
    }


def _text(msg: dict, key: str, limit: int, required: bool = True) -> str:
    value = msg.get(key)
    if not required and value in (None, ""):
        return ""
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ValueError(f"'{key}' must be text of at most {limit} characters")
    return value


def _req(msg: dict) -> str | None:
    req = msg.get("req")
    return req if isinstance(req, str) and _ID.match(req) else None


class Host:
    def __init__(self, db: ThreatDB, analyzer_offline: Analyzer, make_online, settings: settings_mod.Settings,
                 out, settings_file=None, policy_file=None):
        self.db = db
        self.offline = analyzer_offline
        self.make_online = make_online  # () -> Analyzer with DNS, created on first use
        self.online: Analyzer | None = None
        self.settings = settings
        self.settings_file = settings_file
        self.policy_file = policy_file
        self.out = out
        self.lock = threading.Lock()
        self.cache: dict[str, tuple[float, dict]] = {}

    def send(self, obj: dict) -> None:
        data = encode_message(obj)
        with self.lock:
            self.out.write(data)
            self.out.flush()

    # ------------------------------------------------------------------ commands
    def handle(self, msg: dict, pool: ThreadPoolExecutor) -> None:
        kind = msg.get("type")
        req = _req(msg)
        if kind not in _COMMANDS:
            self.send({"type": "error", "req": req, "error": "unknown command"})
            return
        try:
            if kind == "check":
                self.check(msg, req, pool)
                return
            if kind == "expand":  # may take a few seconds: off the reading thread
                pool.submit(self._expand_reply, msg, req)
                return
            reply = getattr(self, f"cmd_{kind}")(msg)
        except PermissionError as exc:
            reply = {"type": "error", "error": str(exc)[:300], "locked": True}
        except ValueError as exc:
            reply = {"type": "error", "error": str(exc)[:300]}
        except Exception:  # noqa: BLE001 - never leak tracebacks (they contain paths)
            reply = {"type": "error", "error": "internal error"}
        reply["req"] = req
        self.send(reply)

    def cmd_hello(self, msg: dict) -> dict:
        st = self.db.status()
        return {"type": "hello", "version": __version__, "settings": self.settings.public(),
                "db": {k: st[k] for k in ("updated", "domains", "urls", "allow", "block", "reported")}}

    def cmd_status(self, msg: dict) -> dict:
        st = self.db.status()
        return {"type": "status", "db": st}

    def cmd_settings(self, msg: dict) -> dict:
        return {"type": "settings", "settings": self.settings.public()}

    def cmd_settings_set(self, msg: dict) -> dict:
        mode = _text(msg, "dns_mode", 20)
        self.settings = settings_mod.set_value("dns_mode", mode, self.settings_file, self.policy_file)
        self.cache.clear()
        return {"type": "settings", "settings": self.settings.public()}

    def cmd_lists(self, msg: dict) -> dict:
        return {"type": "lists", "allow": self.db.entries("allow", 500), "block": self.db.entries("block", 500),
                "reported": self.db.reports(500),
                "organisation": {"allow": self.settings.org_allow[:500], "block": self.settings.org_block[:500]}}

    def cmd_list_add(self, msg: dict) -> dict:
        which = msg.get("list")
        if which not in ("allow", "block"):
            raise ValueError("list must be allow or block")
        m, v = self.db.add_entry(which, _text(msg, "entry", 2048), _text(msg, "note", 300, required=False), "extension")
        self.cache.clear()
        return {"type": "ok", "entry": {"match": m, "value": v}}

    def cmd_list_remove(self, msg: dict) -> dict:
        which = msg.get("list")
        entry = _text(msg, "entry", 2048)
        if which == "reported":
            removed = self.db.unreport(entry)
        elif which in ("allow", "block"):
            removed = self.db.remove_entry(which, entry)
        else:
            raise ValueError("list must be allow, block or reported")
        self.cache.clear()
        return {"type": "ok", "removed": removed}

    def cmd_report(self, msg: dict) -> dict:
        url = self.db.report(_text(msg, "url", 2048), _text(msg, "note", 300, required=False), "extension")
        self.cache.clear()
        return {"type": "ok", "reported": url}

    # ------------------------------------------------------------------ short links (only when you ask)
    def _expand_reply(self, msg: dict, req: str | None) -> None:
        try:
            reply = self.cmd_expand(msg)
        except PermissionError as exc:
            reply = {"type": "error", "error": str(exc)[:300], "locked": True}
        except ValueError as exc:
            reply = {"type": "error", "error": str(exc)[:300]}
        except Exception:  # noqa: BLE001 - never leak tracebacks (they contain paths)
            reply = {"type": "error", "error": "internal error"}
        reply["req"] = req
        self.send(reply)

    def cmd_expand(self, msg: dict) -> dict:
        """Where one short link leads, and the check of that destination.

        Without ``destination`` this program asks the shortening service (one request per short
        link in the chain; the destination is not contacted). With it, the extension found the
        destination in your browser - for services that answer only browsers - and it is checked here.
        """
        found = short_link(_text(msg, "url", 2048))
        if not found:
            raise ValueError("this is not a link from a known link-shortening service")
        url, service = found
        mode = self.settings.short_links
        if mode == "off":
            raise PermissionError("Finding out where short links lead is switched off"
                                  + (" by your organisation's policy" if "short_links" in self.settings.locked else
                                     " (settings: short_links)"))
        dest = msg.get("destination")
        if dest is None and mode == "browser":  # only the browser may reach the internet here
            exp = Expansion(url=url, service=service, browser_needed=True,
                            reason="this device is set to let only your browser ask shortening services")
            return {"type": "expanded", "report": slim(self.offline.analyze(url, None, expansion=exp))}
        if dest is not None:
            if not isinstance(dest, str) or not dest or len(dest) > 8192:
                raise ValueError("invalid destination")
            steps = msg.get("steps", [url])
            if (not isinstance(steps, list) or not 1 <= len(steps) <= 4
                    or not all(isinstance(x, str) and short_link(x) for x in steps)):
                raise ValueError("steps must be 1 to 4 short links")
            exp = Expansion(url=url, service=service, destination=dest, steps=[short_link(x)[0] for x in steps],
                            by="browser")
        else:
            if self.online is None:
                self.online = self.make_online()
            exp = expand_short_link(url, self.online._addresses_of, timeout=6.0, cafile=self.settings.cafile)
        rep = self.offline.analyze(url, None, expansion=exp)
        if self._wants_dns(rep):  # your DNS setting decides whether the destination's name is looked up
            if self.online is None:
                self.online = self.make_online()
            rep = self.online.analyze(url, None, expansion=exp)
        return {"type": "expanded", "report": slim(rep)}

    # ------------------------------------------------------------------ link checks
    def check(self, msg: dict, req: str | None, pool: ThreadPoolExecutor) -> None:
        links = msg.get("links")
        if not isinstance(links, list) or len(links) > MAX_LINKS:
            self.send({"type": "error", "req": req, "error": f"links must be a list of at most {MAX_LINKS}"})
            return
        no_dns = msg.get("no_dns") is True  # navigation checks never leave the device
        for link in links:
            if not isinstance(link, dict) or not isinstance(link.get("id"), str) or not _ID.match(link["id"]):
                continue
            url = link.get("url")
            if not isinstance(url, str) or not url or len(url) > 8192:
                self.send({"type": "result", "req": req, "id": link["id"], "report": {"verdict": "error", "summary": "invalid link"}})
                continue
            raw_ctx = link.get("ctx") if isinstance(link.get("ctx"), dict) else {}
            ctx = {k: str(raw_ctx[k])[:500] for k in _CTX_KEYS if isinstance(raw_ctx.get(k), (str, int, bool))}
            pool.submit(self._check_one, req, link["id"], url, ctx or None, no_dns)

    def _check_one(self, req: str | None, link_id: str, url: str, ctx: dict | None, no_dns: bool = False) -> None:
        key = json.dumps([url, ctx, "off" if no_dns else self.settings.dns_mode], sort_keys=True)
        hit = self.cache.get(key)
        if hit and hit[0] > time.monotonic():
            self.send({"type": "result", "req": req, "id": link_id, "report": hit[1]})
            return
        try:
            rep = self.offline.analyze(url, ctx)
            if not no_dns and self._wants_dns(rep):
                if self.online is None:
                    self.online = self.make_online()
                rep = self.online.analyze(url, ctx)
            out = slim(rep)
        except Exception:  # noqa: BLE001 - one bad link must not take the host down
            out = {"verdict": "error", "summary": "could not check this link", "findings": []}
        if len(self.cache) > 5000:
            self.cache.clear()
        self.cache[key] = (time.monotonic() + CACHE_TTL, out)
        self.send({"type": "result", "req": req, "id": link_id, "report": out})

    def _wants_dns(self, rep: dict) -> bool:
        mode = self.settings.dns_mode
        if mode == "off" or rep.get("error") or rep.get("kind") not in ("url", "email"):
            return False
        url = rep.get("url") or {}
        if not url.get("host_ascii") or url.get("is_ip"):
            return False
        lists = rep.get("lists") or {}
        if lists.get("allowed") or lists.get("blocked") or lists.get("reported"):
            return False  # your own decision already settles it: nothing is sent
        if mode == "all":
            return True
        return rep.get("verdict") in ("caution", "suspicious", "high_risk")

    def run(self, inp) -> None:
        with ThreadPoolExecutor(max_workers=4) as pool:
            while True:
                try:
                    msg = read_message(inp)
                except ProtocolError as exc:
                    self.send({"type": "error", "req": None, "error": f"protocol error: {exc}"})
                    return  # the stream can no longer be trusted to be in sync
                if msg is None:
                    return
                self.handle(msg, pool)


def caller_allowed(argv: list[str]) -> bool:
    """Chrome/Edge pass 'chrome-extension://<id>/', Firefox passes the manifest path and the add-on id."""
    for arg in argv[1:]:
        m = re.match(r"^chrome-extension://([a-p]{32})/?$", arg)
        if m:
            return m.group(1) in CHROME_EXTENSION_IDS
        if arg in FIREFOX_EXTENSION_IDS:
            return True
    return False


def build(out, settings_file=None, policy_file=None, db_file=None) -> Host:
    paths.ensure_data_dir()
    settings = settings_mod.load(settings_file, policy_file)
    db_file = db_file or paths.db_path()
    settings_file = settings_file or paths.settings_path()
    # Cheap start-up check (header and schema only); the updater reads every page each day.
    ensure_healthy(db_file, thorough=False)
    guard.install(write_paths=[str(settings_file), str(settings_file) + ".tmp", *(str(p) for p in backup_files(db_file))],
                  sqlite_paths=[str(p) for p in side_files(db_file)])
    db = ThreatDB(db_file)
    cmap = ConfusableMap.load()
    brands = BrandIndex(default_domains(), cmap)
    offline = Analyzer(brands, cmap, threatdb=db, settings=settings)

    def make_online() -> Analyzer:
        from .dns_check import DnsInvestigator
        from .dns_resolvers import DEFAULT_RESOLVERS, select
        from .dns_transport import DnsClient

        resolvers = select(list(DEFAULT_RESOLVERS))
        client = DnsClient("doh", 4.0, settings.cafile)
        guard.install(endpoints=[ep for r in resolvers for ep in client.endpoints(r)])
        # Links on pages are never expanded by themselves: only "Show where this short link leads" asks.
        return Analyzer(brands, cmap, DnsInvestigator(client, resolvers), Options(expand=False), threatdb=db,
                        settings=settings)

    return Host(db, offline, make_online, settings, out, settings_file, policy_file)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv if argv is None else argv)
    if not caller_allowed(argv):
        sys.stderr.write("This program is started by the Homograph Guard browser extension.\n")
        return 2
    host = build(sys.stdout.buffer)
    host.run(sys.stdin.buffer)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
