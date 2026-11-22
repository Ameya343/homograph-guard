"""Daily threat-intelligence updates for the on-device database.

The feeds are the public lists that DNS filtering services and researchers publish:
phishing links reported by the public (OpenPhish, PhishTank via malware-filter),
national CERT warnings (CERT Polska), community lists (Phishing Army), threat
intelligence aggregated for DNS blocking (HaGeZi TIF) and malware hosts (URLhaus).
Only these lists are downloaded; nothing about what you browse is ever sent.

Safety measures:

* HTTPS only, certificate checked (the system trust store, plus an optional extra
  CA for corporate TLS inspection), redirects only to other allow-listed hosts;
* size limits and strict parsing - a line is used only if it is a valid domain,
  IP address or http(s) link;
* entries that would cover a whole public suffix, a hosting platform or a
  protected brand (paypal.com, google.com, ...) are refused at domain level, so
  a poisoned or mistaken feed cannot make you distrust your bank; links on those
  sites (a malware file on a file-sharing site) are still kept;
* a feed that suddenly shrinks by more than 80% is kept at its previous version;
* each feed is replaced in a single transaction: lookups see the old or the new
  list, never half of one.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import http.client
import ipaddress
import re
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlsplit

from . import __version__
from .brands import BRAND_TLDS, default_domains, normalize_domain
from .domains import PLATFORM_SUFFIXES, known_suffix, split_domain
from .settings import Settings
from .threatdb import ThreatDB, normalize_url

USER_AGENT = f"homograph-guard/{__version__} (feed updater)"
MAX_FEED_BYTES = 64 * 1024 * 1024
TIMEOUT = 60
MIN_KEEP_RATIO = 0.2  # a feed shrinking below 20% of its last size is treated as broken
REFRESH_AFTER = dt.timedelta(hours=20)
RETRY_FIRST = dt.timedelta(minutes=15)  # first pause after a failed download; doubles each time
RETRY_PAUSE = 15.0  # seconds before retrying a dropped connection within the same run


@dataclass(frozen=True)
class Feed:
    name: str
    title: str
    url: str
    fmt: str  # domains | urls | adblock
    category: str  # phishing | malware | threat | ads
    default: bool
    license: str
    homepage: str


FEEDS: tuple[Feed, ...] = (
    Feed("openphish", "OpenPhish community feed", "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
         "urls", "phishing", True, "OpenPhish community licence (non-commercial)", "https://openphish.com/"),
    Feed("phishing-filter", "Phishing Filter (OpenPhish, PhishTank, IPThreat)",
         "https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt", "domains", "phishing", True,
         "CC0 / source licences", "https://gitlab.com/malware-filter/phishing-filter"),
    Feed("urlhaus-filter", "URLhaus malware hosts (abuse.ch)",
         "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains-online.txt", "domains", "malware", True,
         "CC0", "https://gitlab.com/malware-filter/urlhaus-filter"),
    Feed("cert-pl", "CERT Polska warning list", "https://hole.cert.pl/domains/v2/domains.txt", "domains", "phishing", True,
         "CERT Polska open data", "https://cert.pl/en/warning-list/"),
    Feed("phishing-army", "Phishing Army", "https://phishing.army/download/phishing_army_blocklist.txt", "domains",
         "phishing", True, "CC BY-NC 4.0", "https://phishing.army/"),
    Feed("hagezi-tif", "HaGeZi Threat Intelligence Feeds (mini)",
         "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt", "domains",
         "threat", True, "GPL-3.0", "https://github.com/hagezi/dns-blocklists"),
    Feed("adguard-dns", "AdGuard DNS filter (ads and trackers)",
         "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", "adblock", "ads", False,
         "GPL-3.0", "https://github.com/AdguardTeam/AdGuardSDNSFilter"),
)
FEEDS_BY_NAME = {f.name: f for f in FEEDS}
CATEGORY_LABEL = {"phishing": "phishing", "malware": "malware", "threat": "phishing, malware or scams", "ads": "ads and trackers"}

_ADBLOCK_RULE = re.compile(r"^\|\|([a-z0-9.\-_]+)\^(?:\$important)?$")
_PROTECTED: frozenset[str] | None = None
# Shared infrastructure: phishing pages hosted here are blocked link by link, never the whole host.
SHARED_INFRA = frozenset(
    """
    googleapis.com googleusercontent.com amazonaws.com cloudfront.net azureedge.net azurewebsites.net windows.net
    akamaihd.net akamaized.net fastly.net jsdelivr.net githubusercontent.com dropboxusercontent.com sharepoint.com
    live.com office.com office365.com microsoftonline.com 1drv.ms box.com wetransfer.com ipfs.io dweb.link
    cloudflare-ipfs.com discordapp.com discordapp.net cdn.discordapp.com t.me telegram.org whatsapp.com
    forms.gle goo.gl bit.ly linktr.ee notion.site canva.com
    """.split()
)


def protected_domains() -> frozenset[str]:
    """Registrable domains that a feed may never block as a whole: protected brands."""
    global _PROTECTED
    if _PROTECTED is None:
        _PROTECTED = frozenset(default_domains())
    return _PROTECTED


def acceptable_domain(domain: str, extra_protected: frozenset[str] = frozenset()) -> bool:
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        pass
    parts = split_domain(domain)
    if not parts.registrable or not known_suffix(domain):
        return False  # a public suffix, or an unknown TLD
    if domain in PLATFORM_SUFFIXES or parts.suffix in BRAND_TLDS:
        return False  # a whole hosting platform, or a company-owned TLD
    labels = domain.split(".")
    if any(".".join(labels[i:]) in SHARED_INFRA for i in range(len(labels))):
        return False  # anything under shared infrastructure is blocked link by link only
    return parts.registrable not in protected_domains() and parts.registrable not in extra_protected


def parse(feed: Feed, text: str, extra_protected: frozenset[str] = frozenset()) -> tuple[set[str], set[str]]:
    """Return (domains, links) from a feed, keeping only valid, acceptable entries."""
    domains: set[str] = set()
    urls: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#!;[":
            continue
        if feed.fmt == "adblock":
            m = _ADBLOCK_RULE.match(line.lower())
            if not m:
                continue
            line = m.group(1)
        if feed.fmt == "urls" or "://" in line:
            norm = normalize_url(line.split()[0])
            if not norm:
                continue
            host = urlsplit(norm).hostname or ""
            if acceptable_domain(host, extra_protected):
                domains.add(host)  # the phishing host itself
            urls.add(norm)  # the exact link, also when its host is a platform or a brand
            continue
        token = line.split()
        # hosts-file format ("0.0.0.0 evil.example"): these are text, nothing is bound
        if len(token) >= 2 and token[0] in ("0.0.0.0", "127.0.0.1", "::"):  # nosec B104
            token = token[1:]
        cand = token[0].lower().removeprefix("*.").rstrip(".")
        try:
            domain = str(ipaddress.ip_address(cand))
        except ValueError:
            domain = normalize_domain(cand) or ""
        if domain and acceptable_domain(domain, extra_protected):
            domains.add(domain)
    return domains, urls


class _SafeRedirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts: set[str]):
        self.allowed_hosts = allowed_hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urlsplit(newurl)
        if parts.scheme != "https" or (parts.hostname or "").lower() not in self.allowed_hosts:
            raise urllib.error.URLError(f"refused redirect to {parts.scheme}://{parts.hostname}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def feed_url(feed: Feed, settings: Settings) -> str:
    return f"{settings.feed_mirror}{feed.name}.txt" if settings.feed_mirror else feed.url


def allowed_hosts(settings: Settings) -> set[str]:
    hosts = {(urlsplit(feed_url(f, settings)).hostname or "").lower() for f in FEEDS}
    if not settings.feed_mirror:
        hosts |= {"openphish.com", "raw.githubusercontent.com"}
    return hosts


def ssl_context(cafile: str | None) -> ssl.SSLContext:
    ctx = ssl.create_default_context()  # system trust store (on Windows, the Windows certificate store)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if cafile:
        ctx.load_verify_locations(cafile)
    return ctx


def fetch(url: str, settings: Settings, hosts: set[str], timeout: float = TIMEOUT) -> bytes:
    parts = urlsplit(url)
    if parts.scheme != "https" or (parts.hostname or "").lower() not in hosts:
        raise ValueError(f"refusing to download from {url[:100]}")
    proxies = {"https": settings.proxy, "http": settings.proxy} if settings.proxy else urllib.request.getproxies()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({k: v for k, v in proxies.items() if k in ("https", "http")}),
        urllib.request.HTTPSHandler(context=ssl_context(settings.cafile)),
        _SafeRedirects(hosts),
    )
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/plain, */*"})
    with opener.open(req, timeout=timeout) as resp:  # nosec B310 - https only, host allow-listed above
        data = resp.read(MAX_FEED_BYTES + 1)
    if len(data) > MAX_FEED_BYTES:
        raise ValueError("feed is larger than 64 MB")
    return data


@dataclass
class FeedResult:
    name: str
    status: str  # updated | unchanged | kept | failed | disabled | skipped
    domains: int = 0
    urls: int = 0
    detail: str = ""


def enabled_feeds(settings: Settings) -> list[Feed]:
    return [f for f in FEEDS if settings.feeds.get(f.name, f.default)]


def _when(value: str | None) -> dt.datetime | None:
    try:
        return dt.datetime.fromisoformat(value) if value else None
    except ValueError:
        return None


def feed_due(state: dict | None, now: dt.datetime) -> bool:
    """Is this feed due for a download?

    Yes if it was never downloaded or its last good copy is 20 hours old. After failed attempts
    (no network, the computer shut down mid-download, a server error) it is retried with a growing
    pause: 15 minutes, 30 minutes, 1 hour, ... up to 20 hours.
    """
    if not state:
        return True
    last_try = _when(state.get("checked"))
    if state.get("status") == "failed":
        failures = max(1, int(state.get("failures") or 1))
        wait = min(RETRY_FIRST * 2 ** min(failures - 1, 10), REFRESH_AFTER)
        return last_try is None or now - last_try >= wait
    last_ok = _when(state.get("ok_at")) or last_try
    return last_ok is None or now - last_ok >= REFRESH_AFTER


def due_feeds(db: ThreatDB, settings: Settings, now: dt.datetime | None = None) -> list[str]:
    """Names of the enabled feeds that should be downloaded now."""
    now = now or dt.datetime.now(dt.UTC)
    states = db.feed_states()
    return [f.name for f in enabled_feeds(settings) if feed_due(states.get(f.name), now)]


def due(db: ThreatDB, settings: Settings, now: dt.datetime | None = None) -> bool:
    return bool(due_feeds(db, settings, now))


def _transient(exc: BaseException) -> bool:
    """A failure worth retrying in a few seconds: a dropped or not yet available connection, a busy server."""
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code in (408, 425, 429) or exc.code >= 500
    if isinstance(exc, urllib.error.URLError):  # a socket problem, not a refusal (redirect, policy)
        exc = exc.reason if isinstance(exc.reason, BaseException) else None
    if isinstance(exc, ssl.SSLCertVerificationError):
        return False  # an untrusted certificate stays untrusted
    return isinstance(exc, (OSError, http.client.HTTPException))  # refused, reset, DNS not ready, timeout


def _refresh(db: ThreatDB, feed: Feed, settings: Settings, hosts: set[str], extra: frozenset[str],
             force: bool) -> tuple[FeedResult, bool]:
    """Download one feed into the database: (result, worth retrying)."""
    url = feed_url(feed, settings)
    try:
        data = fetch(url, settings, hosts)
        digest = hashlib.sha256(data).hexdigest()
        if not force and db.feed_hash(feed.name) == digest:
            db.touch_feed(feed.name)
            return FeedResult(feed.name, "unchanged"), False
        domains, urls = parse(feed, data.decode("utf-8", "replace"), extra)
        previous = db.feed_count(feed.name)
        if previous and not force and len(domains) + len(urls) < previous * MIN_KEEP_RATIO:
            db.feed_failed(feed.name, feed.title, feed.category, url,
                           f"shrank from {previous} to {len(domains) + len(urls)} entries; kept the previous list", "kept")
            return FeedResult(feed.name, "kept", detail="sudden shrink, previous list kept"), False
        nd, nu = db.replace_feed(feed.name, feed.title, feed.category, url, domains, urls, digest)
        return FeedResult(feed.name, "updated", nd, nu), False
    except Exception as exc:  # noqa: BLE001 - one broken feed must not stop the others
        if isinstance(exc, urllib.error.HTTPError):
            exc.close()  # it holds the server's error response open
        reason = _reason(exc)
        db.feed_failed(feed.name, feed.title, feed.category, url, reason)
        return FeedResult(feed.name, "failed", detail=reason), _transient(exc)


def update(db: ThreatDB, settings: Settings, only: list[str] | None = None, force: bool = False,
           progress=None, retry: bool = True) -> list[FeedResult]:
    """Download the enabled feeds and refresh the database. Never raises for a single feed.

    Each feed is replaced in one transaction, so stopping at any moment (shutdown, power cut)
    leaves every feed either fully old or fully new; whatever was not done is due again (see
    ``feed_due``). A dropped connection is retried once, e.g. while
    the network comes back after the computer wakes up (``RETRY_PAUSE`` seconds later).
    """
    results: dict[str, FeedResult] = {}
    hosts = allowed_hosts(settings)
    extra = frozenset(filter(None, (normalize_domain(e) for e in settings.org_allow)))
    enabled = enabled_feeds(settings)
    todo = []
    for feed in FEEDS:
        if feed not in enabled:
            if db.feed_count(feed.name):
                db.drop_feed(feed.name)
            if not only or feed.name in only:
                results[feed.name] = FeedResult(feed.name, "disabled")
        elif not only or feed.name in only:
            todo.append(feed)
    again = []
    for feed in todo:
        if progress:
            progress(feed)
        results[feed.name], transient = _refresh(db, feed, settings, hosts, extra, force)
        if transient:
            again.append(feed)
    if again and retry:
        time.sleep(RETRY_PAUSE)
        for feed in again:
            if progress:
                progress(feed)
            results[feed.name], _ = _refresh(db, feed, settings, hosts, extra, force)
    return [results[f.name] for f in FEEDS if f.name in results]


def _reason(exc: Exception) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTP {exc.code}"
    if isinstance(exc, urllib.error.URLError):
        inner = exc.reason
        if isinstance(inner, ssl.SSLCertVerificationError):
            return ("TLS certificate not trusted (a proxy may be inspecting TLS: add its CA with --cafile or the "
                    "cafile setting)")
        return f"network error: {str(inner)[:160]}"
    if isinstance(exc, TimeoutError):
        return "timed out"
    return f"{type(exc).__name__}: {str(exc)[:160]}"
