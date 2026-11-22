"""Decode links rewritten by mail-security gateways, redirect services and click trackers.

Security products rewrite every link in a message so that the click goes through
them first: Microsoft Defender Safe Links, Proofpoint URL Defense, FortiMail click
protection, Mimecast, Barracuda, Cisco Secure Email, Trend Micro, Sophos, Check
Point (Avanan) and Symantec. Bulk senders such as Amazon SES wrap links for click
tracking, and Google, Facebook, Slack and others route outbound links through
redirect pages. In all of these, the host you see is the wrapper, not the site you
end up on, so the real destination is decoded here and checked instead.

A decoded destination is only trusted when the wrapper host belongs to the vendor
(for example ``*.safelinks.protection.outlook.com``). FortiMail runs on each
organisation's own server, so ``https://anything/fmlurlsvc/?url=...`` cannot be
verified; such hops are marked ``trusted=False`` and the analyzer checks the wrapper
host as well as the destination.

Nothing here performs I/O: links are decoded as text only.
"""

from __future__ import annotations

import base64
import binascii
import re
import string
from dataclasses import asdict, dataclass, field
from urllib.parse import parse_qs, unquote, urlsplit

MAX_DEPTH = 5
MAX_LEN = 8192

_HTTP = re.compile(r"^https?://", re.IGNORECASE)
_PP_V3 = re.compile(r"/v3/__(?P<url>.+?)__;(?P<enc>[A-Za-z0-9_\-]*)!")
_PP_V3_TOKEN = re.compile(r"\*(\*.)?")
_PP_V3_RUNS = {c: i + 2 for i, c in enumerate(string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_")}
_AVANAN = re.compile(r"/v2/(?:r\d+/)?___(?P<url>.+?)___\.", re.IGNORECASE)

# Query parameters that commonly carry a second address (open redirects).
# Pop-under and redirect ad networks: the ad server picks where the link goes only when it is
# clicked. Serving domains only (not the companies' own websites), from the networks' own
# documentation and security vendors' detections.
AD_NETWORKS: dict[str, tuple[str, ...]] = {
    "ExoClick": ("pemsrv.com", "realsrv.com", "exosrv.com", "exdynsrv.com"),
    "PopAds": ("serve.popads.net", "c1.popads.net", "popadscdn.net"),
    "PopCash": ("popcash.net",),
}
EMBED_PARAMS = ("url", "u", "redirect", "redirect_url", "redirect_uri", "redirecturl", "redir", "target",
                "dest", "destination", "goto", "link", "out", "to", "continue", "next", "return",
                "returnurl", "return_url")


@dataclass
class Hop:
    service: str  # "Microsoft Defender Safe Links"
    vendor: str  # "Microsoft"
    kind: str  # gateway | redirect | tracking | embedded
    host: str  # wrapper host (what the reader sees)
    wrapper_url: str  # the link as it was before this hop was decoded
    url: str | None  # decoded inner link; None when the service hides it
    trusted: bool = True  # wrapper host is the vendor's own domain
    domain_only: str | None = None  # some services reveal only the destination domain
    param: str | None = None  # query parameter that carried the address (embedded hops)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Unwrapped:
    original: str
    destination: str  # final decodable address (== original when nothing was unwrapped)
    hops: list[Hop] = field(default_factory=list)
    embedded: Hop | None = None  # address carried in a parameter of the final link (not followed)

    @property
    def opaque(self) -> Hop | None:
        last = self.hops[-1] if self.hops else None
        return last if last and last.url is None else None

    def to_dict(self) -> dict:
        return {
            "destination": self.destination,
            "hops": [h.to_dict() for h in self.hops],
            "embedded": self.embedded.to_dict() if self.embedded else None,
        }


def _host_is(host: str, *domains: str) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def _first(qs: dict[str, list[str]], *names: str) -> str | None:
    lower = {k.lower(): v for k, v in qs.items()}
    for n in names:
        vals = lower.get(n)
        if vals and vals[0]:
            return vals[0]
    return None


def _clean(url: str | None) -> str | None:
    if not url:
        return None
    url = url.strip()
    if len(url) > MAX_LEN or not _HTTP.match(url):
        return None
    return url


def _b64(text: str) -> str | None:
    t = unquote(text).strip()
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return decoder(t + "=" * (-len(t) % 4)).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
    return None


# ------------------------------------------------------------------ Proofpoint
def _proofpoint_v2(raw: str) -> str | None:
    m = re.search(r"[?&]u=([^&#]+)", raw)
    if not m:
        return None
    return unquote(m.group(1).replace("-", "%").replace("_", "/"))


def _proofpoint_v3(raw: str) -> str | None:
    """Port of Proofpoint's published v3 decoder (``*`` and ``**X`` placeholders)."""
    m = _PP_V3.search(raw)
    if not m:
        return None
    url = unquote(m.group("url"))
    enc = m.group("enc")
    try:
        replacements = base64.urlsafe_b64decode(enc + "==").decode("utf-8") if enc else ""
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    out: list[str] = []
    pos = 0
    used = 0
    for tok in _PP_V3_TOKEN.finditer(url):
        out.append(url[pos:tok.start()])
        if tok.group(0) == "*":
            n = 1
        else:
            n = _PP_V3_RUNS.get(tok.group(0)[-1])
            if n is None:
                return None
        if used + n > len(replacements):
            return None
        out.append(replacements[used:used + n])
        used += n
        pos = tok.end()
    out.append(url[pos:])
    return "".join(out)


# ------------------------------------------------------------------ rules
def _decode_one(url: str) -> Hop | None:
    """Decode one wrapper layer, or return None if ``url`` is not a known wrapper."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return None
    host = parts.hostname.lower().rstrip(".")
    path = parts.path
    qs = parse_qs(parts.query, keep_blank_values=False)

    def hop(service: str, vendor: str, kind: str, inner: str | None, trusted: bool = True,
            domain_only: str | None = None) -> Hop:
        return Hop(service, vendor, kind, host, url, _clean(inner), trusted, domain_only)

    if _host_is(host, "safelinks.protection.outlook.com", "safelinks.protection.office365.us",
                "safelinks.protection.outlook.de", "safelinks.protection.partner.outlook.cn"):
        return hop("Microsoft Defender Safe Links", "Microsoft", "gateway", _first(qs, "url"))
    if host == "statics.teams.cdn.office.net" and "/safelinks/" in path.lower():
        return hop("Microsoft Teams Safe Links", "Microsoft", "gateway", _first(qs, "url"))
    if host == "urldefense.proofpoint.com":
        if path.startswith("/v1/"):
            return hop("Proofpoint URL Defense (v1)", "Proofpoint", "gateway", _first(qs, "u"))
        if path.startswith("/v2/"):
            return hop("Proofpoint URL Defense (v2)", "Proofpoint", "gateway", _proofpoint_v2(url))
    if host in ("urldefense.com", "urldefense.us") and "/v3/__" in url:
        return hop("Proofpoint URL Defense (v3)", "Proofpoint", "gateway", _proofpoint_v3(url))
    if "/fmlurlsvc/" in path.lower() or path.lower().rstrip("/").endswith("/fmlurlsvc"):
        # FortiMail click protection runs on the customer's own appliance: any host is possible.
        return hop("FortiMail URL click protection", "Fortinet", "gateway", _first(qs, "url"), trusted=False)
    if _host_is(host, "mimecast.com", "mimecastprotect.com") and path.startswith("/s/"):
        dom = _first(qs, "domain")
        return hop("Mimecast URL Protect", "Mimecast", "gateway", None,
                   domain_only=dom.lower() if dom and re.fullmatch(r"[\w.\-]{1,253}", dom) else None)
    if host == "linkprotect.cudasvc.com":
        return hop("Barracuda Link Protection", "Barracuda", "gateway", _first(qs, "a"))
    if host == "secure-web.cisco.com":
        segs = path.split("/", 2)  # ['', token, encoded-url]
        return hop("Cisco Secure Email", "Cisco", "gateway", unquote(segs[2]) if len(segs) == 3 else None)
    if host == "clicktime.symantec.com":
        return hop("Symantec Click-time URL Protection", "Broadcom", "gateway", _first(qs, "u"))
    if _host_is(host, "trendmicro.com", "trendmicro.eu") and "/wis/clicktime/" in path.lower():
        return hop("Trend Micro Click-time Protection", "Trend Micro", "gateway", _first(qs, "url"))
    if _host_is(host, "protection.sophos.com"):
        enc = _first(qs, "u")
        dom = _first(qs, "d")
        return hop("Sophos Email Time-of-Click", "Sophos", "gateway", _b64(enc) if enc else None,
                   domain_only=dom.lower() if dom and not enc else None)
    if host == "url.avanan.click":
        m = _AVANAN.search(url)
        return hop("Check Point Harmony Email (Avanan)", "Check Point", "gateway", m.group("url") if m else None)
    if _host_is(host, "awstrack.me"):
        segs = path.split("/")
        inner = unquote(segs[2]) if len(segs) > 2 and segs[1] == "L0" else None
        return hop("Amazon SES click tracking", "Amazon Web Services", "tracking", inner)
    if host in ("google.com", "www.google.com") and path == "/url":
        return hop("Google redirect", "Google", "redirect", _first(qs, "q", "url"))
    if host in ("l.facebook.com", "lm.facebook.com", "l.messenger.com") and path == "/l.php":
        return hop("Facebook link shim", "Meta", "redirect", _first(qs, "u"))
    if host == "l.instagram.com":
        return hop("Instagram link shim", "Meta", "redirect", _first(qs, "u"))
    if host == "slack-redir.net" and path.startswith("/link"):
        return hop("Slack redirect", "Slack", "redirect", _first(qs, "url"))
    if host in ("www.youtube.com", "youtube.com") and path == "/redirect":
        return hop("YouTube redirect", "Google", "redirect", _first(qs, "q"))
    if host in ("www.linkedin.com", "linkedin.com") and (path.startswith("/redir/") or path.startswith("/safety/go")):
        return hop("LinkedIn redirect", "LinkedIn", "redirect", _first(qs, "url"))
    if host == "steamcommunity.com" and path.startswith("/linkfilter"):
        return hop("Steam link filter", "Valve", "redirect", _first(qs, "url", "u"))
    for vendor, domains in AD_NETWORKS.items():
        if _host_is(host, *domains):
            return hop(f"{vendor} ad redirect", vendor, "advert", None)
    # Click trackers that do not reveal the destination.
    if _host_is(host, "sendgrid.net") and "/ls/click" in path:
        return hop("SendGrid click tracking", "Twilio SendGrid", "tracking", None)
    if _host_is(host, "list-manage.com") and path.startswith("/track/click"):
        return hop("Mailchimp click tracking", "Intuit Mailchimp", "tracking", None)
    return None


def ad_source(hop: Hop) -> str | None:
    """The page an ExoClick ad was shown on (its 'p=' parameter), when the link names one."""
    if hop.kind != "advert" or hop.vendor != "ExoClick":
        return None
    try:
        page = _first(parse_qs(urlsplit(hop.wrapper_url).query), "p")
        host = (urlsplit(page).hostname or "").lower().rstrip(".") if page else ""
    except ValueError:
        return None
    return host if re.fullmatch(r"[a-z0-9][a-z0-9.\-]{0,252}", host) else None


def _registrable_guess(host: str) -> str:
    from .domains import split_domain

    return split_domain(host).registrable or host


def _embedded(url: str) -> Hop | None:
    """An absolute address carried in a query parameter of a non-wrapper link."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname or not parts.query:
        return None
    qs = parse_qs(parts.query)
    host = parts.hostname.lower().rstrip(".")
    for name in EMBED_PARAMS:
        val = _clean(_first(qs, name))
        if not val:
            continue
        try:
            inner_host = (urlsplit(val).hostname or "").lower().rstrip(".")
        except ValueError:
            continue
        if inner_host and _registrable_guess(inner_host) != _registrable_guess(host):
            return Hop("Address inside the link", "", "embedded", host, url, val, trusted=False, param=name)
    return None


def unwrap(url: str) -> Unwrapped:
    """Peel off wrapper layers (at most ``MAX_DEPTH``) and report each one."""
    result = Unwrapped(original=url, destination=url)
    if not isinstance(url, str) or len(url) > MAX_LEN:
        return result
    current = url.strip()
    seen = {current}
    for _ in range(MAX_DEPTH):
        h = _decode_one(current)
        if h is None:
            break
        result.hops.append(h)
        if not h.url or h.url in seen:
            break
        seen.add(h.url)
        current = h.url
    if result.hops and result.hops[-1].url:
        result.destination = result.hops[-1].url
    elif result.hops and result.hops[-1].domain_only:
        result.destination = "https://" + result.hops[-1].domain_only + "/"
    elif result.hops:
        result.destination = result.hops[-1].wrapper_url
    if not result.opaque:
        result.embedded = _embedded(result.destination)
    return result
