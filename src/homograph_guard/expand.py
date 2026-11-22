"""Find out where a shortened link leads, without visiting the destination.

Only the link-shortening service is asked. Each step is one HTTPS request whose answer is read
for its redirect (the ``Location`` header, or a meta refresh in the first 64 KB) and then closed;
the redirect is never followed to the destination. The service's address comes from the pinned
DNS resolvers (not the system resolver), the certificate must be valid for its name, private and
local addresses are refused, no cookies are sent, and the User-Agent says honestly what is
asking. A service that only answers web browsers (a "checking your browser" page, as shorturl.at
shows) is reported as such: nothing is done to get past it.

Asking the service tells it, and possibly whoever created the short link, that the link was
looked up, much like a click would - which is why this only runs when network checks are on.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from . import __version__, guard
from .domains import split_domain
from .models import InputError
from .urlsafe import parse_url

SHORTENERS = frozenset(
    "bit.ly tinyurl.com t.co goo.gl ow.ly is.gd buff.ly rebrand.ly cutt.ly shorturl.at rb.gy t.ly "
    "tiny.cc s.id lnkd.in v.gd qrco.de shorturl.asia urlz.fr".split()
)
MAX_STEPS = 4
HTTPS_PORT = 443
MAX_HEADER = 32 * 1024
MAX_BODY = 64 * 1024
USER_AGENT = f"homograph-guard/{__version__} (short link check; does not follow the link)"
_REDIRECTS = (301, 302, 303, 307, 308)
_META_REFRESH = re.compile(rb"""<meta[^>]+http-equiv=["']?refresh["']?[^>]*content=["']?\s*\d*\s*;?\s*url\s*=\s*['"]?([^'">\s]+)""", re.I)
_BROWSER_CHECK = (b"just a moment", b"challenge-platform", b"cf-chl", b"captcha", b"checking your browser")


def shortener_of(host: str | None) -> str | None:
    """The shortening service a host belongs to (its registrable domain), or None."""
    if not host:
        return None
    reg = split_domain(host.lower().rstrip(".")).registrable
    return reg if reg in SHORTENERS else None


def short_link(raw: str) -> tuple[str, str] | None:
    """(https address to ask, service) when ``raw`` is a link on a known shortening service, else None.

    Accepts what people paste ("shorturl.at/zNYEi"); the fragment is dropped (it never reaches the server).
    """
    try:
        p = parse_url(raw)
    except InputError:
        return None
    service = shortener_of(p.host_ascii) if p.kind == "url" and p.has_host and not p.is_ip else None
    if not service or p.scheme not in ("http", "https") or p.port not in (None, 80, 443):
        return None
    return "https://" + p.host_ascii + (p.rest.split("#", 1)[0] or "/"), service


@dataclass
class Expansion:
    url: str  # the short link
    service: str  # e.g. "shorturl.at"
    destination: str | None = None  # where it leads, when the service said so
    steps: list[str] = field(default_factory=list)  # every short link that was asked
    reason: str | None = None  # why there is no destination
    browser_needed: bool = False  # the service answers only web browsers (a bot check)
    final: bool = False  # the service's answer settles it (unknown link, endless chain): a browser would not do better
    by: str = "app"  # who asked the service: "app" (this program) or "browser" (the extension, on request)

    def to_dict(self) -> dict:
        return {"url": self.url, "service": self.service, "destination": self.destination, "steps": self.steps,
                "reason": self.reason, "browser_needed": self.browser_needed, "final": self.final, "by": self.by}


def _target_allowed(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Only public addresses: a short link must not make this program talk to your LAN or itself."""
    return addr.is_global


def _ask(ip: str, host: str, target: str, timeout: float, cafile: str | None) -> tuple[int, dict[str, str], bytes]:
    """One GET to the service: (status, headers, start of the body). Nothing else is read or sent."""
    if guard.installed():
        guard.allow_endpoint(ip, HTTPS_PORT, "tcp")
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if cafile:
        ctx.load_verify_locations(cafile=cafile)
    request = (f"GET {target} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\n"
               "Accept: text/html;q=0.9,*/*;q=0.8\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n")
    with socket.create_connection((ip, HTTPS_PORT), timeout=timeout) as raw, ctx.wrap_socket(raw, server_hostname=host) as tls:
        tls.sendall(request.encode("ascii"))
        data = b""
        while b"\r\n\r\n" not in data and len(data) < MAX_HEADER:
            chunk = tls.recv(4096)
            if not chunk:
                break
            data += chunk
        head, _, body = data.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        try:
            status = int(lines[0].split()[1])
        except (IndexError, ValueError):
            raise OSError("not an HTTP answer") from None
        headers: dict[str, str] = {}
        for line in lines[1:]:
            name, sep, value = line.partition(":")
            if sep and name.strip().lower() not in headers:
                headers[name.strip().lower()] = value.strip()
        if status not in _REDIRECTS:  # a page: read the start of it for a meta refresh or a browser check
            while len(body) < MAX_BODY:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                body += chunk
        return status, headers, body[:MAX_BODY]


def expand(url: str, resolve: Callable[[str], list[str]], timeout: float = 5.0, cafile: str | None = None) -> Expansion | None:
    """Ask the shortening service where ``url`` leads; None if ``url`` is not a short link.

    ``resolve(host)`` returns the host's addresses from the pinned resolvers.
    """
    parts = urlsplit(url)
    service = shortener_of(parts.hostname)
    if not service or parts.scheme.lower() not in ("http", "https"):
        return None
    out = Expansion(url=url, service=service)
    current = url
    for _ in range(MAX_STEPS):
        p = urlsplit(current)
        host = (p.hostname or "").lower().rstrip(".")
        if not shortener_of(host):
            out.destination = current  # left the shortening services: this is where it leads
            return out
        out.steps.append(current)
        try:
            found = resolve(host)
        except (OSError, ValueError):
            found = []
        addresses = []
        for a in found:
            try:
                if _target_allowed(ipaddress.ip_address(a)):
                    addresses.append(a)
            except ValueError:
                continue
        if not addresses:
            out.reason = (f"{host} points at a private or local address, which is never contacted" if found
                          else f"the address of {host} could not be looked up")
            return out
        target = (p.path or "/") + (f"?{p.query}" if p.query else "")
        try:
            status, headers, body = _ask(addresses[0], host, target, timeout, cafile)
        except ssl.SSLCertVerificationError:
            out.reason = f"{host} did not present a valid certificate (a proxy may be inspecting TLS)"
            return out
        except (OSError, ssl.SSLError) as exc:
            out.reason = f"{host} could not be reached ({type(exc).__name__})"
            return out
        nxt = headers.get("location") if status in _REDIRECTS else None
        if not nxt and status == 200:
            m = _META_REFRESH.search(body)
            nxt = m.group(1).decode("latin-1") if m else None
        if not nxt:
            low = body.lower()
            if status in (403, 429, 503) and (any(k in low for k in _BROWSER_CHECK) or headers.get("cf-mitigated")):
                out.browser_needed = True
                out.reason = (f"{service} shows where its links lead only to a web browser (it answered with a "
                              "\"checking your browser\" page). Right-click the link and choose \"Show where this "
                              "short link leads\" (Homograph Guard browser extension): the destination is not opened")
            elif status == 404:
                out.reason = f"{service} does not know this short link (removed, or never existed)"
                out.final = True
            else:
                out.reason = f"{service} answered {status} without saying where the link leads"
            return out
        nxt = urljoin(current, nxt.strip())
        if urlsplit(nxt).scheme.lower() not in ("http", "https"):
            out.destination = nxt  # e.g. a javascript: or data: target, analysed as it is
            return out
        current = nxt
    if shortener_of(urlsplit(current).hostname):
        out.reason = "too many short links in a row"
        out.final = True
    else:
        out.destination = current
    return out
