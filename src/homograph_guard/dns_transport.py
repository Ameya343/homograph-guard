"""DNS transports: DNS-over-HTTPS (RFC 8484), DNS-over-TLS (RFC 7858) and plain UDP/TCP.

Every query goes to a *pinned* resolver IP. DoH and DoT verify the server
certificate against the resolver's own hostname (SNI), so a hostile Wi-Fi or
ISP cannot silently rewrite answers. Plain UDP is offered for networks that
block DoH/DoT, but it can be intercepted - the report says which was used.
"""

from __future__ import annotations

import base64
import http.client
import socket
import ssl
import time
from dataclasses import asdict, dataclass, field

import dns.edns
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype

from . import __version__
from .dns_resolvers import Resolver

TRANSPORTS = ("doh", "dot", "udp")
PRIVATE_ECS = "0.0.0.0/0"  # EDNS Client Subnet "send nothing": the user's network is never revealed
MAX_DNS_RESPONSE = 65535
MAX_RECORDS = 64
BLOCK_EDE_CODES = {15: "Blocked", 16: "Censored", 17: "Filtered", 18: "Prohibited"}
_EDE_NAMES = {
    0: "Other", 1: "Unsupported DNSKEY Algorithm", 3: "Stale Answer", 4: "Forged Answer",
    6: "DNSSEC Bogus", 7: "Signature Expired", 9: "DNSKEY Missing", 10: "RRSIGs Missing",
    13: "Cached Error", 15: "Blocked", 16: "Censored", 17: "Filtered", 18: "Prohibited",
    20: "Not Authoritative", 22: "No Reachable Authority", 23: "Network Error", 24: "Invalid Data",
}

# Organisations that issue publicly-trusted TLS certificates. A resolver certificate
# from anyone else means a middlebox (corporate proxy, AV "web shield", captive portal)
# is intercepting TLS - and could be altering DNS answers too.
PUBLIC_CA_HINTS = (
    "google trust", "digicert", "let's encrypt", "isrg", "sectigo", "comodo", "usertrust",
    "globalsign", "entrust", "identrust", "amazon", "microsoft", "cloudflare", "ssl corp",
    "ssl.com", "certum", "asseco", "buypass", "zerossl", "godaddy", "starfield", "actalis",
    "harica", "hellenic academic", "quovadis", "telia", "swisssign", "trustwave",
    "network solutions", "apple", "secom", "certainly", "gandi", "trustasia", "geotrust",
    "thawte", "rapidssl", "gts ",
)


class DohError(Exception):
    pass


@dataclass
class DnsAnswer:
    resolver: str
    qname: str
    rdtype: str
    transport: str = ""
    rcode: str | None = None
    addresses: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    records: list[str] = field(default_factory=list)  # NS / MX / TXT as text
    ttl: int | None = None
    ad: bool = False
    ede: list[dict] = field(default_factory=list)
    error: str | None = None
    server: str | None = None
    tls_issuer: str | None = None
    elapsed_ms: int | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.rcode is not None

    def to_dict(self) -> dict:
        return asdict(self)


def issuer_org(cert: dict | None) -> str | None:
    if not cert:
        return None
    fields: dict[str, str] = {}
    for rdn in cert.get("issuer", ()):
        for key, value in rdn:
            fields.setdefault(key, value)
    parts = [fields.get("organizationName"), fields.get("commonName")]
    return " / ".join(p for p in parts if p) or None


def looks_intercepted(issuer: str | None) -> bool:
    if not issuer:
        return False
    low = issuer.lower()
    return not any(hint in low for hint in PUBLIC_CA_HINTS)


def _describe_error(exc: BaseException) -> str:
    if isinstance(exc, ssl.SSLCertVerificationError):
        return f"TLS certificate verification failed: {exc.verify_message or exc}"[:300]
    if isinstance(exc, (dns.exception.Timeout, TimeoutError, socket.timeout)):
        return "timed out"
    if isinstance(exc, ConnectionRefusedError):
        return "connection refused"
    if isinstance(exc, PermissionError):
        return f"blocked by sandbox policy: {exc}"[:300]
    if isinstance(exc, DohError):
        return str(exc)[:300]
    return f"{type(exc).__name__}: {exc}"[:300]


def _fill(ans: DnsAnswer, resp: dns.message.Message) -> None:
    ans.rcode = dns.rcode.to_text(resp.rcode())
    ans.ad = bool(resp.flags & dns.flags.AD)
    ttls: list[int] = []
    for rrset in resp.answer:
        ttls.append(int(rrset.ttl))
        if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            ans.addresses.extend(rd.address for rd in rrset)
        elif rrset.rdtype == dns.rdatatype.CNAME:
            ans.cnames.extend(rd.target.to_text(omit_final_dot=True).lower() for rd in rrset)
        elif rrset.rdtype == dns.rdatatype.NS:
            ans.records.extend(rd.target.to_text(omit_final_dot=True).lower() for rd in rrset)
        elif rrset.rdtype == dns.rdatatype.MX:
            ans.records.extend(
                f"{rd.preference} {rd.exchange.to_text(omit_final_dot=True).lower()}" for rd in rrset
            )
        elif rrset.rdtype == dns.rdatatype.TXT:
            for rd in rrset:
                ans.records.append(b"".join(rd.strings).decode("utf-8", "replace")[:500])
    ans.addresses = list(dict.fromkeys(ans.addresses))[:MAX_RECORDS]
    ans.cnames = list(dict.fromkeys(ans.cnames))[:MAX_RECORDS]
    ans.records = list(dict.fromkeys(ans.records))[:MAX_RECORDS]
    ans.ttl = min(ttls) if ttls else None
    for opt in resp.options:
        if int(opt.otype) == int(dns.edns.OptionType.EDE):
            code = int(getattr(opt, "code", -1))
            text = str(getattr(opt, "text", "") or "")
            ans.ede.append({"code": code, "name": _EDE_NAMES.get(code, "Unknown"), "text": text[:200]})


class DnsClient:
    """Send single queries to pinned resolvers over the chosen transport."""

    def __init__(self, transport: str = "doh", timeout: float = 4.0, cafile: str | None = None):
        if transport not in TRANSPORTS:
            raise ValueError(f"transport must be one of {', '.join(TRANSPORTS)}")
        self.transport = transport
        self.timeout = float(timeout)
        self._ctx = ssl.create_default_context()
        if cafile:
            self._ctx.load_verify_locations(cafile=cafile)
        self._ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self._ctx.set_alpn_protocols(["http/1.1"] if transport == "doh" else ["dot"])

    def endpoints(self, r: Resolver) -> list[tuple[str, int, str]]:
        """(ip, port, proto) tuples this client may contact - used for the egress allowlist."""
        if self.transport == "doh":
            return [(ip, r.doh_port, "tcp") for ip in r.ips]
        if self.transport == "dot":
            return [(ip, r.dot_port, "tcp") for ip in r.ips]
        return [(ip, r.udp_port, p) for ip in r.ips for p in ("udp", "tcp")]

    def query(self, r: Resolver, qname: str, rdtype: str, ecs: str = PRIVATE_ECS) -> DnsAnswer:
        """``ecs`` is the EDNS Client Subnet sent with the query. The default ``0.0.0.0/0`` asks the
        resolver *not* to pass your own network on to the domain's DNS servers (RFC 7871 section 7.1.2):
        a phishing domain's name servers belong to the attacker. Regional lookups pass a fixed public
        subnet of the region instead - never yours."""
        ans = DnsAnswer(resolver=r.key, qname=qname, rdtype=rdtype, transport=self.transport)
        last_error = "no address to try"
        address, _, srclen = ecs.partition("/")
        options = [dns.edns.ECSOption(address, int(srclen))]
        for ip in r.ips:
            started = time.monotonic()
            try:
                q = dns.message.make_query(qname, rdtype, use_edns=0, payload=1232, options=options)
                q.flags |= dns.flags.AD
                issuer = None
                if self.transport == "doh":
                    q.id = 0  # RFC 8484 recommends ID 0 for cache-friendly GETs
                    resp, issuer = self._doh(r, ip, q)
                elif self.transport == "dot":
                    resp, issuer = self._dot(r, ip, q)
                else:
                    resp, _tcp = dns.query.udp_with_fallback(q, ip, timeout=self.timeout, port=r.udp_port)
                ans.server, ans.tls_issuer = ip, issuer
                ans.elapsed_ms = int((time.monotonic() - started) * 1000)
                _fill(ans, resp)
                return ans
            except (dns.exception.DNSException, OSError, DohError, ValueError,
                    http.client.HTTPException) as exc:
                last_error = _describe_error(exc)
                if isinstance(exc, (dns.name.NameTooLong, dns.name.LabelTooLong, dns.name.EmptyLabel)):
                    break
        ans.error = last_error
        return ans

    def _tls_connect(self, ip: str, port: int, tls_host: str) -> tuple[ssl.SSLSocket, str | None]:
        raw = socket.create_connection((ip, port), timeout=self.timeout)
        try:
            tls = self._ctx.wrap_socket(raw, server_hostname=tls_host)
        except BaseException:
            raw.close()
            raise
        tls.settimeout(self.timeout)
        return tls, issuer_org(tls.getpeercert())

    def _doh(self, r: Resolver, ip: str, q: dns.message.Message) -> tuple[dns.message.Message, str | None]:
        wire = q.to_wire()
        b64 = base64.urlsafe_b64encode(wire).rstrip(b"=").decode("ascii")
        request = (
            f"GET {r.doh_path}?dns={b64} HTTP/1.1\r\n"
            f"Host: {r.tls_host}\r\n"
            "Accept: application/dns-message\r\n"
            f"User-Agent: homograph-guard/{__version__}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        tls, issuer = self._tls_connect(ip, r.doh_port, r.tls_host)
        with tls:
            tls.sendall(request)
            resp = http.client.HTTPResponse(tls, method="GET")
            try:
                resp.begin()
                if resp.status != 200:
                    via = f" (TLS intercepted by '{issuer}')" if looks_intercepted(issuer) else ""
                    raise DohError(f"HTTP {resp.status} from {r.tls_host}{via}")
                ctype = (resp.getheader("Content-Type") or "").split(";", 1)[0].strip().lower()
                if ctype != "application/dns-message":
                    raise DohError(f"unexpected Content-Type {ctype[:60]!r}")
                body = resp.read(MAX_DNS_RESPONSE + 1)
            finally:
                resp.close()
        if len(body) > MAX_DNS_RESPONSE:
            raise DohError("oversized DNS response")
        msg = dns.message.from_wire(body)
        if not q.is_response(msg):
            raise DohError("answer does not match the question")
        return msg, issuer

    def _dot(self, r: Resolver, ip: str, q: dns.message.Message) -> tuple[dns.message.Message, str | None]:
        tls, issuer = self._tls_connect(ip, r.dot_port, r.tls_host)
        with tls:
            msg = dns.query.tls(q, ip, timeout=self.timeout, port=r.dot_port, sock=tls)
        return msg, issuer
