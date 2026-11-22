"""Multi-resolver DNS investigation.

For the suspect host we ask every configured resolver for A/AAAA records and
compare the answers:

1. Blocking - filtering resolvers (Cloudflare 1.1.1.2, AdGuard default, Quad9)
   are compared with their own unfiltered twin. If the twin returns a real
   address but the filter returns 0.0.0.0 / NXDOMAIN / an EDE "Blocked", the
   provider's threat intelligence has flagged the domain.
2. Consistency - unfiltered resolvers (Google, Cloudflare, AdGuard) should
   agree on the network (ASN) even when CDN IPs differ.
3. Brand infrastructure - when the host imitates a protected brand, the real
   brand is resolved too. Same nameservers / same network suggests a
   defensive registration; a different network is consistent with phishing.

Only DNS packets are sent, and only to the pinned resolver IPs. The suspect
host itself is never contacted here.
"""

from __future__ import annotations

import ipaddress
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .dns_resolvers import Resolver
from .dns_transport import BLOCK_EDE_CODES, DnsAnswer, DnsClient, looks_intercepted
from .domains import split_domain
from .models import Finding

# Sinkhole answers ("null routes") used by filtering resolvers - not a bind address.
NULL_IPS = frozenset({"0.0.0.0", "::"})  # nosec B104
MAX_ASN_IPS = 24
MAX_AS_NAMES = 10

# Networks where anyone can rent space: sharing one with a brand proves nothing.
SHARED_INFRA_ASNS = {
    13335: "Cloudflare", 209242: "Cloudflare", 16509: "Amazon", 14618: "Amazon",
    396982: "Google Cloud", 8075: "Microsoft/Azure", 20940: "Akamai", 16625: "Akamai",
    63949: "Akamai/Linode", 54113: "Fastly", 14061: "DigitalOcean", 16276: "OVH",
    24940: "Hetzner", 20473: "Vultr", 45102: "Alibaba", 37963: "Alibaba", 132203: "Tencent",
    31898: "Oracle", 26496: "GoDaddy", 22612: "Namecheap", 47583: "Hostinger",
    46606: "Unified Layer", 36351: "IBM/SoftLayer", 8560: "IONOS", 51167: "Contabo",
    60068: "CDN77", 9009: "M247", 36459: "GitHub", 19551: "Imperva", 199524: "G-Core",
    21859: "Zenlayer", 35916: "Multacom", 62240: "Clouvider", 197695: "Reg.ru",
    49505: "Selectel", 30633: "Leaseweb", 60781: "Leaseweb", 53667: "FranTech",
    43350: "NForce", 202425: "IP Volume", 212238: "Datacamp", 8100: "QuadraNet",
    29802: "Hivelocity", 32244: "Liquid Web",
}

# Nameserver operators shared by millions of zones: overlap is not evidence of ownership.
GENERIC_NS_PROVIDERS = frozenset(
    """
    cloudflare.com domaincontrol.com registrar-servers.com googledomains.com azure-dns.com
    azure-dns.net azure-dns.org azure-dns.info dnsimple.com dnsimple-edge.net digitalocean.com
    linode.com vultr.com hostinger.com dns-parking.com parkingcrew.net sedoparking.com bodis.com
    above.com afternic.com dan.com ui-dns.com ui-dns.de ui-dns.org ui-dns.biz name.com
    namebrightdns.com dynadot.com porkbun.com nsone.net ultradns.com ultradns.net ultradns.org
    ultradns.biz ultradns.info dynect.net akam.net akamaiedge.net hichina.com dnspod.net
    he.net cloudns.net afraid.org desec.io gandi.net ovh.net hetzner.com wixdns.net
    squarespacedns.com vercel-dns.com bluehost.com hostgator.com siteground.net worldnic.com
    register.com namesilo.com epik.com nic.ru reg.ru websitewelcome.com 1and1.com
    """.split()
)
# Corporate brand-protection registrars park defensive registrations on these.
BRAND_PROTECTION_NS = {"markmonitor.com": "MarkMonitor", "cscdns.net": "CSC Corporate Domains"}

# Big sites answer with different addresses in different parts of the world (CDNs, GeoDNS). To compare a
# look-alike with *all* of a brand's infrastructure, both are looked up as if from each region, using EDNS
# Client Subnet with a fixed public prefix of that region (public cloud ranges). Only these prefixes are
# ever sent - never the user's own network. Google Public DNS honours client subnets; Cloudflare
# deliberately ignores them, so the regional lookups go to Google.
REGIONS: dict[str, str] = {
    "US East": "3.80.0.0/24", "US West": "35.160.0.0/24", "Brazil": "18.228.0.0/24", "UK": "3.8.0.0/24",
    "Germany": "3.120.0.0/24", "India": "13.232.0.0/24", "Singapore": "13.212.0.0/24", "Japan": "13.112.0.0/24",
    "Australia": "13.236.0.0/24", "South Africa": "13.244.0.0/24",
}
ECS_RESOLVER = "google"
MAX_BRAND_IPS = 24


def subnet_of(ip: str) -> str | None:
    """The /24 (IPv4) or /48 (IPv6) block an address belongs to."""
    addr = _ip(ip)
    if addr is None:
        return None
    return str(ipaddress.ip_network(f"{ip}/{24 if addr.version == 4 else 48}", strict=False))


def _in_prefix(ip: str, prefix: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return False


def _ip(a: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(a)
    except ValueError:
        return None


def _is_public(a: str) -> bool:
    ip = _ip(a)
    return bool(ip and ip.is_global)


def _in_networks(a: str, nets: tuple[str, ...]) -> bool:
    ip = _ip(a)
    return bool(ip) and any(ip in ipaddress.ip_network(n) for n in nets)


def _ns_provider(ns_host: str) -> str:
    if "awsdns-" in ns_host:
        return "awsdns"
    return split_domain(ns_host).registrable or ns_host


def cymru_origin_name(ip: str) -> str | None:
    addr = _ip(ip)
    if addr is None:
        return None
    if addr.version == 4:
        return ".".join(reversed(str(addr).split("."))) + ".origin.asn.cymru.com"
    return ".".join(reversed(addr.exploded.replace(":", ""))) + ".origin6.asn.cymru.com"


def parse_cymru_origin(txt: str) -> dict | None:
    # "13335 | 104.16.0.0/13 | US | arin | 2014-03-28"
    fields = [f.strip() for f in txt.split("|")]
    if len(fields) < 3:
        return None
    asns = [int(x) for x in fields[0].split() if x.isdigit()]
    if not asns:
        return None
    return {
        "asn": asns[0],
        "prefix": fields[1] if len(fields) > 1 else "",
        "country": fields[2] if len(fields) > 2 else "",
        "registry": fields[3] if len(fields) > 3 else "",
    }


@dataclass
class DnsReport:
    transport: str
    resolvers: list[dict] = field(default_factory=list)
    consensus: str = "none"
    addresses: list[str] = field(default_factory=list)
    asn: dict[str, dict] = field(default_factory=dict)
    ns: list[str] = field(default_factory=list)
    mx: list[str] | None = None
    brand: dict | None = None
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if k != "findings"}
        return d


class DnsInvestigator:
    def __init__(self, client: DnsClient, resolvers: list[Resolver], asn: bool = True, workers: int = 8,
                 regions: bool = True):
        if not resolvers:
            raise ValueError("at least one resolver is required")
        self.client = client
        self.resolvers = resolvers
        self.by_key = {r.key: r for r in resolvers}
        self.unfiltered = [r for r in resolvers if not r.filtering] or resolvers[:1]
        self.asn_enabled = asn
        self.workers = max(1, workers)
        self.regions = regions and ECS_RESOLVER in self.by_key
        self._origin_cache: dict[str, dict | None] = {}
        self._asname_cache: dict[int, str] = {}

    # ------------------------------------------------------------------ plumbing
    def _run(self, jobs: list[tuple]) -> dict[tuple, DnsAnswer]:
        """Jobs are (resolver, name, type) or (resolver, name, type, region)."""
        jobs = list(dict.fromkeys(jobs))
        if not jobs:
            return {}

        def one(job: tuple) -> DnsAnswer:
            region = job[3] if len(job) > 3 else None
            if region:
                return self.client.query(self.by_key[job[0]], job[1], job[2], ecs=REGIONS[region])
            return self.client.query(self.by_key[job[0]], job[1], job[2])

        with ThreadPoolExecutor(max_workers=min(self.workers, len(jobs))) as pool:
            futures = {job: pool.submit(one, job) for job in jobs}
            return {job: fut.result() for job, fut in futures.items()}

    def _first_ok(self, results, keys, name, rdtype) -> DnsAnswer | None:
        for k in keys:
            a = results.get((k, name, rdtype))
            if a and a.ok:
                return a
        return None

    # ------------------------------------------------------------------ ASN
    def asn_lookup(self, ips: list[str]) -> dict[str, dict]:
        if not self.asn_enabled:
            return {}
        ips = [ip for ip in dict.fromkeys(ips) if _is_public(ip)][:MAX_ASN_IPS]
        refs = [r.key for r in self.unfiltered[:2]]
        todo = [ip for ip in ips if ip not in self._origin_cache]
        jobs = [(k, cymru_origin_name(ip), "TXT") for ip in todo for k in refs[:1]]
        res = self._run([j for j in jobs if j[1]])
        retry = []
        for ip in todo:
            name = cymru_origin_name(ip)
            ans = res.get((refs[0], name, "TXT"))
            if ans and ans.ok:
                self._origin_cache[ip] = next((p for p in map(parse_cymru_origin, ans.records) if p), None)
            elif len(refs) > 1:
                retry.append((refs[1], name, "TXT", ip))
        if retry:
            res2 = self._run([(k, n, t) for k, n, t, _ in retry])
            for k, n, t, ip in retry:
                ans = res2.get((k, n, t))
                self._origin_cache[ip] = (
                    next((p for p in map(parse_cymru_origin, ans.records) if p), None)
                    if ans and ans.ok else None
                )
        asns = {self._origin_cache[ip]["asn"] for ip in ips if self._origin_cache.get(ip)}
        need = [a for a in asns if a not in self._asname_cache][:MAX_AS_NAMES]
        res3 = self._run([(refs[0], f"AS{a}.asn.cymru.com", "TXT") for a in need])
        for a in need:
            ans = res3.get((refs[0], f"AS{a}.asn.cymru.com", "TXT"))
            name = ""
            if ans and ans.ok and ans.records:
                fields = [f.strip() for f in ans.records[0].split("|")]
                name = fields[-1] if len(fields) >= 5 else ""
            self._asname_cache[a] = name
        out: dict[str, dict] = {}
        for ip in ips:
            info = self._origin_cache.get(ip)
            if info:
                out[ip] = {**info, "as_name": self._asname_cache.get(info["asn"], "")}
        return out

    # ------------------------------------------------------------------ main
    def investigate(self, host: str, registrable: str | None, brand: str | None = None,
                    want_mx: bool = False) -> DnsReport:
        rep = DnsReport(transport=self.client.transport)
        refs = [r.key for r in self.unfiltered[:2]]
        jobs: list[tuple[str, str, str]] = []
        for r in self.resolvers:
            jobs += [(r.key, host, "A"), (r.key, host, "AAAA")]
        if registrable:
            jobs += [(k, registrable, "NS") for k in refs]
        if want_mx:
            jobs += [(refs[0], registrable or host, "MX")]
        if brand:
            jobs += [(k, brand, t) for k in refs for t in ("A", "AAAA")]
            jobs += [(k, brand, "NS") for k in refs]
            if self.regions:  # the brand's (and the look-alike's) addresses as seen from every region
                jobs += [(ECS_RESOLVER, name, t, region) for region in REGIONS for name in (brand, host)
                         for t in ("A", "AAAA")]
        results = self._run(jobs)

        # ---- per-resolver view + block detection
        for r in self.resolvers:
            a, aaaa = results[(r.key, host, "A")], results[(r.key, host, "AAAA")]
            reason = None
            if r.filtering and r.peer and r.peer in self.by_key:
                pa, paaaa = results[(r.peer, host, "A")], results[(r.peer, host, "AAAA")]
                # Blocking is judged per name: if the filter hands out a real address for A or AAAA,
                # the site is reachable through it, whatever an empty answer for the other type says.
                if not (self._resolves(r, a, pa) or self._resolves(r, aaaa, paaaa)):
                    reason = self._block_reason(r, a, pa) or self._block_reason(r, aaaa, paaaa)
            rep.resolvers.append({
                "key": r.key, "provider": r.provider, "name": r.name, "filtering": r.filtering,
                "blocks": r.blocks, "a": a.to_dict(), "aaaa": aaaa.to_dict(),
                "blocked": bool(reason), "block_reason": reason or "",
            })
            if reason:
                strong = r.security_only
                rep.findings.append(Finding(
                    "DNS_BLOCKED_SECURITY" if strong else "DNS_BLOCKED_FILTER",
                    "high" if strong else "medium", 40 if strong else 20,
                    f"Blocked by {r.name}",
                    f"{r.provider}'s filtering resolver refuses this domain ({reason}) while its "
                    "unfiltered twin resolves it - the provider's threat intelligence flags it."
                    + ("" if strong else " AdGuard also blocks ad/tracker domains, so treat this as a strong hint, not proof."),
                    {"resolver": r.key, "reason": reason},
                ))

        answered = [results[(r.key, host, t)] for r in self.resolvers for t in ("A", "AAAA")]
        if not any(x.ok for x in answered):
            errors = sorted({x.error or "" for x in answered})
            rep.warnings.append("No resolver answered: " + "; ".join(errors)[:300])
            rep.findings.append(Finding(
                "DNS_UNAVAILABLE", "info", 0, "DNS comparison unavailable",
                "None of the resolvers could be reached (network policy, firewall or offline). "
                "Static analysis results are still valid.", {"errors": errors[:5]},
            ))
            return rep

        issuers = {x.tls_issuer for x in answered if x.tls_issuer}
        bad = sorted(i for i in issuers if looks_intercepted(i))
        if bad:
            rep.warnings.append(f"TLS to the resolvers is intercepted by '{bad[0]}' - DNS answers may be altered.")
            rep.findings.append(Finding(
                "DNS_TLS_INTERCEPTED", "info", 0, "Resolver TLS is being intercepted",
                f"The resolvers' certificates were issued by '{bad[0]}', not a public CA. A proxy, "
                "antivirus web shield or captive portal sits in between; treat DNS results with care.",
                {"issuers": bad},
            ))

        # ---- unfiltered consensus
        unf = [r for r in self.unfiltered]
        a_sets: dict[str, set[str]] = {}
        all_ips: list[str] = []
        rcodes = []
        for r in unf:
            for t in ("A", "AAAA"):
                x = results[(r.key, host, t)]
                if x.ok:
                    rcodes.append(x.rcode)
                    real = [ip for ip in x.addresses if ip not in NULL_IPS]
                    all_ips += real
                    if t == "A" and x.rcode == "NOERROR":
                        a_sets[r.key] = set(real)
        rep.addresses = list(dict.fromkeys(all_ips))
        if rcodes and all(c == "NXDOMAIN" for c in rcodes):
            rep.consensus = "nxdomain"
            rep.findings.append(Finding(
                "DNS_NXDOMAIN", "info", 0, "Domain does not exist in DNS",
                "Not registered, expired, or already taken down. The link cannot load today but "
                "may be activated later - do not treat it as safe.",
            ))
        null_only = [r.key for r in unf
                     if results[(r.key, host, "A")].ok and results[(r.key, host, "A")].addresses
                     and all(ip in NULL_IPS for ip in results[(r.key, host, "A")].addresses)]
        if null_only and len(null_only) == len([r for r in unf if results[(r.key, host, "A")].ok]):
            rep.findings.append(Finding(
                "DNS_NULL_ROUTED", "low", 5, "Domain's own DNS points to 0.0.0.0",
                "Typical of registrar/registry takedowns or parked malicious domains.",
            ))
        private = sorted({ip for ip in rep.addresses if not _is_public(ip)})
        if private:
            rep.findings.append(Finding(
                "DNS_PRIVATE_IP", "medium", 20, "Resolves to a private / internal address",
                f"{', '.join(private[:4])} is not on the public internet. Public names pointing "
                "inside your network enable DNS-rebinding and intranet attacks.",
                {"addresses": private[:10]},
            ))

        rep.asn = self.asn_lookup(rep.addresses)
        non_empty = {k: v for k, v in a_sets.items() if v}
        if len(non_empty) >= 2:
            sets = list(non_empty.values())
            if all(s == sets[0] for s in sets):
                rep.consensus = "identical"
            elif all(sets[i] & sets[j] for i in range(len(sets)) for j in range(i + 1, len(sets))):
                rep.consensus = "overlapping"
            else:
                asn_sets = [{rep.asn[ip]["asn"] for ip in s if ip in rep.asn} for s in sets]
                if all(asn_sets) and all(asn_sets[0] & a for a in asn_sets[1:]):
                    rep.consensus = "different-ips-same-network"
                elif all(asn_sets):
                    rep.consensus = "disagree"
                    rep.findings.append(Finding(
                        "DNS_INCONSISTENT", "medium", 15, "Resolvers disagree on where the domain lives",
                        "Google, Cloudflare and AdGuard returned addresses on different networks. "
                        "Possible DNS manipulation or fast-changing infrastructure (GeoDNS can also do this).",
                        {"answers": {k: sorted(v) for k, v in non_empty.items()}},
                    ))
                else:
                    rep.consensus = "different-ips"
        elif len(non_empty) == 1:
            rep.consensus = "single"

        ttls = [results[(r.key, host, "A")].ttl for r in unf if results[(r.key, host, "A")].ttl is not None]
        distinct_asns = {v["asn"] for v in rep.asn.values()}
        if len(rep.addresses) >= 6 and len(distinct_asns) >= 3 and ttls and min(ttls) <= 300:
            rep.findings.append(Finding(
                "DNS_FAST_FLUX", "medium", 15, "Fast-flux pattern",
                f"{len(rep.addresses)} addresses across {len(distinct_asns)} networks with TTL "
                f"{min(ttls)}s - typical of botnet-hosted phishing.",
            ))

        # ---- nameservers / mail
        if registrable:
            ns = self._first_ok(results, refs, registrable, "NS")
            rep.ns = ns.records if ns else []
        if want_mx:
            mx = self._first_ok(results, refs[:1], registrable or host, "MX")
            rep.mx = mx.records if mx else []
            if mx is not None and not rep.mx:
                rep.findings.append(Finding(
                    "DNS_NO_MX", "low", 5, "Domain cannot receive email",
                    "No MX records: the address is probably used only to send spoofed mail.",
                ))

        if brand and rep.consensus != "nxdomain":
            self._compare_brand(rep, results, refs, brand, host)
        return rep

    @staticmethod
    def _block_page(r: Resolver, f: DnsAnswer, peer: DnsAnswer) -> bool:
        real = [ip for ip in f.addresses if ip not in NULL_IPS]
        return bool(real and r.block_networks and not set(real) & set(peer.addresses)
                    and all(_in_networks(ip, r.block_networks) for ip in real))

    def _resolves(self, r: Resolver, f: DnsAnswer, peer: DnsAnswer) -> bool:
        """The filtering resolver handed out a real address (not a null route or its block page)."""
        return f.ok and any(ip not in NULL_IPS for ip in f.addresses) and not self._block_page(r, f, peer)

    def _block_reason(self, r: Resolver, f: DnsAnswer, peer: DnsAnswer) -> str | None:
        if not f.ok:
            return None
        block_page = self._block_page(r, f, peer)
        if self._resolves(r, f, peer):
            # It resolved to a real address, so nothing was blocked - even if an extended error code
            # is attached (Cloudflare 1.1.1.2 answers web.archive.org normally, with EDE 18).
            return None
        for e in f.ede:
            if e["code"] in BLOCK_EDE_CODES:
                return f"EDE {e['code']} {e['name']}"
        peer_real = peer.ok and peer.rcode == "NOERROR" and any(ip not in NULL_IPS for ip in peer.addresses)
        if not peer_real:
            return None
        if f.addresses and all(ip in NULL_IPS for ip in f.addresses):
            return "answered 0.0.0.0 (null route)"
        if f.rcode in ("NXDOMAIN", "REFUSED"):
            return f"answered {f.rcode}"
        if f.rcode == "NOERROR" and not f.addresses and not f.cnames:
            return "answered with no address"
        if block_page:
            return "answered with the provider's block-page address"
        return None

    def _regional(self, results, name: str) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for region in REGIONS:
            ips: list[str] = []
            for t in ("A", "AAAA"):
                x = results.get((ECS_RESOLVER, name, t, region))
                if x and x.ok:
                    ips += [ip for ip in x.addresses if ip not in NULL_IPS]
            if ips:
                out[region] = list(dict.fromkeys(ips))
        return out

    def _compare_brand(self, rep: DnsReport, results, refs, brand: str, host: str) -> None:
        b_ips: list[str] = []
        for k in refs:
            for t in ("A", "AAAA"):
                x = results.get((k, brand, t))
                if x and x.ok:
                    b_ips += [ip for ip in x.addresses if ip not in NULL_IPS]
        b_regions = self._regional(results, brand) if self.regions else {}
        s_regions = self._regional(results, host) if self.regions else {}
        b_ips = list(dict.fromkeys(b_ips + [ip for ips in b_regions.values() for ip in ips]))
        s_ips = list(dict.fromkeys(rep.addresses + [ip for ips in s_regions.values() for ip in ips]))
        ns = self._first_ok(results, refs, brand, "NS")
        b_ns = ns.records if ns else []
        info = {"domain": brand, "addresses": b_ips[:MAX_BRAND_IPS], "ns": b_ns, "relation": "unknown", "asns": [],
                "regions_checked": len(REGIONS) if self.regions else 0, "brand_regions": b_regions,
                "suspect_regions": s_regions}
        rep.brand = info
        if not s_ips:
            info["relation"] = "suspect-does-not-resolve"
            return
        if not b_ips:
            info["relation"] = "brand-did-not-resolve"
            return
        rep.asn.update(self.asn_lookup(b_ips[:MAX_BRAND_IPS]))
        rep.asn.update(self.asn_lookup([ip for ip in s_ips if ip not in rep.asn][:MAX_ASN_IPS]))
        b_asn = {ip: rep.asn[ip] for ip in b_ips if ip in rep.asn}
        s_asns = {rep.asn[ip]["asn"] for ip in s_ips if ip in rep.asn}
        b_asns = {v["asn"] for v in b_asn.values()}
        info["asns"] = sorted(b_asns)
        info["prefixes"] = sorted({v["prefix"] for v in b_asn.values() if v.get("prefix")})[:20]

        def asn_label(asns: set[int]) -> str:
            names = []
            for a in sorted(asns)[:3]:
                nm = next((v.get("as_name") for v in rep.asn.values() if v["asn"] == a and v.get("as_name")), "")
                names.append(f"AS{a}" + (f" {nm}" if nm else ""))
            return ", ".join(names) or "unknown network"

        def owner_dedicated(ip: str) -> bool:
            info_ip = rep.asn.get(ip)
            return not self.asn_enabled or (info_ip is not None and info_ip["asn"] not in SHARED_INFRA_ASNS)

        where = f" (checked from {len(REGIONS)} regions)" if self.regions else ""
        shared_ips = set(s_ips) & set(b_ips)
        b_subnets = {subnet_of(ip) for ip in b_ips} - {None}
        same_subnet = sorted(ip for ip in s_ips if subnet_of(ip) in b_subnets and owner_dedicated(ip))
        b_prefixes = {v["prefix"] for v in b_asn.values() if v.get("prefix")}
        same_prefix = sorted(ip for ip in s_ips if owner_dedicated(ip) and any(_in_prefix(ip, p) for p in b_prefixes))
        shared_asns = s_asns & b_asns
        dedicated = {a for a in shared_asns if a not in SHARED_INFRA_ASNS}
        if shared_ips and (dedicated or not self.asn_enabled):
            info["relation"] = "same-ip"
            rep.findings.append(Finding(
                "DNS_BRAND_SAME_IP", "info", -20, f"Same IP address as the real {brand}",
                "The look-alike points at the brand's own servers - typical of a defensive "
                "registration that redirects to the real site.",
                {"shared": sorted(shared_ips)[:5]},
            ))
        elif same_subnet:
            info["relation"] = "same-subnet"
            rep.findings.append(Finding(
                "DNS_BRAND_SAME_SUBNET", "info", -15, f"Same network block as the real {brand}",
                f"{same_subnet[0]} is in the same {subnet_of(same_subnet[0])} block as one of {brand}'s addresses"
                f"{where}, on a network that is not a public hosting provider.",
                {"addresses": same_subnet[:5]},
            ))
        elif same_prefix:
            info["relation"] = "same-prefix"
            rep.findings.append(Finding(
                "DNS_BRAND_SAME_PREFIX", "info", -12, f"Inside the real {brand}'s announced network",
                f"{same_prefix[0]} belongs to an address range that {brand}'s network announces{where}.",
                {"addresses": same_prefix[:5]},
            ))
        elif dedicated:
            info["relation"] = "same-network"
            rep.findings.append(Finding(
                "DNS_BRAND_SAME_NET", "info", -10, f"Same network as the real {brand}",
                f"Both live on {asn_label(dedicated)}, which is not a public hosting provider.",
            ))
        elif shared_asns:
            info["relation"] = "shared-provider"
            rep.findings.append(Finding(
                "DNS_BRAND_SHARED_PROVIDER", "info", 0, f"Same hosting provider as {brand} (not evidence)",
                f"Both use {asn_label(shared_asns)}, where anyone can host a site.",
            ))
        elif s_asns and b_asns:
            info["relation"] = "different-network"
            rep.findings.append(Finding(
                "DNS_BRAND_DIFF_NET", "medium", 20, f"Hosted on a different network than the real {brand}",
                f"Look-alike: {asn_label(s_asns)}. Real {brand}{where}: {asn_label(b_asns)}. "
                "Where the user would actually be taken is not the brand's infrastructure.",
            ))

        s_prov = {_ns_provider(n) for n in rep.ns}
        b_prov = {_ns_provider(n) for n in b_ns}
        protection = sorted({BRAND_PROTECTION_NS[p] for p in s_prov if p in BRAND_PROTECTION_NS})
        own = (set(rep.ns) & set(b_ns)) and not (s_prov & b_prov) <= GENERIC_NS_PROVIDERS | {"awsdns"}
        if own:
            rep.findings.append(Finding(
                "DNS_BRAND_SHARED_NS", "info", -25, f"Uses {brand}'s own nameservers",
                "The look-alike is served by the brand's dedicated DNS - strong sign the brand owns it.",
                {"shared_ns": sorted(set(rep.ns) & set(b_ns))[:6]},
            ))
        elif protection:
            rep.findings.append(Finding(
                "DNS_BRAND_PROTECTION_NS", "info", -20, f"Parked with {protection[0]}",
                "Nameservers of a corporate brand-protection registrar - usually a defensive registration.",
            ))
