"""End-to-end DNS tests against the local multi-resolver lab (UDP, TCP, DoT, DoH)."""

import dataclasses

import pytest
from dnslab import cymru

from homograph_guard.analyzer import Analyzer
from homograph_guard.dns_check import DnsInvestigator, cymru_origin_name, parse_cymru_origin
from homograph_guard.dns_transport import DnsClient

UNF = ["google", "cloudflare", "adguard-unfiltered"]
ALL = UNF + ["cloudflare-security", "adguard"]


def fcodes(rep):
    return {f.code for f in rep.findings}


@pytest.fixture
def phish(lab):
    host = "xn--pypal-4ve.com"
    lab.set_all(UNF, host, "A", values=["185.10.10.10"])
    lab.set("cloudflare-security", host, "A", values=["0.0.0.0"])
    lab.set("adguard", host, "A", values=["0.0.0.0"], ede=(15, "Blocked (phishing)"))
    lab.set_all(UNF, host, "NS", values=["ns1.evilhost.example."])
    lab.set_all(UNF, "paypal.com", "A", values=["64.4.250.36"])
    lab.set_all(UNF, "paypal.com", "NS", values=["ns1.p57.dynect.net."])
    cymru(lab, "185.10.10.10", 48282, "185.10.10.0/24", "RU", "HOSTING-RU, RU")
    cymru(lab, "64.4.250.36", 17012, "64.4.240.0/20", "US", "PAYPAL, US")
    return host


@pytest.mark.parametrize("transport", ["doh", "dot", "udp"])
def test_phishing_domain_all_transports(lab, phish, transport):
    inv = DnsInvestigator(DnsClient(transport, timeout=3, cafile=str(lab.ca)), lab.resolvers)
    rep = inv.investigate(phish, phish, brand="paypal.com")
    c = fcodes(rep)
    assert {"DNS_BLOCKED_SECURITY", "DNS_BLOCKED_FILTER", "DNS_BRAND_DIFF_NET"} <= c, c
    assert rep.consensus == "identical" and rep.addresses == ["185.10.10.10"]
    assert rep.asn["185.10.10.10"]["asn"] == 48282 and rep.asn["185.10.10.10"]["as_name"] == "HOSTING-RU, RU"
    blocked = {r["key"]: r["block_reason"] for r in rep.resolvers if r["blocked"]}
    assert blocked["adguard"].startswith("EDE 15") and "0.0.0.0" in blocked["cloudflare-security"]
    if transport in ("doh", "dot"):
        # the lab uses a private CA - exactly what a TLS-intercepting proxy looks like
        assert "DNS_TLS_INTERCEPTED" in c
        assert all(r["a"]["tls_issuer"] for r in rep.resolvers)
    else:
        assert "DNS_TLS_INTERCEPTED" not in c


def test_defensive_registration_is_mitigated(lab):
    host = "xn--80ak6aa92e.com"
    lab.set_all(ALL, host, "A", values=["17.253.144.10"])
    lab.set_all(UNF, host, "NS", values=["a.ns.apple.com.", "b.ns.apple.com."])
    lab.set_all(UNF, "apple.com", "A", values=["17.253.144.10"])
    lab.set_all(UNF, "apple.com", "NS", values=["a.ns.apple.com.", "b.ns.apple.com."])
    cymru(lab, "17.253.144.10", 714, "17.0.0.0/8", "US", "APPLE-ENGINEERING, US")
    inv = DnsInvestigator(DnsClient("udp", timeout=3), lab.resolvers)
    rep = inv.investigate(host, host, brand="apple.com")
    c = fcodes(rep)
    assert {"DNS_BRAND_SAME_IP", "DNS_BRAND_SHARED_NS"} <= c
    assert not any(x.startswith("DNS_BLOCKED") for x in c)
    assert sum(f.weight for f in rep.findings) < 0


def test_shared_cdn_is_not_evidence(lab):
    host = "brand-cdn-twin.example"
    lab.set_all(UNF, host, "A", values=["104.16.1.1"])
    lab.set_all(UNF, "github.com", "A", values=["104.16.2.2"])
    cymru(lab, "104.16.1.1", 13335, "104.16.0.0/13", "US", "CLOUDFLARENET, US")
    cymru(lab, "104.16.2.2", 13335, "104.16.0.0/13", "US", "CLOUDFLARENET, US")
    rep = DnsInvestigator(DnsClient("udp", timeout=3), lab.resolvers).investigate(host, host, brand="github.com")
    assert "DNS_BRAND_SHARED_PROVIDER" in fcodes(rep) and rep.brand["relation"] == "shared-provider"


def test_resolvers_disagree(lab):
    host = "split-brain.example"
    for key, ip, asn in (("google", "45.1.1.1", 1111), ("cloudflare", "46.2.2.2", 2222),
                         ("adguard-unfiltered", "47.3.3.3", 3333)):
        lab.set(key, host, "A", values=[ip])
        cymru(lab, ip, asn, ip + "/32", "NL", f"NET-{asn}")
    rep = DnsInvestigator(DnsClient("udp", timeout=3), lab.resolvers).investigate(host, None)
    assert rep.consensus == "disagree" and "DNS_INCONSISTENT" in fcodes(rep)


def test_cdn_geo_answers_same_network(lab):
    host = "cdn-geo.example"
    for key, ip in (("google", "151.101.1.1"), ("cloudflare", "151.101.65.1"), ("adguard-unfiltered", "151.101.129.1")):
        lab.set(key, host, "A", values=[ip])
        cymru(lab, ip, 54113, "151.101.0.0/16", "US", "FASTLY, US")
    rep = DnsInvestigator(DnsClient("udp", timeout=3), lab.resolvers).investigate(host, None)
    assert rep.consensus == "different-ips-same-network" and "DNS_INCONSISTENT" not in fcodes(rep)


def test_nxdomain_everywhere(lab):
    host = "never-registered.example"
    lab.set_all(ALL, host, "A", rcode="NXDOMAIN")
    lab.set_all(ALL, host, "AAAA", rcode="NXDOMAIN")
    rep = DnsInvestigator(DnsClient("udp", timeout=3), lab.resolvers).investigate(host, host, brand="paypal.com")
    assert rep.consensus == "nxdomain" and "DNS_NXDOMAIN" in fcodes(rep)
    assert not any(c.startswith("DNS_BLOCKED") for c in fcodes(rep))


def test_private_answer_and_block_page(lab):
    host = "rebind.example"
    lab.set_all(UNF, host, "A", values=["10.0.0.5"])
    assert "DNS_PRIVATE_IP" in fcodes(DnsInvestigator(DnsClient("udp", timeout=3), lab.resolvers).investigate(host, None))
    host2 = "blockpage.example"
    lab.set_all(UNF, host2, "A", values=["185.20.20.20"])
    lab.set("adguard", host2, "A", values=["198.51.100.7"])
    rep = DnsInvestigator(DnsClient("udp", timeout=3), lab.resolvers).investigate(host2, None)
    reasons = {r["key"]: r["block_reason"] for r in rep.resolvers if r["blocked"]}
    assert "block-page" in reasons.get("adguard", "")


def test_error_code_with_a_real_answer_is_not_a_block(lab):
    # Seen live: Cloudflare 1.1.1.2 answers web.archive.org with the real address plus EDE 18 "Prohibited".
    host = "archive-like.example"
    lab.set_all(ALL, host, "A", values=["207.241.237.3"])
    lab.set("cloudflare-security", host, "A", values=["207.241.237.3"], ede=(18, "Prohibited"))
    rep = DnsInvestigator(DnsClient("udp", timeout=3), lab.resolvers).investigate(host, None)
    assert not any(c.startswith("DNS_BLOCKED") for c in fcodes(rep))
    # ...also when the code comes with the empty IPv6 answer of a site that has no IPv6
    lab.set("cloudflare-security", host, "AAAA", ede=(18, "Prohibited"))
    rep = DnsInvestigator(DnsClient("udp", timeout=3), lab.resolvers).investigate(host, None)
    assert not any(c.startswith("DNS_BLOCKED") for c in fcodes(rep))
    lab.set("cloudflare-security", host, "AAAA")
    # ...while the same code next to a null route still is one
    lab.set("cloudflare-security", host, "A", values=["0.0.0.0"], ede=(18, "Prohibited"))
    rep = DnsInvestigator(DnsClient("udp", timeout=3), lab.resolvers).investigate(host, None)
    assert "DNS_BLOCKED_SECURITY" in fcodes(rep)


def test_privacy_no_query_reveals_the_users_network(lab, phish):
    lab.ecs_seen.clear()
    DnsInvestigator(DnsClient("udp", timeout=3), lab.resolvers).investigate(phish, phish, brand="paypal.com")
    from homograph_guard.dns_check import REGIONS

    assert lab.ecs_seen, "no queries recorded"
    allowed = {"0.0.0.0/0", *REGIONS.values()}
    assert set(lab.ecs_seen) <= allowed, set(lab.ecs_seen) - allowed  # only "nothing" or fixed regional prefixes
    assert "0.0.0.0/0" in lab.ecs_seen and len(set(lab.ecs_seen) & set(REGIONS.values())) == len(REGIONS)


def test_brand_compared_from_every_region(lab):
    """A brand on a GeoDNS/CDN answers differently per region; a defensive registration hosted in the
    brand's Indian network block is recognised even though the default answer is in the US."""
    from homograph_guard.dns_check import REGIONS

    brand, host = "examplebank.com", "examp1ebank.com"
    us, india, lookalike = "146.75.1.10", "103.21.244.80", "103.21.244.99"  # public ranges; owners invented by the lab
    lab.set_all(UNF, brand, "A", values=[us])  # default (US) answer
    lab.set("google", brand, "A", values=[india], ecs=REGIONS["India"])  # the brand's Indian edge
    lab.set_all(ALL, host, "A", values=[lookalike])  # the look-alike: same /24 as the Indian edge
    cymru(lab, us, 64500, "146.75.0.0/16", "US", "EXAMPLEBANK-US, US")
    cymru(lab, india, 64501, "103.21.244.0/22", "IN", "EXAMPLEBANK-IN, IN")
    cymru(lab, lookalike, 64501, "103.21.244.0/22", "IN", "EXAMPLEBANK-IN, IN")
    rep = DnsInvestigator(DnsClient("udp", timeout=3), lab.resolvers).investigate(host, host, brand=brand)
    assert rep.brand["relation"] == "same-subnet" and "DNS_BRAND_SAME_SUBNET" in fcodes(rep)
    assert rep.brand["brand_regions"]["India"] == [india] and rep.brand["regions_checked"] == len(REGIONS)
    # Without the regional view only the US address is known: the look-alike would look foreign.
    rep = DnsInvestigator(DnsClient("udp", timeout=3), lab.resolvers, regions=False).investigate(host, host, brand=brand)
    assert rep.brand["relation"] == "different-network" and "DNS_BRAND_DIFF_NET" in fcodes(rep)


def test_one_resolver_down(lab, phish):
    broken = [dataclasses.replace(r, udp_port=1) if r.key == "cloudflare" else r for r in lab.resolvers]
    rep = DnsInvestigator(DnsClient("udp", timeout=1), broken).investigate(phish, phish)
    cf = next(r for r in rep.resolvers if r["key"] == "cloudflare")
    assert cf["a"]["error"] and rep.addresses == ["185.10.10.10"]


def test_full_pipeline_with_dns(lab, phish, brands, cmap):
    inv = DnsInvestigator(DnsClient("doh", timeout=3, cafile=str(lab.ca)), lab.resolvers)
    r = Analyzer(brands, cmap, inv).analyze("https://pаypal.com/login")
    assert r["verdict"] == "high_risk" and r["score"] == 100
    found = {f["code"] for f in r["findings"]}
    assert {"BRAND_HOMOGRAPH", "HG_MIXED_SCRIPT", "DNS_BLOCKED_SECURITY", "DNS_BRAND_DIFF_NET"} <= found
    assert r["dns"]["brand"]["domain"] == "paypal.com"


def test_cymru_helpers():
    assert cymru_origin_name("1.2.3.4") == "4.3.2.1.origin.asn.cymru.com"
    assert cymru_origin_name("2001:db8::1").endswith(".8.b.d.0.1.0.0.2.origin6.asn.cymru.com")
    assert parse_cymru_origin("13335 209242 | 104.16.0.0/13 | US | arin | 2014-03-28")["asn"] == 13335
    assert parse_cymru_origin("garbage") is None


def test_links_in_messages_never_query_a_per_reader_sub_domain(lab, brands, cmap):
    """A sub-domain made for one recipient must not reach any DNS server: looking it up would tell
    the sender the message was read. Links in emails and chats are looked up by registered domain."""
    token = "a8f3k2x9q.track.paypa1.com"
    lab.set_all(ALL, "paypa1.com", "A", values=["185.10.10.10"])
    lab.set_all(ALL, token, "A", values=["185.10.10.10"])
    an = Analyzer(brands, cmap, DnsInvestigator(DnsClient("udp", timeout=3), lab.resolvers))

    def queried(ctx):
        lab.queries.clear()
        rep = an.analyze(f"https://{token}/open?id=1", ctx)
        return rep, {q[1].rstrip(".").lower() for q in lab.queries}

    for medium in ("email", "chat"):
        rep, names = queried({"source": "anchor", "text": "View", "medium": medium})
        assert token not in names and "paypa1.com" in names, names
        assert rep["dns"]["looked_up"] == "paypa1.com"
    rep, names = queried({"source": "anchor", "text": "View", "medium": "page"})  # a web page: the full host
    assert token in names and "looked_up" not in rep["dns"]


def test_ad_redirect_headline_versus_dns_blocks(lab, brands, cmap):
    """AdGuard blocks ad networks too, so the ad-network explanation leads; a security-only block still wins."""
    host = "s.pemsrv.com"
    lab.set_all(UNF + ["cloudflare-security"], host, "A", values=["51.38.251.17"])
    lab.set("adguard", host, "A", values=["0.0.0.0"], ede=(15, "Blocked"))
    an = Analyzer(brands, cmap, DnsInvestigator(DnsClient("udp", timeout=3), lab.resolvers, asn=False))
    rep = an.analyze(f"https://{host}/v1/link.php?idzone=1&p=https%3A%2F%2Fnews.example%2F")
    codes = {f["code"] for f in rep["findings"]}
    assert {"AD_REDIRECT", "DNS_BLOCKED_FILTER"} <= codes
    assert rep["summary"] == "Ad network redirect (ExoClick)" and rep["verdict"] == "suspicious"
    lab.set("cloudflare-security", host, "A", values=["0.0.0.0"])
    rep = an.analyze(f"https://{host}/v1/link.php?idzone=1")
    assert rep["summary"].startswith("Blocked by") and "DNS_BLOCKED_SECURITY" in {f["code"] for f in rep["findings"]}
