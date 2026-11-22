import json
from pathlib import Path

import pytest
from conftest import codes

from homograph_guard.unwrap import unwrap

VECTORS = json.loads((Path(__file__).parent / "vectors" / "wrapped_links.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("v", VECTORS, ids=[v["name"] for v in VECTORS])
def test_shared_vectors(v):
    u = unwrap(v["input"])
    assert [h.service for h in u.hops] == v["services"]
    assert u.destination == v["destination"]
    assert (u.embedded.url if u.embedded else None) == v.get("embedded")
    assert bool(u.opaque) == v.get("opaque", False)
    if u.hops:
        assert u.hops[0].trusted == v.get("trusted", True)


def test_depth_and_loops_are_bounded():
    url = "https://www.google.com/url?q=https://www.google.com/url?q=https://example.com/"
    u = unwrap(url)
    assert u.destination == "https://example.com/" and len(u.hops) == 2
    assert unwrap("x" * 9000).hops == []


def test_non_http_destination_is_ignored():
    u = unwrap("https://nam12.safelinks.protection.outlook.com/?url=javascript%3Aalert(1)")
    assert u.hops[0].url is None  # never turned into a "destination"


def test_safe_links_homograph_is_detected_through_the_wrapper(offline):
    rep = offline.analyze(VECTORS[0]["input"])
    assert rep["verdict"] == "high_risk"
    assert {"WRAP_GATEWAY", "BRAND_HOMOGRAPH", "HG_MIXED_SCRIPT"} <= codes(rep)
    assert rep["url"]["host_ascii"] == "xn--pypal-4ve.com"
    assert rep["input"].startswith("https://nam12.safelinks")


def test_unverified_fortimail_checks_both_hosts(offline):
    rep = offline.analyze("https://paypa1-login.example/fmlurlsvc/?url=https%3A%2F%2Fwww.paypal.com%2F")
    assert "WRAP_UNVERIFIED" in codes(rep)
    side = [f for f in rep["findings"] if f["evidence"].get("part") == "wrapper"]
    assert side and any("paypal" in f["title"].lower() for f in side)
    assert rep["verdict"] in ("suspicious", "high_risk")
    assert "unverified" in rep["summary"]


def test_embedded_redirect_target_is_checked(offline):
    rep = offline.analyze("https://news.example.org/out?url=https%3A%2F%2Fpaypal-secure-login.top%2F")
    assert "URL_EMBEDDED_URL" in codes(rep)
    assert any(f["evidence"].get("part") == "embedded" and f["code"] == "BRAND_EMBEDDED" for f in rep["findings"])


def test_opaque_wrapper_is_explained(offline):
    rep = offline.analyze("https://url.uk.m.mimecastprotect.com/s/AbCdEfGhIjKl")
    assert "WRAP_OPAQUE" in codes(rep) and rep["verdict"] == "no_indicators"


EXO = ("https://s.pemsrv.com/v1/link.php?cat=&idzone=5974550&type=8&p=https%3A%2F%2Ftheblank.net%2F&sub=&block=1"
       "&el=&tags=&scr_info=aW5saW5lfHBvcE1hZ2ljfDEx&gdpr=0&cb=596590530&cookieconsent=true")


def test_ad_network_redirect_is_recognised_not_decoded():
    from homograph_guard.unwrap import ad_source

    chain = unwrap(EXO)
    hop = chain.hops[0]
    assert (hop.kind, hop.vendor, hop.url) == ("advert", "ExoClick", None)
    assert chain.destination == EXO and chain.embedded is None  # p= is the page that showed the ad, not a target
    assert ad_source(hop) == "theblank.net"
    assert unwrap("https://www.popads.net/").hops == []  # the company's own website is not an ad link
    assert unwrap("https://serve.popads.net/s?x=1").hops[0].vendor == "PopAds"
