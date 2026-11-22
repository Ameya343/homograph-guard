import json

import pytest
from conftest import codes

from homograph_guard import feeds, settings
from homograph_guard.analyzer import Analyzer
from homograph_guard.threatdb import ThreatDB, normalize_entry, normalize_url, url_candidates


@pytest.fixture
def db(tmp_path):
    d = ThreatDB(tmp_path / "threats.db")
    yield d
    d.close()


@pytest.fixture
def an(db, brands, cmap):
    return Analyzer(brands, cmap, threatdb=db, settings=settings.Settings())


def test_url_normalisation_and_prefixes():
    assert normalize_url("HTTPS://Evil.Example.COM:443/Login/?a=1#frag") == "https://evil.example.com/Login?a=1"
    assert normalize_url("http://[::1]:8080/") == "http://[::1]:8080/"
    assert normalize_url("javascript:alert(1)") is None and normalize_url("https://") is None
    assert url_candidates("https://e.com/a/b?x=1") == ["https://e.com/a/b?x=1", "https://e.com/a/b", "https://e.com/a", "https://e.com/"]


@pytest.mark.parametrize("text,expected", [
    ("Evil-Phish.com", ("domain", "evil-phish.com")),
    ("evil-phish.com/", ("domain", "evil-phish.com")),
    ("https://evil-phish.com/login", ("url", "https://evil-phish.com/login")),
    ("evil-phish.com/login", ("url", "https://evil-phish.com/login")),
    ("pаypal.com", ("domain", "xn--pypal-4ve.com")),
    ("192.0.2.7", ("domain", "192.0.2.7")),
])
def test_entries(text, expected):
    assert normalize_entry(text) == expected


@pytest.mark.parametrize("bad", ["", "co.uk", "com", "github.io", "not a domain", "javascript:alert(1)", "x" * 3000,
                                 "ftp://evil.com/", "' OR 1=1 --"])
def test_bad_entries_are_refused(bad):
    with pytest.raises(ValueError):
        normalize_entry(bad)


def test_feed_parsing_refuses_overbroad_entries():
    army = feeds.FEEDS_BY_NAME["phishing-army"]
    text = ("# comment\npaypal.com\nwww.paypal.com\nlogin.paypal.com\nevil-phish.top\nco.uk\nweebly.com\nabc.weebly.com\n"
            "*.wild-phish.xyz\n0.0.0.0 hosts-phish.com\nbad..domain\nxn--pypal-4ve.com\nlogin.cloud.microsoft\n"
            "firebasestorage.googleapis.com\nx.s3.amazonaws.com\nnot-a-tld.zzzz\n203.0.113.9\n")
    domains, urls = feeds.parse(army, text)
    assert domains == {"evil-phish.top", "abc.weebly.com", "wild-phish.xyz", "hosts-phish.com", "xn--pypal-4ve.com",
                       "203.0.113.9"}
    assert not urls


def test_url_feed_keeps_links_on_platforms_but_not_their_hosts():
    op = feeds.FEEDS_BY_NAME["openphish"]
    domains, urls = feeds.parse(op, "https://paypa1-login.com/x/y\nhttps://docs.google.com/forms/d/e/abc/viewform\n"
                                    "https://storage.googleapis.com/b/p.html\nhttp://luskasdev.github.io/Phishing\njavascript:x\n")
    assert domains == {"paypa1-login.com", "luskasdev.github.io"}
    assert urls == {"https://paypa1-login.com/x/y", "https://docs.google.com/forms/d/e/abc/viewform",
                    "https://storage.googleapis.com/b/p.html", "http://luskasdev.github.io/Phishing"}


def test_adblock_format_only_takes_plain_domain_rules():
    ag = feeds.FEEDS_BY_NAME["adguard-dns"]
    domains, _ = feeds.parse(ag, "! title\n||ads.tracker-net.com^\n||x.com^$third-party\n@@||ok.com^\n||y.top^$important\n")
    assert domains == {"ads.tracker-net.com", "y.top"}


def test_lookup_verdicts(db, an):
    op = feeds.FEEDS_BY_NAME["openphish"]
    d, u = feeds.parse(op, "https://paypa1-login.com/x/y\nhttps://docs.google.com/forms/d/e/abc/viewform\n")
    db.replace_feed(op.name, op.title, op.category, op.url, d, u, "h")
    rep = an.analyze("https://login.paypa1-login.com/anything")  # sub-domain of a listed host
    assert rep["verdict"] == "high_risk" and "FEED_LISTED" in codes(rep)
    assert rep["summary"].startswith("Listed by OpenPhish")
    rep = an.analyze("https://docs.google.com/forms/d/e/abc/viewform?usp=sf_link")  # listed link, longer
    assert "FEED_LISTED" in codes(rep)
    assert "FEED_LISTED" not in codes(an.analyze("https://docs.google.com/forms/d/e/other/viewform"))
    wrapped = an.analyze("https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fpaypa1-login.com%2Fx%2Fy")
    assert "FEED_LISTED" in codes(wrapped)  # the decoded destination is looked up


def test_user_lists_and_reports(db, an):
    db.add_entry("block", "https://good-site.com/login", "seen in a phish")
    rep = an.analyze("https://good-site.com/login?step=2")
    assert rep["verdict"] == "high_risk" and rep["summary"] == "On your blocklist"
    assert an.analyze("https://good-site.com/")["verdict"] == "no_indicators"  # only that link
    db.add_entry("allow", "paypa1.com", "my test site")
    rep = an.analyze("https://www.paypa1.com/")
    assert rep["verdict"] == "no_indicators" and rep["summary"] == "On your allowlist" and "LIST_ALLOWED" in codes(rep)
    db.report("https://paypa1.com/evil")
    rep = an.analyze("https://paypa1.com/evil")
    assert rep["verdict"] == "high_risk" and rep["summary"] == "You reported this link as phishing"
    db.add_entry("block", "paypa1.com")  # blocking removes the allow entry for the same value
    assert not db.entries("allow") and an.analyze("https://paypa1.com/")["summary"] == "On your blocklist"
    exported = db.export_lists()
    assert {e["value"] for e in exported["block"]} == {"paypa1.com", "https://good-site.com/login"}


def test_organisation_policy_lists(db, brands, cmap, tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"dns_mode": "off", "block": ["corp-phish.com"], "allow": ["partner-paypa1.com"]}))
    s = settings.load(tmp_path / "user.json", policy)
    assert s.locked == {"dns_mode"}
    with pytest.raises(PermissionError):
        settings.set_value("dns_mode", "all", tmp_path / "user.json", policy)
    an = Analyzer(brands, cmap, threatdb=db, settings=s)
    assert an.analyze("https://x.corp-phish.com/")["summary"] == "On your organisation's blocklist"
    assert an.analyze("https://partner-paypa1.com/")["verdict"] == "no_indicators"


def test_import_rejects_garbage(db):
    with pytest.raises(ValueError):
        db.import_lists({"allow": ["x"]})
    n = db.import_lists({"format": "homograph-guard-lists/1", "allow": [{"value": "ok-site.com"}, {"value": "co.uk"}, "junk"],
                         "block": [{"value": 5}], "reported": [{"url": "https://phish-site.com/a"}]})
    assert n == 2


def test_sql_injection_is_inert(db):
    with pytest.raises(ValueError):
        db.add_entry("block", "x.com'); DROP TABLE user_entries; --")
    db.add_entry("block", "https://evil-site.com/?q=';DROP TABLE reports;--")
    assert db.entries("block")[0]["value"].startswith("https://evil-site.com/?q=")
    assert db.status()["block"] == 1
