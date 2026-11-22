import pytest
from conftest import codes

from homograph_guard.brands import osa_distance
from homograph_guard.unicode_tools import char_script, parse_unicode_confusables, restriction_level, scripts_of


def test_scripts():
    assert char_script("a") == "Latin" and char_script("а") == "Cyrillic"
    assert char_script("α") == "Greek" and char_script("-") == "Common"
    assert char_script("一") == "Han" and char_script("́") == "Inherited"
    assert scripts_of("pаypal") == {"Latin", "Cyrillic"}
    assert restriction_level({"Latin", "Han", "Hiragana"}) == "highly-restrictive"
    assert restriction_level({"Latin", "Cyrillic"}) == "minimally-restrictive"


def test_skeleton_tiers(cmap):
    assert cmap.strict("pаypаl") == "paypal"
    assert cmap.strict("аррӏе") == "apple"  # palochka -> l
    assert cmap.loose("pàypał") == "paypal"
    assert cmap.collapse("rnicros0ft") == cmap.collapse("microsoft")
    assert cmap.lookalike("ɡ") == ("g", "confusable")
    assert cmap.lookalike("é") == ("e", "diacritic")
    assert cmap.lookalike("q") is None


def test_official_confusables_parser():
    text = "﻿# comment\n0430 ;\t0061 ;\tMA\t# ( а → a )\n006D ;\t0072 006E ;\tMA\t# m → rn\n"
    assert parse_unicode_confusables(text) == {"а": "a", "m": "rn"}


def test_osa_distance():
    assert osa_distance("paypal", "paypall") == 1
    assert osa_distance("paypal", "papyal") == 1  # transposition
    assert osa_distance("paypal", "google", 2) == 3


@pytest.mark.parametrize("url,brand,kind", [
    ("https://pаypal.com", "paypal.com", "homograph"),
    ("https://xn--80ak6aa92e.com", "apple.com", "homograph"),
    ("https://ɡoogle.com", "google.com", "homograph"),
    ("https://faceboök.com", "facebook.com", "lookalike"),
    ("https://paypa1.com", "paypal.com", "lookalike"),
    ("https://rnicrosoft.com", "microsoft.com", "lookalike"),
    ("https://paypall.com", "paypal.com", "typosquat"),
    ("https://paypal.com.account-verify.info", "paypal.com", "subdomain_spoof"),
    ("https://sbi-kyc-update.in", "sbi.co.in", "embedded"),
    ("https://amazon.co", "amazon.com", "tld_swap"),
    ("https://hdfcbаnk.com", "hdfcbank.com", "homograph"),
])
def test_brand_matches(offline, url, brand, kind):
    r = offline.analyze(url)
    top = r["brand_matches"][0]
    assert (top["brand"], top["kind"]) == (brand, kind)


@pytest.mark.parametrize("url", [
    "https://google.com", "https://accounts.google.com/x", "https://www.amazon.in/", "https://münchen.de",
    "https://яндекс.рф", "https://日本語.jp",
    "https://한국.kr", "https://appleinsider.com", "https://docs.python.org", "https://startups.com",
])
def test_legitimate_names_stay_quiet(offline, url):
    r = offline.analyze(url)
    assert r["verdict"] == "no_indicators", r["findings"]


def test_mixed_script_and_whole_script(offline):
    assert "HG_MIXED_SCRIPT" in codes(offline.analyze("https://soсial.com"))
    r = offline.analyze("https://хх.com")
    assert "HG_WHOLE_SCRIPT" in codes(r) and r["verdict"] in ("suspicious", "high_risk")
    native = offline.analyze("https://xn--e1aybc.xn--p1ai")  # тест.рф
    whole = [f for f in native["findings"] if f["code"] == "HG_WHOLE_SCRIPT"]
    assert whole and whole[0]["severity"] == "low"


def test_char_map(offline):
    r = offline.analyze("https://pаypal.com")
    chars = r["labels"][0]["chars"]
    odd = [c for c in chars if c["odd_script"]]
    assert len(odd) == 1 and odd[0]["codepoint"] == "U+0430" and odd[0]["looks_like"] == "a"


def test_high_risk_examples(offline):
    for url in ("https://xn--80ak6aa92e.com", "https://www.paypal.com@evil.example",
                "https://evil.example\\@google.com/", "javascript:alert(1)"):
        assert offline.analyze(url)["verdict"] in ("high_risk", "suspicious"), url
    assert offline.analyze("https://xn--80ak6aa92e.com")["verdict"] == "high_risk"


def test_email_reports(offline):
    r = offline.analyze("PayPal Support <service@paypa1.com>")
    assert r["kind"] == "email" and {"BRAND_LOOKALIKE", "EMAIL_DISPLAY_NAME_BRAND"} <= codes(r)


def test_input_error_report(offline):
    r = offline.analyze("http://a\x00b")
    assert r["verdict"] == "error" and r["error"]
