import pytest

from homograph_guard.models import InputError
from homograph_guard.urlsafe import parse_url


def fcodes(p):
    return {f.code for f in p.findings}


def test_plain_url():
    p = parse_url("https://Example.COM:443/a?b#c")
    assert p.host_ascii == "example.com" and p.port is None and p.rest == "/a?b#c"
    assert not p.findings


def test_bare_domain_and_port():
    assert parse_url("example.com").host_ascii == "example.com"
    p = parse_url("localhost:8080/x")
    assert p.host_ascii == "localhost" and p.port == 8080


def test_userinfo_deception_uses_last_at():
    p = parse_url("https://www.paypal.com@evil.example/login")
    assert p.host_ascii == "evil.example"
    assert "URL_USERINFO_DECEPTION" in fcodes(p)


def test_backslash_parser_confusion():
    p = parse_url("https://evil.example\\@google.com/")
    assert p.host_ascii == "evil.example"  # what a browser opens
    assert "URL_PARSER_CONFUSION" in fcodes(p)


@pytest.mark.parametrize("host,ip", [("0x7f.1", "127.0.0.1"), ("2130706433", "127.0.0.1"),
                                     ("0177.0.0.1", "127.0.0.1"), ("192.168.1", "192.168.0.1")])
def test_obfuscated_ipv4(host, ip):
    p = parse_url(f"http://{host}/")
    assert p.is_ip and p.host_ascii == ip
    assert {"URL_OBFUSCATED_IP", "URL_INTERNAL_IP"} <= fcodes(p)


def test_ipv6_literal():
    p = parse_url("http://[::1]:8080/")
    assert p.is_ip and p.ip_version == 6 and p.port == 8080


def test_percent_encoded_host():
    p = parse_url("https://%67oogle.com/")
    assert p.host_ascii == "google.com"
    assert "URL_PERCENT_HOST" in fcodes(p)


def test_fullwidth_and_ideographic_dot():
    p = parse_url("https://ｇｏｏｇｌｅ。com")
    assert p.host_ascii == "google.com"
    assert "IDN_NORMALIZED" in fcodes(p)


def test_soft_hyphen_is_flagged_and_removed():
    p = parse_url("https://pay­pal.com")
    assert p.host_ascii == "paypal.com"
    assert {"URL_INVISIBLE", "IDN_NORMALIZED"} <= fcodes(p)


def test_bidi_control():
    p = parse_url("https://example.com/‮gnp.exe")
    assert "URL_BIDI" in fcodes(p)


def test_percent_encoded_rlo_in_host():
    p = parse_url("https://ex%E2%80%AEmoc.elgoog")
    assert "URL_BIDI" in fcodes(p)


def test_punycode_decoding():
    p = parse_url("https://xn--80ak6aa92e.com")
    assert p.host_unicode == "аррӏе.com"


def test_unicode_to_punycode():
    p = parse_url("http://pаypal.com")
    assert p.host_ascii == "xn--pypal-4ve.com"


def test_invalid_punycode_flagged():
    p = parse_url("http://xn--a.com")
    assert "IDN_INVALID" in fcodes(p)


def test_zero_width_joiner_is_invalid_idna():
    p = parse_url("https://e‍xample.com")
    assert not p.idna_valid and "URL_INVISIBLE" in fcodes(p)


@pytest.mark.parametrize("url", ["javascript:alert(1)", "JaVaScRiPt:alert(1)", " data:text/html,hi",
                                 "java\tscript:alert(1)"])
def test_dangerous_schemes(url):
    p = parse_url(url)
    assert not p.has_host and "URL_DANGEROUS_SCHEME" in fcodes(p)


def test_app_handler_scheme():
    p = parse_url('ms-msdt:/id PCWDiagnostic /param "IT_BrowseForFile=x"')
    assert "URL_APP_HANDLER" in fcodes(p)


def test_remote_file_share():
    p = parse_url("file://attacker.example/share/x.lnk")
    assert "URL_REMOTE_FILE" in fcodes(p) and p.host_ascii == "attacker.example"
    assert "URL_FILE_SCHEME" in fcodes(parse_url("file:///etc/passwd"))


def test_fake_slash_and_dot():
    assert "IDN_FAKE_SLASH" in fcodes(parse_url("https://accounts.google.com∕login.evil.example"))
    assert "IDN_FAKE_DOT" in fcodes(parse_url("https://paypal·com.evil.example"))


def test_refang():
    p = parse_url("hxxps://evil[.]example[.]com/x")
    assert p.host_ascii == "evil.example.com" and p.scheme == "https"
    assert "INPUT_DEFANGED" in fcodes(p)


def test_email_forms():
    p = parse_url("PayPal Service <service@pаypal.com>")
    assert p.kind == "email" and p.display_name == "PayPal Service" and p.host_ascii == "xn--pypal-4ve.com"
    q = parse_url("mailto:help@example.com?subject=hi")
    assert q.kind == "email" and q.host_ascii == "example.com"
    r = parse_url("paypal.com <x@evil.example>")
    assert "EMAIL_DISPLAY_NAME_DOMAIN" in fcodes(r)


@pytest.mark.parametrize("bad", ["", "   ", "http://a\x00b.com", "x" * 9000, "http://[::1", "http://a.com:99999/"])
def test_rejects_garbage(bad):
    with pytest.raises(InputError):
        parse_url(bad)


def test_long_label_survives():
    p = parse_url("https://" + "a" * 70 + ".com")
    assert p.host_ascii.startswith("a")
