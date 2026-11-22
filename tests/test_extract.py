from conftest import codes

from homograph_guard.extract import extract_eml, extract_html, extract_text, find_text_urls

HTML = """<html><head><title>https://title.example</title><style>.x{}</style></head><body>
<a href="https://paypa1.com/login">https://www.paypal.com/signin</a>
<div style="display: none"><a href="https://hidden.example/track">x</a></div>
<p hidden><a href="https://attr-hidden.example/">y</a></p>
<a href="https://ok.example/"><img alt="Open invoice"></a>
<span style="font-size:0px">https://tiny.example/x</span>
<a style="position:absolute;left:-9999px" href="https://offscreen.example/">z</a>
<!-- https://comment.example/ -->
<script>location.href="https://script.example/go"</script>
<form action="https://collect.example/post"><input name=p></form>
<meta http-equiv="refresh" content="0; url=https://meta.example/">
<svg><a xlink:href="https://svg.example/"><text>svg</text></a></svg>
<a href="/relative">rel</a><a href="#top">top</a>
<a href="mailto:help@paypa1.com">Contact PayPal</a>
</body></html>"""


def _by_url(links):
    return {lk.url: lk for lk in links}


def test_html_finds_visible_hidden_and_embedded_links():
    found = _by_url(extract_html(HTML, "HTML body"))
    assert found["https://paypa1.com/login"].text == "https://www.paypal.com/signin"
    assert found["https://hidden.example/track"].hidden == "display:none"
    assert found["https://attr-hidden.example/"].hidden == "hidden attribute"
    assert found["https://ok.example/"].text == "Open invoice"  # alt text of a linked image
    assert found["https://tiny.example/x"].hidden == "font-size:0"
    assert found["https://offscreen.example/"].hidden == "moved off-screen"
    assert found["https://comment.example/"].hidden == "inside an HTML comment"
    assert found["https://script.example/go"].hidden == "inside a script"
    assert found["https://collect.example/post"].source == "form"
    assert found["https://meta.example/"].source == "meta-refresh"
    assert found["https://svg.example/"].source == "anchor"
    assert found["mailto:help@paypa1.com"].text == "Contact PayPal"
    assert "https://title.example" not in found
    assert not any(u.endswith("/relative") or u.endswith("#top") for u in found)


def test_base_href_resolves_relative_links():
    found = extract_html('<base href="https://docs.example/a/"><a href="b/c">x</a>')
    assert found[0].url == "https://docs.example/a/b/c"


def test_text_urls_defanged_and_bare_domains():
    urls = find_text_urls("Go to hxxps://evil[.]com/login, www.example.org. or pаypal.com! "
                          "Not setup.py, not me@paypal.com, (see https://en.wikipedia.org/wiki/A_(b)).")
    assert urls == ["hxxps://evil.com/login", "www.example.org", "pаypal.com", "https://en.wikipedia.org/wiki/A_(b)"]


def test_chat_export_text():
    chat = "[11/13/26, 10:15] Bank: Your KYC expires, update at sbi-kyc-update.in now\n[10:16] Me: ok"
    assert [lk.url for lk in extract_text(chat)] == ["sbi-kyc-update.in"]


def test_eml_headers_bodies_and_attachments():
    msg = (
        b'From: "PayPal" <service@paypa1.com>\r\nReply-To: help@micros0ft.com\r\nSubject: hi\r\n'
        b'MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="b"\r\n\r\n'
        b'--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nSee https://plain.example/x\r\n'
        b'--b\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n'
        b'<a href=3D"https://paypa1.com/">PayPal.com</a>\r\n'
        b'--b\r\nContent-Type: text/html; name="invoice.html"\r\nContent-Disposition: attachment; filename="invoice.html"\r\n'
        b'Content-Transfer-Encoding: base64\r\n\r\nPHNjcmlwdD5sb2NhdGlvbj0iaHR0cHM6Ly9hdHRhY2guZXhhbXBsZS8iPC9zY3JpcHQ+\r\n'
        b'--b--\r\n'
    )
    found = _by_url(extract_eml(msg))
    assert found["PayPal <service@paypa1.com>"].where == "From header"
    assert found["help@micros0ft.com"].where == "Reply-To header"
    assert found["https://plain.example/x"].where == "plain-text body"
    assert found["https://paypa1.com/"].text == "PayPal.com"
    assert found["https://attach.example/"].where == "attachment invoice.html"


def test_link_text_mismatch_and_hidden_findings(offline):
    rep = offline.analyze("https://paypa1.com/login", {"source": "anchor", "text": "https://www.paypal.com/signin"})
    assert "LINK_TEXT_MISMATCH" in codes(rep) and rep["verdict"] == "high_risk"
    same = offline.analyze("https://www.paypal.com/help", {"source": "anchor", "text": "paypal.com/help"})
    assert "LINK_TEXT_MISMATCH" not in codes(same)
    plain = offline.analyze("https://example.net/", {"source": "anchor", "text": "Click here to read invoice.pdf"})
    assert "LINK_TEXT_MISMATCH" not in codes(plain)  # .pdf is not a domain
    hidden = offline.analyze("https://example.net/", {"source": "anchor", "text": "x", "hidden": "display:none"})
    assert "LINK_HIDDEN" in codes(hidden) and hidden["context"]["hidden"] == "display:none"


def test_wrapped_link_text_mismatch_uses_the_real_destination(offline):
    safe = ("https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.paypal.com%2Fsignin&data=x")
    rep = offline.analyze(safe, {"source": "anchor", "text": "www.paypal.com/signin"})
    assert "LINK_TEXT_MISMATCH" not in codes(rep)  # Safe Links host is not the destination
