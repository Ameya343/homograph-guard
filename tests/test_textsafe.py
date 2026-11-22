from homograph_guard.report import render_text, to_json
from homograph_guard.textsafe import defang_url, safe_text


def test_safe_text_escapes_dangerous_characters():
    s = safe_text("moc.elgoog‮\x1b[31m​ok")
    assert "‮" not in s and "\x1b" not in s and "​" not in s
    assert "<U+202E>" in s and "<U+001B>" in s and "<U+200B>" in s


def test_safe_text_truncates():
    assert len(safe_text("a" * 5000, 100)) == 100


def test_defang():
    assert defang_url("https", "evil.example", "/x") == "hxxps[://]evil[.]example/x"


def test_json_is_ascii_only(offline):
    out = to_json([offline.analyze("https://pаypal.com/‮")])
    assert out.isascii()


def test_text_report_never_contains_raw_controls(offline):
    text = render_text(offline.analyze("https://pay​pal.com/‮abc\x1b[2J"), color=False)
    for bad in ("‮", "​", "\x1b"):
        assert bad not in text
