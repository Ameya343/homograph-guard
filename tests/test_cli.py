import json
import subprocess
import sys
from pathlib import Path

from homograph_guard.cli import main

ENTRY = Path(__file__).resolve().parent.parent / "src" / "homograph_guard" / "_entry.py"


def run_entry(*args, stdin=""):
    """Run the CLI exactly like the Docker image / GUI worker: python -I with the guard on."""
    return subprocess.run([sys.executable, "-I", str(ENTRY), *args], input=stdin,
                          capture_output=True, text=True, encoding="utf-8", timeout=120)


def test_exit_codes_and_json(capsys):
    assert main(["--no-guard", "--no-dns", "--json", "https://google.com"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0]["verdict"] == "no_indicators"
    assert main(["--no-guard", "--no-dns", "--json", "https://xn--80ak6aa92e.com"]) == 4
    assert main(["--no-guard", "--no-dns", "--json", "https://paypa1.com"]) == 3


def test_jsonl_and_custom_brand(capsys):
    rc = main(["--no-guard", "--no-dns", "--jsonl", "--only-my-brands", "--brand", "acme-corp.in",
               "https://acme-cоrp.in/login", "https://google.com"])
    lines = capsys.readouterr().out.strip().splitlines()
    assert rc == 4 and len(lines) == 2
    first = json.loads(lines[0])
    assert first["brand_matches"][0]["brand"] == "acme-corp.in"
    assert json.loads(lines[1])["brand_matches"] == []  # built-in list disabled


def test_guarded_subprocess_stdin_and_output_file(tmp_path):
    out = tmp_path / "report.json"
    proc = run_entry("--no-dns", "--json", "--stdin", "-o", str(out),
                     stdin="# comment\nhttps://pаypal.com\nPayPal <x@paypa1.com>\n\n")
    assert proc.returncode == 4, proc.stderr
    data = json.loads(out.read_text())
    assert [d["verdict"] for d in data] == ["high_risk", "suspicious"]
    assert "sandbox" not in proc.stderr


def test_guarded_text_report_is_sanitised():
    proc = run_entry("--no-dns", "--no-color", "https://pay​pal.com/‮exe.pdf")
    assert proc.returncode in (3, 4)
    assert "‮" not in proc.stdout and "​" not in proc.stdout and "<U+202E>" in proc.stdout


def test_dns_failure_is_graceful():
    # Points at an unroutable documentation address: the guard allows it, the network does not.
    proc = run_entry("--json", "--timeout", "1", "--transport", "udp", "--resolvers", "google",
                     "--no-asn", "https://example.com")
    assert proc.returncode in (0, 1, 3, 4), proc.stderr
    data = json.loads(proc.stdout)
    assert data[0]["dns"] is not None


def test_usage_errors():
    proc = run_entry()
    assert proc.returncode == 2
    proc = run_entry("--resolvers", "nope", "https://x.com")
    assert proc.returncode == 2 and "unknown resolver" in proc.stderr


EML = (
    'From: "PayPal" <service@paypa1.com>\nSubject: limited\nMIME-Version: 1.0\nContent-Type: text/html; charset=utf-8\n\n'
    '<a href="https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fpaypa1.com%2Fsignin">'
    'https://www.paypal.com/signin</a><div style="display:none"><a href="https://t.example/o">.</a></div>\n'
)


def test_guarded_eml_from_stdin():
    proc = run_entry("--no-dns", "--json", "--eml", "-", stdin=EML)
    assert proc.returncode == 4, proc.stderr
    data = json.loads(proc.stdout)
    sender = next(d for d in data if (d.get("context") or {}).get("where") == "From header")
    assert sender["input"] == "PayPal <service@paypa1.com>" and sender["verdict"] == "suspicious"
    wrapped = next(d for d in data if d.get("wrapped"))
    assert wrapped["wrapped"]["destination"] == "https://paypa1.com/signin"
    assert {"LINK_TEXT_MISMATCH", "WRAP_GATEWAY"} <= {f["code"] for f in wrapped["findings"]}
    hidden = next(d for d in data if (d.get("context") or {}).get("hidden"))
    assert hidden["context"]["hidden"] == "display:none"
    assert "sandbox" not in proc.stderr


def test_byte_order_mark_is_ignored(tmp_path):
    # Windows PowerShell adds a UTF-8 BOM when piping into programs; Notepad saves files with one.
    proc = run_entry("--no-dns", "--jsonl", "--eml", "-", stdin="﻿" + EML)
    reports = [json.loads(line) for line in proc.stdout.splitlines()]
    assert any((r.get("context") or {}).get("where") == "From header" for r in reports)
    proc = run_entry("--no-dns", "--jsonl", "--stdin", stdin="﻿https://pаypal.com\n")
    assert proc.returncode == 4 and json.loads(proc.stdout)["input"] == "https://pаypal.com"
    listing = tmp_path / "links.txt"
    listing.write_bytes(b"\xef\xbb\xbfhttps://xn--80ak6aa92e.com\n")
    assert run_entry("--no-dns", "-f", str(listing)).returncode == 4


def test_text_and_html_extraction(tmp_path, capsys):
    chat = tmp_path / "chat.txt"
    chat.write_text("[10:15] Bank: update KYC at sbi-kyc-update.in\n[10:16] Me: ok", encoding="utf-8")
    assert main(["--no-guard", "--no-dns", "--jsonl", "--text", str(chat)]) == 3
    assert json.loads(capsys.readouterr().out)["input"] == "sbi-kyc-update.in"
    page = tmp_path / "p.html"
    page.write_text("<p>nothing here</p>", encoding="utf-8")
    assert main(["--no-guard", "--no-dns", "--html", str(page)]) == 0  # no links is not an error


def test_list_resolvers(capsys):
    assert main(["--list-resolvers"]) == 0
    out = capsys.readouterr().out
    assert "94.140.14.140" in out and "security.cloudflare-dns.com" in out and "dns.google" in out


def test_first_use_creates_the_data_folder_before_the_sandbox(tmp_path):
    """A fresh install: no data folder yet, the database commands run under the guard."""
    import os

    home = tmp_path / "new" / "data"
    env = {**os.environ, "HGUARD_HOME": str(home), "HGUARD_POLICY": str(tmp_path / "no-policy.json")}

    def cli(*args):
        return subprocess.run([sys.executable, "-I", str(ENTRY), *args], capture_output=True, text=True,
                              encoding="utf-8", timeout=120, env=env)

    first = cli("block", "add", "blocked-on-first-use.com")
    assert first.returncode == 0, first.stderr
    assert home.is_dir()
    if os.name == "posix":
        assert home.stat().st_mode & 0o777 == 0o700  # owner only
    for args in (("db", "status"), ("block", "list"), ("allow", "add", "partner.example.com")):
        res = cli(*args)  # the folder now exists: nothing may try to create it or change it again
        assert res.returncode == 0, (args, res.stderr)
    res = cli("--no-dns", "--json", "https://www.blocked-on-first-use.com/login")
    assert res.returncode == 4 and "LIST_BLOCKED" in res.stdout, res.stderr
