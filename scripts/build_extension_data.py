"""Export the Python package's detection data for the browser extension.

    python scripts/build_extension_data.py           # writes extension/lib/data.js
    python scripts/build_extension_data.py --check   # exit 1 if data.js is out of date (CI)

The extension re-implements the analysis in JavaScript, but every table it relies on
(confusables, brand skeletons, public suffixes, lure words, resolver catalogue, ...)
comes from here, so both tools flag the same things.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import publicsuffixlist  # noqa: E402

from homograph_guard import __version__, analyzer, brands, dns_check, dns_resolvers, domains, homograph  # noqa: E402
from homograph_guard import unicode_tools, unwrap, urlsafe  # noqa: E402
from homograph_guard.dns_transport import BLOCK_EDE_CODES  # noqa: E402
from homograph_guard.textsafe import BIDI_CONTROLS, INVISIBLE  # noqa: E402

OUT = ROOT / "extension" / "lib" / "data.js"
VECTORS = ROOT / "tests" / "vectors" / "analysis.json"

# Offline analysis cases both implementations must agree on (verdict, score and finding codes).
CASES: list[tuple[str, dict | None]] = [
    ("https://pаypal.com/login", None),
    ("https://xn--80ak6aa92e.com", None),
    ("https://xn--pypal-4ve.com", None),
    ("https://ɡoogle.com", None),
    ("https://faceboök.com", None),
    ("https://paypa1.com", None),
    ("https://rnicrosoft.com", None),
    ("https://paypall.com", None),
    ("https://paypal.com.account-verify.info/login", None),
    ("https://sbi-kyc-update.in", None),
    ("https://www.paypal.com@evil.example", None),
    ("http://evil.com\\@google.com", None),
    ("http://%67oogle.com", None),
    ("https://ｇｏｏｇｌｅ．com", None),
    ("http://0x7f.1", None),
    ("http://3232235777", None),
    ("http://192.168.1.1/admin", None),
    ("https://[::1]/", None),
    ("javascript:alert(1)", None),
    ("ms-msdt:/id PCWDiagnostic /skip force", None),
    ("file://attacker.example/share/doc.lnk", None),
    ("PayPal <service@paypa1.com>", None),
    ("service@paypal.com <x@mail-paypal.net>", None),
    ("hxxps://evil[.]com/login", None),
    ("https://pay​pal.com", None),
    ("https://example.com/‮exe.pdf", None),
    ("https://accounts.google.com∕login.evil.example", None),
    ("https://google.com", None),
    ("https://www.paypal.com/signin", None),
    ("https://my-site.github.io/paypal/login", None),
    ("https://bit.ly/abc", None),
    ("https://login-secure-verify.top/", None),
    ("https://аррӏе.рф", None),
    ("https://example.com:8443/x", None),
    ("https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fp%D0%B0ypal.com%2Flogin&data=05", None),
    ("https://paypa1-login.example/fmlurlsvc/?url=https%3A%2F%2Fwww.paypal.com%2F", None),
    ("https://protect-eu.mimecast.com/s/AbCdEfGhIjKl?domain=micr0soft-support.com", None),
    ("https://news.example.org/out?url=https%3A%2F%2Fpaypal-secure-login.top%2F", None),
    ("https://abcdefgh.r.us-east-1.awstrack.me/L0/https:%2F%2Fwww.amaz0n-billing.com%2Faccount/1/x", None),
    ("https://www.google.com/url?q=https://paypa1.com/&sa=D", None),
    ("https://paypa1.com/login", {"source": "anchor", "text": "https://www.paypal.com/signin", "where": "HTML body"}),
    ("https://example.net/", {"source": "anchor", "text": "Read invoice.pdf", "where": "HTML body"}),
    ("https://example.net/t", {"source": "anchor", "text": ".", "hidden": "display:none", "where": "HTML body"}),
    ("https://example.net/", {"source": "anchor", "text": "support.example.net"}),
    ("mailto:help@paypa1.com", {"source": "anchor", "text": "help@paypal.com"}),
    # False positives found by testing on real sites in Edge and Chrome
    ("https://www.githubstatus.com/incidents/x", {"source": "anchor", "text": "Elevated errors on GitHub.com"}),
    ("https://example-shop.com/", {"source": "anchor", "text": "https://example-shop.in/"}),
    ("https://status.cloud.microsoft/", None),
    ("https://github.blog/changelog/", {"source": "anchor", "text": "Changelog", "hidden": "display:none", "medium": "page"}),
    ("https://evil.example/", {"source": "anchor", "text": "https://www.paypal.com/signin to keep your account"}),
    ("https://evil.example/", {"source": "anchor", "text": "“PayPal.com”"}),
    # Pop-under ad redirect (the destination is picked by the ad server at click time)
    ("https://s.pemsrv.com/v1/link.php?cat=&idzone=5974550&type=8&p=https%3A%2F%2Ftheblank.net%2F&sub=&block=1&el="
     "&tags=&scr_info=aW5saW5lfHBvcE1hZ2ljfDEx&gdpr=0&cb=596590530&cookieconsent=true", None),
    ("https://serve.popads.net/s?cid=12", {"source": "anchor", "text": "Download", "medium": "page"}),
    ("https://www.popads.net/", None),
    # Short links: where they lead is not known offline, so they are a caution
    ("https://shorturl.at/zNYEi", None),
    ("shorturl.at/zNYEi", None),
    ("https://bit.ly/3abc", {"source": "anchor", "text": "https://bit.ly/3abc", "medium": "email"}),
    ("https://bit.ly/3abc", {"source": "anchor", "text": "www.paypal.com", "medium": "email"}),
]


def build_vectors() -> str:
    cmap = unicode_tools.ConfusableMap.load()
    an = analyzer.Analyzer(brands.BrandIndex(brands.default_domains(), cmap), cmap)
    out = []
    for raw, ctx in CASES:
        rep = an.analyze(raw, ctx)
        out.append({"input": raw, "context": ctx, "verdict": rep["verdict"], "score": rep["score"],
                    "codes": sorted(f["code"] for f in rep["findings"]),
                    "host_ascii": (rep.get("url") or {}).get("host_ascii")})
    return json.dumps(out, ensure_ascii=True, indent=1) + "\n"


def _ranges(codepoints: frozenset[int] | set[int]) -> list[list[int]]:
    out: list[list[int]] = []
    for cp in sorted(codepoints):
        if out and out[-1][1] == cp - 1:
            out[-1][1] = cp
        else:
            out.append([cp, cp])
    return out


def _psl_rules() -> list[str]:
    path = Path(publicsuffixlist.__file__).with_name("public_suffix_list.dat")
    rules = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("//"):
            rules.append(line.split()[0].lower())
    return rules


def build() -> str:
    cmap = unicode_tools.ConfusableMap.load()
    index = brands.BrandIndex(brands.default_domains(), cmap)
    data = {
        "VERSION": __version__,
        "CONFUSABLES": dict(sorted(cmap._table.items())),
        "LOOSE_EXTRA": unicode_tools._LOOSE_EXTRA,
        "LATIN_CONFUSABLE_SCRIPTS": sorted(unicode_tools.LATIN_CONFUSABLE_SCRIPTS),
        "NATIVE_TLDS": {k: sorted(v) for k, v in homograph.NATIVE_TLDS.items()},
        "BRANDS": [[b.domain, b.sld, b.suffix, b.sld_strict, b.sld_loose, b.sld_collapse, b.full_collapse]
                   for b in index.brands.values()],
        "GENERIC_WORD_BRANDS": sorted(brands.GENERIC_WORD_BRANDS),
        "BRAND_TLDS": sorted(brands.BRAND_TLDS),
        "LURE_WORDS": sorted(analyzer.LURE_WORDS),
        "URL_SHORTENERS": sorted(analyzer.URL_SHORTENERS),
        "ABUSED_TLDS": sorted(analyzer.ABUSED_TLDS),
        "PLATFORM_SUFFIXES": sorted(domains.PLATFORM_SUFFIXES),
        "DANGEROUS_SCHEMES": sorted(urlsafe.DANGEROUS_SCHEMES),
        "APP_HANDLER_SCHEMES": sorted(urlsafe.APP_HANDLER_SCHEMES),
        "INFO_SCHEMES": sorted(urlsafe.INFO_SCHEMES),
        "DEFAULT_PORTS": urlsafe.DEFAULT_PORTS,
        "FAKE_SLASHES": "".join(sorted(urlsafe.FAKE_SLASHES)),
        "FAKE_DOTS": "".join(sorted(urlsafe.FAKE_DOTS)),
        "FAKE_HYPHENS": "".join(sorted(urlsafe.FAKE_HYPHENS)),
        "BIDI_CONTROLS": sorted(BIDI_CONTROLS),
        "INVISIBLE_RANGES": _ranges(INVISIBLE),
        "SHARED_INFRA_ASNS": {str(k): v for k, v in dns_check.SHARED_INFRA_ASNS.items()},
        "GENERIC_NS_PROVIDERS": sorted(dns_check.GENERIC_NS_PROVIDERS),
        "BRAND_PROTECTION_NS": dns_check.BRAND_PROTECTION_NS,
        "BLOCK_EDE_CODES": {str(k): v for k, v in BLOCK_EDE_CODES.items()},
        "AD_NETWORKS": {k: list(v) for k, v in unwrap.AD_NETWORKS.items()},
        "REGIONS": dns_check.REGIONS,
        "ECS_RESOLVER": dns_check.ECS_RESOLVER,
        "RESOLVERS": [
            {"key": r.key, "provider": r.provider, "name": r.name, "filtering": r.filtering,
             "url": f"https://{r.tls_host}{r.doh_path}", "peer": r.peer, "blocks": r.blocks,
             "blockNetworks": list(r.block_networks), "securityOnly": r.security_only}
            for r in (dns_resolvers.CATALOG[k] for k in dns_resolvers.DEFAULT_RESOLVERS)
        ],
        "PSL": "\n".join(_psl_rules()),
    }
    lines = [
        "// Generated by scripts/build_extension_data.py from the homograph-guard Python package.",
        "// Do not edit by hand: run `python scripts/build_extension_data.py` instead.",
        "/* eslint-disable */",
    ]
    for key, value in data.items():
        # ensure_ascii keeps look-alike and invisible characters as visible \\u escapes in the source
        lines.append(f"export const {key} = {json.dumps(value, ensure_ascii=True, separators=(',', ':'))};")
    return "\n".join(lines) + "\n"


def main() -> int:
    outputs = {OUT: build(), VECTORS: build_vectors()}
    if "--check" in sys.argv:
        stale = [p for p, text in outputs.items() if (p.read_text(encoding="utf-8") if p.exists() else "") != text]
        for p in stale:
            print(f"{p.relative_to(ROOT)} is out of date: run python scripts/build_extension_data.py")
        if not stale:
            print("extension data and analysis vectors are up to date")
        return 1 if stale else 0
    for path, text in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {path.relative_to(ROOT)} ({len(text) // 1024} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
