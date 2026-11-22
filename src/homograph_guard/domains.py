"""Registrable-domain splitting (public suffix list) and hosting-platform hints."""

from __future__ import annotations

from dataclasses import dataclass, field

try:  # bundled snapshot of the Public Suffix List, no network access
    from publicsuffixlist import PublicSuffixList

    _PSL = PublicSuffixList(only_icann=False, accept_unknown=True)
    _PSL_STRICT = PublicSuffixList(only_icann=False, accept_unknown=False)
except Exception:  # pragma: no cover - optional dependency
    _PSL = _PSL_STRICT = None

# Fallback when publicsuffixlist is not installed: common multi-label suffixes.
_FALLBACK_SUFFIXES = frozenset(
    """
    co.uk org.uk ac.uk gov.uk ltd.uk plc.uk me.uk net.uk sch.uk nhs.uk
    co.in net.in org.in gov.in ac.in edu.in res.in nic.in firm.in gen.in ind.in
    co.jp ne.jp or.jp ac.jp go.jp com.au net.au org.au edu.au gov.au co.nz org.nz govt.nz
    com.br net.br org.br gov.br com.cn net.cn org.cn gov.cn com.tw com.hk com.sg com.my
    co.za com.mx com.ar com.tr co.kr or.kr com.ua co.il com.sa com.eg com.pk com.bd com.np
    com.lk com.ng co.ke com.ph co.id or.id com.vn com.co com.pe com.ve com.ec com.uy
    """.split()
)

# Free hosting, tunnelling and site-builder platforms heavily abused for phishing.
PLATFORM_SUFFIXES = frozenset(
    """
    github.io gitlab.io pages.dev workers.dev r2.dev netlify.app vercel.app herokuapp.com
    firebaseapp.com web.app appspot.com blogspot.com azurewebsites.net cloudfront.net
    s3.amazonaws.com glitch.me ngrok.io ngrok.app ngrok-free.app ngrok-free.dev
    trycloudflare.com 000webhostapp.com duckdns.org onrender.com repl.co replit.app
    replit.dev surge.sh fly.dev railway.app deno.dev webflow.io framer.app framer.website
    godaddysites.com square.site myshopify.com wixsite.com weebly.com weeblysite.com
    translate.goog firebaseio.com carrd.co notion.site sites.google.com storage.googleapis.com
    blob.core.windows.net web.core.windows.net ipfs.io dweb.link serveo.net loca.lt
    """.split()
)


@dataclass
class DomainParts:
    host: str
    registrable: str  # e.g. example.co.uk ("" if the host is itself a public suffix)
    sld: str  # label directly left of the suffix, e.g. "example"
    suffix: str  # e.g. "co.uk"
    subdomains: list[str] = field(default_factory=list)
    platform: str | None = None  # matched abuse-prone hosting platform, if any


def _fallback_suffix(labels: list[str]) -> str:
    for n in (3, 2):
        if len(labels) > n and ".".join(labels[-n:]) in (_FALLBACK_SUFFIXES | PLATFORM_SUFFIXES):
            return ".".join(labels[-n:])
    return labels[-1] if labels else ""


def split_domain(host_ascii: str) -> DomainParts:
    host = host_ascii.lower().rstrip(".")
    labels = [lb for lb in host.split(".") if lb]
    suffix = ""
    if _PSL is not None:
        try:
            suffix = _PSL.publicsuffix(host) or ""
        except Exception:  # pragma: no cover - defensive
            suffix = ""
    if not suffix:
        suffix = _fallback_suffix(labels)
    suffix_labels = suffix.split(".") if suffix else []
    rest = labels[: len(labels) - len(suffix_labels)] if suffix_labels else labels
    if not rest:
        return DomainParts(host, "", "", suffix, [], _platform(host))
    sld = rest[-1]
    registrable = ".".join([sld, *suffix_labels])
    return DomainParts(host, registrable, sld, suffix, rest[:-1], _platform(host))


_COMMON_TLDS = frozenset("com net org info biz io co app dev xyz top online site shop in uk us de ru cn".split())


def known_suffix(host: str) -> bool:
    """True when ``host`` ends in a real public suffix and has a label left of it."""
    h = host.lower().rstrip(".")
    if "." not in h:
        return False
    if not h.isascii():
        try:
            import idna

            h = idna.encode(h, uts46=True, transitional=False, std3_rules=False).decode("ascii")
        except (UnicodeError, ValueError):  # not a valid IDN (idna.IDNAError is a UnicodeError)
            last = h.rsplit(".", 1)[-1]
            return last.isascii() and last in _COMMON_TLDS
    if _PSL_STRICT is None:
        return h.rsplit(".", 1)[-1] in _COMMON_TLDS
    try:
        suffix = _PSL_STRICT.publicsuffix(h)
    except Exception:  # noqa: BLE001 - defensive
        return False
    return bool(suffix) and suffix != h


def _platform(host: str) -> str | None:
    for plat in PLATFORM_SUFFIXES:
        if host == plat or host.endswith("." + plat):
            return plat
    return None
