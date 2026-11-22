"""Pipeline: parse -> character analysis -> brand matching -> DNS comparison -> score."""

from __future__ import annotations

import datetime as dt
import ipaddress
import re
import sqlite3
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from . import __version__
from .brands import BrandIndex, BrandMatch, host_to_unicode, normalize_domain
from .dns_check import DnsInvestigator
from .domains import known_suffix, split_domain
from .expand import SHORTENERS, Expansion, expand as expand_short_link, short_link, shortener_of
from .homograph import analyze_labels
from .models import Finding, InputError
from .scoring import VERDICT_LABELS, score
from .textsafe import defang_url
from .tls_peek import tls_peek
from .unicode_tools import ConfusableMap
from .unwrap import Hop, Unwrapped, ad_source, unwrap
from .urlsafe import _DOMAINISH_RE, parse_url

SCHEMA = "homograph-guard/1"
MAX_ECHO = 2048

_BRAND_TITLES = {
    "official": "Official domain of {brand}",
    "owned_tld": "{brand} is under a company-owned top-level domain",
    "homograph": "Homograph of {brand}",
    "lookalike": "Look-alike of {brand}",
    "tld_swap": "Same name as {brand} under another TLD",
    "typosquat": "Typosquat of {brand}",
    "subdomain_spoof": "{brand} used as a sub-domain decoy",
    "embedded": "Brand name of {brand} inside another domain",
}
_STRONG_KINDS = ("homograph", "lookalike", "subdomain_spoof", "typosquat")
_GENUINE_KINDS = ("official", "owned_tld")  # brand matches that are not impersonation
MESSAGE_MEDIA = ("email", "chat")  # context["medium"] of links found in messages (see _core: DNS privacy)

# Words phishing kits put next to a brand name ("paypal-secure-login", "sbi-kyc-update").
LURE_WORDS = frozenset(
    """
    login logon signin verify verification secure security update account accounts kyc wallet
    bonus reward rewards gift refund unlock suspend suspended alert confirm billing payment auth
    authenticate otp recovery recover password reset helpdesk banking netbanking claim prize
    invoice delivery tracking parcel customs restore validate activate activation webscr 2fa mfa
    sso session unblock reactivate
    """.split()
)
URL_SHORTENERS = SHORTENERS
# TLDs that consistently top abuse statistics (cheap or free registration).
ABUSED_TLDS = frozenset(
    """
    top xyz icu cyou buzz click rest cfd sbs bond lol quest gq ml cf tk ga zip mov country kim
    work men loan gdn monster beauty hair skin makeup autos boats yachts mom pics cam
    """.split()
)


@dataclass
class Options:
    tls_peek: bool = False
    timeout: float = 4.0
    cafile: str | None = None
    # Ask link-shortening services where their links lead (needs network checks; see expand.py).
    expand: bool = True
    # ... also for links found in emails and chats. Off by default: the service counts the lookup
    # like a click, which the person who made the short link can see.
    expand_in_messages: bool = False
    no_expand_reason: str | None = None  # why expand is off, when a setting or policy turned it off


def _brand_finding(m: BrandMatch, weighted: bool) -> Finding:
    return Finding(
        f"BRAND_{m.kind.upper()}", m.severity if weighted or m.kind == "official" else "info",
        m.weight if weighted else 0, _BRAND_TITLES[m.kind].format(brand=m.brand), m.detail,
        {"brand": m.brand, "kind": m.kind},
    )


class Analyzer:
    def __init__(self, brands: BrandIndex, cmap: ConfusableMap,
                 investigator: DnsInvestigator | None = None, options: Options | None = None,
                 threatdb=None, settings=None):
        self.brands = brands
        self.cmap = cmap
        self.dns = investigator
        self.options = options or Options()
        self.threatdb = threatdb  # ThreatDB on this device: feeds, allow/block lists, reports
        self.settings = settings

    def analyze(self, raw: str, context: dict | None = None, expansion: Expansion | None = None) -> dict:
        """Analyse one link (or email address).

        Links rewritten by security gateways or redirectors are decoded first and the
        real destination is analysed. ``context`` describes where an extracted link was
        found: ``{"text": shown text, "hidden": reason, "source": "anchor", "where": ...}``.
        Short links are expanded by asking the shortening service (network checks only), or
        ``expansion`` says where the link leads (found out by the browser extension).
        """
        chain = unwrap(raw) if isinstance(raw, str) else Unwrapped(raw, raw)
        in_message = (context or {}).get("medium") in MESSAGE_MEDIA
        short = self._short_link(chain.destination, in_message, expansion) if isinstance(raw, str) else None
        if short and short.destination:
            chain = _through_shortener(chain, short)
        report, findings, matches = self._core(chain.destination, dns_name="domain" if in_message else "host")
        report["input"] = raw[:MAX_ECHO] if isinstance(raw, str) else raw
        if short:
            report["short_link"] = short.to_dict()
            if not short.destination:
                findings = [_unexpanded(f, short) if f.code == "URL_SHORTENER" else f for f in findings]
        if chain.hops or chain.embedded:
            report["wrapped"] = chain.to_dict()
            findings += self._wrapper_findings(chain)
        if context:
            report["context"] = {k: str(v)[:500] for k, v in context.items() if v not in (None, "")}
            findings += self._link_context_findings(report["context"], report)
        if self.threatdb is not None and report["error"] is None:
            try:
                findings += self._db_findings(raw, chain, report)
            except sqlite3.DatabaseError:  # damaged or locked: the other checks still count
                report["lists"] = {"error": "the threat database on this device could not be read"}
                findings.append(Finding(
                    "DB_UNAVAILABLE", "info", 0, "The threat database on this device could not be read",
                    "The other checks ran as usual. The database is checked, and rebuilt with your lists if it "
                    "is damaged, at the next update.",
                ))
        if report["error"] is None:
            self._finish(report, findings, matches)
        return report

    def _short_link(self, target: str, in_message: bool, given: Expansion | None) -> Expansion | None:
        """Where a short link leads, or why that is not known. None when ``target`` is not a short link."""
        found = short_link(target)
        if not found:
            return None
        url, service = found
        if given is not None:
            return given if shortener_of(urlsplit(given.url).hostname) == service else None
        if not self.dns:
            why = "network checks are off, so the shortening service was not asked"
        elif not self.options.expand:
            why = self.options.no_expand_reason or "asking link-shortening services is switched off"
        elif in_message and not self.options.expand_in_messages:
            why = ("it is in a message, and asking the shortening service counts as a click that the person who "
                   "made the short link can see")
        else:
            return expand_short_link(url, self._addresses_of, timeout=self.options.timeout, cafile=self.options.cafile)
        return Expansion(url=url, service=service, reason=why)

    def _addresses_of(self, host: str) -> list[str]:
        """A shortening service's addresses, from the pinned unfiltered resolvers (never the system resolver)."""
        for r in self.dns.unfiltered:
            for rdtype in ("A", "AAAA"):
                ans = self.dns.client.query(r, host, rdtype)
                if ans.addresses:
                    return ans.addresses
        return []

    def _db_findings(self, raw: str, chain: Unwrapped, report: dict) -> list[Finding]:
        """Look the link up in the database on this device (feeds, your lists, your reports)."""
        from .feeds import CATEGORY_LABEL, FEEDS_BY_NAME

        org_allow = self.settings.org_allow if self.settings else ()
        org_block = self.settings.org_block if self.settings else ()
        host = (report.get("url") or {}).get("host_ascii")
        look = self.threatdb.lookup(host, chain.destination, org_allow, org_block)
        if chain.hops:  # the link as written can be listed too (a known-bad tracker or wrapper host)
            outer = self.threatdb.lookup(chain.hops[0].host, raw, org_allow, org_block)
            look.blocked = look.blocked or outer.blocked
            look.feeds += [h for h in outer.feeds if h.source not in {x.source for x in look.feeds}]
        report["lists"] = {
            "allowed": look.allowed.__dict__ if look.allowed else None,
            "blocked": look.blocked.__dict__ if look.blocked else None,
            "reported": bool(look.reported),
            "feeds": [h.source for h in look.feeds],
        }
        out: list[Finding] = []
        if look.blocked:
            org = look.blocked.source == "organisation"
            out.append(Finding(
                "LIST_BLOCKED", "critical", 80, "On your organisation's blocklist" if org else "On your blocklist",
                f"{look.blocked.value} was blocked {'by your organisation' if org else 'by you'}."
                + (f" Note: {look.blocked.note}" if look.blocked.note else ""),
                {"entry": look.blocked.value, "by": look.blocked.source},
            ))
        if look.reported:
            out.append(Finding("LIST_REPORTED", "critical", 80, "You reported this link as phishing",
                               f"Reported as {look.reported.value}.", {"entry": look.reported.value}))
        trusted = look.allowed is not None and not look.blocked and not look.reported
        weighted = False
        for hit in look.feeds[:6]:
            feed = FEEDS_BY_NAME.get(hit.source)
            title = feed.title if feed else hit.source
            category = feed.category if feed else "threat"
            harmful = category != "ads"
            weight = 70 if harmful and not weighted and not trusted else 0
            weighted = weighted or weight > 0
            out.append(Finding(
                "FEED_LISTED" if harmful else "FEED_ADS", "high" if weight else "info", weight,
                f"Listed by {title} ({CATEGORY_LABEL.get(category, category)})",
                f"The {'link' if hit.match == 'url' else 'domain'} {hit.value} is on this list, downloaded to this device "
                "and refreshed daily. Nothing was sent anywhere to check it.",
                {"feed": hit.source, "entry": hit.value, "category": category},
            ))
        if trusted:
            org = look.allowed.source == "organisation"
            out.append(Finding(
                "LIST_ALLOWED", "info", -100, "On your organisation's allowlist" if org else "On your allowlist",
                f"{look.allowed.value} is trusted {'by your organisation' if org else 'by you'}, so warnings are switched off for it.",
                {"entry": look.allowed.value, "by": look.allowed.source},
            ))
        return out

    def _finish(self, report: dict, findings: list[Finding], matches: list[BrandMatch]) -> None:
        total, verdict = score(findings)
        report["findings"] = [f.to_dict() for f in findings]
        report["score"] = total
        report["verdict"] = verdict
        report["verdict_label"] = VERDICT_LABELS[verdict]
        report["summary"] = _summary(verdict, findings, matches)
        hop = next((h for h in (report.get("wrapped") or {}).get("hops", []) if not h["trusted"]), None)
        if hop and verdict != "no_indicators":
            report["summary"] = f"{report['summary']} - via an unverified {hop['service']} link on {hop['host']}"
        short = report.get("short_link") or {}
        if short.get("destination"):
            dest = (report.get("url") or {}).get("host_unicode") or (report.get("url") or {}).get("host_ascii") \
                or short["destination"][:120]
            if verdict == "no_indicators":
                report["summary"] = f"Short link to {dest}: no look-alike characters or deception tricks found"
            elif not report["summary"].startswith("Short link"):
                report["summary"] = f"{report['summary']} - behind a {short['service']} short link to {dest}"
        listed = {f.code: f for f in findings}
        for code in ("LIST_BLOCKED", "LIST_REPORTED"):
            if code in listed:
                report["summary"] = listed[code].title
                break
        else:
            feed = next((f for f in findings if f.code == "FEED_LISTED" and f.weight > 0), None)
            if feed:
                report["summary"] = feed.title
            elif "LIST_ALLOWED" in listed and verdict == "no_indicators":
                report["summary"] = listed["LIST_ALLOWED"].title

    def _wrapper_findings(self, chain: Unwrapped) -> list[Finding]:
        out: list[Finding] = []
        short = [h for h in chain.hops if h.kind == "shortener"]
        if short:
            dest = urlsplit(chain.destination).hostname or chain.destination[:120]
            via = ", then ".join(h.vendor for h in short)
            out.append(Finding(
                "URL_SHORTENER_EXPANDED", "low", 10, f"Short link ({short[0].vendor}) leads to {dest}",
                f"{via} said where this short link leads; that destination was not opened, and it is what was "
                "checked here. Short links hide where they go, which phishing messages use to get past filters "
                "and readers.",
                {"services": [h.vendor for h in short], "destination": chain.destination[:500]},
            ))
        for h in chain.hops:
            if not h.trusted:
                out.append(Finding(
                    "WRAP_UNVERIFIED", "medium", 20, f"Looks like a {h.service} link on {h.host}",
                    f"{h.vendor} runs this service on each organisation's own server, so nothing proves "
                    f"{h.host} is yours. The browser goes to {h.host} first and only then, if it chooses, "
                    "to the decoded destination checked below.",
                    {"service": h.service, "host": h.host},
                ))
                out += self._side_findings(h.wrapper_url, f"Wrapper host {h.host}: ", "wrapper")
            elif h.kind == "gateway":
                out.append(Finding(
                    "WRAP_GATEWAY", "info", 0, f"Rewritten by {h.service}",
                    f"{h.vendor} wrapped this link for click-time scanning. The real destination was "
                    "decoded from it, and that is what was checked here."
                    if h.url or h.domain_only else
                    f"{h.vendor} wrapped this link and does not reveal where it leads.",
                    {"service": h.service, "host": h.host},
                ))
            elif h.kind == "redirect":
                out.append(Finding(
                    "WRAP_REDIRECT", "low", 10, f"Passes through {h.service}",
                    f"The link starts at {h.host} but forwards to another site. Phishers use trusted "
                    "redirect pages so that filters and readers only see the well-known name.",
                    {"service": h.service, "host": h.host},
                ))
            elif h.kind == "tracking":
                out.append(Finding(
                    "WRAP_TRACKING", "info", 0, f"Click tracking by {h.service}",
                    "Normal for newsletters. The destination was decoded and checked."
                    if h.url else "The tracker hides the destination; it cannot be decoded offline.",
                    {"service": h.service, "host": h.host},
                ))
            elif h.kind == "shortener":
                pass  # explained above
            elif h.kind == "advert":
                shown_on = ad_source(h)
                out.append(Finding(
                    "AD_REDIRECT", "medium", 25, f"Ad network redirect ({h.vendor})",
                    f"{h.host} belongs to the {h.vendor} ad network. Its ad server picks where this link leads "
                    "only when it is clicked, so the destination cannot be checked in advance. Pop-under and "
                    "redirect ads like this often lead to scam pages, fake prizes and unwanted downloads."
                    + (f" The link names {shown_on} as the page that showed the ad." if shown_on else ""),
                    {"network": h.vendor, "host": h.host, **({"shown_on": shown_on} if shown_on else {})},
                ))
        opaque = chain.opaque
        if opaque and opaque.kind == "advert":
            pass  # explained by AD_REDIRECT above
        elif opaque and opaque.domain_only:
            out.append(Finding(
                "WRAP_DOMAIN_ONLY", "info", 0, f"{opaque.service} reveals only the destination domain",
                f"The full address is hidden; the domain {opaque.domain_only} was checked.",
            ))
        elif opaque:
            out.append(Finding(
                "WRAP_OPAQUE", "info", 0, f"Destination hidden by {opaque.service}",
                "Only the wrapper could be checked. Open such links only if you expected them.",
            ))
        if chain.embedded:
            e = chain.embedded
            out.append(Finding(
                "URL_EMBEDDED_URL", "low", 10, f"Carries another address in '{e.param}='",
                f"The site at {e.host} may forward you to {e.url[:120]}. Open redirects like this are "
                "used to borrow a trusted name.",
                {"param": e.param, "embedded": e.url[:500]},
            ))
            out += self._side_findings(e.url, "Embedded address: ", "embedded")
        return out

    def _side_findings(self, url: str, prefix: str, part: str) -> list[Finding]:
        """Scored findings for a second address (wrapper host, embedded redirect target)."""
        _, found, _ = self._core(url, dns_name=None)  # offline checks only; the destination gets the DNS checks
        side = []
        for f in found:
            if f.weight <= 0 or f.code == "INPUT_DEFANGED":
                continue
            side.append(Finding(f.code, f.severity, f.weight, prefix + f.title, f.detail, {**f.evidence, "part": part}))
        return side

    def _link_context_findings(self, ctx: dict, report: dict) -> list[Finding]:
        out: list[Finding] = []
        url = report.get("url") or {}
        real = url.get("registrable") or url.get("host_ascii") or ""
        shown = ctx.get("text", "")
        written = {split_domain(h["host"]).registrable for h in (report.get("wrapped") or {}).get("hops", [])
                   if h.get("kind") == "shortener"}
        if shown and real and ctx.get("source") in ("anchor", "area"):
            fake = self._shown_domain(shown, real)
            if fake in written:
                fake = None  # the text shows the short link itself, which is what the link is
            if fake and split_domain(fake).sld == split_domain(real).sld:
                out.append(Finding(
                    "LINK_TEXT_MISMATCH", "low", 10, f"Link text shows {fake} but opens {real}",
                    f"Same name with a different ending. Companies often own both (amazon.com and "
                    f"amazon.in), but check that {real} really belongs to the same organisation.",
                    {"shown": shown[:300], "shown_domain": fake, "real_domain": real},
                ))
            elif fake:
                official = fake in self.brands.brands
                out.append(Finding(
                    "LINK_TEXT_MISMATCH", "high" if official else "medium", 40 if official else 30,
                    f"Link text shows {fake} but opens {real}",
                    f"The reader sees '{shown[:120]}', but clicking goes to {real}. Showing one address "
                    "and linking another is the most common phishing trick in email and chat.",
                    {"shown": shown[:300], "shown_domain": fake, "real_domain": real},
                ))
        if ctx.get("hidden") and ctx.get("medium") == "page":
            out.append(Finding(
                "LINK_HIDDEN", "info", 0, f"Hidden on the page ({ctx['hidden']})",
                "Websites hide links in menus and pop-ups all the time; it was checked anyway.",
                {"reason": ctx["hidden"]},
            ))
        elif ctx.get("hidden"):
            out.append(Finding(
                "LINK_HIDDEN", "low", 10, f"Hidden link ({ctx['hidden']})",
                "The reader cannot see this link. Hidden links are used to slip addresses past "
                "filters, to track opens, or to trigger automatic redirects.",
                {"reason": ctx["hidden"]},
            ))
        return out

    def _shown_domain(self, shown: str, real: str) -> str | None:
        """The domain a link's text presents as its address, when that is not the real domain.

        Only text that *is* an address counts ("https://www.paypal.com/signin", "PayPal.com"):
        a sentence that merely mentions a domain ("Elevated errors on GitHub.com") does not.
        """
        text = shown.strip().strip("<>()[]{}\"'“”‘’«»")
        if re.search(r"\s", text):
            if not re.match(r"(?i)^(?:https?://|www\.)", text):
                return None
            text = text.split()[0]
        for token in _DOMAINISH_RE.findall(text)[:5]:
            d = normalize_domain(token)
            if not d or not known_suffix(d):
                continue
            reg = split_domain(d).registrable
            if reg and reg != real and not real.endswith("." + reg):
                return reg
        return None

    def _core(self, raw: str, dns_name: str | None = "host") -> tuple[dict, list[Finding], list[BrandMatch]]:
        """``dns_name``: "host" looks up the full host name, "domain" only its registered domain
        (links in emails and chats), None makes no DNS query."""
        report: dict = {
            "schema": SCHEMA,
            "tool_version": __version__,
            "analyzed_at": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat(),
            "input": raw[:MAX_ECHO],
            "kind": None,
            "defanged": None,
            "url": None,
            "labels": [],
            "brand_matches": [],
            "findings": [],
            "dns": None,
            "tls": None,
            "score": 0,
            "verdict": "error",
            "verdict_label": VERDICT_LABELS["error"],
            "summary": "",
            "error": None,
        }
        try:
            p = parse_url(raw)
        except InputError as exc:
            report["error"] = str(exc)
            report["summary"] = f"Could not analyse: {exc}"
            return report, [], []

        findings: list[Finding] = list(p.findings)
        matches: list[BrandMatch] = []
        report["kind"] = p.kind
        url: dict = {
            "scheme": p.scheme, "host_unicode": p.host_unicode or None, "host_ascii": p.host_ascii,
            "port": p.port, "is_ip": p.is_ip, "idna_valid": p.idna_valid, "has_host": p.has_host,
            "userinfo": p.userinfo, "email_local": p.email_local, "display_name": p.display_name,
            "registrable": None, "suffix": None, "subdomains": [], "platform": None,
        }
        report["url"] = url
        if p.has_host and p.host_ascii:
            shown = p.host_ascii if p.kind != "email" else f"{p.email_local}@{p.host_ascii}"
            report["defanged"] = defang_url(p.scheme, p.host_ascii, p.rest[:200], p.port) \
                if p.kind == "url" else shown.replace(".", "[.]").replace("@", "[@]")

        if p.has_host and p.host_ascii and p.is_ip:
            if self.dns:
                report["dns"] = {"asn": self.dns.asn_lookup([p.host_ascii])}
        elif p.has_host and p.host_ascii:
            parts = split_domain(p.host_ascii)
            url.update(registrable=parts.registrable or None, suffix=parts.suffix or None,
                       subdomains=parts.subdomains, platform=parts.platform)
            labels, hg = analyze_labels(p.host_unicode, p.host_ascii, parts, self.cmap)
            report["labels"] = [lb.to_dict() for lb in labels]
            findings += hg
            matches = self.brands.match(parts, p.host_unicode)
            report["brand_matches"] = [m.to_dict() for m in matches]
            for i, m in enumerate(matches):
                findings.append(_brand_finding(m, weighted=(i == 0)))
            findings += self._decoy_findings(p, parts.registrable)
            findings += self._context_findings(p, parts, matches, findings)
            if parts.platform:
                findings.append(Finding(
                    "URL_FREE_HOSTING", "low", 10, f"Hosted on {parts.platform}",
                    "Anyone can publish on this platform in minutes; it is heavily used for phishing pages.",
                    {"platform": parts.platform},
                ))
            if len(parts.subdomains) >= 4:
                findings.append(Finding(
                    "URL_DEEP_SUBDOMAINS", "low", 10, f"{len(parts.subdomains)} levels of sub-domains",
                    "Long chains push the real domain off the edge of a phone's address bar.",
                ))
            if self.dns and dns_name:
                top = next((m.brand for m in matches if m.kind not in _GENUINE_KINDS), None)
                # In a message, look up only the registered domain: a per-recipient token in a
                # sub-domain (a8f3k2.track.example.com) would tell the sender the message was read.
                name = parts.registrable if dns_name == "domain" and p.kind == "url" and parts.registrable else p.host_ascii
                d = self.dns.investigate(name, parts.registrable or None, brand=top, want_mx=(p.kind == "email"))
                findings += d.findings
                report["dns"] = d.to_dict()
                if name != p.host_ascii:
                    report["dns"]["looked_up"] = name
                if self.options.tls_peek and p.kind == "url" and name == p.host_ascii:
                    report["tls"] = self._tls(p.host_ascii, parts.registrable, d.addresses, findings)
                elif self.options.tls_peek and p.kind == "url":
                    report["tls"] = {"error": "not done for a link in a message: connecting to it would tell the sender"}
            elif self.options.tls_peek:
                report["tls"] = {"error": "TLS peek needs DNS results (it never uses the system resolver)"}
        return report, findings, matches

    def _brand_in_domain_text(self, text: str) -> BrandMatch | None:
        d = normalize_domain(text)
        if not d:
            return None
        parts = split_domain(d)
        for m in self.brands.match(parts, host_to_unicode(d)):
            if m.kind == "official" or m.kind in _STRONG_KINDS:
                return m
        return None

    def _decoy_findings(self, p, registrable: str) -> list[Finding]:
        """Brand names used as decoration: before '@', in the sender name, in the mailbox name."""
        out: list[Finding] = []
        if p.userinfo:
            m = self._brand_in_domain_text(unquote(p.userinfo.split(":", 1)[0]))
            if m and m.brand != registrable:
                out.append(Finding(
                    "URL_USERINFO_BRAND", "high", 30, f"{m.brand} used as a decoy before '@'",
                    f"The link starts with something that reads like {m.brand}, but that part is "
                    f"only a username; the real destination is {registrable}.",
                    {"brand": m.brand},
                ))
        if p.kind == "email" and p.email_local:
            m = self._brand_in_domain_text(p.email_local)
            if m and m.brand != registrable:
                out.append(Finding(
                    "EMAIL_LOCAL_BRAND", "high", 25, f"Mailbox name imitates {m.brand}",
                    f"'{p.email_local[:60]}@' looks like {m.brand}, but the mail domain is {registrable}.",
                    {"brand": m.brand},
                ))
        if p.kind == "email" and p.display_name:
            hits = self.brands.names_in_text(p.display_name, exclude=registrable)
            if hits:
                out.append(Finding(
                    "EMAIL_DISPLAY_NAME_BRAND", "medium", 20, f"Sender name mentions {hits[0].sld}",
                    f"The display name invokes '{hits[0].sld}' but the message comes from {registrable}, "
                    f"not {hits[0].domain}.",
                    {"brands": [b.domain for b in hits[:5]]},
                ))
        return out

    def _context_findings(self, p, parts, matches: list[BrandMatch], so_far: list[Finding]) -> list[Finding]:
        out: list[Finding] = []
        owner = ".".join([*parts.subdomains, parts.sld])
        host_words = set(re.split(r"[^\w]+", host_to_unicode(owner).lower()))
        path_words = set(re.split(r"[^\w]+", unquote(p.rest).lower())) if p.kind == "url" else set()
        lures = sorted((host_words | path_words) & LURE_WORDS)
        branded = any(m.kind not in _GENUINE_KINDS for m in matches) or any(
            f.code in ("URL_USERINFO_BRAND", "EMAIL_LOCAL_BRAND", "EMAIL_DISPLAY_NAME_BRAND") for f in so_far)
        host_lures = sorted(host_words & LURE_WORDS)
        if lures and branded:
            out.append(Finding(
                "URL_LURE_WORDS", "medium", 20, "Brand name combined with credential-lure words",
                f"Words like {', '.join(lures[:4])} next to a brand are typical of phishing kits.",
                {"words": lures[:10]},
            ))
        elif len(host_lures) >= 2:
            out.append(Finding(
                "URL_LURE_WORDS", "low", 10, "Credential-lure words in the hostname",
                f"The hostname is built from {', '.join(host_lures[:4])}.", {"words": host_lures[:10]},
            ))
        if parts.registrable in URL_SHORTENERS:
            out.append(Finding(
                "URL_SHORTENER", "low", 15, f"Short link hides where it leads ({parts.registrable})",
                "Short links are a common way to get a phishing site past filters and readers. Network checks "
                "ask the shortening service where it leads, without opening the destination.",
                {"service": parts.registrable},
            ))
        tld = parts.suffix.rsplit(".", 1)[-1] if parts.suffix else ""
        if tld in ABUSED_TLDS:
            out.append(Finding(
                "URL_ABUSED_TLD", "low", 5, f".{tld} is among the most abused TLDs",
                "Not proof of anything, but phishing concentrates in cheap or free TLDs."
                + (" .zip/.mov names are also confused with file names." if tld in ("zip", "mov") else ""),
            ))
        if p.kind == "url" and not any(m.kind in _STRONG_KINDS for m in matches):
            in_path = self.brands.names_in_text(unquote(p.rest), exclude=parts.registrable)
            if in_path and (parts.platform or lures):
                out.append(Finding(
                    "URL_PATH_BRAND", "low", 10, f"'{in_path[0].sld}' in the path of an unrelated site",
                    f"The page path invokes {in_path[0].domain} on {parts.registrable}.",
                    {"brands": [b.domain for b in in_path[:5]]},
                ))
        confusion = next((f for f in so_far if f.code == "URL_PARSER_CONFUSION"), None)
        if confusion:
            m = self._brand_in_domain_text(confusion.evidence.get("naive_host", ""))
            if m:
                out.append(Finding(
                    "URL_PARSER_CONFUSION_BRAND", "high", 25, f"Filters would believe this is {m.brand}",
                    "The parser mismatch makes the link look like a trusted brand to scanners.",
                    {"brand": m.brand},
                ))
        return out

    def _tls(self, host: str, registrable: str, addresses: list[str], findings: list[Finding]) -> dict:
        ips = [a for a in addresses if ipaddress.ip_address(a).is_global]
        ips.sort(key=lambda a: ipaddress.ip_address(a).version)
        if not ips:
            return {"error": "no public address to connect to"}
        t = tls_peek(ips[0], host, timeout=self.options.timeout, cafile=self.options.cafile)
        if t.get("error") and not t.get("sha256"):
            findings.append(Finding("TLS_UNREACHABLE", "info", 0, "No TLS service reachable",
                                    t["error"], {"ip": ips[0]}))
            return t
        if t.get("verify_error"):
            findings.append(Finding(
                "TLS_INVALID", "medium", 15, "Certificate is not valid for this site",
                f"The server's certificate failed verification: {t['verify_error']}.",
            ))
        age = t.get("age_days")
        if age is not None and age <= 7:
            findings.append(Finding(
                "TLS_NEW_CERT", "low", 10, f"Certificate issued {age} days ago",
                "Brand-new certificates are common for freshly set-up phishing sites.",
            ))
        others: list[str] = []
        for san in (t.get("san") or [])[:100]:
            h = san.lower().removeprefix("*.").rstrip(".")
            if not h or h == host:
                continue
            parts = split_domain(h)
            if not parts.registrable or parts.registrable == registrable:
                continue
            strong = [m for m in self.brands.match(parts, host_to_unicode(h)) if m.kind in _STRONG_KINDS]
            if strong:
                others.append(f"{san} (imitates {strong[0].brand})")
        if others:
            t["san_lookalikes"] = others[:20]
            findings.append(Finding(
                "TLS_SAN_LOOKALIKES", "high", 20, "Certificate also covers other look-alike domains",
                "The same certificate lists more impersonation domains - a sign of a phishing kit.",
                {"domains": others[:20]},
            ))
        return t


def _through_shortener(chain: Unwrapped, short: Expansion) -> Unwrapped:
    """The chain with the short link's steps as hops, and its destination unwrapped in turn."""
    inner = unwrap(short.destination)
    steps = short.steps or [short.url]
    hops = list(chain.hops)
    for i, step in enumerate(steps):
        host = (urlsplit(step).hostname or "").lower()
        service = shortener_of(host) or host
        nxt = steps[i + 1] if i + 1 < len(steps) else short.destination
        hops.append(Hop(f"{service} short link", service, "shortener", host, step, nxt, trusted=True))
    return Unwrapped(chain.original, inner.destination, hops + inner.hops, inner.embedded)


def _unexpanded(f: Finding, short: Expansion) -> Finding:
    """URL_SHORTENER, saying why the destination is not known."""
    why = short.reason or "the shortening service did not say"
    return Finding(f.code, f.severity, f.weight, f.title,
                   f"Where it leads is not known: {why}. Short links are a common way to get a phishing site "
                   "past filters and readers; open it only if you expected it from someone you trust.",
                   {**f.evidence, "reason": why, "browser_needed": short.browser_needed})


def _summary(verdict: str, findings: list[Finding], matches: list[BrandMatch]) -> str:
    official = next((m for m in matches if m.kind == "official"), None)
    strong = next((m for m in matches if m.kind in _STRONG_KINDS), None)
    blocked = next((f for f in findings if f.code.startswith("DNS_BLOCKED")), None)
    advert = next((f for f in findings if f.code == "AD_REDIRECT"), None)
    if strong:
        return f"Imitates {strong.brand} ({strong.kind.replace('_', ' ')})"
    if advert and not (blocked and blocked.code == "DNS_BLOCKED_SECURITY"):
        return advert.title  # explains a block by AdGuard, which also filters ad networks
    if blocked:
        return blocked.title
    if official and verdict == "no_indicators":
        return f"Registrable domain is {official.brand} (protected brand, no homograph tricks)"
    scored = sorted((f for f in findings if f.weight > 0), key=lambda f: -f.weight)
    if verdict == "no_indicators":
        extra = f" ({len(scored)} minor note{'s' if len(scored) != 1 else ''})" if scored else ""
        return "No look-alike characters or deception tricks found" + extra
    if official and verdict == "caution":
        return f"{scored[0].title} (domain itself is {official.brand})" if scored else official.brand
    return scored[0].title if scored else "Deception indicators found"
