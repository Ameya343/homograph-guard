"""Defensive URL / email-address parsing that mirrors what a *browser* would do.

Attackers exploit differences between URL parsers (``evil.com\\@good.com``,
``http://0x7f.1``, ``https://www.paypal.com@evil.example``). This module
re-implements the parts of the WHATWG URL Standard that decide which host a
browser would really contact, and records every trick it had to undo.

Email addresses (``Name <user@domain>``, ``mailto:``) are accepted too: the
domain part goes through the same homograph analysis.

Nothing here performs I/O: the input is only ever treated as data.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit

import idna

from .models import Finding, InputError
from .textsafe import BIDI_CONTROLS, INVISIBLE

MAX_URL_LENGTH = 8192
MAX_HOST_LENGTH = 1024

DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21}
SPECIAL_SCHEMES = frozenset(DEFAULT_PORTS)
DANGEROUS_SCHEMES = frozenset({"javascript", "data", "vbscript", "blob", "filesystem"})
# Protocol handlers that launch local applications - classic one-click vectors
# (ms-msdt was "Follina" CVE-2022-30190; search-ms and ms-appinstaller are abused for malware drops).
APP_HANDLER_SCHEMES = frozenset(
    {
        "ms-msdt", "search-ms", "search", "ms-search", "ms-officecmd", "ms-word", "ms-excel",
        "ms-powerpoint", "ms-visio", "ms-access", "ms-publisher", "ms-project", "ms-appinstaller",
        "ms-settings", "ms-cxh", "ms-cxh-full", "ms-officeapp", "mk", "its", "ms-its", "hcp",
        "shell", "vbefile", "jar", "intent", "itms-services", "steam", "ldap", "ldaps", "smb",
        "afp", "nfs", "telnet", "ssh", "vnc", "rdp", "callto", "skype", "zoommtg", "tg",
        "chrome", "edge", "microsoft-edge", "res", "jnlp", "jnlps",
    }
)
INFO_SCHEMES = frozenset({"tel", "sms", "about", "urn", "news", "geo", "magnet"})

_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]{0,31}):")
_EMAIL_RE = re.compile(r"^(?:(?P<name>[^<>]{0,200}?)\s*<)?(?P<local>[^\s<>@/]{1,200})@(?P<domain>[^\s<>@/?#]{1,300})>?$")
_DOMAINISH_RE = re.compile(r"[a-z0-9¡-￿-]+(?:\.[a-z0-9¡-￿-]+)+", re.IGNORECASE)
_UNICODE_DOTS = str.maketrans({"。": ".", "．": ".", "｡": "."})
_FORBIDDEN_HOST_CHARS = set("\x00\t\n\r #/:<>?@[\\]^|%") | {chr(c) for c in range(0x20)} | {"\x7f"}

FAKE_SLASHES = frozenset("∕⁄⧸╱／ノ丿⼃")
FAKE_DOTS = frozenset("·։・܁܂꘎․٠۰･‧")
FAKE_HYPHENS = frozenset("ー一‐‑‒–—―−⁃˗ᅳㅡ⸺")


@dataclass
class ParsedURL:
    input: str
    kind: str = "url"  # url | email | other
    scheme: str = ""
    userinfo: str | None = None
    host_input: str = ""  # host as written (after percent-decoding), lower-cased
    host_unicode: str = ""  # canonical Unicode form (what a browser could display)
    host_ascii: str | None = None  # A-label / punycode form actually sent to DNS
    port: int | None = None
    rest: str = ""  # path + query + fragment
    is_ip: bool = False
    ip_version: int | None = None
    idna_valid: bool = True
    has_host: bool = True
    email_local: str | None = None
    display_name: str | None = None
    findings: list[Finding] = field(default_factory=list)

    def add(self, *args, **kwargs) -> None:
        self.findings.append(Finding(*args, **kwargs))


def _cp(ch: str) -> str:
    return f"U+{ord(ch):04X}"


def _describe(ch: str) -> str:
    return f"{_cp(ch)} {unicodedata.name(ch, 'UNNAMED')}"


# --------------------------------------------------------------------------- hidden chars
def _scan_hidden(raw: str, p: ParsedURL) -> None:
    bidi = [(i, _describe(c)) for i, c in enumerate(raw) if ord(c) in BIDI_CONTROLS]
    if bidi:
        p.add(
            "URL_BIDI", "high", 40, "Bidirectional control characters",
            "These can visually reverse or reorder parts of the link (the 'RLO' trick), "
            "so what you read is not what the browser opens.",
            {"characters": bidi[:20]},
        )
    hidden = [
        (i, _describe(c)) for i, c in enumerate(raw)
        if ord(c) in INVISIBLE and ord(c) not in BIDI_CONTROLS
    ]
    if hidden:
        p.add(
            "URL_INVISIBLE", "high", 30, "Invisible characters",
            "Zero-width or invisible characters are hidden from the reader but change the "
            "string; they are used to dodge filters and to fake well-known names.",
            {"characters": hidden[:20]},
        )
    controls = [
        (i, _cp(c)) for i, c in enumerate(raw)
        if unicodedata.category(c) == "Cc" and c not in "\t\n\r"
    ]
    if controls:
        p.add(
            "URL_CONTROL_CHARS", "medium", 20, "Control characters",
            "Raw control characters have no place in a link and can corrupt logs or terminals.",
            {"characters": controls[:20]},
        )


# --------------------------------------------------------------------------- IPv4 (WHATWG)
def _parse_ipv4_whatwg(host: str) -> ipaddress.IPv4Address | None:
    """WHATWG IPv4 parser: accepts 0x7f.1, 017700000001, 2130706433, ..."""
    parts = host.split(".")
    if len(parts) > 1 and parts[-1] == "":
        parts = parts[:-1]
    if not parts or len(parts) > 4:
        return None
    nums: list[int] = []
    for part in parts:
        if part == "":
            return None
        try:
            if part[:2].lower() == "0x":
                n = int(part[2:] or "0", 16)
            elif len(part) > 1 and part[0] == "0":
                n = int(part[1:], 8)
            elif part.isdigit():
                n = int(part, 10)
            else:
                return None
        except ValueError:
            return None
        nums.append(n)
    if any(n > 255 for n in nums[:-1]):
        return None
    if nums[-1] >= 256 ** (5 - len(nums)):
        return None
    value = nums[-1]
    for i, n in enumerate(nums[:-1]):
        value += n * 256 ** (3 - i)
    return ipaddress.IPv4Address(value)


def _ends_in_number(host: str) -> bool:
    parts = host.split(".")
    if len(parts) > 1 and parts[-1] == "":
        parts = parts[:-1]
    last = parts[-1] if parts else ""
    if last.isdigit():
        return True
    return last[:2].lower() == "0x" and all(c in "0123456789abcdefABCDEF" for c in last[2:])


# --------------------------------------------------------------------------- IDNA
def _uts46_changes(host: str) -> list[str]:
    """Characters a browser would silently rewrite or drop (fullwidth, soft hyphen, ...)."""
    changes: list[str] = []
    for ch in dict.fromkeys(host):
        if ch.isascii():
            continue
        try:
            mapped = idna.uts46_remap(ch, std3_rules=False, transitional=False)
        except (idna.IDNAError, UnicodeError, ValueError):
            continue
        if mapped != ch:
            shown = mapped if mapped else "(removed)"
            changes.append(f"{_describe(ch)} -> {shown!r}")
    return changes


def _idna_process(host: str, p: ParsedURL) -> None:
    host = host.rstrip(".") or host
    if host.isascii():
        p.host_ascii = host
        ulabels: list[str] = []
        bad: list[str] = []
        for label in host.split("."):
            if label.startswith("xn--"):
                try:
                    ulabels.append(idna.decode(label))
                except (idna.IDNAError, UnicodeError, ValueError):
                    try:
                        ulabels.append(label[4:].encode("ascii").decode("punycode"))
                    except (UnicodeError, ValueError):
                        ulabels.append(label)
                    bad.append(label)
            else:
                ulabels.append(label)
        p.host_unicode = ".".join(ulabels)
        if bad:
            p.idna_valid = False
            p.add(
                "IDN_INVALID", "medium", 20, "Malformed internationalized label",
                "A punycode (xn--) label is not valid IDNA2008. Browsers may refuse it or show "
                "it raw; legitimate sites do not publish such names.",
                {"labels": bad},
            )
        return

    try:
        ascii_host = idna.encode(host, uts46=True, transitional=False, std3_rules=False).decode("ascii")
        p.host_ascii = ascii_host
        p.host_unicode = idna.decode(ascii_host)
    except (idna.IDNAError, UnicodeError, ValueError) as exc:
        p.idna_valid = False
        try:
            mapped = idna.uts46_remap(host, std3_rules=False, transitional=False)
        except (idna.IDNAError, UnicodeError, ValueError):
            mapped = unicodedata.normalize("NFKC", host).lower()
        labels = re.split(r"[.。．｡]", mapped)
        alabels = []
        for label in labels:
            if label.isascii():
                alabels.append(label)
            else:
                try:
                    alabels.append("xn--" + label.encode("punycode").decode("ascii"))
                except (UnicodeError, ValueError):
                    alabels.append(label)
        p.host_unicode = ".".join(labels)
        p.host_ascii = ".".join(alabels)
        p.add(
            "IDN_INVALID", "medium", 20, "Hostname is not a valid internationalized domain",
            "Modern browsers would refuse this host, but mail clients, chat apps and older "
            "software may still display it convincingly. Reason: " + str(exc)[:200],
            {"idna_error": str(exc)[:200]},
        )

    changes = _uts46_changes(host)
    if changes:
        p.add(
            "IDN_NORMALIZED", "medium", 25, "Host uses characters a browser silently rewrites",
            "Full-width letters, soft hyphens, zero-width spaces and similar characters are "
            "mapped or dropped before the lookup. The text you see is not the domain you get.",
            {"rewrites": changes[:20], "effective_host": p.host_unicode},
        )


def _fake_separators(host: str, p: ParsedURL) -> None:
    slashes = sorted({_describe(c) for c in host if c in FAKE_SLASHES})
    dots = sorted({_describe(c) for c in host if c in FAKE_DOTS})
    hyphens = sorted({_describe(c) for c in host if c in FAKE_HYPHENS})
    if slashes:
        p.add(
            "IDN_FAKE_SLASH", "high", 40, "Look-alike slash inside the hostname",
            "A character that looks like '/' makes the host read like a trusted site followed "
            "by a path, e.g. 'accounts.google.com∕login.evil.example'.",
            {"characters": slashes},
        )
    if dots:
        p.add(
            "IDN_FAKE_DOT", "high", 35, "Look-alike dot inside the hostname",
            "A character that looks like '.' fakes a domain boundary the browser does not see.",
            {"characters": dots},
        )
    if hyphens:
        p.add(
            "IDN_FAKE_HYPHEN", "medium", 20, "Look-alike hyphen inside the hostname",
            "Characters such as 'ー' (Katakana) or '一' (CJK) pass for '-' next to Latin text.",
            {"characters": hyphens},
        )


def _set_ip(p: ParsedURL, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    p.is_ip = True
    p.ip_version = ip.version
    p.host_ascii = p.host_unicode = p.host_input = str(ip)
    p.add(
        "URL_IP_HOST", "medium", 15, "Raw IP address instead of a domain",
        "Real services almost never send links to bare IP addresses.",
        {"ip": str(ip)},
    )
    if not ip.is_global:
        p.add(
            "URL_INTERNAL_IP", "medium", 25, "Link points at a private or local address",
            f"{ip} is not on the public internet. A link like this can attack your router, "
            "localhost services or intranet apps (CSRF / one-click exploit).",
            {"ip": str(ip)},
        )


# --------------------------------------------------------------------------- host handling
def _analyse_host(host: str, p: ParsedURL) -> None:
    """Shared host pipeline for URLs and email domains."""
    if not host:
        raise InputError("no host found")
    if len(host) > MAX_HOST_LENGTH:
        raise InputError("host is unreasonably long")

    if "%" in host:
        try:
            decoded = unquote(host, encoding="utf-8", errors="strict")
        except UnicodeDecodeError:
            decoded = host
        if decoded != host:
            p.add(
                "URL_PERCENT_HOST", "medium", 25, "Percent-encoded hostname",
                f"The host is written in %-escapes; a browser decodes it to '{decoded[:120]}'. "
                "Legitimate links never need this.",
                {"decoded": decoded[:200]},
            )
            host = decoded
            before = {f.code for f in p.findings}
            hidden = ParsedURL(input=decoded)
            _scan_hidden(decoded, hidden)
            p.findings += [f for f in hidden.findings if f.code not in before]

    if host.startswith("[") and host.endswith("]"):
        try:
            ip6 = ipaddress.IPv6Address(host[1:-1])
        except ValueError as exc:
            raise InputError(f"invalid IPv6 address: {exc}") from None
        _set_ip(p, ip6)
        return

    host_lower = host.lower().translate(_UNICODE_DOTS)
    p.host_input = host_lower
    _fake_separators(host_lower, p)

    forbidden = sorted({c for c in host_lower if c in _FORBIDDEN_HOST_CHARS})
    if forbidden:
        p.idna_valid = False
        p.add(
            "URL_FORBIDDEN_HOST_CHARS", "medium", 20, "Characters a browser forbids in a hostname",
            "Browsers reject this host, but it may still be shown convincingly in messages.",
            {"characters": [_cp(c) for c in forbidden]},
        )

    if host_lower.isascii() and _ends_in_number(host_lower):
        ip4 = _parse_ipv4_whatwg(host_lower)
        if ip4 is None:
            raise InputError("host ends in a number but is not a valid IPv4 address")
        if host_lower.rstrip(".") != str(ip4):
            p.add(
                "URL_OBFUSCATED_IP", "high", 35, "Obfuscated IP address",
                f"'{host_lower[:60]}' is really the IPv4 address {ip4}. Hex, octal and integer "
                "forms exist only to hide where the link goes.",
                {"ip": str(ip4)},
            )
        _set_ip(p, ip4)
        return

    _idna_process(host_lower, p)
    if p.host_ascii and len(p.host_ascii) > 253:
        p.idna_valid = False


def _parse_email(s: str, p: ParsedURL) -> ParsedURL:
    m = _EMAIL_RE.match(s)
    if not m:
        raise InputError("could not find an email address")
    p.kind = "email"
    p.scheme = "mailto"
    p.email_local = m.group("local")
    name = (m.group("name") or "").strip().strip('"').strip()
    p.display_name = name or None
    domain = m.group("domain")
    _analyse_host(domain, p)
    local = p.email_local or ""
    if _DOMAINISH_RE.fullmatch(local) and any(c.isalpha() for c in local.rsplit(".", 1)[-1]):
        p.add(
            "EMAIL_LOCAL_LOOKS_LIKE_DOMAIN", "medium", 25, "The part before '@' looks like a domain",
            f"'{local[:80]}@' is only the mailbox name; the address belongs to "
            f"'{(p.host_unicode or domain)[:80]}'.",
            {"local_part": local[:200]},
        )
    if name:
        shown = _DOMAINISH_RE.findall(name)
        real = (p.host_unicode or "").lower()
        fakes = [d for d in shown if d.lower().rstrip(".") != real and not real.endswith("." + d.lower())]
        if fakes:
            p.add(
                "EMAIL_DISPLAY_NAME_DOMAIN", "high", 35, "Display name shows a different domain",
                f"The sender name says '{fakes[0][:80]}' but the mail really comes from "
                f"'{real[:80]}'. Mail apps often show only the name.",
                {"display_name": name[:200], "real_domain": real},
            )
    return p


def _file_url(after: str, p: ParsedURL) -> ParsedURL:
    p.scheme = "file"
    norm = after.replace("\\", "/")
    host = ""
    if norm.startswith("//") and not norm.startswith("///"):
        host = norm[2:].split("/", 1)[0]
    if host and host.lower() != "localhost":
        p.add(
            "URL_REMOTE_FILE", "high", 45, "Link to a remote file share",
            f"file:// links to '{host[:80]}' make Windows connect over SMB and can leak your "
            "NTLM credentials without any further click.",
            {"host": host[:200]},
        )
        _analyse_host(host, p)
    else:
        p.has_host = False
        p.add(
            "URL_FILE_SCHEME", "medium", 25, "Link to a local file",
            "file: links open files on your own machine; mail and chat links should never need this.",
        )
    return p


def parse_url(raw: str) -> ParsedURL:
    """Parse ``raw`` (URL or email address) the way a browser or mail client would."""
    if not isinstance(raw, str):
        raise InputError("input must be text")
    if len(raw) > MAX_URL_LENGTH:
        raise InputError(f"input is longer than {MAX_URL_LENGTH} characters")
    if "\x00" in raw:
        raise InputError("input contains a NUL byte")
    p = ParsedURL(input=raw)
    _scan_hidden(raw, p)

    s = raw.strip("".join(chr(c) for c in range(0x21)))
    if re.search(r"[\t\n\r]", s):
        s = re.sub(r"[\t\n\r]", "", s)
        p.add(
            "URL_WHITESPACE_TRICK", "low", 10, "Tabs or newlines inside the URL",
            "Browsers delete them silently; they are used to break naive URL filters.",
        )
    if not s:
        raise InputError("empty input")

    refanged = _refang(s)
    if refanged != s:
        p.add(
            "INPUT_DEFANGED", "info", 0, "Input was defanged",
            "Re-fanged for analysis (hxxp -> http, [.] -> .). Nothing was opened.",
        )
        s = refanged

    m = _SCHEME_RE.match(s)
    scheme = m.group(1).lower() if m else ""
    after = s[m.end():] if m else s
    if m and ("." in scheme or re.match(r"^\d+([/?#]|$)", after)):
        m, scheme, after = None, "", s  # "example.com:8080" or "localhost:8080" - a bare host

    if m:
        if scheme == "mailto":
            target = unquote(after.split("?", 1)[0].split(",", 1)[0])
            return _parse_email(target, p)
        if scheme == "file":
            return _file_url(after, p)
        if scheme in DANGEROUS_SCHEMES:
            p.scheme, p.has_host, p.rest = scheme, False, after
            p.add(
                "URL_DANGEROUS_SCHEME", "critical", 60, f"'{scheme}:' link",
                "This link runs code or embeds content instead of opening a website. "
                "Never click it - it is a common one-click attack vector.",
                {"scheme": scheme},
            )
            return p
        if scheme in APP_HANDLER_SCHEMES:
            p.scheme, p.has_host, p.rest = scheme, False, after
            embedded = re.findall(r"https?://[^\s|\"'<>]+", after)[:3]
            p.add(
                "URL_APP_HANDLER", "high", 45, f"'{scheme}:' launches a local application",
                "Protocol handlers hand the link to a desktop app instead of the browser. "
                "ms-msdt: (Follina), search-ms: and ms-appinstaller: have all been used for "
                "one-click malware delivery.",
                {"scheme": scheme, "embedded_urls": embedded},
            )
            return p
        if scheme in INFO_SCHEMES:
            p.scheme, p.has_host, p.rest = scheme, False, after
            return p

    if not m and "@" in s and _EMAIL_RE.match(s) and "/" not in s.split("@", 1)[0]:
        return _parse_email(s, p)

    if m and scheme in SPECIAL_SCHEMES:
        slashes = len(after) - len(after.lstrip("/\\"))
        if after[:slashes] != "//":
            p.add(
                "URL_SLASH_TRICK", "low", 10, "Unusual slashes after the scheme",
                "Browsers accept any mix of '/' and '\\' here; odd forms are used to evade filters.",
                {"written": after[:slashes]},
            )
        rest = after[slashes:]
    elif m and after.startswith("//"):
        rest = after[2:]
        p.add(
            "URL_UNUSUAL_SCHEME", "low", 10, f"Unusual scheme '{scheme}:'",
            "Not a normal web link; check which application would handle it.",
            {"scheme": scheme},
        )
    elif m:
        p.scheme, p.has_host, p.rest = scheme, False, after
        p.kind = "other"
        p.add(
            "URL_UNUSUAL_SCHEME", "medium", 20, f"Unknown scheme '{scheme}:'",
            "Not a web link. Unknown schemes may be handled by local applications.",
            {"scheme": scheme},
        )
        return p
    elif s.startswith("//"):
        scheme, rest = "https", s[2:]
    else:
        scheme, rest = "http", s  # bare domain pasted without a scheme
    p.scheme = scheme or "http"

    special = p.scheme in SPECIAL_SCHEMES
    end = len(rest)
    for i, ch in enumerate(rest):
        if ch in "/?#" or (special and ch == "\\"):
            end = i
            break
    authority, p.rest = rest[:end], rest[end:]
    cut = min([i for i in (p.rest.find("?"), p.rest.find("#")) if i >= 0], default=len(p.rest))
    if special and ("\\" in p.rest[:cut] or rest[end:end + 1] == "\\"):
        p.rest = p.rest[:cut].replace("\\", "/") + p.rest[cut:]
        p.add(
            "URL_BACKSLASH", "low", 10, "Backslash in the URL",
            "Browsers treat '\\' as '/', other software does not.",
        )

    if "@" in authority:
        userinfo, _, hostport = authority.rpartition("@")
        p.userinfo = userinfo
        user_part = unquote(userinfo.split(":", 1)[0])
        if "." in user_part and any(c.isalpha() for c in user_part):
            p.add(
                "URL_USERINFO_DECEPTION", "high", 40, "Fake domain placed before '@'",
                f"Everything before '@' is a username, not the site. '{user_part[:80]}' is "
                "decoration; the browser really goes to the host after the '@'.",
                {"userinfo": user_part[:200]},
            )
        else:
            p.add(
                "URL_USERINFO", "low", 10, "Credentials embedded in the URL",
                "Links with user:password@ are rare in legitimate mail and blocked by many browsers.",
            )
    else:
        hostport = authority

    port_text = ""
    if hostport.startswith("["):
        close = hostport.find("]")
        if close == -1:
            raise InputError("unterminated IPv6 address")
        host, tail = hostport[: close + 1], hostport[close + 1:]
        if tail and not tail.startswith(":"):
            raise InputError("garbage after IPv6 address")
        port_text = tail[1:]
    else:
        host, sep, port_text = hostport.rpartition(":")
        if not sep:
            host, port_text = hostport, ""
    if port_text:
        if not port_text.isdigit() or int(port_text) > 65535:
            raise InputError(f"invalid port {port_text[:20]!r}")
        port = int(port_text)
        if port != DEFAULT_PORTS.get(p.scheme):
            p.port = port
            p.add(
                "URL_ODD_PORT", "low", 5, f"Non-standard port {port}",
                "Phishing kits on throwaway servers often listen on unusual ports.",
            )

    _analyse_host(host, p)
    _check_parser_confusion(p, s if m else f"{p.scheme}://{s}", host)
    return p


_REFANG = (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("(dot)", "."),
           ("[://]", "://"), ("[:]", ":"), ("[@]", "@"), ("[at]", "@"))


def _refang(s: str) -> str:
    out = s
    for fanged, plain in _REFANG:
        if fanged in out.lower():
            out = re.sub(re.escape(fanged), plain, out, flags=re.IGNORECASE)
    if re.match(r"(?i)^h(xx|\*\*)p", out):
        out = "http" + out[4:]
    return out


def _check_parser_confusion(p: ParsedURL, candidate: str, browser_host: str) -> None:
    """Compare with Python's urllib parser - a stand-in for 'other software'."""
    try:
        naive = urlsplit(candidate).hostname
    except ValueError:
        return
    if not naive:
        return
    ours = browser_host.lower().rstrip(".").strip("[]")
    if naive.lower().rstrip(".").strip("[]") != ours:
        p.add(
            "URL_PARSER_CONFUSION", "high", 35, "Different software sees a different host",
            f"A browser opens '{ours[:80]}' but common URL parsers (mail filters, scripts) "
            f"read the host as '{naive[:80]}'. This mismatch is a deliberate filter bypass.",
            {"browser_host": ours[:200], "naive_host": naive[:200]},
        )
