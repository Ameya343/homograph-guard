"""Find every link in an email, an HTML page or free text - including the hidden ones.

Phishing rarely relies on the link you can see. This module also reports:

* anchors whose visible text shows one address while ``href`` goes elsewhere;
* links hidden with CSS (``display:none``, zero size, off-screen, transparent,
  ``font-size:0``), the ``hidden`` attribute, HTML comments or scripts;
* addresses written as plain text (chat messages, plain-text mail), including
  defanged ``hxxp://evil[.]com`` forms;
* form targets, iframes, meta refreshes, image maps and SVG links in HTML
  attachments;
* the From, Reply-To and Sender headers of an email.

The input is parsed as data with the standard library only. Nothing is fetched,
rendered or executed.
"""

from __future__ import annotations

import email
import email.policy
import re
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from urllib.parse import urljoin

MAX_INPUT = 16 * 1024 * 1024
MAX_LINKS = 1000
MAX_TEXT = 300

_VOID = frozenset("area base br col embed hr img input link meta param source track wbr".split())
_SKIP_TEXT = frozenset({"style", "title"})
_URL_ATTRS = {
    "a": ("href", "xlink:href"), "area": ("href",), "form": ("action",), "iframe": ("src",),
    "frame": ("src",), "embed": ("src",), "object": ("data",), "button": ("formaction",),
    "input": ("formaction",),
}
_DATA_ATTRS = ("data-href", "data-url", "data-link", "data-saferedirecturl")

# Free-text addresses: full URLs (also hxxp and [://]), www. hosts, and bare domains.
_REFANG = (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("(dot)", "."),
           ("[://]", "://"), ("[:]", ":"))
_TEXT_URL = re.compile(
    r"""(?ix)
    (?<![@\w.\-])
    (?:
        (?:h(?:tt|xx|\*\*)ps?|ftp)://[^\s<>"'`]+
      | www\d{0,3}\.[^\s<>"'`]+
      | (?:[\w\-]{1,63}\.){1,8}(?:xn--[a-z0-9\-]{2,59}|[^\W\d_]{2,24})(?::\d{2,5})?(?:/[^\s<>"'`]*)?
    )
    """
)
_TRAILING = ".,;:!?'\")]}>*"
# TLDs that are also common file extensions: a bare "setup.py" is not a link.
_FILEISH_TLDS = frozenset("py md rs sh pl pm ps sc so zip mov gz ms cc".split())


@dataclass
class FoundLink:
    url: str
    source: str  # anchor | area | form | iframe | frame | embed | object | meta-refresh | attribute | text | header
    text: str = ""  # what the reader sees (anchor text, alt text, header display)
    hidden: str | None = None  # why the reader cannot see it
    where: str = ""  # "HTML body", "plain-text body", "From header", "attachment invoice.html"

    def context(self) -> dict:
        return {k: v for k, v in asdict(self).items() if k != "url" and v not in (None, "")}


def _norm_space(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def _style_hidden(style: str) -> str | None:
    s = style.lower().replace(" ", "")
    decl = dict(d.split(":", 1) for d in s.split(";") if ":" in d)

    def num(v: str) -> float | None:
        m = re.match(r"^(-?\d+(?:\.\d+)?)", v or "")
        return float(m.group(1)) if m else None

    if decl.get("display", "").startswith("none"):
        return "display:none"
    if decl.get("visibility", "") in ("hidden", "collapse"):
        return "visibility:hidden"
    if (o := num(decl.get("opacity", ""))) is not None and o < 0.05:
        return "opacity:0"
    if (f := num(decl.get("font-size", ""))) is not None and f <= 0.5:
        return "font-size:0"
    if decl.get("color", "") in ("transparent", "rgba(0,0,0,0)"):
        return "transparent text"
    w, h = num(decl.get("width", "")), num(decl.get("height", ""))
    mw, mh = num(decl.get("max-width", "")), num(decl.get("max-height", ""))
    if (h == 0 or mh == 0 or w == 0 or mw == 0) and decl.get("overflow", "") == "hidden":
        return "zero size"
    if w == 0 and h == 0:
        return "zero size"
    if decl.get("position", "") in ("absolute", "fixed"):
        for side in ("left", "top", "right", "bottom", "text-indent"):
            v = num(decl.get(side, ""))
            if v is not None and v <= -500:
                return "moved off-screen"
    if (ti := num(decl.get("text-indent", ""))) is not None and ti <= -500:
        return "moved off-screen"
    if re.search(r"scale\(0(\.0+)?\)", decl.get("transform", "")):
        return "scaled to zero"
    if decl.get("clip", "").startswith("rect(0") or decl.get("clip-path", "").startswith("inset(50%"):
        return "clipped away"
    return None


def _attr_hidden(tag: str, attrs: dict[str, str]) -> str | None:
    if "hidden" in attrs:
        return "hidden attribute"
    if tag == "input" and attrs.get("type", "").lower() == "hidden":
        return "hidden form field"
    if attrs.get("style"):
        why = _style_hidden(attrs["style"])
        if why:
            return why
    for dim in ("width", "height"):
        if attrs.get(dim, "").strip() in ("0", "0px", "1", "1px") and tag in ("img", "iframe", "a", "div", "span"):
            return "zero size"
    return None


def find_text_urls(text: str) -> list[str]:
    """Addresses written as plain text (also defanged), in order of appearance."""
    if not text:
        return []
    scan = text
    for fanged, plain in _REFANG:
        if fanged in scan.lower():
            scan = re.sub(re.escape(fanged), plain, scan, flags=re.IGNORECASE)
    out: list[str] = []
    for m in _TEXT_URL.finditer(scan):
        url = m.group(0)
        while url and url[-1] in _TRAILING:
            if url[-1] == ")" and url.count("(") >= url.count(")"):
                break
            url = url[:-1]
        if not url:
            continue
        low = url.lower()
        if "://" not in low and not low.startswith("www"):
            host = re.split(r"[/:]", url, maxsplit=1)[0]
            if not _known_suffix(host):
                continue
            if host.rsplit(".", 1)[-1].lower() in _FILEISH_TLDS:
                continue
        out.append(url)
    return out


def _known_suffix(host: str) -> bool:
    from .domains import known_suffix

    return known_suffix(host)


class _Collector(HTMLParser):
    def __init__(self, where: str, base: str | None = None):
        super().__init__(convert_charrefs=True)
        self.where = where
        self.base = base
        self.links: list[FoundLink] = []
        self.stack: list[tuple[str, str | None]] = []  # (tag, hidden reason inherited)
        self.anchor: dict | None = None
        self.in_script = 0
        self.skip_text = 0

    # -- helpers
    def _hidden(self) -> str | None:
        for _, why in reversed(self.stack):
            if why:
                return why
        return None

    def _abs(self, url: str) -> str:
        url = url.strip()
        if self.base and not re.match(r"^[a-z][a-z0-9+.\-]*:", url, re.IGNORECASE) and not url.startswith("//"):
            return urljoin(self.base, url)
        if url.startswith("//"):
            return "https:" + url
        return url

    def _add(self, url: str, source: str, text: str = "", hidden: str | None = None) -> None:
        url = url.strip()
        if not url or url.startswith("#") or len(self.links) >= MAX_LINKS:
            return
        relative = not re.match(r"^[a-z][a-z0-9+.\-]*:", url, re.IGNORECASE) and not url.startswith("//")
        if relative and not self.base and not find_text_urls(url):  # relative, no base: nowhere to go
            return
        self.links.append(FoundLink(self._abs(url), source, _norm_space(text)[:MAX_TEXT], hidden, self.where))

    # -- parser callbacks
    def handle_starttag(self, tag: str, attrs_list: list) -> None:
        attrs = {k.lower(): (v or "") for k, v in attrs_list}
        tag = tag.lower()
        why = _attr_hidden(tag, attrs)
        if tag == "base" and attrs.get("href") and not self.base:
            self.base = attrs["href"].strip()
        if tag == "meta" and attrs.get("http-equiv", "").lower() == "refresh":
            m = re.search(r"url\s*=\s*['\"]?([^'\";]+)", attrs.get("content", ""), re.IGNORECASE)
            if m:
                self._add(m.group(1), "meta-refresh", "", "automatic redirect")
        hidden = why or self._hidden()
        for attr in _URL_ATTRS.get(tag, ()):
            if attrs.get(attr):
                if tag in ("a", "area") and attr in ("href", "xlink:href"):
                    if tag == "a":
                        self.anchor = {"url": attrs[attr], "text": [], "alt": [], "title": attrs.get("title", ""),
                                       "hidden": hidden}
                    else:
                        self._add(attrs[attr], "area", attrs.get("alt", ""), hidden)
                else:
                    self._add(attrs[attr], tag, "", hidden)
        for attr in _DATA_ATTRS:
            if attrs.get(attr) and attr != "data-saferedirecturl":
                self._add(attrs[attr], "attribute", attr, hidden)
        if tag == "img" and self.anchor is not None and attrs.get("alt"):
            self.anchor["alt"].append(attrs["alt"])
        if tag == "script":
            self.in_script += 1
        if tag in _SKIP_TEXT:
            self.skip_text += 1
        if tag not in _VOID:
            self.stack.append((tag, why))

    def handle_startendtag(self, tag: str, attrs_list: list) -> None:
        self.handle_starttag(tag, attrs_list)
        if tag.lower() not in _VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "a" and self.anchor is not None:
            a = self.anchor
            self.anchor = None
            text = " ".join(a["text"]) or " ".join(a["alt"]) or a["title"]
            self._add(a["url"], "anchor", text, a["hidden"])
        if tag == "script" and self.in_script:
            self.in_script -= 1
        if tag in _SKIP_TEXT and self.skip_text:
            self.skip_text -= 1
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break

    def handle_data(self, data: str) -> None:
        if self.anchor is not None and not self.in_script:
            self.anchor["text"].append(data)
            return
        if self.skip_text:
            return
        hidden = "inside a script" if self.in_script else self._hidden()
        for url in find_text_urls(data):
            self._add(url, "text", "", hidden)

    def handle_comment(self, data: str) -> None:
        for url in find_text_urls(data):
            self._add(url, "text", "", "inside an HTML comment")


def _dedupe(links: list[FoundLink]) -> list[FoundLink]:
    seen: set[tuple] = set()
    out = []
    for lk in links:
        key = (lk.url, lk.source, lk.text, lk.hidden)
        if key not in seen:
            seen.add(key)
            out.append(lk)
    return out[:MAX_LINKS]


def extract_html(html: str, where: str = "HTML page", base: str | None = None) -> list[FoundLink]:
    if len(html) > MAX_INPUT:
        raise ValueError("HTML is larger than 16 MB")
    c = _Collector(where, base)
    try:
        c.feed(html)
        c.close()
    except (AssertionError, ValueError):  # malformed markup: keep what was found
        pass
    if c.anchor is not None:  # unterminated <a>
        a = c.anchor
        c._add(a["url"], "anchor", " ".join(a["text"]), a["hidden"])
    return _dedupe(c.links)


def extract_text(text: str, where: str = "text") -> list[FoundLink]:
    if len(text) > MAX_INPUT:
        raise ValueError("text is larger than 16 MB")
    return _dedupe([FoundLink(u, "text", "", None, where) for u in find_text_urls(text)])


def _decode_part(part) -> str:
    payload = part.get_payload(decode=True) or b""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def extract_eml(data: bytes) -> list[FoundLink]:
    """Headers, bodies and HTML/SVG attachments of an RFC 5322 message."""
    if len(data) > MAX_INPUT:
        raise ValueError("message is larger than 16 MB")
    data = data.removeprefix(b"\xef\xbb\xbf")  # a byte-order mark would hide the first header
    msg = email.message_from_bytes(data, policy=email.policy.default)
    links: list[FoundLink] = []
    for header in ("From", "Reply-To", "Sender"):
        for value in msg.get_all(header, []) or []:
            v = _norm_space(str(value))
            if "@" in v:
                links.append(FoundLink(v[:500], "header", "", None, f"{header} header"))
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        name = part.get_filename() or ""
        attached = part.get_content_disposition() == "attachment" or bool(name)
        where = f"attachment {name}" if attached else ""
        low = name.lower()
        if ctype == "text/html" or low.endswith((".html", ".htm", ".shtml", ".xhtml")):
            links += extract_html(_decode_part(part), where or "HTML body")
        elif ctype == "image/svg+xml" or low.endswith(".svg"):
            links += extract_html(_decode_part(part), where or "SVG image")
        elif ctype == "text/plain" and not attached:
            links += extract_text(_decode_part(part), "plain-text body")
        if len(links) >= MAX_LINKS:
            break
    return _dedupe(links)
