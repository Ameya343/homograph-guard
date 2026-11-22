"""Protected-brand index and look-alike matching."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import asdict, dataclass
from importlib import resources
from pathlib import Path

import idna

from .domains import DomainParts, split_domain
from .unicode_tools import ConfusableMap

MAX_BRANDS = 20000
MAX_BRAND_FILE = 4 * 1024 * 1024
# Brand names that are everyday words: still protected against homographs and typos,
# but not flagged merely for appearing as a word inside another domain.
GENERIC_WORD_BRANDS = frozenset(
    "box live office target visa wise cash meta zoom slack notion signal ledger phantom steam "
    "bing india uber ea x mail booking battle crypto blockchain proton".split()
)
# ICANN "dotBrand" top-level domains: run by one company for itself, closed to everyone else
# (e.g. status.cloud.microsoft). A name under them cannot be a third party's impersonation.
BRAND_TLDS = frozenset(
    "google goog youtube gmail android chrome microsoft azure bing xbox windows office apple amazon aws "
    "bbc hsbc barclays citi chase amex americanexpress visa netflix yahoo sony samsung cisco intel ibm dell "
    "bmw adobe fedex ups dhl".split()
)
_ASCII_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)+$")


def label_to_unicode(label: str) -> str:
    if not label.startswith("xn--"):
        return label
    try:
        return idna.decode(label)
    except (idna.IDNAError, UnicodeError, ValueError):
        try:
            return label[4:].encode("ascii").decode("punycode")
        except (UnicodeError, ValueError):
            return label


def host_to_unicode(host: str) -> str:
    return ".".join(label_to_unicode(lb) for lb in host.split("."))


def normalize_domain(text: str) -> str | None:
    d = text.strip().lower()
    if not d or d.startswith("#"):
        return None
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0].split(":", 1)[0].rstrip(".")
    if d.startswith("*."):
        d = d[2:]
    if not d.isascii():
        try:
            d = idna.encode(d, uts46=True, transitional=False).decode("ascii")
        except (idna.IDNAError, UnicodeError, ValueError):
            return None
    return d if _ASCII_DOMAIN.match(d) else None


def read_domain_file(path: str) -> list[str]:
    p = Path(path)
    if p.stat().st_size > MAX_BRAND_FILE:
        raise ValueError(f"{path}: brand file is unexpectedly large")
    return [d for d in (normalize_domain(x) for x in p.read_text(encoding="utf-8").splitlines()) if d]


def default_domains() -> list[str]:
    text = resources.files("homograph_guard").joinpath("data/brands.txt").read_text(encoding="utf-8")
    return [d for d in (normalize_domain(x) for x in text.splitlines()) if d]


def osa_distance(a: str, b: str, limit: int = 2) -> int:
    """Optimal-string-alignment (Damerau) distance, short-circuited above ``limit``."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


@dataclass(frozen=True)
class Brand:
    domain: str  # ASCII registrable domain
    sld: str  # Unicode label left of the suffix
    suffix: str  # Unicode suffix
    sld_strict: str
    sld_loose: str
    sld_collapse: str
    full_collapse: str


@dataclass
class BrandMatch:
    brand: str
    kind: str  # official | owned_tld | homograph | lookalike | tld_swap | typosquat | subdomain_spoof | embedded
    weight: int
    severity: str
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


class BrandIndex:
    def __init__(self, domains: list[str], cmap: ConfusableMap):
        self.cmap = cmap
        self.brands: dict[str, Brand] = {}
        self._strict: dict[str, list[Brand]] = defaultdict(list)
        self._loose: dict[str, list[Brand]] = defaultdict(list)
        self._collapse: dict[str, list[Brand]] = defaultdict(list)
        for d in domains[:MAX_BRANDS]:
            parts = split_domain(d)
            if not parts.registrable or parts.registrable in self.brands:
                continue
            sld = label_to_unicode(parts.sld)
            suffix = host_to_unicode(parts.suffix)
            b = Brand(
                domain=parts.registrable,
                sld=sld,
                suffix=suffix,
                sld_strict=cmap.strict(sld),
                sld_loose=cmap.loose(sld),
                sld_collapse=cmap.collapse(sld),
                full_collapse=cmap.collapse(f"{sld}.{suffix}"),
            )
            self.brands[b.domain] = b
            self._strict[b.sld_strict].append(b)
            self._loose[b.sld_loose].append(b)
            self._collapse[b.sld_collapse].append(b)

    def __len__(self) -> int:
        return len(self.brands)

    def match(self, parts: DomainParts, host_unicode: str) -> list[BrandMatch]:
        reg = parts.registrable
        if not reg:
            return []
        if reg in self.brands:
            return [BrandMatch(reg, "official", 0, "info", f"The registrable domain is {reg} itself.")]
        if parts.suffix in BRAND_TLDS:
            return [BrandMatch(reg, "owned_tld", 0, "info",
                               f"Only the company that runs .{parts.suffix} can register names under it, "
                               "so this is not someone else imitating a brand.")]
        c = self.cmap
        sld = label_to_unicode(parts.sld)
        suffix = host_to_unicode(parts.suffix)
        s_strict, s_loose, s_col = c.strict(sld), c.loose(sld), c.collapse(sld)
        best: dict[str, BrandMatch] = {}

        def offer(m: BrandMatch) -> None:
            if m.brand not in best or m.weight > best[m.brand].weight:
                best[m.brand] = m

        swapped: set[str] = set()
        for b in self._strict.get(s_strict, ()):
            if sld == b.sld:
                if b.sld in swapped:
                    continue
                swapped.add(b.sld)
                offer(BrandMatch(
                    b.domain, "tld_swap", 15, "medium",
                    f"Same name as {b.domain} but under .{suffix}. Big brands own many such "
                    "domains - the DNS comparison helps tell them apart.",
                ))
            else:
                same_suffix = c.strict(suffix) == c.strict(b.suffix)
                offer(BrandMatch(
                    b.domain, "homograph", 50 if same_suffix else 40, "high",
                    f"'{sld}' is written with look-alike characters to imitate '{b.sld}'"
                    + ("." if same_suffix else f" (on .{suffix} instead of .{b.suffix})."),
                ))
        for b in self._loose.get(s_loose, ()):
            if sld != b.sld:
                offer(BrandMatch(
                    b.domain, "lookalike", 45, "high",
                    f"'{sld}' differs from '{b.sld}' only by accents, marks or stroke letters.",
                ))
        for b in self._collapse.get(s_col, ()):
            if sld != b.sld:
                offer(BrandMatch(
                    b.domain, "lookalike", 40, "high",
                    f"'{sld}' imitates '{b.sld}' with ASCII look-alikes (rn/m, vv/w, 0/o, 1/l/i).",
                ))
        if len(s_col) >= 4:
            for b in self.brands.values():
                bc = b.sld_collapse
                if (len(bc) >= 5 and bc != s_col and abs(len(bc) - len(s_col)) <= 1
                        and osa_distance(s_col, bc, 1) == 1):
                    offer(BrandMatch(
                        b.domain, "typosquat", 25, "medium",
                        f"'{sld}' is one typo away from '{b.sld}'.",
                    ))

        host_col = c.collapse(host_unicode)
        owner_part = c.collapse(".".join([*parts.subdomains, sld]))  # never the public suffix
        tokens = [t for t in re.split(r"[.\-_/]", owner_part) if t]
        for b in self.brands.values():
            if b.domain == reg:
                continue
            if re.search(rf"(^|[./]){re.escape(b.full_collapse)}[./]", host_col):
                offer(BrandMatch(
                    b.domain, "subdomain_spoof", 30, "high",
                    f"'{b.domain}' is used as a decoy prefix; the real site is {reg}.",
                ))
            elif b.sld in GENERIC_WORD_BRANDS or b.sld == sld:
                continue
            elif len(b.sld_collapse) >= 3 and b.sld_collapse in tokens:
                offer(BrandMatch(
                    b.domain, "embedded", 20, "medium",
                    f"The brand name '{b.sld}' appears inside an unrelated domain ({reg}).",
                ))
            elif len(b.sld_collapse) >= 6 and any(b.sld_collapse in t for t in tokens):
                offer(BrandMatch(
                    b.domain, "embedded", 8, "low",
                    f"'{b.sld}' is contained in the hostname of {reg}.",
                ))
        return sorted(best.values(), key=lambda m: -m.weight)[:5]

    def names_in_text(self, text: str, exclude: str = "") -> list[Brand]:
        """Brands whose name appears as a whole word in free text (paths, sender names)."""
        words = set(re.split(r"[^\w]+", self.cmap.collapse(text)))
        return [b for b in self.brands.values()
                if len(b.sld_collapse) >= 4 and b.sld_collapse in words
                and b.sld not in GENERIC_WORD_BRANDS and b.domain != exclude]
