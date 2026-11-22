"""Unicode script detection and confusable "skeletons" (after Unicode TR39).

Three comparison tiers are used, from strict to aggressive:

* ``strict``   - TR39-style skeleton: NFD, map every confusable to its
  prototype, NFD again. ``pаypal`` (Cyrillic а) == ``paypal``.
* ``loose``    - strict plus diacritics and stroke letters removed.
  ``pàypał`` == ``paypal``.
* ``collapse`` - loose plus ASCII-level tricks: rn->m, vv->w, 0->o, 1/i->l.
  ``rnicros0ft`` == ``microsoft``.
"""

from __future__ import annotations

import unicodedata
from functools import lru_cache
from pathlib import Path

from .confusables_data import CURATED

# Keyword (as found in Unicode character names) -> script name.
_SCRIPT_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("CANADIAN SYLLABICS", "Canadian_Aboriginal"),
    ("YI SYLLABLE", "Yi"),
    ("CJK", "Han"),
    ("KANGXI", "Han"),
    ("LATIN", "Latin"),
    ("CYRILLIC", "Cyrillic"),
    ("GREEK", "Greek"),
    ("COPTIC", "Coptic"),
    ("ARMENIAN", "Armenian"),
    ("HEBREW", "Hebrew"),
    ("ARABIC", "Arabic"),
    ("SYRIAC", "Syriac"),
    ("THAANA", "Thaana"),
    ("NKO", "Nko"),
    ("DEVANAGARI", "Devanagari"),
    ("BENGALI", "Bengali"),
    ("GURMUKHI", "Gurmukhi"),
    ("GUJARATI", "Gujarati"),
    ("ORIYA", "Oriya"),
    ("TAMIL", "Tamil"),
    ("TELUGU", "Telugu"),
    ("KANNADA", "Kannada"),
    ("MALAYALAM", "Malayalam"),
    ("SINHALA", "Sinhala"),
    ("THAI", "Thai"),
    ("LAO", "Lao"),
    ("TIBETAN", "Tibetan"),
    ("MYANMAR", "Myanmar"),
    ("GEORGIAN", "Georgian"),
    ("HANGUL", "Hangul"),
    ("ETHIOPIC", "Ethiopic"),
    ("CHEROKEE", "Cherokee"),
    ("OGHAM", "Ogham"),
    ("RUNIC", "Runic"),
    ("KHMER", "Khmer"),
    ("MONGOLIAN", "Mongolian"),
    ("HIRAGANA", "Hiragana"),
    ("KATAKANA", "Katakana"),
    ("BOPOMOFO", "Bopomofo"),
    ("TIFINAGH", "Tifinagh"),
    ("VAI", "Vai"),
    ("LISU", "Lisu"),
    ("GLAGOLITIC", "Glagolitic"),
    ("BALINESE", "Balinese"),
    ("JAVANESE", "Javanese"),
    ("SUNDANESE", "Sundanese"),
    ("BUGINESE", "Buginese"),
    ("TAGALOG", "Tagalog"),
    ("ADLAM", "Adlam"),
    ("OSAGE", "Osage"),
)

IGNORABLE_SCRIPTS = frozenset({"Common", "Inherited"})

# Scripts whose letters are commonly mistaken for Latin ones.
LATIN_CONFUSABLE_SCRIPTS = frozenset(
    {
        "Cyrillic", "Greek", "Armenian", "Cherokee", "Georgian", "Coptic", "Lisu",
        "Canadian_Aboriginal", "Tifinagh", "Nko", "Vai", "Osage", "Adlam", "Unknown",
    }
)

# Script mixes that are normal for Japanese, Chinese and Korean text (TR39 "Highly Restrictive").
_CJK_COMBOS = (
    frozenset({"Latin", "Han", "Hiragana", "Katakana"}),
    frozenset({"Latin", "Han", "Bopomofo"}),
    frozenset({"Latin", "Han", "Hangul"}),
)

# Letters with built-in strokes/hooks that NFD cannot strip (loose tier only).
_LOOSE_EXTRA = {
    "đ": "d",  # LATIN SMALL LETTER D WITH STROKE
    "ħ": "h",  # LATIN SMALL LETTER H WITH STROKE
    "ŧ": "t",  # LATIN SMALL LETTER T WITH STROKE
    "ƀ": "b",  # LATIN SMALL LETTER B WITH STROKE
    "ɨ": "i",  # LATIN SMALL LETTER I WITH STROKE
    "ʉ": "u",  # LATIN SMALL LETTER U BAR
    "ǥ": "g",  # LATIN SMALL LETTER G WITH STROKE
    "ɍ": "r",  # LATIN SMALL LETTER R WITH STROKE
    "ɏ": "y",  # LATIN SMALL LETTER Y WITH STROKE
    "ȼ": "c",  # LATIN SMALL LETTER C WITH STROKE
    "ɇ": "e",  # LATIN SMALL LETTER E WITH STROKE
    "ɉ": "j",  # LATIN SMALL LETTER J WITH STROKE
    "ß": "ss",  # LATIN SMALL LETTER SHARP S
    "æ": "ae",  # LATIN SMALL LETTER AE
    "œ": "oe",  # LATIN SMALL LIGATURE OE
}

_COLLAPSE_SEQ = (("rn", "m"), ("vv", "w"))
_COLLAPSE_CHARS = str.maketrans({"0": "o", "1": "l", "i": "l", "|": "l"})

MAX_CONFUSABLES_FILE = 8 * 1024 * 1024


@lru_cache(maxsize=16384)
def char_script(ch: str) -> str:
    """Best-effort Unicode script of a single character (no external data needed)."""
    if ch.isascii():
        return "Latin" if ch.isalpha() else "Common"
    name = unicodedata.name(ch, "")
    if not name:
        return "Unknown"
    cat = unicodedata.category(ch)
    if cat[0] in "PSZC":
        return "Common"
    if name.startswith("COMBINING ") or cat == "Me":
        return "Inherited"
    words = set(name.replace("-", " ").split())
    for keyword, script in _SCRIPT_KEYWORDS:
        if (" " in keyword and keyword in name) or keyword in words:
            return script
    if cat[0] == "M":
        return "Inherited"
    if cat == "Nd" and name.startswith("DIGIT "):
        return "Common"
    return "Unknown"


def scripts_of(text: str) -> set[str]:
    return {char_script(c) for c in text} - IGNORABLE_SCRIPTS


def restriction_level(scripts: set[str]) -> str:
    """Approximate Unicode TR39 restriction level for a set of scripts."""
    s = set(scripts) - IGNORABLE_SCRIPTS
    if not s:
        return "ascii"
    if len(s) == 1:
        return "single-script"
    if any(s <= combo for combo in _CJK_COMBOS):
        return "highly-restrictive"
    if "Latin" in s and len(s) == 2 and not (s & LATIN_CONFUSABLE_SCRIPTS):
        return "moderately-restrictive"
    return "minimally-restrictive"


def parse_unicode_confusables(text: str) -> dict[str, str]:
    """Parse the official ``confusables.txt`` (single-code-point sources only)."""
    table: dict[str, str] = {}
    for raw in text.lstrip("﻿").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split(";")]
        if len(parts) < 2:
            continue
        try:
            src = "".join(chr(int(h, 16)) for h in parts[0].split())
            tgt = "".join(chr(int(h, 16)) for h in parts[1].split())
        except ValueError:
            continue
        if len(src) == 1 and tgt:
            table[src] = tgt
    return table


def _close(table: dict[str, str]) -> dict[str, str]:
    """Resolve chains (a->b, b->c) so a single mapping pass is idempotent."""
    closed: dict[str, str] = {}
    for src, tgt in table.items():
        cur = tgt
        for _ in range(6):
            nxt = "".join(table.get(c, c) for c in cur)
            if nxt == cur:
                break
            cur = nxt
        closed[src] = cur
    return closed


class ConfusableMap:
    """Confusable lookup + skeleton functions."""

    def __init__(self, table: dict[str, str], source: str = "curated"):
        self._table = _close(table)
        self.source = source

    @classmethod
    def load(cls, unicode_file: str | None = None) -> ConfusableMap:
        table: dict[str, str] = {}
        source = f"curated ({len(CURATED)} entries)"
        if unicode_file:
            path = Path(unicode_file)
            if path.stat().st_size > MAX_CONFUSABLES_FILE:
                raise ValueError("confusables file is unexpectedly large")
            official = parse_unicode_confusables(path.read_text(encoding="utf-8"))
            if len(official) < 1000:
                raise ValueError("file does not look like Unicode confusables.txt")
            table.update(official)
            source = f"Unicode confusables.txt ({len(official)}) + curated ({len(CURATED)})"
        table.update(CURATED)  # curated wins (e.g. palochka -> 'l', not 'i')
        return cls(table, source)

    def __len__(self) -> int:
        return len(self._table)

    def _map(self, s: str) -> str:
        return "".join(self._table.get(c, c) for c in s)

    def strict(self, s: str) -> str:
        t = unicodedata.normalize("NFD", s.casefold())
        t = self._map(t).casefold()
        t = self._map(t)
        return unicodedata.normalize("NFD", t)

    def loose(self, s: str) -> str:
        t = self.strict(s)
        t = "".join(c for c in t if not unicodedata.category(c).startswith("M"))
        t = "".join(_LOOSE_EXTRA.get(c, c) for c in t)
        return unicodedata.normalize("NFC", t)

    def collapse(self, s: str) -> str:
        t = self.loose(s)
        for seq, repl in _COLLAPSE_SEQ:
            t = t.replace(seq, repl)
        return t.translate(_COLLAPSE_CHARS)

    def lookalike(self, ch: str) -> tuple[str, str] | None:
        """Return (ascii_lookalike, kind) for a non-ASCII char, kind in {confusable, diacritic}."""
        if ch.isascii():
            return None
        strict = self.strict(ch)
        if strict != ch and strict.isascii() and strict.strip():
            return strict, "confusable"
        loose = self.loose(ch)
        if loose != ch and loose.isascii() and loose.strip():
            return loose, "diacritic"
        return None
