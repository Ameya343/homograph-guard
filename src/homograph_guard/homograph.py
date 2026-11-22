"""Character-level homograph analysis of a hostname (mixed scripts, whole-script look-alikes)."""

from __future__ import annotations

import unicodedata
from collections import Counter
from dataclasses import asdict, dataclass, field

from .brands import label_to_unicode
from .domains import DomainParts
from .models import Finding
from .unicode_tools import (
    IGNORABLE_SCRIPTS,
    LATIN_CONFUSABLE_SCRIPTS,
    ConfusableMap,
    char_script,
    restriction_level,
    scripts_of,
)

# TLDs where an all-<script> label is normal (Chrome allows whole-script look-alikes there).
NATIVE_TLDS: dict[str, frozenset[str]] = {
    "Cyrillic": frozenset(
        "ru su by ua kz kg tj uz mk mn rs bg ba "
        "рф бел укр қаз мкд мон срб бг рус москва онлайн сайт орг ком дети".split()
    ),
    "Greek": frozenset("gr cy eu ελ ευ".split()),
    "Armenian": frozenset("am հայ".split()),
    "Georgian": frozenset("ge გე".split()),
}


@dataclass
class CharInfo:
    label: int
    position: int
    char: str
    codepoint: str
    name: str
    script: str
    looks_like: str | None = None
    lookalike_kind: str | None = None
    odd_script: bool = False


@dataclass
class LabelReport:
    index: int
    unicode: str
    ascii: str
    scripts: list[str]
    restriction: str
    is_suffix: bool
    chars: list[CharInfo] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def analyze_labels(
    host_unicode: str, host_ascii: str, parts: DomainParts, cmap: ConfusableMap
) -> tuple[list[LabelReport], list[Finding]]:
    ulabels = host_unicode.split(".")
    alabels = host_ascii.split(".")
    if len(alabels) != len(ulabels):
        alabels = [""] * len(ulabels)
    n_suffix = len(parts.suffix.split(".")) if parts.suffix else 0
    tld_u = label_to_unicode(alabels[-1]) if alabels[-1] else ulabels[-1]

    reports: list[LabelReport] = []
    findings: list[Finding] = []
    punycode_labels: list[str] = []
    for idx, (ul, al) in enumerate(zip(ulabels, alabels, strict=True)):
        is_suffix = idx >= len(ulabels) - n_suffix
        scripts = scripts_of(ul)
        level = restriction_level(scripts)
        rep = LabelReport(idx, ul, al, sorted(scripts), level, is_suffix)
        reports.append(rep)
        if al.startswith("xn--") or not ul.isascii():
            punycode_labels.append(f"{ul} = {al or '?'}")
        if ul.isascii():
            continue

        counts = Counter(char_script(c) for c in ul if char_script(c) not in IGNORABLE_SCRIPTS)
        majority = counts.most_common(1)[0][0] if counts else ""
        for pos, ch in enumerate(ul):
            script = char_script(ch)
            look = cmap.lookalike(ch)
            rep.chars.append(CharInfo(
                label=idx, position=pos + 1, char=ch, codepoint=f"U+{ord(ch):04X}",
                name=unicodedata.name(ch, "UNNAMED"), script=script,
                looks_like=look[0] if look else None, lookalike_kind=look[1] if look else None,
                odd_script=bool(len(counts) > 1 and script not in IGNORABLE_SCRIPTS and script != majority),
            ))
        if is_suffix:
            continue

        odd = [f"{ci.char} {ci.codepoint} ({ci.script}" + (f", looks like '{ci.looks_like}'" if ci.looks_like else "") + ")"
               for ci in rep.chars if ci.odd_script]
        if level == "minimally-restrictive":
            classic = "Latin" in scripts and bool(scripts & LATIN_CONFUSABLE_SCRIPTS)
            findings.append(Finding(
                "HG_MIXED_SCRIPT", "high" if classic else "medium", 45 if classic else 25,
                f"Mixed scripts in '{ul}': {', '.join(sorted(scripts))}",
                "Legitimate names almost never mix these alphabets inside one label. This is "
                "the classic IDN homograph pattern." if classic else
                "Unusual mix of writing systems inside one label.",
                {"label": ul, "scripts": sorted(scripts), "odd_characters": odd[:20]},
            ))
        elif level == "moderately-restrictive":
            findings.append(Finding(
                "HG_SCRIPT_MIX_UNUSUAL", "low", 5, f"Latin mixed with {', '.join(sorted(scripts - {'Latin'}))}",
                "Allowed by browsers, but uncommon.", {"label": ul, "scripts": sorted(scripts)},
            ))

        if level == "single-script" and scripts and next(iter(scripts)) != "Latin":
            script = next(iter(scripts))
            letters = [c for c in ul if char_script(c) not in IGNORABLE_SCRIPTS]
            mapped = [cmap.lookalike(c) for c in letters]
            if letters and all(m and m[0].isalnum() for m in mapped):
                spelled = "".join(m[0] for m in mapped if m)
                native = tld_u in NATIVE_TLDS.get(script, frozenset())
                findings.append(Finding(
                    "HG_WHOLE_SCRIPT", "low" if native else "high", 5 if native else 40,
                    f"'{ul}' is entirely {script} but reads as Latin '{spelled}'",
                    ("Normal under this country-code TLD, but still visually identical to a Latin name."
                     if native else
                     f"Every letter is a {script} look-alike of a Latin letter. Browsers such as Chrome "
                     "refuse to display such names in Unicode under non-native TLDs."),
                    {"label": ul, "script": script, "reads_as": spelled, "native_tld": native},
                ))

        if level == "single-script" and scripts == {"Latin"}:
            tricks = [f"{ci.char} {ci.codepoint} -> '{ci.looks_like}'" for ci in rep.chars
                      if ci.lookalike_kind == "confusable" and (ci.looks_like or "").isalnum()]
            if tricks:
                findings.append(Finding(
                    "HG_LATIN_LOOKALIKE", "medium", 20, f"Rare Latin look-alike letters in '{ul}'",
                    "Characters such as ɡ (script g), ı (dotless i) or ɑ (alpha) imitate plain ASCII letters.",
                    {"label": ul, "characters": tricks[:20]},
                ))

    if punycode_labels:
        findings.insert(0, Finding(
            "IDN_PUNYCODE", "info", 0, "Internationalized domain name",
            "The real DNS name is the punycode (xn--) form shown here; browsers decide whether to "
            "show you the Unicode or the punycode.",
            {"labels": punycode_labels[:10]},
        ))
    return reports, findings
