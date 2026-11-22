"""Make attacker-controlled text safe to show to a human.

Hostnames, DNS records and certificate fields all come from the attacker.
Printing them raw can reorder text on screen (bidi controls, the "RLO" trick),
hide characters (zero-width), or inject terminal escape sequences. Everything
shown by the CLI or GUI goes through :func:`safe_text` first.
"""

from __future__ import annotations

import unicodedata

BIDI_CONTROLS = frozenset(
    {0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}
)

INVISIBLE = frozenset(
    {
        0x00AD, 0x034F, 0x061C, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180B, 0x180C, 0x180D,
        0x180E, 0x180F, 0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064,
        0x3164, 0xFEFF, 0xFFA0,
    }
    | set(range(0xFE00, 0xFE10))  # variation selectors
    | set(range(0xE0000, 0xE0080))  # tag characters
    | set(range(0xE0100, 0xE01F0))  # variation selectors supplement
)

_ESCAPE_CATEGORIES = {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}


def is_dangerous_char(ch: str) -> bool:
    cp = ord(ch)
    if cp in BIDI_CONTROLS or cp in INVISIBLE:
        return True
    cat = unicodedata.category(ch)
    if cat in _ESCAPE_CATEGORIES:
        return True
    return cat == "Zs" and ch != " "


def safe_text(value: object, max_len: int = 600) -> str:
    """Return a printable, non-deceptive rendering of ``value``.

    Control, format, bidi and invisible characters become ``<U+XXXX>``.
    Over-long strings are truncated with a marker.
    """
    s = "" if value is None else str(value)
    out: list[str] = []
    for ch in s:
        if is_dangerous_char(ch):
            out.append(f"<U+{ord(ch):04X}>")
        else:
            out.append(ch)
    result = "".join(out)
    if len(result) > max_len:
        result = result[: max_len - 1] + "…"
    return result


def defang_host(host: str) -> str:
    return host.replace(".", "[.]")


def defang_url(scheme: str, host: str, rest: str = "", port: int | None = None) -> str:
    """Render a URL that will not auto-link in terminals, editors or chat tools."""
    sch = scheme.lower()
    if sch.startswith("http"):
        sch = "hxxp" + sch[4:]
    port_part = f":{port}" if port else ""
    return f"{sch}[://]{defang_host(host)}{port_part}{rest}"
