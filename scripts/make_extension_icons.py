"""Draw the extension's toolbar icons (a shield with a check mark) without any image library.

    python scripts/make_extension_icons.py      # writes extension/icons/{on,off}-{16,32,48,128}.png
"""

from __future__ import annotations

import math
import struct
import zlib
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "extension" / "icons"
SIZES = (16, 32, 48, 128)
THEMES = {"on": ((36, 83, 212), (24, 56, 160)), "off": ((150, 158, 170), (118, 126, 138))}
SS = 4  # supersampling per axis


def _shield(x: float, y: float) -> bool:
    """Unit-square shield: flat top with rounded shoulders, straight sides, pointed bottom."""
    if y < 0.08 or y > 0.94:
        return False
    if y <= 0.56:
        half = 0.40
        if y < 0.18:  # rounded shoulders
            dy = 0.18 - y
            half = 0.30 + math.sqrt(max(0.0, 0.10 ** 2 - dy ** 2))
    else:
        t = (y - 0.56) / 0.38
        half = 0.40 * (1 - t ** 1.35)
    return abs(x - 0.5) <= half


def _segment_dist(px, py, ax, ay, bx, by) -> float:
    vx, vy = bx - ax, by - ay
    t = max(0.0, min(1.0, ((px - ax) * vx + (py - ay) * vy) / (vx * vx + vy * vy)))
    return math.hypot(px - (ax + t * vx), py - (ay + t * vy))


def _check(x: float, y: float, width: float) -> bool:
    pts = ((0.30, 0.50), (0.45, 0.65), (0.71, 0.36))
    return min(_segment_dist(x, y, *pts[0], *pts[1]), _segment_dist(x, y, *pts[1], *pts[2])) <= width / 2


def _pixel(size: int, px: int, py: int, top, bottom) -> tuple[int, int, int, int]:
    cover = check = 0
    width = 0.11 if size >= 32 else 0.15
    for sy in range(SS):
        for sx in range(SS):
            x = (px + (sx + 0.5) / SS) / size
            y = (py + (sy + 0.5) / SS) / size
            if _shield(x, y):
                cover += 1
                if _check(x, y, width):
                    check += 1
    n = SS * SS
    if not cover:
        return (0, 0, 0, 0)
    t = py / max(1, size - 1)
    base = [round(top[i] + (bottom[i] - top[i]) * t) for i in range(3)]
    f = check / cover
    rgb = [round(base[i] * (1 - f) + 255 * f) for i in range(3)]
    return (*rgb, round(255 * cover / n))


def _png(size: int, pixels: list[tuple[int, int, int, int]]) -> bytes:
    raw = b"".join(b"\x00" + b"".join(struct.pack("4B", *pixels[y * size + x]) for x in range(size)) for y in range(size))

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def _ico(images: dict[int, bytes]) -> bytes:
    """A Windows .ico holding PNG images (supported since Windows Vista)."""
    header = struct.pack("<HHH", 0, 1, len(images))
    entries, offset, blobs = b"", 6 + 16 * len(images), b""
    for size, png in sorted(images.items()):
        entries += struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(png), offset)
        offset += len(png)
        blobs += png
    return header + entries + blobs


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, (top, bottom) in THEMES.items():
        for size in SIZES:
            pixels = [_pixel(size, x, y, top, bottom) for y in range(size) for x in range(size)]
            (OUT / f"{name}-{size}.png").write_bytes(_png(size, pixels))
    print(f"wrote {len(THEMES) * len(SIZES)} icons to {OUT}")
    top, bottom = THEMES["on"]
    images = {s: _png(s, [_pixel(s, x, y, top, bottom) for y in range(s) for x in range(s)])
              for s in (16, 20, 24, 32, 40, 48, 64, 128, 256)}
    ico = OUT.parent.parent / "packaging" / "windows" / "app.ico"
    ico.parent.mkdir(parents=True, exist_ok=True)
    ico.write_bytes(_ico({s: images[s] for s in (16, 24, 32, 48, 64, 256)}))
    print(f"wrote {ico}")
    # The desktop window's icon (instead of Tk's feather): .ico on Windows, PNGs elsewhere
    gui = OUT.parent.parent / "src" / "homograph_guard" / "gui" / "icons"
    gui.mkdir(parents=True, exist_ok=True)
    (gui / "app.ico").write_bytes(_ico(images))
    for s in (16, 32, 48, 64, 128, 256):
        (gui / f"app-{s}.png").write_bytes(images[s])
    print(f"wrote the window icons to {gui}")


if __name__ == "__main__":
    main()
