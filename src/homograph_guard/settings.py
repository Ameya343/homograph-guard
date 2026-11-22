"""User settings, optionally overridden by an organisation-wide policy file.

Settings live in ``settings.json`` in the data directory. A policy file (written by
an administrator, see ENTERPRISE.md) can set the same keys plus organisation-wide
allow/block lists; keys it sets are locked and cannot be changed by the user.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import paths

DNS_MODES = ("off", "suspicious", "all")
DNS_MODE_HELP = {
    "off": "Only the database on this device is used. No link is sent anywhere.",
    "suspicious": "Links that already look suspicious are also checked with Google, Cloudflare and AdGuard DNS.",
    "all": "Every link is also checked with Google, Cloudflare and AdGuard DNS.",
}
SHORT_LINK_MODES = ("app", "browser", "off")
SHORT_LINK_HELP = {
    "app": "When network checks are on, or when you ask, this app asks the shortening service where a short link "
           "leads (the destination is not opened). Services that answer only browsers are asked by your browser.",
    "browser": "Only your browser asks, when you choose \"Show where this short link leads\" (for networks where "
               "only the browser may reach the internet).",
    "off": "Shortening services are never asked; short links stay a caution.",
}
_PROXY_RE = re.compile(r"^https?://[A-Za-z0-9.\-\[\]:]{1,253}(?::\d{1,5})?/?$")
_MIRROR_RE = re.compile(r"^https://[A-Za-z0-9.\-]{1,253}(?::\d{1,5})?(?:/[\w.\-~/%]*)?$")
USER_KEYS = ("dns_mode", "short_links", "feeds", "proxy", "cafile")
POLICY_KEYS = (*USER_KEYS, "feed_mirror", "allow", "block", "update_hour")
MAX_FILE = 1024 * 1024


@dataclass
class Settings:
    dns_mode: str = "off"
    short_links: str = "app"  # who may ask link-shortening services where short links lead (SHORT_LINK_HELP)
    feeds: dict[str, bool] = field(default_factory=dict)  # per-feed on/off, overriding the defaults
    proxy: str | None = None  # None: use the system / environment proxy settings
    cafile: str | None = None  # extra CA bundle, e.g. a corporate TLS-inspection root
    feed_mirror: str | None = None  # organisation mirror serving <feed>.txt (policy only)
    update_hour: int = 9
    org_allow: list[str] = field(default_factory=list)
    org_block: list[str] = field(default_factory=list)
    locked: frozenset[str] = frozenset()

    def public(self) -> dict:
        """What the extension may see: no file paths, no proxy credentials."""
        return {"dns_mode": self.dns_mode, "dns_modes": list(DNS_MODES), "short_links": self.short_links,
                "locked": sorted(self.locked),
                "managed": bool(self.locked or self.org_allow or self.org_block)}


def _validate(key: str, value, from_policy: bool):
    from .feeds import FEEDS_BY_NAME

    if key == "dns_mode":
        if value not in DNS_MODES:
            raise ValueError(f"dns_mode must be one of {', '.join(DNS_MODES)}")
        return value
    if key == "short_links":
        if value not in SHORT_LINK_MODES:
            raise ValueError(f"short_links must be one of {', '.join(SHORT_LINK_MODES)}")
        return value
    if key == "feeds":
        if not isinstance(value, dict) or not all(isinstance(k, str) and isinstance(v, bool) for k, v in value.items()):
            raise ValueError("feeds must map feed names to true/false")
        unknown = set(value) - set(FEEDS_BY_NAME)
        if unknown:
            raise ValueError(f"unknown feed(s): {', '.join(sorted(unknown))}")
        return dict(value)
    if key == "proxy":
        if value in (None, ""):
            return None
        if not isinstance(value, str) or not _PROXY_RE.match(value):
            raise ValueError("proxy must look like http://proxy.example:8080")
        return value
    if key == "cafile":
        if value in (None, ""):
            return None
        if not isinstance(value, str) or len(value) > 1024:
            raise ValueError("cafile must be a path")
        return value
    if key == "feed_mirror" and from_policy:
        if value in (None, ""):
            return None
        if not isinstance(value, str) or not _MIRROR_RE.match(value):
            raise ValueError("feed_mirror must be an https:// URL")
        return value.rstrip("/") + "/"
    if key == "update_hour" and from_policy:
        if not isinstance(value, int) or not 0 <= value <= 23:
            raise ValueError("update_hour must be 0-23")
        return value
    if key in ("allow", "block") and from_policy:
        if not isinstance(value, list) or not all(isinstance(x, str) and len(x) <= 2048 for x in value):
            raise ValueError(f"{key} must be a list of domains or links")
        return value[:10000]
    raise ValueError(f"unknown setting {key!r}")


def _read_json(path: Path) -> dict:
    try:
        if not path.is_file() or path.stat().st_size > MAX_FILE:
            return {}
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def load(user_file: Path | None = None, policy_file: Path | None = None) -> Settings:
    s = Settings()
    for key, value in _read_json(user_file or paths.settings_path()).items():
        if key in USER_KEYS:
            try:
                setattr(s, key, _validate(key, value, from_policy=False))
            except ValueError:
                continue  # a broken setting falls back to its default
    locked: set[str] = set()
    for key, value in _read_json(policy_file or paths.policy_file()).items():
        if key not in POLICY_KEYS:
            continue
        try:
            value = _validate(key, value, from_policy=True)
        except ValueError:
            continue
        if key == "allow":
            s.org_allow = value
        elif key == "block":
            s.org_block = value
        else:
            setattr(s, key, value)
            locked.add(key)
    s.locked = frozenset(locked)
    return s


def save(s: Settings, user_file: Path | None = None) -> None:
    path = user_file or paths.settings_path()
    data = {k: getattr(s, k) for k in USER_KEYS if k not in s.locked}
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def set_value(key: str, value, user_file: Path | None = None, policy_file: Path | None = None) -> Settings:
    s = load(user_file, policy_file)
    if key not in USER_KEYS:
        raise ValueError(f"{key!r} cannot be changed here")
    if key in s.locked:
        raise PermissionError(f"{key} is set by your organisation's policy")
    setattr(s, key, _validate(key, value, from_policy=False))
    save(s, user_file)
    return s
