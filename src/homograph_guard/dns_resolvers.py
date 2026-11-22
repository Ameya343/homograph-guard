"""Catalogue of public resolvers.

Every resolver is contacted on a *pinned* IP address; the TLS certificate is
verified against ``tls_host``. No system resolver is ever used, so neither the
local network's DNS nor a hijacked bootstrap lookup can influence results.

Sources (checked 2026-10):
  Google      https://developers.google.com/speed/public-dns
  Cloudflare  https://developers.cloudflare.com/1.1.1.1/setup/
              (1.1.1.2 "security" answers 0.0.0.0 for malicious domains)
  AdGuard     https://adguard-dns.io/en/public-dns.html
  Quad9       https://quad9.net/
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Resolver:
    key: str
    provider: str
    name: str
    filtering: bool
    ips: tuple[str, ...]
    tls_host: str
    doh_path: str = "/dns-query"
    peer: str | None = None  # unfiltered counterpart used to detect blocking
    blocks: str = ""
    block_networks: tuple[str, ...] = ()  # provider ranges that indicate a block page
    security_only: bool = False  # blocks only malware/phishing (stronger signal)
    doh_port: int = 443
    dot_port: int = 853
    udp_port: int = 53


CATALOG: dict[str, Resolver] = {
    r.key: r
    for r in (
        Resolver("google", "Google", "Google Public DNS", False, ("8.8.8.8", "8.8.4.4"), "dns.google"),
        Resolver("cloudflare", "Cloudflare", "Cloudflare 1.1.1.1", False, ("1.1.1.1", "1.0.0.1"),
                 "cloudflare-dns.com"),
        Resolver("cloudflare-security", "Cloudflare", "Cloudflare 1.1.1.2 (malware blocking)", True,
                 ("1.1.1.2", "1.0.0.2"), "security.cloudflare-dns.com", peer="cloudflare",
                 blocks="malware and phishing", security_only=True),
        Resolver("adguard-unfiltered", "AdGuard", "AdGuard DNS non-filtering", False,
                 ("94.140.14.140", "94.140.14.141"), "unfiltered.adguard-dns.com"),
        Resolver("adguard", "AdGuard", "AdGuard DNS default", True, ("94.140.14.14", "94.140.15.15"),
                 "dns.adguard-dns.com", peer="adguard-unfiltered",
                 blocks="ads, trackers and phishing", block_networks=("94.140.14.0/23",)),
        Resolver("adguard-family", "AdGuard", "AdGuard DNS family", True, ("94.140.14.15", "94.140.15.16"),
                 "family.adguard-dns.com", peer="adguard-unfiltered",
                 blocks="ads, trackers and adult content", block_networks=("94.140.14.0/23",)),
        Resolver("quad9", "Quad9", "Quad9 (threat blocking)", True, ("9.9.9.9", "149.112.112.112"),
                 "dns.quad9.net", peer="quad9-unfiltered", blocks="malware and phishing",
                 security_only=True),
        Resolver("quad9-unfiltered", "Quad9", "Quad9 unfiltered", False, ("9.9.9.10", "149.112.112.10"),
                 "dns10.quad9.net"),
    )
}

DEFAULT_RESOLVERS = ("google", "cloudflare", "cloudflare-security", "adguard", "adguard-unfiltered")


def select(keys: list[str] | tuple[str, ...]) -> list[Resolver]:
    """Resolve keys to resolvers, pulling in unfiltered peers needed for block detection."""
    chosen: list[str] = []
    for key in keys:
        key = key.strip().lower()
        if not key:
            continue
        if key not in CATALOG:
            raise ValueError(f"unknown resolver {key!r}; choose from {', '.join(CATALOG)}")
        if key not in chosen:
            chosen.append(key)
        peer = CATALOG[key].peer
        if peer and peer not in chosen:
            chosen.append(peer)
    return [CATALOG[k] for k in chosen]
