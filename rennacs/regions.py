"""Country/region scopes from RIPE delegated statistics.

Scanning "Europe" needs a definition, and the only defensible one is the registry's:
RIPE's delegated-extended file lists every IPv4 block and IPv6 prefix per country
code. This module turns that into scopes, so a sweep is a country list rather than a
hand-maintained CIDR soup.

IPv4 is finite and enumerable (Western + Eastern Europe is ~768M addresses). IPv6 is
not: a country holds hundreds of thousands of prefixes, so IPv6 scopes are prefix
lists to be sampled or intersected with a hitlist, never brute-forced.
"""

from __future__ import annotations

import ipaddress
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

DELEGATED = "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest"
CACHE_TTL = 24 * 3600

WESTERN_EUROPE = frozenset({
    "AD", "AT", "BE", "CH", "DE", "DK", "ES", "FI", "FO", "FR", "GB", "GG", "GI",
    "IE", "IM", "IS", "IT", "JE", "LI", "LU", "MC", "MT", "NL", "NO", "PT", "SE", "SM",
})
EASTERN_EUROPE = frozenset({
    "AL", "BA", "BG", "BY", "CZ", "EE", "GR", "HR", "HU", "LT", "LV", "MD", "ME",
    "MK", "PL", "RO", "RS", "RU", "SI", "SK", "TR", "UA", "XK",
})

REGIONS = {"western": WESTERN_EUROPE, "eastern": EASTERN_EUROPE}

# Only these are worth scanning: "available"/"reserved" blocks have no holder yet, so
# including them inflates the estimate and wastes packets on empty space.
_LIVE = {"allocated", "assigned"}


@dataclass
class Scope:
    countries: list[str] = field(default_factory=list)
    ipv4: list[ipaddress.IPv4Network] = field(default_factory=list)
    ipv6: list[ipaddress.IPv6Network] = field(default_factory=list)

    @property
    def ipv4_addresses(self) -> int:
        return sum(n.num_addresses for n in self.ipv4)

    def summary(self) -> dict:
        return {
            "countries": len(self.countries),
            "ipv4_blocks": len(self.ipv4),
            "ipv4_addresses": self.ipv4_addresses,
            "ipv6_prefixes": len(self.ipv6),
            "estimated_days_at_500cps": round(self.ipv4_addresses / 500 / 86400, 1),
        }


def fetch(path: Path, timeout: float = 120.0) -> Path:
    """Download (or reuse) the delegated file. Returns the local path."""
    if path.exists() and (time.time() - path.stat().st_mtime) < CACHE_TTL:
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(DELEGATED, timeout=timeout) as resp:
        path.write_bytes(resp.read(64_000_000))
    return path


def parse(path: Path, countries: set[str]) -> Scope:
    """Collect the delegated space of ``countries`` from a delegated file."""
    scope = Scope(countries=sorted(countries))
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split("|")
        if len(parts) < 7 or parts[1] not in countries:
            continue
        kind, start, value, status = parts[2], parts[3], parts[4], parts[6]
        if status not in _LIVE:
            continue
        try:
            count = int(value)
            first = ipaddress.ip_address(start)
            last = ipaddress.ip_address(int(first) + count - 1)
            nets = ipaddress.summarize_address_range(first, last)
        except (ValueError, TypeError):
            continue
        if kind == "ipv4":
            scope.ipv4.extend(n for n in nets if isinstance(n, ipaddress.IPv4Network))
        elif kind == "ipv6":
            scope.ipv6.extend(n for n in nets if isinstance(n, ipaddress.IPv6Network))
    return scope


def resolve(regions: list[str], countries: list[str] | None = None) -> set[str]:
    """Union the requested regions, optionally narrowed to explicit country codes."""
    picked: set[str] = set()
    for name in regions:
        key = name.strip().lower()
        if key not in REGIONS:
            raise ValueError(f"unknown region {name!r}; choose from {sorted(REGIONS)}")
        picked |= REGIONS[key]
    if countries:
        wanted = {c.strip().upper() for c in countries if c.strip()}
        unknown = wanted - picked
        if unknown:
            raise ValueError(f"countries outside the requested regions: {sorted(unknown)}")
        picked = wanted
    return picked
