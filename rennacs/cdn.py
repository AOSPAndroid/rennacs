"""Edge / CDN classification — is this address a WAF edge or a real origin?

A Shodan-style index is only half useful: the interesting question is *which*
addresses are edge nodes (Cloudflare, CloudFront, Akamai, Fastly, Azure, GCP) and
which are the origin servers hiding behind them. An origin that answers directly is
reachable with no WAF, no rate limit and no bot management.

Ranges are refreshed from each provider's published list and cached locally; a small
bundled seed keeps the classifier useful offline. A stale cache is reported as stale
rather than silently trusted, because a wrong "edge" verdict sends an operator to the
wrong host.
"""

from __future__ import annotations

import ipaddress
import json
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

CACHE_TTL = 7 * 24 * 3600

# Published, machine-readable sources. Each returns newline CIDRs or JSON we can map.
_SOURCES = {
    "cloudflare": ("https://www.cloudflare.com/ips-v4", "lines"),
    "fastly": ("https://api.fastly.com/public-ip-list", "fastly"),
    "cloudfront": ("https://ip-ranges.amazonaws.com/ip-ranges.json", "aws"),
}

# Offline seed: enough of each provider's space to classify correctly without network.
_SEED = {
    "cloudflare": [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    ],
    "fastly": ["151.101.0.0/16", "199.232.0.0/16", "23.235.32.0/20", "43.249.72.0/22"],
    "cloudfront": [
        "13.32.0.0/15", "13.224.0.0/14", "13.249.0.0/16", "13.227.0.0/16",
        "52.84.0.0/15", "54.182.0.0/16", "99.86.0.0/16", "18.238.0.0/15",
        "18.244.0.0/15", "3.160.0.0/14", "143.204.0.0/16", "3.162.0.0/16",
        "18.245.0.0/16", "3.165.0.0/16",
    ],
    "akamai": [
        "23.32.0.0/11", "23.192.0.0/11", "96.6.0.0/15", "96.16.0.0/15",
        "184.24.0.0/13", "104.64.0.0/10", "2.16.0.0/13", "88.221.0.0/16",
    ],
    "azure": ["13.107.0.0/16", "20.0.0.0/8", "40.64.0.0/10", "51.104.0.0/13"],
    "gcp": ["34.96.0.0/12", "35.190.0.0/17", "142.250.0.0/15", "34.111.0.0/16"],
    "imperva": ["45.60.0.0/16", "107.154.0.0/16", "199.83.128.0/21"],
    "sucuri": ["192.124.249.0/24", "66.248.200.0/22"],
}

# Providers whose edge is a reverse proxy for the *whole* site (so a hit means the
# origin is still hidden) versus ranges that are just "some cloud".
_PROXY_EDGE = {"cloudflare", "cloudfront", "akamai", "fastly", "imperva", "sucuri"}


@dataclass
class EdgeMap:
    """Classifies addresses against edge ranges, with provenance for every verdict."""

    path: Path | None = None
    _nets: dict[str, list[ipaddress._BaseNetwork]] = field(default_factory=dict)
    fetched_at: float = 0.0
    source: str = "seed"

    def __post_init__(self) -> None:
        if isinstance(self.path, str):
            self.path = Path(self.path)
        self._load()

    def _load(self) -> None:
        if self.path and self.path.exists():
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                self.fetched_at = float(raw.get("fetched_at", 0))
                self.source = "cache"
                for provider, cidrs in raw.get("ranges", {}).items():
                    self._nets[provider] = _parse(cidrs)
                return
            except (OSError, ValueError):
                pass
        self._nets = {p: _parse(c) for p, c in _SEED.items()}
        self.source = "seed"

    @property
    def stale(self) -> bool:
        return self.source != "cache" or (time.time() - self.fetched_at) > CACHE_TTL

    def refresh(self, timeout: float = 20.0) -> dict[str, int]:
        """Pull every published list. Returns provider -> CIDR count. Network errors are
        per-provider and never abort the whole refresh."""
        out: dict[str, int] = {}
        ranges: dict[str, list[str]] = {}
        for provider, (url, kind) in _SOURCES.items():
            try:
                with urllib.request.urlopen(url, timeout=timeout) as resp:
                    body = resp.read(4_000_000).decode("utf-8", "replace")
                cidrs = _extract(body, kind)
            except Exception:  # noqa: BLE001 - one dead source must not kill the refresh
                cidrs = []
            if cidrs:
                ranges[provider] = cidrs
                out[provider] = len(cidrs)
        if not ranges:
            return out
        # Keep seed ranges for providers we could not refresh, so a partial outage
        # never narrows the classifier.
        for provider, cidrs in _SEED.items():
            ranges.setdefault(provider, cidrs)
        self._nets = {p: _parse(c) for p, c in ranges.items()}
        self.fetched_at = time.time()
        self.source = "cache"
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(
                json.dumps({"fetched_at": self.fetched_at, "ranges": ranges}),
                encoding="utf-8",
            )
        return out

    def classify(self, ip: str) -> str | None:
        """Return the provider name when ``ip`` is an edge address, else ``None``."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for provider, nets in self._nets.items():
            if any(addr in net for net in nets):
                return provider
        return None

    def is_proxy_edge(self, ip: str) -> bool:
        return self.classify(ip) in _PROXY_EDGE


def _parse(cidrs: list[str]) -> list[ipaddress._BaseNetwork]:
    nets = []
    for cidr in cidrs:
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    return nets


def _extract(body: str, kind: str) -> list[str]:
    if kind == "lines":
        return [ln.strip() for ln in body.splitlines() if "/" in ln]
    if kind == "fastly":
        data = json.loads(body)
        return list(data.get("addresses", [])) + list(data.get("ipv6_addresses", []))
    if kind == "aws":
        data = json.loads(body)
        return [p["ip_prefix"] for p in data.get("prefixes", [])
                if p.get("service") == "CLOUDFRONT"]
    return []
