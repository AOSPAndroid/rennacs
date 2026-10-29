"""Certificate-transparency harvest and origin/grey-cloud classification.

Every publicly trusted certificate is logged. A CT log therefore hands you the
hostname inventory of a target for free — including the `dev`, `staging` and
`admin` names that never appear in a sitemap.

The valuable part is not the list, it is the split: names that resolve to an edge
provider are the protected surface, names that resolve straight to a hosting IP are
the origin surface. Those are the ones worth pointing a scanner at.
"""

from __future__ import annotations

import json
import socket
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from .cdn import EdgeMap

CRT_SH = "https://crt.sh/?q={q}&output=json"
_MAX_BYTES = 8_000_000


@dataclass
class HostClass:
    name: str
    addresses: list[str] = field(default_factory=list)
    edge: str | None = None

    @property
    def is_origin(self) -> bool:
        return bool(self.addresses) and self.edge is None


def harvest(domain: str, timeout: float = 45.0) -> list[str]:
    """Return every hostname CT logs know for ``domain`` (wildcards stripped)."""
    query = urllib.parse.quote(f"%.{domain}")
    req = urllib.request.Request(
        CRT_SH.format(q=query),
        headers={"User-Agent": "Rennacs/0.1 (+ct-harvest)", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read(_MAX_BYTES).decode("utf-8", "replace")
    names: set[str] = set()
    for entry in json.loads(body):
        for raw in str(entry.get("name_value", "")).splitlines():
            name = raw.strip().lower().lstrip("*.").rstrip(".")
            if name.endswith(domain) and " " not in name:
                names.add(name)
    return sorted(names)


def resolve(name: str, timeout: float = 5.0) -> list[str]:
    """Resolve A/AAAA records, best effort, deduplicated and sorted."""
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(name, None)
    except (socket.gaierror, OSError):
        return []
    finally:
        socket.setdefaulttimeout(old)
    return sorted({str(info[4][0]) for info in infos})


def classify(names: list[str], edges: EdgeMap, workers: int = 24) -> list[HostClass]:
    """Resolve and label each name. Pure DNS: no packets reach the target."""
    from concurrent.futures import ThreadPoolExecutor

    def one(name: str) -> HostClass:
        addrs = resolve(name)
        provider = None
        for addr in addrs:
            provider = edges.classify(addr)
            if provider:
                break
        return HostClass(name=name, addresses=addrs, edge=provider)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(one, names))


def split(classes: list[HostClass]) -> tuple[list[HostClass], list[HostClass]]:
    """(origin candidates, edge-protected hosts)."""
    origins = [c for c in classes if c.is_origin]
    protected = [c for c in classes if c.edge]
    return origins, protected
