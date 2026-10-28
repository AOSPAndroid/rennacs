"""Naive vulnerability tagging — the Rennacs take on Shodan's `vuln:` / CVE tags.

Given a fingerprinted (product, version), this matches a small, hand-written rule set
and returns the CVEs that *version ranges* suggest the host might be exposed to.

This is deliberately simple and **advisory only**. Real exposure depends on backported
patches, configuration, and distro versioning that a banner can't reveal (a "nginx
1.18.0" on Debian may well be patched). The point is to show the *mechanism* — map a
service fingerprint to known-CVE heuristics — not to be a scanner you'd trust.

Each rule matches a product and an optional version window [min_version, max_version)
plus optional exact versions. Version comparison ignores suffixes like "p1"/"-3ubuntu".
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Vuln:
    cve: str
    severity: str        # low | medium | high | critical
    summary: str

    def as_dict(self) -> dict:
        return {"cve": self.cve, "severity": self.severity, "summary": self.summary}


# Rule: product (exact, case-insensitive), optional min/max version, optional exact set.
# A version matches when: (min is None or v >= min) and (max is None or v < max),
# OR v is in the exact set.
_RULES = [
    {
        "product": "OpenSSH", "min": "8.5", "max": "9.8",
        "vuln": Vuln("CVE-2024-6387", "high",
                     "regreSSHion: unauthenticated RCE in sshd (8.5p1–9.7p1)"),
    },
    {
        "product": "nginx", "max": "1.21.0",
        "vuln": Vuln("CVE-2021-23017", "high",
                     "Off-by-one in the DNS resolver, potential RCE"),
    },
    {
        "product": "Apache httpd", "exact": {"2.4.49"},
        "vuln": Vuln("CVE-2021-41773", "critical",
                     "Path traversal and RCE via mod_cgi"),
    },
    {
        "product": "Apache httpd", "exact": {"2.4.49", "2.4.50"},
        "vuln": Vuln("CVE-2021-42013", "critical",
                     "Path traversal / RCE (incomplete fix for CVE-2021-41773)"),
    },
    {
        "product": "vsftpd", "exact": {"2.3.4"},
        "vuln": Vuln("CVE-2011-2523", "critical",
                     "Backdoor command execution in vsftpd 2.3.4"),
    },
    {
        "product": "Exim", "max": "4.94.2",
        "vuln": Vuln("CVE-2020-28017", "high",
                     "'21Nails' buffer overflow family in Exim < 4.94.2"),
    },
    {
        "product": "Microsoft IIS", "exact": {"6.0"},
        "vuln": Vuln("CVE-2017-7269", "high",
                     "Buffer overflow in the WebDAV ScStoragePathFromUrl"),
    },
]


def _parse_version(v: str) -> tuple[int, ...]:
    """Extract a comparable numeric tuple from a version string.

    "9.6p1" -> (9, 6); "1.24.0" -> (1, 24, 0); "2.4.49" -> (2, 4, 49). Non-numeric
    suffixes are dropped. Returns () when no numbers are present.
    """
    m = re.match(r"\s*(\d+(?:\.\d+)*)", v or "")
    if not m:
        return ()
    return tuple(int(x) for x in m.group(1).split("."))


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    """Compare two version tuples, padding the shorter with zeros."""
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def check(product: str, version: str) -> list[Vuln]:
    """Return the Vulns suggested for a (product, version). Empty if none/unknown."""
    if not product:
        return []
    v = _parse_version(version)
    out: list[Vuln] = []
    for rule in _RULES:
        if rule["product"].lower() != product.lower():
            continue
        exact = rule.get("exact")
        if exact and version in exact:
            out.append(rule["vuln"])
            continue
        if not v:
            continue  # need a parseable version for range rules
        lo = rule.get("min")
        hi = rule.get("max")
        if lo is not None and _cmp(v, _parse_version(lo)) < 0:
            continue
        if hi is not None and _cmp(v, _parse_version(hi)) >= 0:
            continue
        if lo is None and hi is None:
            continue  # a pure-exact rule that didn't match above
        out.append(rule["vuln"])
    # de-dup by CVE, keep order
    seen, deduped = set(), []
    for vl in out:
        if vl.cve not in seen:
            seen.add(vl.cve)
            deduped.append(vl)
    return deduped
