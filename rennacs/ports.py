"""Port lists and a small service-name table.

The named lists mirror the way real scanners ship "top N" port sets so a classroom
scan finishes quickly instead of walking all 65535 ports.
"""

from __future__ import annotations

import re

# A compact "top 100-ish" set: the ports most likely to be listening on real hosts.
TOP_100 = [
    7, 20, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
    139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544,
    548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1433, 1521, 1723,
    1883, 2000, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2181, 2375, 2376, 3000,
    3306, 3389, 3690, 4444, 4567, 4848, 5000, 5060, 5432, 5555, 5601, 5672, 5900,
    5984, 6000, 6379, 6443, 7000, 7001, 7077, 8000, 8008, 8080, 8081, 8083, 8086,
    8088, 8443, 8888, 9000, 9042, 9090, 9200, 9300, 11211, 27017,
]

# A tiny list for very fast smoke tests.
TOP_20 = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1723, 3306,
          3389, 5900, 8080, 8443, 8888]

# Curated TCP coverage, not a claim to enumerate all services or protocols.
# DNS, SMB, mail, databases and administrative endpoints are intentionally included.
WEB = sorted({80, 81, 443, 3000, 5000, 5601, 8000, 8008, 8080, 8081, 8083,
              8086, 8088, 8443, 8888, 9000, 9090})
REMOTE = sorted({21, 22, 23, 513, 514, 990, 1723, 3389, 5900, 5901, 5985, 5986})
MAIL = sorted({25, 110, 119, 143, 465, 587, 993, 995, 4190})
DATABASES = sorted({1433, 1521, 2181, 3306, 5432, 5984, 6379, 7000, 7001,
                    8086, 9042, 9160, 9200, 9300, 11211, 27017, 27018})
INFRASTRUCTURE = sorted({53, 88, 111, 135, 139, 179, 389, 445, 515, 548, 554,
                         631, 636, 873, 1883, 2049, 2375, 2376, 3268, 3269,
                         4369, 5060, 5061, 5671, 5672, 6443, 6514, 6667,
                         8530, 8531, 8883, 9092, 10000, 15672, 25672})
MULTISERVICE = sorted(set(TOP_100).union(WEB, REMOTE, MAIL, DATABASES, INFRASTRUCTURE))

NAMED = {
    "top20": TOP_20,
    "top100": TOP_100,
    "web": WEB,
    "remote": REMOTE,
    "mail": MAIL,
    "databases": DATABASES,
    "infrastructure": INFRASTRUCTURE,
    "multiservice": MULTISERVICE,
}


def resolve(spec: str) -> list[int]:
    """Resolve comma-separated TCP profiles, ports and inclusive ranges.

    ``all`` and ``all-tcp`` both mean 1..65535. Named profiles can be mixed
    with individual ports/ranges. Validate the ENTIRE specification and bound
    both range endpoints before expanding anything; malformed/empty specs raise
    ValueError rather than silently planning no work or allocating huge ranges.
    """
    if not isinstance(spec, str):
        raise ValueError("port specification must be a nonempty string")
    selections = []
    for part in spec.strip().lower().split(","):
        part = part.strip()
        if part in NAMED:
            selections.append(NAMED[part])
        elif part in {"all", "all-tcp"}:
            selections.append((1, 65535))
        else:
            match = re.fullmatch(r"([0-9]{1,5})(?:\s*-\s*([0-9]{1,5}))?", part)
            if not match:
                raise ValueError(f"invalid port or unknown TCP profile: {part!r}")
            lo = int(match[1])
            hi = int(match[2]) if match[2] is not None else lo
            if not 1 <= lo <= hi <= 65535:
                raise ValueError(f"port range must satisfy 1 <= start <= end <= 65535: {part!r}")
            selections.append((lo, hi))
    out: set[int] = set()
    for selection in selections:
        if isinstance(selection, tuple):
            out.update(range(selection[0], selection[1] + 1))
        else:
            out.update(selection)
    return sorted(out)


# Well-known service names, used as a fallback label when fingerprinting can't do
# better than "something is listening here".
SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 1433: "ms-sql", 1521: "oracle", 1883: "mqtt",
    3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql", 5601: "kibana",
    5672: "amqp", 5900: "vnc", 5984: "couchdb", 6379: "redis", 8080: "http-proxy",
    8443: "https-alt", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}
