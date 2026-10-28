"""Port lists and a small service-name table.

The named lists mirror the way real scanners ship "top N" port sets so a classroom
scan finishes quickly instead of walking all 65535 ports.
"""

from __future__ import annotations

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

NAMED = {
    "top20": TOP_20,
    "top100": TOP_100,
}


def resolve(spec: str) -> list[int]:
    """Turn a ports spec into a sorted list of ints.

    Accepts a named list ("top20", "top100"), a comma list ("22,80,443"), ranges
    ("8000-8100"), or "all" (1-65535). Combinations like "22,80,8000-8100" work too.
    """
    spec = spec.strip().lower()
    if spec in NAMED:
        return sorted(NAMED[spec])
    if spec == "all":
        return list(range(1, 65536))

    out: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            out.update(range(int(lo), int(hi) + 1))
        else:
            out.add(int(part))
    bad = [p for p in out if not (1 <= p <= 65535)]
    if bad:
        raise ValueError(f"ports out of range: {sorted(bad)[:5]}")
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
