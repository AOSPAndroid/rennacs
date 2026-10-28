"""Import REAL host data from Shodan InternetDB — real device data, no scanning.

The honest way to populate Rennacs with real internet-device data is NOT to scan the
internet yourself (abusive, and often illegal) — it's to read an existing, authorized,
legal data source. Shodan's `InternetDB <https://internetdb.shodan.io>`_ is a free,
no-API-key endpoint that returns a lightweight summary of what Shodan already crawled
for an IP: open ports, hostnames, CPEs (product/version), CVEs, and tags.

This module turns that into Rennacs host records:

* each open port becomes a service (product/version mapped from CPEs by typical port),
* the CPE OS becomes the host's OS,
* InternetDB's CVE list becomes real vuln tags (then enriched by :mod:`rennacs.cvenow`),
* hostnames and tags are stored for display and the ``tag:`` filter.

It reuses the hardened HTTP helper (host-allowlisted redirects, size cap) and caches
every lookup, so re-imports are free and the tool degrades gracefully if the API is
unreachable. Reading InternetDB is a passive database lookup, not a scan, so it isn't
gated by the scan-authorization policy.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
import time

from ._http import FETCH_ERRORS, SafeFetcher
from .ports import SERVICE_NAMES

BASE = "https://internetdb.shodan.io"
_TLS_PORTS = {443, 465, 636, 993, 995, 8443, 9443}
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)

# CPE product token -> (display name, typical ports) so we can attach a product/version
# to the right open port. Unknown products are title-cased and attached to any port.
_CPE_APP = {
    "openssh": ("OpenSSH", [22]),
    "http_server": ("Apache httpd", [80, 8080, 8000, 443, 8443]),
    "nginx": ("nginx", [80, 8080, 8000, 443, 8443]),
    "lighttpd": ("lighttpd", [80, 443]),
    "ntp": ("NTP", [123]),
    "mysql": ("MySQL", [3306]),
    "mariadb": ("MariaDB", [3306]),
    "postgresql": ("PostgreSQL", [5432]),
    "redis": ("Redis", [6379]),
    "exim": ("Exim", [25, 465, 587]),
    "postfix": ("Postfix", [25, 465, 587]),
    "dovecot": ("Dovecot", [110, 143, 993, 995]),
    "vsftpd": ("vsftpd", [21]),
    "proftpd": ("ProFTPD", [21]),
    "internet_information_services": ("Microsoft IIS", [80, 443, 8080, 8443]),
    "iis": ("Microsoft IIS", [80, 443, 8080, 8443]),
    "cloudflare": ("Cloudflare", [80, 443, 8080, 8443]),
    "openssl": ("OpenSSL", [443, 8443, 993, 995]),
}
_CPE_OS = {
    "ubuntu_linux": "Ubuntu", "debian_linux": "Debian", "windows": "Windows",
    "centos": "CentOS", "fedora": "Fedora", "freebsd": "FreeBSD",
    "linux_kernel": "Linux", "mac_os_x": "macOS",
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS idb_cache (
    ip         TEXT PRIMARY KEY,
    success    INTEGER,
    json       TEXT,
    fetched_at TEXT
);
"""


def _parse_cpe(cpe: str):
    """cpe:/a:openbsd:openssh:6.6.1p1 -> ('a', 'openssh', '6.6.1p1'). Best-effort."""
    s = cpe.strip()
    if s.startswith("cpe:2.3:"):
        parts = s.split(":")          # cpe:2.3:a:vendor:product:version:...
        if len(parts) >= 6:
            return parts[2], parts[4].lower(), (parts[5] if parts[5] != "*" else "")
        return "", "", ""
    m = re.match(r"cpe:/([aoh]):([^:]*):([^:]*)(?::([^:]*))?", s)
    if not m:
        return "", "", ""
    return m.group(1), (m.group(3) or "").lower(), (m.group(4) or "")


def normalize(ip: str, raw: dict) -> dict:
    """Turn an InternetDB response into a Rennacs host document (real data)."""
    ports = sorted({int(p) for p in (raw.get("ports") or []) if _is_port(p)})
    hostnames = [h for h in (raw.get("hostnames") or []) if h][:12]
    tags = [t for t in (raw.get("tags") or []) if t][:16]
    vulns = [c.upper() for c in (raw.get("vulns") or []) if _CVE_RE.match(str(c))]

    os_name = ""
    apps = []     # (display, version, typical_ports)
    for cpe in (raw.get("cpes") or []):
        kind, product, version = _parse_cpe(cpe)
        if not product:
            continue
        if kind == "o":
            os_name = os_name or _CPE_OS.get(product, product.replace("_", " ").title())
        elif kind == "a":
            disp, pports = _CPE_APP.get(product, (product.replace("_", " ").title(), []))
            apps.append((disp, version, pports))

    services = []
    for p in ports:
        svc = {"port": p, "transport": "tcp", "service": SERVICE_NAMES.get(p, ""),
               "os": os_name, "has_ssl": p in _TLS_PORTS, "vulns": []}
        for disp, ver, pports in apps:
            if p in pports:
                svc["product"], svc["version"] = disp, ver
                break
        services.append(svc)

    # An app CPE whose typical port wasn't in the port list still tells us the product —
    # attach the first such unmatched app to the first productless service.
    assigned = {s["port"] for s in services if s.get("product")}
    for disp, ver, pports in apps:
        if not any(p in assigned for p in pports):
            for s in services:
                if not s.get("product"):
                    s["product"], s["version"] = disp, ver
                    assigned.add(s["port"])
                    break

    # InternetDB vulns are host-level (not tied to a port). Attach them to the web
    # service when there is one (most such CVEs are web-service CVEs), else the first
    # product service, else the first service. cve.now then enriches them with real
    # CVSS/KEV. The summary says it's host-level so nothing is misattributed silently.
    if vulns and services:
        web = next((s for s in services if s.get("product")
                    and s["port"] in (80, 443, 8080, 8443)), None)
        target = web or next((s for s in services if s.get("product")), services[0])
        target["vulns"] = [{"cve": c, "severity": "", "source": "shodan-internetdb",
                            "summary": "Host-level vulnerability reported by Shodan "
                                       "InternetDB."}
                           for c in vulns]

    return {"ip": ip, "hostnames": hostnames, "tags": tags, "services": services}


def _is_port(p) -> bool:
    try:
        return 1 <= int(p) <= 65535
    except (TypeError, ValueError):
        return False


class InternetDB:
    """Cached client for Shodan InternetDB (free, no key)."""

    def __init__(self, db_path: str = "rennacs.db", *, timeout: float = 8.0,
                 offline: bool = False, now_iso: str = ""):
        self.db_path = db_path
        self.offline = offline
        self.timeout = timeout
        self._now = now_iso
        self._fetcher = SafeFetcher(allowed_hosts=("internetdb.shodan.io",),
                                    user_agent="Rennacs/0.3 internetdb")
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def _stamp(self) -> str:
        if self._now:
            return self._now
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()

    def _cached(self, ip: str):
        row = self.conn.execute(
            "SELECT success, json FROM idb_cache WHERE ip=?", (ip,)).fetchone()
        if row is None:
            return None
        if not row["success"]:
            return {"__absent__": True}
        try:
            return json.loads(row["json"])
        except (TypeError, ValueError):
            return None

    def lookup(self, ip: str, *, allow_network: bool = True) -> dict | None:
        """Return a normalized host doc for ``ip`` (real data), or None. Cache-first."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if addr.version != 4:
            return None
        cached = self._cached(ip)
        if cached is not None:
            return None if cached.get("__absent__") else cached
        if self.offline or not allow_network:
            return None
        try:
            raw = self._fetcher.get_json(f"{BASE}/{ip}", timeout=self.timeout)
        except FETCH_ERRORS:
            return None
        # InternetDB returns {"detail":"No information available"} (404) for unknown IPs.
        if not isinstance(raw, dict) or "ports" not in raw:
            self._store_absent(ip)
            return None
        doc = normalize(ip, raw)
        self._store(ip, doc)
        return doc

    def _store(self, ip: str, doc: dict) -> None:
        self.conn.execute(
            """INSERT INTO idb_cache(ip, success, json, fetched_at) VALUES(?,1,?,?)
               ON CONFLICT(ip) DO UPDATE SET success=1, json=excluded.json,
                   fetched_at=excluded.fetched_at""",
            (ip, json.dumps(doc), self._stamp()))
        self.conn.commit()

    def _store_absent(self, ip: str) -> None:
        self.conn.execute(
            """INSERT INTO idb_cache(ip, success, json, fetched_at) VALUES(?,0,NULL,?)
               ON CONFLICT(ip) DO UPDATE SET success=0, json=NULL,
                   fetched_at=excluded.fetched_at""",
            (ip, self._stamp()))
        self.conn.commit()

    def import_targets(self, ips: list[str], idx, *, rate: float = 1.0,
                       on_result=None) -> dict:
        """Look up each ip and index the real data it returns.

        ``rate`` throttles lookups/second (InternetDB's free tier is ~1/s). Returns
        {requested, found, services} counts.
        """
        counts = {"requested": 0, "found": 0, "services": 0}
        min_gap = 1.0 / rate if rate else 0.0
        last = 0.0
        for ip in ips:
            counts["requested"] += 1
            if min_gap and self._cached(ip) is None and not self.offline:
                wait = min_gap - (time.monotonic() - last)
                if wait > 0:
                    time.sleep(wait)
                last = time.monotonic()
            doc = self.lookup(ip)
            if doc and doc.get("services"):
                idx.insert_raw(doc)
                counts["found"] += 1
                counts["services"] += len(doc["services"])
            if on_result:
                on_result(ip, doc, counts)
        return counts


# A curated set of real, well-known public hosts to import for an instant real-data
# demo (public resolvers across the world + scanme.nmap.org, which exists for scan tests).
STARTER = [
    "45.33.32.156",      # scanme.nmap.org — rich, meant for testing
    "8.8.8.8", "8.8.4.4",          # Google
    "1.1.1.1", "1.0.0.1",          # Cloudflare
    "9.9.9.9",                     # Quad9
    "208.67.222.222",              # OpenDNS (US)
    "77.88.8.8",                   # Yandex (RU)
    "94.140.14.14",                # AdGuard (CY)
    "114.114.114.114",             # 114DNS (CN)
    "80.80.80.80",                 # Freenom World
    "185.228.168.9",               # CleanBrowsing
    "156.154.70.1",                # Neustar/UltraDNS
    "64.6.64.6",                   # UltraDNS
    "4.2.2.2",                     # Level3
]
