#!/usr/bin/env python3
"""Load a realistic demo dataset so you can explore the UI without scanning anything.

The banners below are hand-written samples of what real services return. They let you
try every filter (port, product, has_ssl, net, country, org, ...) against a varied set
of fake hosts. Run:

    python demo_seed.py            # writes into rennacs.db
    python cli.py web              # then browse http://127.0.0.1:5000
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone

from rennacs.db import Index

_now = datetime.now(timezone.utc)


def _ts(days_ago: float) -> str:
    return (_now - timedelta(days=days_ago)).isoformat()


DEMO = [
    {
        "ip": "192.168.1.10", "hostnames": ["gateway.lab.local"],
        "org": "Private network (RFC1918)", "seen_at": _ts(0.2),
        "services": [
            {"port": 22, "service": "ssh", "product": "OpenSSH", "version": "8.9p1",
             "os": "Ubuntu",
             "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"},
            {"port": 80, "service": "http", "product": "nginx", "version": "1.24.0",
             "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0 (Ubuntu)\r\n"
                       "Content-Type: text/html\r\nContent-Length: 612"},
            {"port": 443, "service": "https", "product": "nginx", "version": "1.24.0",
             "has_ssl": True, "ssl_cn": "gateway.lab.local",
             "ssl_issuer": "Rennacs Lab CA",
             "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0 (Ubuntu)"},
        ],
    },
    {
        "ip": "192.168.1.20", "hostnames": ["db01.lab.local"],
        "org": "Private network (RFC1918)", "seen_at": _ts(0.5),
        "services": [
            {"port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.6p1",
             "os": "Debian",
             "banner": "SSH-2.0-OpenSSH_9.6p1 Debian-3"},
            {"port": 3306, "service": "mysql", "product": "MySQL", "version": "8.0.36",
             "banner": "J\x00\x00\x00\n8.0.36-0ubuntu0.22.04.1\x00"},
            {"port": 6379, "service": "redis", "product": "Redis",
             "banner": "-ERR unknown command 'INFO', with args beginning with:\r\n"
                       "# Server\r\nredis_version:7.2.4"},
        ],
    },
    {
        "ip": "192.168.1.30", "hostnames": ["win-fs01.lab.local"],
        "org": "Private network (RFC1918)", "seen_at": _ts(1.1),
        "services": [
            {"port": 135, "service": "msrpc", "os": "Windows", "banner": ""},
            {"port": 445, "service": "microsoft-ds", "os": "Windows", "banner": ""},
            {"port": 3389, "service": "ms-wbt-server", "os": "Windows",
             "banner": ""},
            {"port": 8080, "service": "http", "product": "Microsoft IIS",
             "version": "10.0", "os": "Windows",
             "banner": "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n"
                       "X-Powered-By: ASP.NET"},
        ],
    },
    {
        "ip": "192.168.1.50", "hostnames": ["iot-cam.lab.local"],
        "org": "Private network (RFC1918)", "seen_at": _ts(2.3),
        "services": [
            {"port": 554, "service": "rtsp",
             "banner": "RTSP/1.0 200 OK\r\nServer: GStreamer RTSP server"},
            {"port": 80, "service": "http", "product": "lighttpd", "version": "1.4.55",
             "banner": "HTTP/1.1 401 Unauthorized\r\nServer: lighttpd/1.4.55\r\n"
                       "WWW-Authenticate: Basic realm=\"IP Camera\""},
        ],
    },
    {
        "ip": "10.0.0.5", "hostnames": ["mail.lab.local"],
        "org": "Private network (RFC1918)", "seen_at": _ts(0.8),
        "services": [
            {"port": 25, "service": "smtp", "product": "Postfix",
             "banner": "220 mail.lab.local ESMTP Postfix (Debian/GNU)"},
            {"port": 143, "service": "imap", "product": "Dovecot",
             "banner": "* OK [CAPABILITY IMAP4rev1] Dovecot ready."},
            {"port": 993, "service": "imaps", "product": "Dovecot", "has_ssl": True,
             "ssl_cn": "mail.lab.local", "ssl_issuer": "Rennacs Lab CA",
             "banner": "* OK [CAPABILITY IMAP4rev1] Dovecot ready."},
        ],
    },
    {
        "ip": "192.168.1.66", "hostnames": ["legacy-web.lab.local"],
        "org": "Private network (RFC1918)", "seen_at": _ts(3.0),
        "services": [
            # Deliberately old versions so the heuristic vuln tagger lights up.
            {"port": 21, "service": "ftp", "product": "vsftpd", "version": "2.3.4",
             "os": "Linux",
             "banner": "220 (vsFTPd 2.3.4)"},
            {"port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.2p1",
             "os": "Debian",
             "banner": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2"},
            {"port": 80, "service": "http", "product": "Apache httpd",
             "version": "2.4.49", "os": "CentOS",
             "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (CentOS)\r\n"
                       "Content-Type: text/html"},
        ],
    },
    # A couple of well-known PUBLIC resolvers, purely as recognisable demo data —
    # these were NOT scanned by Rennacs; the banners are illustrative.
    {
        "ip": "8.8.8.8", "hostnames": ["dns.google"],
        "country": "US", "city": "Mountain View", "org": "Google LLC",
        "asn": "AS15169", "seen_at": _ts(0.1),
        "services": [
            {"port": 53, "service": "dns", "banner": "(DNS recursion enabled)"},
            {"port": 443, "service": "https", "product": "HTTP server",
             "has_ssl": True, "ssl_cn": "dns.google",
             "ssl_issuer": "Google Trust Services",
             "banner": "HTTP/1.1 200 OK\r\nServer: scaffolding on HTTPServer2\r\n"
                       "Content-Type: text/html"},
        ],
    },
    {
        "ip": "1.1.1.1", "hostnames": ["one.one.one.one"],
        "country": "US", "city": "Los Angeles", "org": "Cloudflare, Inc.",
        "asn": "AS13335", "seen_at": _ts(0.3),
        "services": [
            {"port": 53, "service": "dns", "banner": "(DNS recursion enabled)"},
            {"port": 443, "service": "https", "product": "nginx", "has_ssl": True,
             "ssl_cn": "cloudflare-dns.com", "ssl_issuer": "DigiCert Inc",
             "banner": "HTTP/1.1 200 OK\r\nServer: cloudflare\r\n"
                       "Content-Type: text/html"},
        ],
    },
]


# A spread of well-known PUBLIC resolvers around the world. They carry no coordinates
# here, so `python cli.py geo` geolocates them live and they populate the world map
# across several countries. Banners are illustrative (these hosts were NOT scanned).
GLOBAL = [
    ("208.67.222.222", "resolver1.opendns.com", "OpenDNS, LLC"),
    ("77.88.8.8", "dns.yandex.ru", "Yandex LLC"),
    ("94.140.14.14", "dns.adguard-dns.com", "AdGuard"),
    ("114.114.114.114", "public1.114dns.com", "114DNS"),
    ("185.228.168.9", "security-filter-dns.cleanbrowsing.org", "CleanBrowsing"),
    ("80.80.80.80", "pdns.freenom.world", "Freenom World"),
    ("64.6.64.6", "rec1pubns1.ultradns.net", "UltraDNS"),
    ("156.154.70.1", "rdns1.neustar.biz", "Neustar"),
]
for _ip, _host, _org in GLOBAL:
    DEMO.append({
        "ip": _ip, "hostnames": [_host], "seen_at": _ts(1.0),
        "services": [
            {"port": 53, "service": "dns", "banner": "(DNS recursion enabled)"},
            {"port": 443, "service": "https", "product": "HTTP server", "has_ssl": True,
             "ssl_cn": _host, "ssl_issuer": "DigiCert Inc",
             "banner": f"HTTP/1.1 200 OK\r\nServer: dns-over-https\r\n"
                       f"Content-Type: application/dns-message"},
        ],
    })


def main() -> int:
    db = sys.argv[1] if len(sys.argv) > 1 else "rennacs.db"
    idx = Index(db)
    for doc in DEMO:
        idx.insert_raw(doc)
    s = idx.stats()
    idx.close()
    print(f"Seeded {len(DEMO)} hosts into {db}.")
    print(f"Index now holds {s['hosts']} hosts / {s['services']} services.")
    print("Optional: python cli.py enrich   (real CVSS + CISA-KEV from cve.now)")
    print("Launch the UI:  python cli.py web")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
