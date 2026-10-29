"""Static synthetic inventory for isolated automated tests only.

No host below was scanned. Banners, locations and advisory correlations are
invented test inputs, including entries that use recognizable public IPs.
Never import this module from production code or load it into a user database.
"""

from copy import deepcopy
import hashlib
import json


def with_test_source(doc: dict) -> dict:
    """Copy synthetic input and simulate a validated import only inside tests.

    The reserved .invalid reference cannot be mistaken for a live data provider.
    Hash the original JSON input, not its mutable copy or generated metadata.
    """
    result = deepcopy(doc)
    payload = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    result["provenance"] = {
        "kind": "import", "source": "test-fixture",
        "retrieved_at": "2026-10-27T00:00:00+00:00",
        "reference": "https://fixtures.invalid/inventory",
        "payload_sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
    }
    return result


TEST_DATA = [
    {
        "ip": "192.168.1.10", "hostnames": ["gateway.lab.local"],
        "org": "Private network (RFC1918)", "seen_at": "2026-10-26T19:12:00+00:00",
        "services": [
            {"port": 22, "service": "ssh", "product": "OpenSSH", "version": "8.9p1",
             "os": "Ubuntu", "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"},
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
        "org": "Private network (RFC1918)", "seen_at": "2026-10-26T12:00:00+00:00",
        "services": [
            {"port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.6p1",
             "os": "Debian", "banner": "SSH-2.0-OpenSSH_9.6p1 Debian-3"},
            {"port": 3306, "service": "mysql", "product": "MySQL", "version": "8.0.36",
             "banner": "J\x00\x00\x00\n8.0.36-0ubuntu0.22.04.1\x00"},
            {"port": 6379, "service": "redis", "product": "Redis",
             "banner": "-ERR unknown command 'INFO', with args beginning with:\r\n"
                       "# Server\r\nredis_version:7.2.4"},
        ],
    },
    {
        "ip": "192.168.1.30", "hostnames": ["win-fs01.lab.local"],
        "org": "Private network (RFC1918)", "seen_at": "2026-10-25T21:36:00+00:00",
        "services": [
            {"port": 135, "service": "msrpc", "os": "Windows", "banner": ""},
            {"port": 445, "service": "microsoft-ds", "os": "Windows", "banner": ""},
            {"port": 3389, "service": "ms-wbt-server", "os": "Windows", "banner": ""},
            {"port": 8080, "service": "http", "product": "Microsoft IIS",
             "version": "10.0", "os": "Windows",
             "banner": "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n"
                       "X-Powered-By: ASP.NET"},
        ],
    },
    {
        "ip": "192.168.1.50", "hostnames": ["iot-cam.lab.local"],
        "org": "Private network (RFC1918)", "seen_at": "2026-10-24T16:48:00+00:00",
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
        "org": "Private network (RFC1918)", "seen_at": "2026-10-26T04:48:00+00:00",
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
        "org": "Private network (RFC1918)", "seen_at": "2026-10-24T00:00:00+00:00",
        "services": [
            {"port": 21, "service": "ftp", "product": "vsftpd", "version": "2.3.4",
             "os": "Linux", "banner": "220 (vsFTPd 2.3.4)"},
            {"port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.2p1",
             "os": "Debian", "banner": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2"},
            {"port": 80, "service": "http", "product": "Apache httpd",
             "version": "2.4.49", "os": "CentOS",
             "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (CentOS)\r\n"
                       "Content-Type: text/html"},
        ],
    },
    {
        "ip": "8.8.8.8", "hostnames": ["dns.google"],
        "country": "US", "city": "Mountain View", "org": "Google LLC",
        "asn": "AS15169", "lat": 37.386, "lon": -122.084,
        "seen_at": "2026-10-26T21:36:00+00:00",
        "services": [
            {"port": 53, "service": "dns", "banner": "(DNS recursion enabled)"},
            {"port": 443, "service": "https", "product": "HTTP server",
             "has_ssl": True, "ssl_cn": "dns.google", "ssl_issuer": "Google Trust Services",
             "banner": "HTTP/1.1 200 OK\r\nServer: scaffolding on HTTPServer2\r\n"
                       "Content-Type: text/html"},
        ],
    },
    {
        "ip": "1.1.1.1", "hostnames": ["one.one.one.one"],
        "country": "US", "city": "Los Angeles", "org": "Cloudflare, Inc.",
        "asn": "AS13335", "lat": 34.053, "lon": -118.243,
        "seen_at": "2026-10-26T16:48:00+00:00",
        "services": [
            {"port": 53, "service": "dns", "banner": "(DNS recursion enabled)"},
            {"port": 443, "service": "https", "product": "nginx", "has_ssl": True,
             "ssl_cn": "cloudflare-dns.com", "ssl_issuer": "DigiCert Inc",
             "banner": "HTTP/1.1 200 OK\r\nServer: cloudflare\r\nContent-Type: text/html"},
        ],
    },
    {
        "ip": "208.67.222.222", "hostnames": ["resolver1.opendns.com"],
        "seen_at": "2026-10-26T00:00:00+00:00",
        "services": [
            {"port": 53, "service": "dns", "banner": "(DNS recursion enabled)"},
            {"port": 443, "service": "https", "product": "HTTP server", "has_ssl": True,
             "ssl_cn": "resolver1.opendns.com", "ssl_issuer": "DigiCert Inc",
             "banner": "HTTP/1.1 200 OK\r\nServer: dns-over-https\r\n"
                       "Content-Type: application/dns-message"},
        ],
    },
    {
        "ip": "77.88.8.8", "hostnames": ["dns.yandex.ru"],
        "seen_at": "2026-10-26T00:00:00+00:00",
        "services": [
            {"port": 53, "service": "dns", "banner": "(DNS recursion enabled)"},
            {"port": 443, "service": "https", "product": "HTTP server", "has_ssl": True,
             "ssl_cn": "dns.yandex.ru", "ssl_issuer": "DigiCert Inc",
             "banner": "HTTP/1.1 200 OK\r\nServer: dns-over-https\r\n"
                       "Content-Type: application/dns-message"},
        ],
    },
    {
        "ip": "94.140.14.14", "hostnames": ["dns.adguard-dns.com"],
        "seen_at": "2026-10-26T00:00:00+00:00",
        "services": [
            {"port": 53, "service": "dns", "banner": "(DNS recursion enabled)"},
            {"port": 443, "service": "https", "product": "HTTP server", "has_ssl": True,
             "ssl_cn": "dns.adguard-dns.com", "ssl_issuer": "DigiCert Inc",
             "banner": "HTTP/1.1 200 OK\r\nServer: dns-over-https\r\n"
                       "Content-Type: application/dns-message"},
        ],
    },
    {
        "ip": "114.114.114.114", "hostnames": ["public1.114dns.com"],
        "seen_at": "2026-10-26T00:00:00+00:00",
        "services": [
            {"port": 53, "service": "dns", "banner": "(DNS recursion enabled)"},
            {"port": 443, "service": "https", "product": "HTTP server", "has_ssl": True,
             "ssl_cn": "public1.114dns.com", "ssl_issuer": "DigiCert Inc",
             "banner": "HTTP/1.1 200 OK\r\nServer: dns-over-https\r\n"
                       "Content-Type: application/dns-message"},
        ],
    },
    {
        "ip": "185.228.168.9", "hostnames": ["security-filter-dns.cleanbrowsing.org"],
        "seen_at": "2026-10-26T00:00:00+00:00",
        "services": [
            {"port": 53, "service": "dns", "banner": "(DNS recursion enabled)"},
            {"port": 443, "service": "https", "product": "HTTP server", "has_ssl": True,
             "ssl_cn": "security-filter-dns.cleanbrowsing.org", "ssl_issuer": "DigiCert Inc",
             "banner": "HTTP/1.1 200 OK\r\nServer: dns-over-https\r\n"
                       "Content-Type: application/dns-message"},
        ],
    },
    {
        "ip": "80.80.80.80", "hostnames": ["pdns.freenom.world"],
        "seen_at": "2026-10-26T00:00:00+00:00",
        "services": [
            {"port": 53, "service": "dns", "banner": "(DNS recursion enabled)"},
            {"port": 443, "service": "https", "product": "HTTP server", "has_ssl": True,
             "ssl_cn": "pdns.freenom.world", "ssl_issuer": "DigiCert Inc",
             "banner": "HTTP/1.1 200 OK\r\nServer: dns-over-https\r\n"
                       "Content-Type: application/dns-message"},
        ],
    },
    {
        "ip": "64.6.64.6", "hostnames": ["rec1pubns1.ultradns.net"],
        "seen_at": "2026-10-26T00:00:00+00:00",
        "services": [
            {"port": 53, "service": "dns", "banner": "(DNS recursion enabled)"},
            {"port": 443, "service": "https", "product": "HTTP server", "has_ssl": True,
             "ssl_cn": "rec1pubns1.ultradns.net", "ssl_issuer": "DigiCert Inc",
             "banner": "HTTP/1.1 200 OK\r\nServer: dns-over-https\r\n"
                       "Content-Type: application/dns-message"},
        ],
    },
    {
        "ip": "156.154.70.1", "hostnames": ["rdns1.neustar.biz"],
        "seen_at": "2026-10-26T00:00:00+00:00",
        "services": [
            {"port": 53, "service": "dns", "banner": "(DNS recursion enabled)"},
            {"port": 443, "service": "https", "product": "HTTP server", "has_ssl": True,
             "ssl_cn": "rdns1.neustar.biz", "ssl_issuer": "DigiCert Inc",
             "banner": "HTTP/1.1 200 OK\r\nServer: dns-over-https\r\n"
                       "Content-Type: application/dns-message"},
        ],
    },
]
