"""Banner -> (product, version, os) fingerprinting.

This is the small, readable cousin of Shodan's service-detection database. Each rule is
a regular expression over a service banner; the first match fills in product / version /
os on the ServiceResult. The goal is to show the *mechanism* (regex rules over banners)
rather than to be exhaustive.

A rule is: (compiled_regex, product, extract_version_fn, os_hint, service_hint)
"""

from __future__ import annotations

import re

# Each entry: pattern, product, version-group-name (or None), os_hint, service_hint
_RULES = [
    # SSH, e.g. "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
    (r"SSH-\d+\.\d+-OpenSSH[_-](?P<version>[\w.]+)", "OpenSSH", "version",
     None, "ssh"),
    (r"SSH-\d+\.\d+-(?P<raw>dropbear[_-]?(?P<version>[\w.]+)?)", "Dropbear SSH",
     "version", None, "ssh"),
    (r"SSH-\d+\.\d+-", "SSH", None, None, "ssh"),

    # HTTP Server header, e.g. "Server: nginx/1.25.3"
    (r"[Ss]erver:\s*nginx/(?P<version>[\w.]+)", "nginx", "version", None, "http"),
    (r"[Ss]erver:\s*nginx", "nginx", None, None, "http"),
    (r"[Ss]erver:\s*Apache/(?P<version>[\w.]+)", "Apache httpd", "version",
     None, "http"),
    (r"[Ss]erver:\s*Apache", "Apache httpd", None, None, "http"),
    (r"[Ss]erver:\s*Microsoft-IIS/(?P<version>[\w.]+)", "Microsoft IIS", "version",
     "Windows", "http"),
    (r"[Ss]erver:\s*lighttpd/(?P<version>[\w.]+)", "lighttpd", "version", None,
     "http"),
    (r"[Ss]erver:\s*Caddy", "Caddy", None, None, "http"),
    (r"[Ss]erver:\s*gunicorn/(?P<version>[\w.]+)", "gunicorn", "version", None,
     "http"),
    (r"[Ss]erver:\s*Werkzeug/(?P<version>[\w.]+)", "Werkzeug", "version", None,
     "http"),
    (r"HTTP/1\.[01]\s+\d{3}", "HTTP server", None, None, "http"),

    # Both FTP and SMTP greet with a "220" line, so the specific product rules for
    # BOTH protocols must come before either generic "220" catch-all — otherwise a
    # generic FTP rule would swallow "220 ... ESMTP Postfix". Order within here is
    # specific-product-first, generic-last.

    # FTP, e.g. "220 (vsFTPd 3.0.5)"
    (r"220.*vsFTPd (?P<version>[\w.]+)", "vsftpd", "version", "Linux", "ftp"),
    (r"220.*ProFTPD (?P<version>[\w.]+)", "ProFTPD", "version", None, "ftp"),
    (r"220.*FileZilla Server", "FileZilla Server", None, "Windows", "ftp"),

    # SMTP, e.g. "220 mail.example.com ESMTP Postfix"
    (r"220.*Postfix", "Postfix", None, None, "smtp"),
    (r"220.*Exim (?P<version>[\w.]+)", "Exim", "version", None, "smtp"),
    (r"220.*Microsoft ESMTP", "Microsoft Exchange", None, "Windows", "smtp"),
    (r"^220[ -].*(SMTP|ESMTP)", "SMTP server", None, None, "smtp"),

    # Generic FTP catch-all LAST: only a bare "220" with no SMTP marker reaches here.
    (r"^220[ -]", "FTP server", None, None, "ftp"),

    # Databases
    (r"(?P<version>\d+\.\d+\.\d+)\x00.*mysql_native_password", "MySQL", "version",
     None, "mysql"),
    (r"[\x05-\x0a]\x00\x00\x00.{0,2}(?P<version>\d+\.\d+\.\d+)", "MySQL", "version",
     None, "mysql"),
    (r"-ERR .*redis", "Redis", None, None, "redis"),
    (r"redis_version:(?P<version>[\w.]+)", "Redis", "version", None, "redis"),
    (r"\$\d+\r\n# Server", "Redis", None, None, "redis"),
    (r"MongoDB", "MongoDB", None, None, "mongodb"),

    # Caching / messaging
    (r"VERSION (?P<version>[\w.]+)", "Memcached", "version", None, "memcached"),

    # Mail / IMAP / POP
    (r"\* OK.*Dovecot", "Dovecot", None, None, "imap"),
    (r"\+OK.*POP3", "POP3 server", None, None, "pop3"),
    (r"\* OK.*IMAP", "IMAP server", None, None, "imap"),

    # RDP / VNC
    (r"RFB (?P<version>\d+\.\d+)", "VNC", "version", None, "vnc"),

    # Telnet
    (r"\xff[\xfb-\xfe]", "Telnet", None, None, "telnet"),
]

_COMPILED = [(re.compile(p, re.I | re.S), prod, ver, os_, svc)
             for (p, prod, ver, os_, svc) in _RULES]


def fingerprint(svc) -> None:
    """Mutate ``svc`` in place, filling product/version/os/service from its banner."""
    banner = svc.banner or ""
    for rx, product, ver_group, os_hint, svc_hint in _COMPILED:
        m = rx.search(banner)
        if not m:
            continue
        svc.product = product
        if ver_group:
            try:
                svc.version = m.group(ver_group) or ""
            except (IndexError, re.error):
                svc.version = ""
        if os_hint and not svc.os:
            svc.os = os_hint
        if svc_hint and not svc.service:
            svc.service = svc_hint
        # also sniff an OS token out of the banner tail (e.g. "Ubuntu", "Debian")
        _os = _os_from_banner(banner)
        if _os and not svc.os:
            svc.os = _os
        return
    # No product match: at least keep the coarse service name from the port table.
    _os = _os_from_banner(banner)
    if _os and not svc.os:
        svc.os = _os


_OS_TOKENS = [
    (r"Ubuntu", "Ubuntu"),
    (r"Debian", "Debian"),
    (r"CentOS", "CentOS"),
    (r"Red Hat|RHEL", "Red Hat"),
    (r"Fedora", "Fedora"),
    (r"Win(dows|64|32)", "Windows"),
    (r"FreeBSD", "FreeBSD"),
    (r"Alpine", "Alpine Linux"),
    (r"Raspbian", "Raspbian"),
]
_OS_COMPILED = [(re.compile(p, re.I), name) for p, name in _OS_TOKENS]


def _os_from_banner(banner: str) -> str:
    for rx, name in _OS_COMPILED:
        if rx.search(banner):
            return name
    return ""
