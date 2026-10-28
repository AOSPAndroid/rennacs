"""The scanner: the Rennacs equivalent of Shodan's crawlers.

For each (host, port) it does a plain TCP connect, then tries to coax a banner out of
the service, and for TLS ports it reads the certificate subject. Everything is a
*connect* scan (full handshake) using asyncio, which is the friendly, unprivileged way
to do this — no raw sockets, no SYN scanning.

The scan is small by design. It walks an explicit target list and an explicit port
list, every target passes through :mod:`rennacs.authz` first, and concurrency is
bounded so it behaves on a lab network.
"""

from __future__ import annotations

import asyncio
import ipaddress
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import ports as portlib
from .authz import NotAuthorized, Policy
from .fingerprint import fingerprint
from .vulns import check as vulncheck

# Probes we send for services that stay silent until spoken to. Keyed by port; the
# default is "send nothing and just read" (works for SSH, FTP, SMTP, etc. which greet
# you first).
_PROBES = {
    80: b"GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: Rennacs/0.1\r\n\r\n",
    8080: b"GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: Rennacs/0.1\r\n\r\n",
    8000: b"GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: Rennacs/0.1\r\n\r\n",
    8888: b"GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: Rennacs/0.1\r\n\r\n",
    443: b"GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: Rennacs/0.1\r\n\r\n",
    8443: b"GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: Rennacs/0.1\r\n\r\n",
    6379: b"INFO\r\n",            # redis
    11211: b"version\r\n",        # memcached
}

_TLS_PORTS = {443, 465, 636, 993, 995, 8443, 9443}


@dataclass
class ServiceResult:
    """One open port on one host — Shodan calls this a 'banner'."""

    port: int
    transport: str = "tcp"
    banner: str = ""
    service: str = ""        # coarse name, e.g. "http"
    product: str = ""        # fingerprinted, e.g. "nginx"
    version: str = ""
    os: str = ""
    has_ssl: bool = False
    ssl_cn: str = ""         # certificate subject common name
    ssl_issuer: str = ""
    vulns: list = field(default_factory=list)  # list of {cve, severity, summary}
    seen_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class HostResult:
    """Everything Rennacs knows about one host — the indexed 'document'."""

    ip: str
    hostnames: list[str] = field(default_factory=list)
    services: list[ServiceResult] = field(default_factory=list)
    seen_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def expand_targets(spec: str) -> list[str]:
    """Expand a target spec into individual IP strings.

    Accepts a single IP, a CIDR ("192.168.1.0/24"), or a comma-separated mix. For
    CIDRs the network/broadcast addresses are dropped for IPv4 /31-and-wider blocks.
    Hostnames are returned as-is (the scanner resolves them at connect time).
    """
    out: list[str] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            net = ipaddress.ip_network(part, strict=False)
        except ValueError:
            out.append(part)   # a hostname
            continue
        if net.num_addresses == 1:
            out.append(str(net.network_address))
        else:
            hosts = list(net.hosts())
            out.extend(str(h) for h in hosts)
    return out


async def _grab(host: str, port: int, timeout: float) -> ServiceResult | None:
    """Connect to one port; return a ServiceResult if open, else None."""
    use_tls = port in _TLS_PORTS
    ssl_cn = ssl_issuer = ""
    banner = ""

    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx), timeout
            )
            # Pull the peer certificate subject / issuer for the SSL panel.
            try:
                sslobj = writer.get_extra_info("ssl_object")
                cert = sslobj.getpeercert() if sslobj else None
                if cert:
                    ssl_cn = _rdn(cert.get("subject"), "commonName")
                    ssl_issuer = _rdn(cert.get("issuer"), "organizationName") or \
                        _rdn(cert.get("issuer"), "commonName")
            except Exception:
                pass
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout
            )
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None

    try:
        probe = _PROBES.get(port)
        if probe is not None:
            try:
                writer.write(probe % host.encode() if b"%s" in probe else probe)
                await writer.drain()
            except Exception:
                pass
        try:
            data = await asyncio.wait_for(reader.read(2048), timeout)
            banner = data.decode("latin-1", "replace").strip()
        except asyncio.TimeoutError:
            banner = ""
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    svc = ServiceResult(
        port=port,
        banner=banner,
        service=portlib.SERVICE_NAMES.get(port, ""),
        has_ssl=use_tls,
        ssl_cn=ssl_cn,
        ssl_issuer=ssl_issuer,
    )
    fingerprint(svc)   # fills product / version / os / refines service
    svc.vulns = [v.as_dict() for v in vulncheck(svc.product, svc.version)]
    return svc


def _rdn(name, key: str) -> str:
    """Pull a value (by key) out of a getpeercert() subject/issuer tuple-of-tuples."""
    if not name:
        return ""
    for rdn in name:
        for k, v in rdn:
            if k == key:
                return v
    return ""


async def scan_host(host: str, port_list: list[int], *, timeout: float = 2.0,
                    concurrency: int = 200) -> HostResult:
    """Scan one host across ``port_list`` and return a HostResult (open ports only)."""
    sem = asyncio.Semaphore(concurrency)

    async def one(p: int):
        async with sem:
            return await _grab(host, p, timeout)

    results = await asyncio.gather(*(one(p) for p in port_list))
    services = [r for r in results if r is not None]
    services.sort(key=lambda s: s.port)
    return HostResult(ip=host, services=services)


async def scan(targets: str, port_spec: str = "top100", *, policy: Policy | None = None,
               timeout: float = 2.0, host_concurrency: int = 32,
               on_host=None) -> list[HostResult]:
    """Scan every host in ``targets`` across ``port_spec``.

    ``policy`` gates which hosts may be scanned. ``on_host`` is an optional callback
    invoked with each HostResult as it completes (used by the CLI for live output and
    to stream rows into the index).
    """
    policy = policy or Policy()
    port_list = portlib.resolve(port_spec)
    hosts = expand_targets(targets)

    allowed: list[str] = []
    for h in hosts:
        try:
            # Hostnames can't be policy-checked until resolved; allow and let the OS
            # resolve. For lab/classroom use targets are usually literal IPs.
            ipaddress.ip_address(h)
            policy.check(h)
        except NotAuthorized:
            raise
        except ValueError:
            pass  # hostname — allowed through
        allowed.append(h)

    sem = asyncio.Semaphore(host_concurrency)
    out: list[HostResult] = []

    async def one(h: str):
        async with sem:
            hr = await scan_host(h, port_list, timeout=timeout)
            if hr.services:           # only keep hosts that answered
                out.append(hr)
                if on_host:
                    on_host(hr)
            return hr

    await asyncio.gather(*(one(h) for h in allowed))
    out.sort(key=lambda hr: ipaddress.ip_address(hr.ip) if _is_ip(hr.ip) else hr.ip)
    return out


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False
