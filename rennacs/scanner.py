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
import math
import socket
import ssl
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID

from . import ports as portlib
from .authz import Policy
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

# Preserve HTTP Host / TLS SNI while _grab connects only to an approved IP.
# Task-local context keeps the established three-argument connector seam intact.
_TARGET_HOSTNAME: ContextVar[str | None] = ContextVar("target_hostname", default=None)


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

    ssl_sans: list[str] = field(default_factory=list)
    ssl_trust: str = "not_observed"  # parsed metadata is never proof of trust


@dataclass
class HostResult:
    """Everything Rennacs knows about one host — the indexed 'document'."""

    ip: str
    hostnames: list[str] = field(default_factory=list)
    services: list[ServiceResult] = field(default_factory=list)
    seen_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    # Attempted scope, not a claim that missing services were confirmed closed.
    scanned_ports: list[int] | None = None


_MAX_DIRECT_HOSTS = 4096
_MAX_PORT_WORKERS = 200


def expand_targets(spec: str) -> list[str]:
    """Expand a small explicit scope; use sweep for larger address spaces.

    Count the entire scope before iterating any CIDR. Hostnames are resolved and
    policy-checked by scan(), never implicitly trusted by this expansion helper.
    """
    parts = []
    count = 0
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            net = ipaddress.ip_network(part, strict=False)
        except ValueError:
            parts.append(part)
            count += 1
        else:
            parts.append(net)
            size = net.num_addresses
            if size > 2:
                size -= 2 if net.version == 4 else 1
            count += size
        if count > _MAX_DIRECT_HOSTS:
            raise ValueError(f"Direct scans support at most {_MAX_DIRECT_HOSTS} targets; "
                             "use sweep for larger scopes")

    out: list[str] = []
    for part in parts:
        if isinstance(part, str):
            out.append(part)
        else:
            out.extend(str(host) for host in part.hosts())
    return out


def _check_timeout(timeout: float) -> None:
    try:
        valid = (type(timeout) in (int, float) and timeout > 0
                 and math.isfinite(timeout))
    except OverflowError:
        valid = False
    if not valid:
        raise ValueError("timeout must be a finite positive number")


async def _grab(host: str, port: int, timeout: float) -> ServiceResult | None:
    """Observe one TCP service, bounding connect/drain/read/close separately.

    None means not_observed, not confirmed closed. TLS metadata is collected
    without certificate or hostname verification and must not imply trust.
    """
    _check_timeout(timeout)
    use_tls = port in _TLS_PORTS
    server_name = _TARGET_HOSTNAME.get() or host
    ssl_cn = ssl_issuer = ""
    ssl_sans: list[str] = []
    banner = ""

    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx,
                                        server_hostname=server_name), timeout
            )
            # Pull the peer certificate subject / issuer for the SSL panel.
            try:
                sslobj = writer.get_extra_info("ssl_object")
                der = sslobj.getpeercert(binary_form=True) if sslobj else None
                if der:
                    cert = x509.load_der_x509_certificate(der)
                    common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                    issuers = (cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
                               or cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME))
                    ssl_cn = common_names[0].value if common_names else ""
                    ssl_issuer = issuers[0].value if issuers else ""
                    try:
                        sans = cert.extensions.get_extension_for_class(
                            x509.SubjectAlternativeName).value
                        ssl_sans = [str(name.value) for name in sans
                                    if isinstance(name, (x509.DNSName, x509.IPAddress))]
                    except x509.ExtensionNotFound:
                        pass
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
                writer.write(probe % server_name.encode("idna") if b"%s" in probe else probe)
                await asyncio.wait_for(writer.drain(), timeout)
            except Exception:
                pass
        try:
            data = await asyncio.wait_for(reader.read(2048), timeout)
            banner = data.decode("latin-1", "replace").strip()
        except (asyncio.TimeoutError, OSError):
            banner = ""
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout)
        except asyncio.CancelledError:
            writer.transport.abort()
            raise
        except Exception:
            writer.transport.abort()

    svc = ServiceResult(
        port=port,
        banner=banner,
        service=portlib.SERVICE_NAMES.get(port, ""),
        has_ssl=use_tls,
        ssl_cn=ssl_cn,
        ssl_issuer=ssl_issuer,
        ssl_sans=ssl_sans,
        ssl_trust="unverified" if use_tls else "not_observed",
    )
    fingerprint(svc)   # fills product / version / os / refines service
    svc.vulns = [v.as_dict() for v in vulncheck(svc.product, svc.version)]
    return svc


async def scan_host(host: str, port_list: list[int], *, timeout: float = 2.0,
                    concurrency: int = 200) -> HostResult:
    """Observe selected ports using at most 200 port workers, not one task/port.

    This low-level connector takes a concrete destination; scan() supplies the
    policy boundary. scanned_ports records attempted scope, not confirmed closure.
    """
    _check_timeout(timeout)
    if type(concurrency) is not int or concurrency <= 0:
        raise ValueError("concurrency must be a positive integer")
    ports = sorted(set(port_list))
    pending = iter(ports)
    services: list[ServiceResult] = []

    async def worker():
        for port in pending:
            result = await _grab(host, port, timeout)
            if result is not None:
                services.append(result)

    workers = [asyncio.create_task(worker())
               for _ in range(min(concurrency, _MAX_PORT_WORKERS, len(ports)))]
    try:
        await asyncio.gather(*workers)
    finally:
        for task in workers:
            if not task.done():
                task.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
    services.sort(key=lambda s: s.port)
    return HostResult(ip=host, services=services, scanned_ports=ports)


async def scan(targets: str, port_spec: str = "top100", *, policy: Policy | None = None,
               timeout: float = 2.0, host_concurrency: int = 32,
               on_host=None) -> list[HostResult]:
    """Scan every host in ``targets`` across ``port_spec``.

    Resolve and policy-check every destination before probing any of them; only
    checked IPs reach the connector. Hostnames remain observational DNS metadata
    and supply HTTP Host / TLS SNI (the first alias for a shared destination).

    ``on_host`` receives ALL completed HostResults, including empty observations;
    the returned list contains only live hosts. Direct scopes are limited to 4096
    targets; larger address spaces belong in sweep().
    """
    _check_timeout(timeout)
    if type(host_concurrency) is not int or host_concurrency <= 0:
        raise ValueError("host_concurrency must be a positive integer")
    policy = policy or Policy()
    port_list = portlib.resolve(port_spec)
    hosts = expand_targets(targets)

    allowed: dict[str, list[str]] = {}
    loop = asyncio.get_running_loop()
    for h in hosts:
        try:
            destinations = [str(ipaddress.ip_address(h))]
        except ValueError:
            records = await asyncio.wait_for(
                loop.getaddrinfo(h, None, type=socket.SOCK_STREAM,
                                 proto=socket.IPPROTO_TCP), timeout
            )
            destinations = list(dict.fromkeys(
                str(ipaddress.ip_address(record[4][0])) for record in records
            ))
            if not destinations:
                raise OSError(f"No TCP addresses resolved for {h}")
        for destination in destinations:
            policy.check(destination)
            names = allowed.setdefault(destination, [])
            if len(allowed) > _MAX_DIRECT_HOSTS:
                raise ValueError(f"Direct scans support at most {_MAX_DIRECT_HOSTS} targets; "
                                 "use sweep for larger scopes")
            if h != destination and h not in names:
                names.append(h)

    sem = asyncio.Semaphore(host_concurrency)
    out: list[HostResult] = []

    async def one(h: str):
        async with sem:
            token = _TARGET_HOSTNAME.set(allowed[h][0] if allowed[h] else None)
            try:
                hr = await scan_host(h, port_list, timeout=timeout)
            finally:
                _TARGET_HOSTNAME.reset(token)
            hr.hostnames = allowed[h]
            if hr.services:           # only keep hosts that answered
                out.append(hr)
            if on_host:
                on_host(hr)
            return hr

    tasks = [asyncio.create_task(one(host)) for host in allowed]
    try:
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    out.sort(key=lambda hr: (ipaddress.ip_address(hr.ip).version,
                            int(ipaddress.ip_address(hr.ip))))
    return out
