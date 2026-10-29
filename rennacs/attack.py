"""Attack-side helpers: prove an origin, then identify what is on it.

Discovery is worthless until an address is *proven* to serve the target. An origin
candidate is only real when it answers the vhost — over TLS SNI and/or a Host header —
with the same application the edge serves. That check is what turns a DNS guess into
an attackable host, and it is the step most people skip.

Nothing here exploits anything: it confirms reachability and collects identity
(title, server, favicon hash) so a human or an agent can decide what to send next.
"""

from __future__ import annotations

import hashlib
import http.client
import re
import socket
import ssl
from dataclasses import dataclass

_TITLE = re.compile(rb"<title[^>]*>(.{0,200}?)</title>", re.IGNORECASE | re.DOTALL)
_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36"


@dataclass
class Identity:
    ip: str
    host: str
    port: int
    status: int = 0
    server: str = ""
    title: str = ""
    favicon: str = ""
    location: str = ""
    tls_cn: str = ""
    error: str = ""

    @property
    def reachable(self) -> bool:
        return self.status > 0

    @property
    def serves_vhost(self) -> bool:
        """A 2xx/3xx with a body is the origin answering for this name."""
        return 200 <= self.status < 400 and not self.error


def _tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False          # we are proving reachability, not trust
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch(ip: str, host: str, port: int = 443, path: str = "/", *,
          tls: bool = True, timeout: float = 8.0) -> Identity:
    """Request ``path`` from ``ip`` while presenting ``host`` as SNI and Host header."""
    ident = Identity(ip=ip, host=host, port=port)
    conn: http.client.HTTPConnection | None = None
    try:
        if tls:
            conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=_tls_context())
            sock = socket.create_connection((ip, port), timeout)
            wrapped = _tls_context().wrap_socket(sock, server_hostname=host)
            conn.sock = wrapped
            cert = wrapped.getpeercert()
            if cert:
                for rdn in cert.get("subject", ()):
                    for key, value in rdn:
                        if key == "commonName":
                            ident.tls_cn = value
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        conn.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", host)
        conn.putheader("User-Agent", _UA)
        conn.putheader("Accept", "*/*")
        conn.endheaders()
        resp = conn.getresponse()
        ident.status = resp.status
        ident.server = resp.getheader("Server", "") or ""
        ident.location = resp.getheader("Location", "") or ""
        body = resp.read(200_000)
        match = _TITLE.search(body)
        if match:
            ident.title = match.group(1).decode("utf-8", "replace").strip()[:200]
        ident.favicon = favicon_hash(body)
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        ident.error = f"{type(exc).__name__}: {exc}"
    finally:
        if conn is not None:
            conn.close()
    return ident


def favicon_hash(body: bytes) -> str:
    """Stable content hash for pivoting between hosts serving the same app.

    Shodan uses an mmh3 hash of the base64 favicon; without that dependency this is a
    truncated SHA-256 of the body, which pivots just as well inside one index.
    """
    if not body:
        return ""
    return hashlib.sha256(body).hexdigest()[:16]


def compare(edge: Identity, origin: Identity) -> dict:
    """Judge whether ``origin`` plausibly serves the same app as ``edge``."""
    reasons = []
    if not origin.reachable:
        return {"same": False, "reasons": [f"origin unreachable ({origin.error})"]}
    if edge.title and origin.title and edge.title == origin.title:
        reasons.append("identical title")
    if edge.favicon and origin.favicon and edge.favicon == origin.favicon:
        reasons.append("identical favicon hash")
    if edge.server and origin.server and edge.server == origin.server:
        reasons.append(f"identical server header ({origin.server})")
    return {"same": bool(reasons), "reasons": reasons or ["no shared identity markers"]}
