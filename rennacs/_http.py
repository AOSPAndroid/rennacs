"""Shared hardened HTTP helper for Rennacs's outbound API clients.

Both the cve.now and geolocation integrations talk to small public JSON APIs. This
helper centralises the safety properties they need:

* **Host-allowlisted redirects** — follow redirects only to an expected host set (and
  never to an IP literal / private host), so a hostile or compromised upstream can't use
  a redirect to make Rennacs probe internal services (blind SSRF).
* **Size-capped reads** — a bounded read so a giant/endless body can't exhaust memory.
* **One error surface** — :data:`FETCH_ERRORS` collects every network/parse/read error
  (including ``http.client.HTTPException``) so callers degrade in a single ``except``.

It is intentionally tiny and dependency-free (stdlib ``urllib`` only).
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import urllib.error
import urllib.request
from urllib.parse import urlparse

DEFAULT_MAX_BYTES = 4 * 1024 * 1024

# The soft-failure set: any of these means "couldn't fetch" -> fall back to cache.
FETCH_ERRORS = (urllib.error.URLError, urllib.error.HTTPError,
                http.client.HTTPException, TimeoutError, ValueError, OSError)


def host_allowed(newurl: str, hosts: tuple, suffixes: tuple) -> bool:
    """True if ``newurl`` is https, not an IP literal, and in the host allowlist."""
    u = urlparse(newurl)
    if u.scheme != "https":
        return False
    host = (u.hostname or "").lower()
    if not host:
        return False
    try:
        ipaddress.ip_address(host)      # never follow a redirect to a bare IP
        return False
    except ValueError:
        pass
    return host in hosts or any(host == s.lstrip(".") or host.endswith(s)
                                for s in suffixes)


class _AllowlistRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, hosts, suffixes):
        self._hosts = hosts
        self._suffixes = suffixes

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not host_allowed(newurl, self._hosts, self._suffixes):
            return None                 # stop -> surfaces as HTTPError, caught by caller
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class SafeFetcher:
    """A reusable GET-JSON client with redirect allowlist and size cap."""

    def __init__(self, *, allowed_hosts=(), allowed_suffixes=(), user_agent="Rennacs",
                 max_bytes: int = DEFAULT_MAX_BYTES):
        self.user_agent = user_agent
        self.max_bytes = max_bytes
        self._opener = urllib.request.build_opener(
            _AllowlistRedirect(tuple(allowed_hosts), tuple(allowed_suffixes)))

    def get_json(self, url: str, *, timeout: float = 8.0):
        req = urllib.request.Request(url, headers={"User-Agent": self.user_agent,
                                                   "Accept": "application/json"})
        with self._opener.open(req, timeout=timeout) as resp:
            clen = resp.headers.get("Content-Length")
            if clen and clen.isdigit() and int(clen) > self.max_bytes:
                raise ValueError("response exceeds size cap")
            body = resp.read(self.max_bytes + 1)
            if len(body) > self.max_bytes:
                raise ValueError("response exceeds size cap")
            return json.loads(body.decode("utf-8", "replace"))
