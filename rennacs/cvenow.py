"""cve.now integration — turn Rennacs's heuristic CVE guesses into sourced facts.

`cve.now <https://cve.now>`_ is a free, no-auth public feed that merges CVE List, OSV,
GitHub Advisories, NVD and CISA KEV. Rennacs uses it two ways:

1. **Enrich** — for every CVE our offline heuristic (:mod:`rennacs.vulns`) flags, look
   up the authoritative entry and attach the real CVSS score, CISA-KEV exploited flag,
   a model-written summary, reference links, and the affected version ranges. The
   ranges let us *validate* our match: if the detected version falls inside cve.now's
   affected window we mark it confirmed; if it's clearly outside we say so; if the two
   version schemes can't be compared we leave it "heuristic only" rather than hiding it.
2. **Feed** — pull the latest Critical / KEV entries for a "recent vulnerabilities"
   panel, mirroring cve.now's own homepage.

Design rules that matter for a scanner that mostly runs on offline lab networks:

* **Never block a scan on the network.** Indexing only ever reads the local cache;
  talking to cve.now is an explicit, separate step (``cli.py enrich`` / ``cve-refresh``).
* **Degrade gracefully.** Any network error falls back to cached data, then to the
  heuristic. cve.now being down never breaks Rennacs.
* **Cache everything** in the same SQLite file, with a TTL, so repeated lookups are free
  and the enriched data survives offline.
* **Send nothing sensitive.** The only things that leave the machine are public CVE IDs
  (and, for the feed, generic filter/tech slugs). No scan data, no host info, no auth.
* **No new dependencies / SSRF-aware.** Uses only the stdlib ``urllib``. Every id is
  validated before it goes into the request URL, redirects are constrained to the
  cve.now host set (never an arbitrary or private host), and responses are size-capped.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import re
import sqlite3
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlparse

from .vulns import _cmp, _parse_version

BASE = "https://cve.now"
USER_AGENT = "Rennacs/0.2 (+educational; https://cve.now integration)"
MAX_RESPONSE_BYTES = 4 * 1024 * 1024   # 4 MiB: ample for one entry or a 30-item list

# The id is interpolated into the FIRST request URL, so accept CVE/GHSA/OSV ids only
# (path-injection guard). Redirect targets are constrained separately, below.
_ID_RE = re.compile(r"^(?:CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|"
                    r"[A-Z]{2,}-\d{4}-\d{3,})$")

# cve.now's single-entry endpoint 302-redirects to its Vercel blob CDN, so redirects are
# allowed only to cve.now itself and *.blob.vercel-storage.com, over https, never to an
# arbitrary or private host. This blocks a hostile/again cve.now from using a redirect to
# make Rennacs probe internal/LAN services (blind SSRF).
_REDIRECT_OK_HOSTS = ("cve.now",)
_REDIRECT_OK_SUFFIXES = (".blob.vercel-storage.com",)


def _redirect_host_ok(newurl: str) -> bool:
    u = urlparse(newurl)
    if u.scheme != "https":
        return False
    host = (u.hostname or "").lower()
    if not host:
        return False
    # Never follow a redirect straight to an IP literal (esp. private/loopback).
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    return host in _REDIRECT_OK_HOSTS or any(
        host == s[1:] or host.endswith(s) for s in _REDIRECT_OK_SUFFIXES)


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    """Follow redirects only to the cve.now host set; block everything else.

    Returning None makes urllib stop and surface the original 3xx as an HTTPError,
    which the callers already catch and degrade from.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _redirect_host_ok(newurl):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)

_CACHE_SCHEMA = """
CREATE TABLE IF NOT EXISTS cve_cache (
    cve        TEXT PRIMARY KEY,
    exists_    INTEGER,          -- 1 if cve.now has it, 0 if looked up and absent
    json       TEXT,             -- normalized entry json (or null when absent)
    fetched_at TEXT
);
CREATE TABLE IF NOT EXISTS cve_feed (
    cve        TEXT PRIMARY KEY,
    title      TEXT,
    url        TEXT,
    severity   TEXT,
    cvss       REAL,
    kev        INTEGER DEFAULT 0,
    product    TEXT,
    published  TEXT,
    fetched_at TEXT
);
CREATE TABLE IF NOT EXISTS cve_meta (
    key        TEXT PRIMARY KEY,
    value      TEXT
);
"""

# cve.now exposes a curated set of technology slugs on /feed?tech=<slug>. Only these
# Rennacs-relevant products have one (OpenSSH, vsftpd, Exim, Postfix, Dovecot, IIS do
# NOT — their CVEs are still reachable by id, just not as a per-technology feed).
PRODUCT_TECH = {
    "nginx": "nginx",
    "apache httpd": "apache-httpd",
    "redis": "redis",
    "mysql": "mysql",
    "mariadb": "mariadb",
    "postgresql": "postgresql",
    "openssl": "openssl",
    "php": "php",
}


def tech_slug(product: str) -> str:
    """cve.now technology slug for a Rennacs product name, or '' if none exists."""
    return PRODUCT_TECH.get((product or "").strip().lower(), "")


def valid_id(cve: str) -> bool:
    return bool(cve and _ID_RE.match(cve.strip()))


def severity_from_cvss(cvss) -> str:
    """CVSS base score -> qualitative label (CVSS v3/v4 bands)."""
    try:
        c = float(cvss)
    except (TypeError, ValueError):
        return ""
    if c >= 9.0:
        return "critical"
    if c >= 7.0:
        return "high"
    if c >= 4.0:
        return "medium"
    if c > 0.0:
        return "low"
    return "none"


def version_in_ranges(version: str, affected: list) -> str:
    """Is ``version`` inside any affected range? -> 'yes' | 'no' | 'unknown'.

    cve.now ranges are ``{introduced, fixed}`` (fixed is exclusive). Our detected
    version comes from a service banner and may use a different scheme than the package
    version cve.now tracks, so we only ever return 'no' when the version clearly parses
    and sits outside *every* range. When in doubt we return 'unknown' — enrichment must
    never suppress a heuristic finding just because two version schemes disagree.
    """
    v = _parse_version(version)
    if not v or not affected:
        return "unknown"
    saw_comparable = False      # a range with >=1 parseable bound that we could test
    incomparable = False        # a bounded range whose bounds we couldn't parse
    for a in affected:
        for r in a.get("ranges", []) or []:
            intro = r.get("introduced")
            fixed = r.get("fixed")
            if not intro and not fixed:
                continue
            pi = _parse_version(intro) if intro else ()
            pf = _parse_version(fixed) if fixed else ()
            if not pi and not pf:
                incomparable = True   # bounds present but unparseable -> can't judge
                continue
            saw_comparable = True
            if pi and _cmp(v, pi) < 0:
                continue  # below this range's start
            if pf and _cmp(v, pf) >= 0:
                continue  # at/after the fix -> not this range
            return "yes"  # positively placed within [introduced, fixed)
    if not saw_comparable:
        return "unknown"
    # Every comparable range excluded v: 'no' only if nothing was incomparable.
    return "unknown" if incomparable else "no"


def normalize_entry(raw: dict) -> dict:
    """Map a cve.now entry (/api/v1/entries/<id>) to the fields Rennacs displays."""
    sev = raw.get("severity") or {}
    cvss = sev.get("cvss")
    exploitation = raw.get("exploitation") or {}
    summary = raw.get("summary") or {}
    affected = []
    for a in raw.get("affected", []) or []:
        affected.append({
            "vendor": a.get("vendor", ""),
            "product": a.get("product", ""),
            "ranges": [{"introduced": r.get("introduced", ""),
                        "fixed": r.get("fixed", "")}
                       for r in (a.get("ranges") or [])],
        })
    cve_id = raw.get("id") or raw.get("feedId") or ""
    return {
        "cve": cve_id,
        "title": raw.get("title", ""),
        "cvss": cvss,
        "severity": severity_from_cvss(cvss) if cvss is not None else "",
        "vector": sev.get("vector", ""),
        "kev": bool(exploitation.get("kev")),
        "summary": (summary.get("text") or raw.get("originalDescription") or "")[:800],
        "affected": affected,
        "references": [r.get("url", "") for r in (raw.get("references") or [])
                       if r.get("url")][:8],
        "url": f"{BASE}/{cve_id}" if cve_id else BASE,
        "published": raw.get("publishedAt", ""),
        "source": "cve.now",
    }


@dataclass
class _Result:
    entry: dict | None
    from_cache: bool


class CVENow:
    """Cache-backed cve.now client. Shares the Rennacs SQLite file by default."""

    def __init__(self, db_path: str = "rennacs.db", *, ttl_hours: int = 24,
                 timeout: float = 6.0, offline: bool = False, now_iso: str = ""):
        self.db_path = db_path
        self.ttl_hours = ttl_hours
        self.timeout = timeout
        self.offline = offline
        # Scripts/tests pass a timestamp in (Date.now is unavailable in some contexts);
        # default to the real clock here in normal app/CLI use.
        self._now = now_iso
        # A dedicated opener whose redirect handler is host-constrained (SSRF guard).
        self._opener = urllib.request.build_opener(_SafeRedirect())
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_CACHE_SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # -- low-level HTTP ----------------------------------------------------------

    def _get_json(self, url: str):
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                                   "Accept": "application/json"})
        # The safe opener follows the /api/v1/entries -> blob CDN redirect but only to
        # the cve.now host set. Cap the read so a hostile/buggy response can't OOM us;
        # ValueError (raised here or by json) is caught by callers as a soft failure.
        with self._opener.open(req, timeout=self.timeout) as resp:
            clen = resp.headers.get("Content-Length")
            if clen and clen.isdigit() and int(clen) > MAX_RESPONSE_BYTES:
                raise ValueError("cve.now response exceeds size cap")
            body = resp.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise ValueError("cve.now response exceeds size cap")
            return json.loads(body.decode("utf-8", "replace"))

    def _stamp(self) -> str:
        if self._now:
            return self._now
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()

    # -- single-entry enrichment -------------------------------------------------

    def _cached(self, cve: str) -> dict | None:
        row = self.conn.execute(
            "SELECT exists_, json, fetched_at FROM cve_cache WHERE cve=?",
            (cve,)).fetchone()
        if row is None:
            return None
        if not row["exists_"]:
            return {"__absent__": True, "__fetched_at__": row["fetched_at"]}
        try:
            data = json.loads(row["json"])
        except (TypeError, ValueError):
            return None
        data["__fetched_at__"] = row["fetched_at"]
        return data

    def _is_stale(self, fetched_at: str) -> bool:
        """True if a cached row is older than ttl_hours (best-effort; never crashes)."""
        if not fetched_at or self.ttl_hours is None:
            return False
        try:
            from datetime import datetime, timezone
            then = datetime.fromisoformat(fetched_at.replace("Z", "+00:00"))
            now = (datetime.fromisoformat(self._now.replace("Z", "+00:00"))
                   if self._now else datetime.now(timezone.utc))
            if then.tzinfo is None:
                then = then.replace(tzinfo=timezone.utc)
            return (now - then).total_seconds() > self.ttl_hours * 3600
        except (ValueError, TypeError):
            return False

    def entry(self, cve: str, *, allow_network: bool = True,
              force: bool = False) -> dict | None:
        """Return the normalized cve.now entry for ``cve``, or None if unavailable.

        Cache-first, honoring ttl_hours. On a miss or stale entry, fetches from cve.now
        unless offline/allow_network is False. ``force`` bypasses the cache for a
        refresh (used by ``cli.py enrich``). A confirmed-absent lookup is cached so we
        don't re-fetch 404s (but ``force`` re-checks those too).
        """
        cve = (cve or "").strip()
        if not valid_id(cve):
            return None
        cached = self._cached(cve)
        can_net = allow_network and not self.offline
        if cached is not None and not (force and can_net):
            stale = self._is_stale(cached.get("__fetched_at__", ""))
            if not (stale and can_net):
                if cached.get("__absent__"):
                    return None
                cached.pop("__fetched_at__", None)
                return cached

        # A usable present entry to fall back to if the refresh fails (never discard
        # good data on a transient error — that is the degrade-gracefully contract).
        fallback = None
        if cached is not None and not cached.get("__absent__"):
            fallback = {k: v for k, v in cached.items() if k != "__fetched_at__"}

        if not can_net:
            return fallback
        try:
            raw = self._get_json(f"{BASE}/api/v1/entries/{cve}")
        except urllib.error.HTTPError as e:
            if e.code in (404, 400):
                self._store_absent(cve)   # authoritative "does not exist"
                return None
            return fallback               # 5xx/429/blocked redirect -> keep cache
        except (urllib.error.URLError, http.client.HTTPException, TimeoutError,
                ValueError, OSError):
            return fallback               # network/parse failure -> keep cache
        if not isinstance(raw, dict) or not (raw.get("id") or raw.get("feedId")):
            # A malformed/ambiguous 200 is NOT evidence of absence — do not overwrite
            # a good cached entry; just fall back.
            return fallback
        norm = normalize_entry(raw)
        self._store_entry(cve, norm)
        return norm

    def _store_entry(self, cve: str, norm: dict) -> None:
        self.conn.execute(
            """INSERT INTO cve_cache(cve, exists_, json, fetched_at) VALUES(?,1,?,?)
               ON CONFLICT(cve) DO UPDATE SET exists_=1, json=excluded.json,
                   fetched_at=excluded.fetched_at""",
            (cve, json.dumps(norm), self._stamp()))
        self.conn.commit()

    def _store_absent(self, cve: str) -> None:
        self.conn.execute(
            """INSERT INTO cve_cache(cve, exists_, json, fetched_at) VALUES(?,0,NULL,?)
               ON CONFLICT(cve) DO UPDATE SET exists_=0, json=NULL,
                   fetched_at=excluded.fetched_at""",
            (cve, self._stamp()))
        self.conn.commit()

    # -- merge enrichment onto a heuristic vuln ----------------------------------

    def enrich_vuln(self, vuln: dict, version: str = "",
                    *, allow_network: bool = True) -> dict:
        """Return a copy of a heuristic vuln dict merged with cve.now data.

        Adds: cvss, kev, vector, url, source, title, summary (authoritative), and
        ``confirmed`` ('yes'|'no'|'unknown') from the affected-range validation.
        Leaves the heuristic fields intact when cve.now has nothing.
        """
        out = dict(vuln)
        out.setdefault("confirmed", "unknown")
        out.setdefault("enriched", False)
        entry = self.entry(vuln.get("cve", ""), allow_network=allow_network)
        if not entry:
            return out
        out["enriched"] = True
        out["source"] = "cve.now"
        out["url"] = entry.get("url", "")
        if entry.get("cvss") is not None:
            out["cvss"] = entry["cvss"]
        if entry.get("severity"):
            out["severity"] = entry["severity"]   # prefer authoritative band
        out["kev"] = entry.get("kev", False)
        out["vector"] = entry.get("vector", "")
        out["title"] = entry.get("title", "")
        if entry.get("summary"):
            out["summary"] = entry["summary"]       # prefer sourced summary
        out["references"] = entry.get("references", [])
        out["confirmed"] = version_in_ranges(version, entry.get("affected", []))
        return out

    # -- latest-critical feed ----------------------------------------------------

    def refresh_feed(self, *, filters=("critical", "kev"), limit: int = 30) -> int:
        """Fetch the latest entries and store them in cve_feed. Returns count stored.

        Uses the structured list endpoint (/api/v1/entries?filter=...), newest first.
        List items are flat (id, title, cvss, kev, product, publishedAt). Network
        failures leave the existing cached feed untouched and return 0.
        """
        if self.offline:
            return 0
        flt = ",".join(filters)
        try:
            data = self._get_json(f"{BASE}/api/v1/entries?filter={flt}")
        except (urllib.error.URLError, urllib.error.HTTPError,
                http.client.HTTPException, TimeoutError, ValueError, OSError):
            return 0
        items = _entries_list(data)
        stamp = self._stamp()
        stored = 0
        for raw in items[:limit]:
            norm = _list_item(raw)
            if not norm.get("cve"):
                continue
            self.conn.execute(
                """INSERT INTO cve_feed(cve, title, url, severity, cvss, kev, product,
                       published, fetched_at) VALUES(?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(cve) DO UPDATE SET title=excluded.title,
                       url=excluded.url, severity=excluded.severity,
                       cvss=excluded.cvss, kev=excluded.kev, product=excluded.product,
                       published=excluded.published, fetched_at=excluded.fetched_at""",
                (norm["cve"], norm.get("title", ""), norm.get("url", ""),
                 norm.get("severity", ""), norm.get("cvss"),
                 1 if norm.get("kev") else 0, norm.get("product", ""),
                 norm.get("published", ""), stamp))
            stored += 1
        self._set_meta("feed_fetched_at", stamp)
        self.conn.commit()
        return stored

    def refresh_stats(self) -> dict:
        """Fetch /api/stats (catalog freshness / totals) and cache it. Returns it."""
        if self.offline:
            return self.catalog_stats()
        try:
            data = self._get_json(f"{BASE}/api/stats")
        except (urllib.error.URLError, urllib.error.HTTPError,
                http.client.HTTPException, TimeoutError, ValueError, OSError):
            return self.catalog_stats()
        if isinstance(data, dict):
            self._set_meta("stats", json.dumps(data))
            self._set_meta("stats_fetched_at", self._stamp())
            self.conn.commit()
        return self.catalog_stats()

    def latest(self, limit: int = 20) -> list[dict]:
        """Read the cached latest-critical feed (does not hit the network)."""
        rows = self.conn.execute(
            "SELECT cve, title, url, severity, cvss, kev, product, published "
            "FROM cve_feed ORDER BY published DESC, cve DESC LIMIT ?",
            (limit,)).fetchall()
        return [dict(r) for r in rows]

    def catalog_stats(self) -> dict:
        row = self.conn.execute(
            "SELECT value FROM cve_meta WHERE key='stats'").fetchone()
        if not row:
            return {}
        try:
            return json.loads(row["value"])
        except (TypeError, ValueError):
            return {}

    def _set_meta(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO cve_meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    def feed_fetched_at(self) -> str:
        row = self.conn.execute(
            "SELECT value FROM cve_meta WHERE key='feed_fetched_at'").fetchone()
        return row["value"] if row else ""


def _entries_list(data) -> list:
    """Pull the item array out of the list endpoint response (shape-tolerant)."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("entries", "items", "data", "results"):
            if isinstance(data.get(key), list):
                return data[key]
    return []


def _list_item(raw: dict) -> dict:
    """Normalize a flat list-endpoint item (/api/v1/entries).

    Shape: {id, title, firstSeenAt, publishedAt, cvss, statedSeverity, kev, product,
    fix}. cvss/kev/product are top-level (not nested like a single entry).
    """
    cve = (raw.get("id", "") or "").split("#", 1)[0]
    cvss = raw.get("cvss")
    return {
        "cve": cve,
        "title": raw.get("title", ""),
        "url": f"{BASE}/{cve}" if cve else BASE,
        "severity": severity_from_cvss(cvss) if cvss is not None else "",
        "cvss": cvss,
        "kev": bool(raw.get("kev")),
        "product": raw.get("product", "") or "",
        "published": raw.get("publishedAt") or raw.get("firstSeenAt", ""),
    }
