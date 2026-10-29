"""Geo/org enrichment — the Rennacs equivalent of Shodan's GeoIP + WHOIS annotations.

Two source-backed layers, with unknown public locations left unknown:

* :func:`enrich` is the **offline** layer used at index time (never hits the network):
  loopback/private ranges get classification labels, and an optional MaxMind GeoLite2
  database is used when present. No public coordinates or organisations are canned.
* :class:`GeoLocator` is the **network** layer, invoked by an explicit ``cli.py geo``
  step (like ``cli.py enrich`` for CVEs). It looks up real coordinates for public hosts
  via a free, keyless API (ipwho.is by default), caches them locally, and fills in each
  host's lat/lon/country/city/org so they appear on the world map. It degrades
  gracefully (cache, then offline) and never geolocates private/loopback addresses,
  which have no public location.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import sqlite3
import time
from dataclasses import dataclass

from ._http import FETCH_ERRORS, SafeFetcher


@dataclass
class Geo:
    country: str = ""
    city: str = ""
    org: str = ""
    asn: str = ""
    lat: float | None = None   # for the map view; None == not geolocated
    lon: float | None = None


# Optional offline MaxMind GeoLite2-City database (best accuracy, no network). Set the
# path via RENNACS_GEOLITE2 or drop GeoLite2-City.mmdb next to the project.
_MMDB_ENV = "RENNACS_GEOLITE2"
_mmdb_reader = None
_mmdb_tried = False


def _maxmind(ip: str) -> Geo | None:
    """Look ip up in a MaxMind GeoLite2 DB if geoip2 + an .mmdb are available."""
    global _mmdb_reader, _mmdb_tried
    if _mmdb_tried and _mmdb_reader is None:
        return None
    if _mmdb_reader is None:
        _mmdb_tried = True
        path = os.environ.get(_MMDB_ENV) or "GeoLite2-City.mmdb"
        if not os.path.exists(path):
            return None
        try:
            import geoip2.database  # type: ignore
            _mmdb_reader = geoip2.database.Reader(path)
        except Exception:
            _mmdb_reader = None
            return None
    try:
        r = _mmdb_reader.city(ip)
        return Geo(country=(r.country.iso_code or ""),
                   city=(r.city.name or ""), org="",
                   asn="", lat=r.location.latitude, lon=r.location.longitude)
    except Exception:
        return None


def enrich(ip: str) -> Geo:
    """Offline geo lookup used at index time. Never touches the network."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return Geo()

    if addr.is_loopback:
        return Geo(country="", city="localhost", org="Local host", asn="")
    if addr.is_private:
        return Geo(country="", city="LAN", org="Private network (RFC1918)", asn="")

    mm = _maxmind(ip)
    if mm is not None:
        return mm
    return Geo()


def is_geolocatable(ip: str) -> bool:
    """True only for public addresses — private/loopback have no public location."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved)


_GEO_SCHEMA = """
CREATE TABLE IF NOT EXISTS geo_cache (
    ip         TEXT PRIMARY KEY,
    success    INTEGER,
    json       TEXT,
    fetched_at TEXT
);
"""


class GeoLocator:
    """Cached, network IP geolocation (default provider: ipwho.is, free + keyless)."""

    PROVIDERS = {
        "ipwho.is": ("https://ipwho.is/{ip}", ("ipwho.is",)),
    }

    def __init__(self, db_path: str = "rennacs.db", *, provider: str = "ipwho.is",
                 timeout: float = 8.0, offline: bool = False, now_iso: str = ""):
        self.db_path = db_path
        self.offline = offline
        self.timeout = timeout
        self._now = now_iso
        self._url_tmpl, hosts = self.PROVIDERS.get(provider, self.PROVIDERS["ipwho.is"])
        self._fetcher = SafeFetcher(allowed_hosts=hosts, user_agent="Rennacs/0.3 geo")
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_GEO_SCHEMA)
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
            "SELECT success, json FROM geo_cache WHERE ip=?", (ip,)).fetchone()
        if row is None:
            return None
        if not row["success"]:
            return {"__absent__": True}
        try:
            cached = json.loads(row["json"])
            return cached if _geo_from_dict(cached) is not None else None
        except (TypeError, ValueError):
            return None

    def locate(self, ip: str, *, allow_network: bool = True) -> Geo | None:
        """Return a :class:`Geo` for a public ip, or None. Cache-first, then network."""
        if not is_geolocatable(ip):
            return None
        cached = self._cached(ip)
        if cached is not None:
            return None if cached.get("__absent__") else _geo_from_dict(cached)
        if self.offline or not allow_network:
            return None
        try:
            raw = self._fetcher.get_json(self._url_tmpl.format(ip=ip),
                                         timeout=self.timeout)
        except FETCH_ERRORS:
            return None
        if (not isinstance(raw, dict) or raw.get("success") is not True
                or ("ip" in raw and raw["ip"] != ip)):
            # ipwho.is returns {success:false} for private/invalid — cache the absence
            self._store_absent(ip)
            return None
        geo = _normalize_ipwhois(raw)
        if geo is None:
            return None
        self._store(ip, geo)
        return geo

    def _store(self, ip: str, geo: Geo) -> None:
        self.conn.execute(
            """INSERT INTO geo_cache(ip, success, json, fetched_at) VALUES(?,1,?,?)
               ON CONFLICT(ip) DO UPDATE SET success=1, json=excluded.json,
                   fetched_at=excluded.fetched_at""",
            (ip, json.dumps(_geo_to_dict(geo)), self._stamp()))
        self.conn.commit()

    def _store_absent(self, ip: str) -> None:
        self.conn.execute(
            """INSERT INTO geo_cache(ip, success, json, fetched_at) VALUES(?,0,NULL,?)
               ON CONFLICT(ip) DO UPDATE SET success=0, json=NULL,
                   fetched_at=excluded.fetched_at""",
            (ip, self._stamp()))
        self.conn.commit()

    def locate_missing(self, idx, *, limit: int = 0, rate: float = 1.0,
                       on_progress=None) -> dict:
        """Geolocate every public host in the index that lacks coordinates.

        ``rate`` throttles network lookups (requests/second) to stay within the free
        provider's limits. Updates each host's lat/lon/country/city/org. Returns
        {candidates, located, failed} counts.
        """
        ips = [ip for ip in idx.hosts_without_geo() if is_geolocatable(ip)]
        if limit:
            ips = ips[:limit]
        counts = {"candidates": len(ips), "located": 0, "failed": 0}
        min_gap = 1.0 / rate if rate else 0.0
        last = 0.0
        for i, ip in enumerate(ips, 1):
            if min_gap and self._cached(ip) is None and not self.offline:
                wait = min_gap - (time.monotonic() - last)
                if wait > 0:
                    time.sleep(wait)
                last = time.monotonic()
            geo = self.locate(ip)
            if geo and geo.lat is not None:
                idx.update_host_geo(ip, geo)
                counts["located"] += 1
            else:
                counts["failed"] += 1
            if on_progress:
                on_progress(i, counts)
        return counts


def _coordinates_valid(lat, lon) -> bool:
    return (type(lat) in (int, float) and type(lon) in (int, float)
            and -90 <= lat <= 90 and -180 <= lon <= 180)


def _text_fields_valid(*values) -> bool:
    for value in values:
        if value is None:
            continue
        if not isinstance(value, str):
            return False
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            return False
    return True


def _normalize_ipwhois(raw: dict) -> Geo | None:
    if not _coordinates_valid(raw.get("latitude"), raw.get("longitude")):
        return None
    conn = raw.get("connection", {})
    if conn is None:
        conn = {}
    if not isinstance(conn, dict):
        return None
    if not _text_fields_valid(raw.get("country_code"), raw.get("country"),
                              raw.get("city"), conn.get("org"), conn.get("isp")):
        return None
    asn = conn.get("asn")
    if asn is not None and (type(asn) is not int or not 1 <= asn <= 4294967295):
        return None
    return Geo(
        country=raw.get("country_code") or raw.get("country") or "",
        city=raw.get("city", "") or "",
        org=conn.get("org") or conn.get("isp", "") or "",
        asn=(f"AS{asn}" if asn else ""),
        lat=raw.get("latitude"),
        lon=raw.get("longitude"),
    )


def _geo_to_dict(g: Geo) -> dict:
    return {"country": g.country, "city": g.city, "org": g.org, "asn": g.asn,
            "lat": g.lat, "lon": g.lon}


def _geo_from_dict(d: dict) -> Geo | None:
    if not isinstance(d, dict) or not _coordinates_valid(d.get("lat"), d.get("lon")):
        return None
    if not _text_fields_valid(*(d.get(key) for key in ("country", "city", "org", "asn"))):
        return None
    asn = d.get("asn") or ""
    if asn and (not re.fullmatch(r"AS[1-9][0-9]{0,9}", asn)
                or int(asn[2:]) > 4294967295):
        return None
    return Geo(country=d.get("country") or "", city=d.get("city") or "",
              org=d.get("org") or "", asn=asn,
              lat=d.get("lat"), lon=d.get("lon"))
