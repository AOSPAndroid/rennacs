"""Tests for geolocation (offline enrich + network GeoLocator) and the global map."""

import pytest

from rennacs._http import host_allowed
from rennacs.db import Index
from rennacs.geoip import GeoLocator, Geo, enrich, is_geolocatable
from rennacs.query import compile_query


# -- offline enrich / helpers -------------------------------------------------

def test_is_geolocatable():
    assert is_geolocatable("8.8.8.8") is True
    assert is_geolocatable("192.168.1.1") is False
    assert is_geolocatable("127.0.0.1") is False
    assert is_geolocatable("169.254.1.1") is False
    assert is_geolocatable("not-an-ip") is False


def test_enrich_offline():
    assert enrich("8.8.8.8").city == "Mountain View"         # known
    assert enrich("192.168.1.9").org.startswith("Private")   # private
    assert enrich("127.0.0.1").city == "localhost"           # loopback
    assert enrich("203.0.113.9").lat is None                 # unknown public -> empty


def test_http_host_allowed_guard():
    assert host_allowed("https://ipwho.is/8.8.8.8", ("ipwho.is",), ()) is True
    assert host_allowed("http://ipwho.is/8.8.8.8", ("ipwho.is",), ()) is False   # not https
    assert host_allowed("https://evil.com/", ("ipwho.is",), ()) is False
    assert host_allowed("https://127.0.0.1/", ("ipwho.is",), ()) is False        # IP literal


# -- GeoLocator with a fake fetcher (no network) ------------------------------

# Genuinely-global IPs (the RFC5737 doc ranges are is_private in Python 3.12).
_FAKE_GEO = {
    "81.2.69.142": {"success": True, "country": "United Kingdom", "country_code": "GB",
                    "city": "London", "latitude": 51.51, "longitude": -0.13,
                    "connection": {"org": "Example GmbH", "asn": 64500}},
    "45.33.32.156": {"success": True, "country": "United States", "country_code": "US",
                     "city": "Ashburn", "latitude": 39.0, "longitude": -77.5,
                     "connection": {"org": "Example Inc", "asn": 64501}},
    "45.33.32.200": {"success": False, "message": "Reserved range"},
}


class FakeGeoFetch:
    def __init__(self):
        self.calls = []

    def get_json(self, url, timeout=8.0):
        self.calls.append(url)
        ip = url.rstrip("/").rsplit("/", 1)[-1]
        if ip in _FAKE_GEO:
            return _FAKE_GEO[ip]
        return {"success": False}


@pytest.fixture
def geo(tmp_path):
    g = GeoLocator(str(tmp_path / "g.db"), now_iso="2026-10-27T00:00:00Z")
    g._fetcher = FakeGeoFetch()
    yield g
    g.close()


def test_locate_public_and_caches(geo):
    g = geo.locate("81.2.69.142")
    assert g.lat == 51.51 and g.country == "GB" and g.asn == "AS64500"
    n = len(geo._fetcher.calls)
    geo.locate("81.2.69.142")                 # cache hit, no new call
    assert len(geo._fetcher.calls) == n


def test_locate_private_never_fetches(geo):
    assert geo.locate("10.0.0.5") is None
    assert geo._fetcher.calls == []


def test_locate_unsuccessful_is_cached_absent(geo):
    assert geo.locate("45.33.32.200") is None
    calls = len(geo._fetcher.calls)
    assert geo.locate("45.33.32.200") is None   # not re-fetched
    assert len(geo._fetcher.calls) == calls


def test_offline_geolocator_no_network(tmp_path):
    g = GeoLocator(str(tmp_path / "o.db"), offline=True)
    g._fetcher = FakeGeoFetch()
    assert g.locate("81.2.69.142") is None
    assert g._fetcher.calls == []
    g.close()


def test_locate_missing_updates_index(tmp_path):
    idx = Index(str(tmp_path / "m.db"))
    idx.insert_raw({"ip": "81.2.69.142", "services": [{"port": 443, "service": "https"}]})
    idx.insert_raw({"ip": "45.33.32.156", "services": [{"port": 53, "service": "dns"}]})
    idx.insert_raw({"ip": "192.168.1.9", "services": [{"port": 22, "service": "ssh"}]})
    g = GeoLocator(str(tmp_path / "m.db"), now_iso="2026-10-27T00:00:00Z")
    g._fetcher = FakeGeoFetch()
    counts = g.locate_missing(idx, rate=0)
    assert counts["candidates"] == 2          # the private host is skipped
    assert counts["located"] == 2
    doc = idx.host("81.2.69.142")
    assert doc["lat"] == 51.51 and doc["country"] == "GB"
    g.close()
    idx.close()


# -- query-filtered world map -------------------------------------------------

def run_map(idx, q):
    where, params = compile_query(q)
    return idx.map_points(where, params)


def test_map_points_country_breakdown(seeded_index):
    m = seeded_index.map_points()
    ids = {p["ip"] for p in m["located"]}
    assert "8.8.8.8" in ids and "1.1.1.1" in ids
    assert any(c["country"] for c in m["countries"])


def test_map_filter_by_query(seeded_index):
    # OpenSSH (port 22) only exists on private hosts, which have no coordinates
    m = run_map(seeded_index, "port:22")
    assert m["located"] == []
    # port 53 exists on the located public resolvers
    m2 = run_map(seeded_index, "port:53")
    assert {p["ip"] for p in m2["located"]} == {"8.8.8.8", "1.1.1.1"}


def test_hosts_without_geo(seeded_index):
    missing = seeded_index.hosts_without_geo()
    assert "192.168.1.10" in missing          # private, no coords
    assert "8.8.8.8" not in missing           # known coords


def test_update_host_geo(empty_index):
    empty_index.insert_raw({"ip": "81.2.69.142",
                            "services": [{"port": 443, "service": "https"}]})
    empty_index.update_host_geo("81.2.69.142",
                                Geo(country="DE", city="Berlin", org="X",
                                    asn="AS1", lat=52.5, lon=13.4))
    doc = empty_index.host("81.2.69.142")
    assert doc["lat"] == 52.5 and doc["country"] == "DE"
