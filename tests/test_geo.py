"""Tests for geolocation (offline enrich + network GeoLocator) and the global map."""

import pytest
from inventory_fixture import with_test_source

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


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "9.9.9.9", "81.2.69.142"])
def test_public_offline_enrichment_has_no_canned_location(ip, monkeypatch):
    monkeypatch.setattr("rennacs.geoip._maxmind", lambda ip: None)
    assert enrich(ip) == Geo()


def test_enrich_offline():
    assert enrich("192.168.1.9").org.startswith("Private")   # classification, not geo
    assert enrich("127.0.0.1").city == "localhost"
    assert enrich("203.0.113.9").lat is None


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


@pytest.mark.parametrize("payload", [[], {"lat": True, "lon": 1}, {"lat": 500, "lon": 0}])
def test_malformed_geo_cache_stays_unknown_offline_and_refetches_online(geo, payload):
    import json
    geo.conn.execute("INSERT INTO geo_cache VALUES(?,1,?,?)",
                     ("81.2.69.142", json.dumps(payload), "2026-10-27T00:00:00Z"))
    geo.conn.commit()
    assert geo.locate("81.2.69.142", allow_network=False) is None
    assert geo.locate("81.2.69.142").lat == 51.51
    assert geo._fetcher.calls == ["https://ipwho.is/81.2.69.142"]


@pytest.mark.parametrize("fields", [
    {"country": {}}, {"city": []}, {"org": True},
    *({key: text} for key in ("country", "city", "org")
      for text in ("\ud800", "\udfff")),
    *({"asn": asn} for asn in [
        True, False, 123, 123.0, [], "ASTrue", "ASAS123", "AS0", "AS01",
        "AS4294967296", " AS123", "AS123\n", "AS１２３",
    ]),
])
def test_malformed_cached_fields_refetch_before_index_update(geo, empty_index, fields):
    import json
    ip = "81.2.69.142"
    empty_index.insert_raw(with_test_source({
        "ip": ip, "services": [{"port": 443, "service": "https"}],
    }))
    payload = {"lat": 1, "lon": 2, **fields}
    geo.conn.execute("INSERT INTO geo_cache VALUES(?,1,?,?)",
                     (ip, json.dumps(payload), "2026-10-27T00:00:00Z"))
    geo.conn.commit()

    assert geo.locate(ip, allow_network=False) is None
    assert geo.locate_missing(empty_index, rate=0) == {
        "candidates": 1, "located": 1, "failed": 0,
    }
    doc = empty_index.host(ip)
    assert (doc["country"], doc["city"], doc["org"], doc["asn"], doc["lat"], doc["lon"]) == (
        "GB", "London", "Example GmbH", "AS64500", 51.51, -0.13,
    )
    assert geo.locate(ip, allow_network=False).asn == "AS64500"
    assert geo._fetcher.calls == [f"https://ipwho.is/{ip}"]


def test_locate_private_never_fetches(geo):
    assert geo.locate("10.0.0.5") is None
    assert geo._fetcher.calls == []


@pytest.mark.parametrize("raw", [
    {"success": "false", "latitude": 1, "longitude": 2},
    {"success": True},
    {"success": True, "latitude": True, "longitude": 2},
    {"success": True, "latitude": "51.5", "longitude": 2},
    {"success": True, "latitude": 91, "longitude": 2},
    {"success": True, "latitude": 1, "longitude": -181},
    {"success": True, "latitude": float("nan"), "longitude": 2},
    {"success": True, "latitude": 1, "longitude": 2, "ip": "1.1.1.1"},
    {"success": True, "latitude": 1, "longitude": 2, "connection": []},
])
def test_provider_failure_or_malformed_geo_never_produces_coordinates(geo, raw):
    geo._fetcher.get_json = lambda *args, **kwargs: raw
    assert geo.locate("8.8.8.8") is None
    assert geo.locate("8.8.8.8", allow_network=False) is None


@pytest.mark.parametrize("fields", [
    {"country_code": {"name": "US"}, "city": ["X"],
     "connection": {"org": ["X"], "asn": 123}},
    {"country_code": {"name": "US"}},
    {"country": ["United States"]},
    {"city": ["X"]},
    {"connection": {"org": ["X"]}},
    {"connection": {"isp": {"name": "X"}}},
    *({key: text} for key in ("country_code", "country", "city")
      for text in ("\ud800", "\udfff")),
    *({"connection": {key: text}} for key in ("org", "isp")
      for text in ("\ud800", "\udfff")),
])
def test_malformed_provider_text_rejected_before_index_update(geo, empty_index, fields):
    ip = "8.8.8.8"
    empty_index.insert_raw(with_test_source({
        "ip": ip, "services": [{"port": 53, "service": "dns"}],
    }))
    raw = {"success": True, "ip": ip, "latitude": 1, "longitude": 2, **fields}
    geo._fetcher.get_json = lambda *args, **kwargs: raw

    assert geo.locate_missing(empty_index, rate=0) == {
        "candidates": 1, "located": 0, "failed": 1,
    }
    doc = empty_index.host(ip)
    assert doc["lat"] is None and doc["lon"] is None
    assert all(doc[key] == "" for key in ("country", "city", "org", "asn"))
    assert geo.locate(ip, allow_network=False) is None
    assert geo.conn.execute("SELECT 1 FROM geo_cache WHERE ip=?", (ip,)).fetchone() is None


@pytest.mark.parametrize("source, field, target", [
    ("provider", "country_code", "country"), ("provider", "country", "country"),
    ("provider", "city", "city"), ("provider", "org", "org"),
    ("provider", "isp", "org"),
    ("cache", "country", "country"), ("cache", "city", "city"),
    ("cache", "org", "org"),
])
def test_valid_unicode_preserved_through_cache_and_index(geo, empty_index, source, field, target):
    import json
    ip = "8.8.8.8"
    text = "Qu\u00e9bec \u6771\u4eac \U0001f6f0 e\u0301"
    empty_index.insert_raw(with_test_source({
        "ip": ip, "services": [{"port": 53, "service": "dns"}],
    }))
    if source == "cache":
        payload = {"lat": 1, "lon": 2, field: text}
        geo.conn.execute("INSERT INTO geo_cache VALUES(?,1,?,?)",
                         (ip, json.dumps(payload), "2026-10-27T00:00:00Z"))
        geo.conn.commit()
    else:
        fields = {"connection": {field: text}} if field in ("org", "isp") else {field: text}
        raw = {"success": True, "latitude": 1, "longitude": 2, **fields}
        geo._fetcher.get_json = lambda *args, **kwargs: raw

    assert geo.locate_missing(empty_index, rate=0) == {
        "candidates": 1, "located": 1, "failed": 0,
    }
    assert geo.locate(ip, allow_network=False) == Geo(**{target: text}, lat=1, lon=2)
    doc = empty_index.host(ip)
    assert doc[target] == text
    assert (doc["lat"], doc["lon"]) == (1, 2)


@pytest.mark.parametrize("asn", [True, False, "AS123", "123", 123.0, 1.5,
                                 [], {}, -1, 0, 4294967296])
def test_malformed_provider_asn_never_invents_identifier(geo, asn):
    raw = {"success": True, "latitude": 1, "longitude": 2,
           "connection": {"asn": asn}}
    geo._fetcher.get_json = lambda *args, **kwargs: raw
    assert geo.locate("8.8.8.8") is None
    assert geo.locate("8.8.8.8", allow_network=False) is None


@pytest.mark.parametrize("source", ["provider", "provider-null-connection", "cache"])
def test_null_optional_fields_remain_unknown_through_index(geo, empty_index, source):
    import json
    ip = "8.8.8.8"
    empty_index.insert_raw(with_test_source({
        "ip": ip, "services": [{"port": 53, "service": "dns"}],
    }))
    if source == "cache":
        payload = {"lat": 1, "lon": 2,
                   "country": None, "city": None, "org": None, "asn": None}
        geo.conn.execute("INSERT INTO geo_cache VALUES(?,1,?,?)",
                         (ip, json.dumps(payload), "2026-10-27T00:00:00Z"))
        geo.conn.commit()
    else:
        connection = (None if source == "provider-null-connection" else
                      {"org": None, "isp": None, "asn": None})
        raw = {"success": True, "latitude": 1, "longitude": 2,
               "country_code": None, "country": None, "city": None,
               "connection": connection}
        geo._fetcher.get_json = lambda *args, **kwargs: raw

    assert geo.locate_missing(empty_index, rate=0) == {
        "candidates": 1, "located": 1, "failed": 0,
    }
    assert geo.locate(ip, allow_network=False) == Geo(lat=1, lon=2)
    doc = empty_index.host(ip)
    assert all(doc[key] == "" for key in ("country", "city", "org", "asn"))
    assert (doc["lat"], doc["lon"]) == (1, 2)
    assert geo._fetcher.calls == []


@pytest.mark.parametrize("asn", [1, 4294967295])
def test_provider_integer_asn_boundaries_survive_cache(geo, asn):
    raw = {"success": True, "latitude": 1, "longitude": 2,
           "country": "United States", "connection": {"isp": "Example", "asn": asn}}
    geo._fetcher.get_json = lambda *args, **kwargs: raw
    expected = Geo(country="United States", org="Example", asn=f"AS{asn}", lat=1, lon=2)
    assert geo.locate("8.8.8.8") == expected
    assert geo.locate("8.8.8.8", allow_network=False) == expected


@pytest.mark.parametrize("fields, asn", [
    ({}, ""), ({"asn": ""}, ""),
    ({"asn": "AS1"}, "AS1"), ({"asn": "AS4294967295"}, "AS4294967295"),
])
def test_valid_cached_optional_fields_need_no_refetch(geo, fields, asn):
    import json
    payload = {"lat": 1, "lon": 2, **fields}
    geo.conn.execute("INSERT INTO geo_cache VALUES(?,1,?,?)",
                     ("8.8.8.8", json.dumps(payload), "2026-10-27T00:00:00Z"))
    geo.conn.commit()
    assert geo.locate("8.8.8.8") == Geo(asn=asn, lat=1, lon=2)
    assert geo._fetcher.calls == []


def test_provider_network_failure_stays_unknown(geo):
    def fail(*args, **kwargs):
        raise TimeoutError("provider unavailable")
    geo._fetcher.get_json = fail
    assert geo.locate("8.8.8.8") is None
    assert geo.locate("8.8.8.8", allow_network=False) is None


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
    idx.insert_raw(with_test_source({"ip": "81.2.69.142", "services": [{"port": 443, "service": "https"}]}))
    idx.insert_raw(with_test_source({"ip": "45.33.32.156", "services": [{"port": 53, "service": "dns"}]}))
    idx.insert_raw(with_test_source({"ip": "192.168.1.9", "services": [{"port": 22, "service": "ssh"}]}))
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
    empty_index.insert_raw(with_test_source({"ip": "81.2.69.142",
                            "services": [{"port": 443, "service": "https"}]}))
    empty_index.update_host_geo("81.2.69.142",
                                Geo(country="DE", city="Berlin", org="X",
                                    asn="AS1", lat=52.5, lon=13.4))
    doc = empty_index.host("81.2.69.142")
    assert doc["lat"] == 52.5 and doc["country"] == "DE"
