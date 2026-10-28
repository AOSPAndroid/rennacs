"""Tests for the Shodan InternetDB importer (real-data ingest), with a fake fetcher."""

import pytest

from rennacs.db import Index
from rennacs.internetdb import InternetDB, _parse_cpe, normalize
from rennacs.query import compile_query

# A real-shaped InternetDB response (modeled on scanme.nmap.org).
RAW_SCANME = {
    "cpes": ["cpe:/o:canonical:ubuntu_linux", "cpe:/a:ntp:ntp:3",
             "cpe:/a:openbsd:openssh:6.6.1p1", "cpe:/a:apache:http_server:2.4.7"],
    "hostnames": ["scanme.nmap.org"],
    "ip": "45.33.32.156",
    "ports": [22, 80, 123, 31337],
    "tags": ["cloud", "self-signed"],
    "vulns": ["CVE-2017-9798", "CVE-2021-26691", "CVE-2013-6438"],
}


def test_parse_cpe_uri_and_formatted():
    assert _parse_cpe("cpe:/a:openbsd:openssh:6.6.1p1") == ("a", "openssh", "6.6.1p1")
    assert _parse_cpe("cpe:/o:canonical:ubuntu_linux") == ("o", "ubuntu_linux", "")
    assert _parse_cpe("cpe:2.3:a:nginx:nginx:1.18.0:*:*") == ("a", "nginx", "1.18.0")
    assert _parse_cpe("garbage") == ("", "", "")


def test_normalize_maps_ports_products_os():
    doc = normalize("45.33.32.156", RAW_SCANME)
    assert doc["ip"] == "45.33.32.156"
    assert doc["hostnames"] == ["scanme.nmap.org"]
    assert doc["tags"] == ["cloud", "self-signed"]
    by_port = {s["port"]: s for s in doc["services"]}
    assert set(by_port) == {22, 80, 123, 31337}
    assert by_port[22]["product"] == "OpenSSH" and by_port[22]["version"] == "6.6.1p1"
    assert by_port[80]["product"] == "Apache httpd" and by_port[80]["version"] == "2.4.7"
    assert by_port[123]["product"] == "NTP"
    assert all(s["os"] == "Ubuntu" for s in doc["services"])


def test_normalize_attaches_vulns_to_web_service():
    doc = normalize("45.33.32.156", RAW_SCANME)
    by_port = {s["port"]: s for s in doc["services"]}
    cves = {v["cve"] for v in by_port[80]["vulns"]}        # web service carries them
    assert "CVE-2017-9798" in cves and len(cves) == 3
    assert by_port[22]["vulns"] == []                       # not misattributed to ssh
    assert all(v["source"] == "shodan-internetdb" for v in by_port[80]["vulns"])


def test_normalize_filters_bad_data():
    doc = normalize("1.2.3.4", {"ports": [80, 99999, "x"], "vulns": ["not-a-cve"],
                                "hostnames": ["a"], "tags": []})
    assert [s["port"] for s in doc["services"]] == [80]     # bad ports dropped
    assert all(not s["vulns"] for s in doc["services"])     # bad CVE dropped


class FakeIDB:
    def __init__(self):
        self.calls = []
        self.data = {"45.33.32.156": RAW_SCANME}

    def get_json(self, url, timeout=8.0):
        self.calls.append(url)
        ip = url.rstrip("/").rsplit("/", 1)[-1]
        if ip in self.data:
            return self.data[ip]
        return {"detail": "No information available"}     # InternetDB 404 shape


@pytest.fixture
def idb(tmp_path):
    c = InternetDB(str(tmp_path / "i.db"), now_iso="2026-10-27T00:00:00Z")
    c._fetcher = FakeIDB()
    yield c
    c.close()


def test_lookup_and_cache(idb):
    doc = idb.lookup("45.33.32.156")
    assert doc and len(doc["services"]) == 4
    n = len(idb._fetcher.calls)
    idb.lookup("45.33.32.156")                 # cache hit
    assert len(idb._fetcher.calls) == n


def test_lookup_unknown_is_cached_absent(idb):
    assert idb.lookup("203.0.113.200") is None  # (also private in 3.12, returns None)
    assert idb.lookup("8.8.8.8") is None        # not in fake data -> absent
    calls = len(idb._fetcher.calls)
    idb.lookup("8.8.8.8")                        # not re-fetched
    assert len(idb._fetcher.calls) == calls


def test_offline_no_network(tmp_path):
    c = InternetDB(str(tmp_path / "o.db"), offline=True)
    c._fetcher = FakeIDB()
    assert c.lookup("45.33.32.156") is None
    assert c._fetcher.calls == []
    c.close()


def test_import_targets_indexes_real_data(tmp_path):
    idx = Index(str(tmp_path / "x.db"))
    c = InternetDB(str(tmp_path / "x.db"), now_iso="2026-10-27T00:00:00Z")
    c._fetcher = FakeIDB()
    counts = c.import_targets(["45.33.32.156", "8.8.8.8"], idx, rate=0)
    assert counts["requested"] == 2 and counts["found"] == 1
    doc = idx.host("45.33.32.156")
    assert doc["tags"] == ["cloud", "self-signed"]
    assert any(s["product"] == "OpenSSH" for s in doc["services"])
    c.close()
    idx.close()


def test_tag_filter(tmp_path):
    idx = Index(str(tmp_path / "t.db"))
    idx.insert_raw(normalize("45.33.32.156", RAW_SCANME))
    where, params = compile_query("tag:self-signed")
    rows, total = idx.search(where, params)
    assert total >= 1 and all(r["ip"] == "45.33.32.156" for r in rows)
    # a tag that isn't present returns nothing
    where2, p2 = compile_query("tag:honeypot")
    assert idx.search(where2, p2)[1] == 0
    idx.close()
