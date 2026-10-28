"""Tests for the SQLite index: storage, search, stats and the map query."""

import pytest

from rennacs.db import Index, ip_to_int
from rennacs.query import compile_query


def run(idx: Index, q: str):
    where, params = compile_query(q)
    return idx.search(where, params)


def test_ip_to_int_roundtrip():
    assert ip_to_int("0.0.0.0") == 0
    assert ip_to_int("255.255.255.255") == (1 << 32) - 1
    assert ip_to_int("192.168.1.1") == 3232235777
    assert ip_to_int("not-an-ip") is None
    assert ip_to_int("2001:db8::1") is None   # ipv6 -> None


def test_seed_counts(seeded_index, demo):
    s = seeded_index.stats()
    assert s["hosts"] == len(demo)
    assert s["services"] > 0


def test_port_filter(seeded_index):
    rows, total = run(seeded_index, "port:22")
    assert total >= 1
    assert all(r["port"] == 22 for r in rows)


def test_net_filter_scopes_subnet(seeded_index):
    rows, total = run(seeded_index, "net:192.168.1.0/24")
    assert total > 0
    assert all(r["ip"].startswith("192.168.1.") for r in rows)


def test_has_ssl_filter(seeded_index):
    rows, _ = run(seeded_index, "has_ssl:true")
    assert rows and all(r["has_ssl"] == 1 for r in rows)


def test_vuln_present_on_vulnerable_host(seeded_index):
    doc = seeded_index.host("192.168.1.66")
    assert doc is not None
    all_cves = {v["cve"] for s in doc["services"] for v in s["vulns"]}
    assert "CVE-2011-2523" in all_cves      # vsftpd 2.3.4
    assert "CVE-2021-41773" in all_cves     # apache 2.4.49
    assert doc["vuln_count"] >= 3


def test_has_vuln_filter(seeded_index):
    rows, total = run(seeded_index, "has_vuln:true")
    assert total >= 1
    assert all(r["vulns"] for r in rows)


def test_vuln_specific_cve(seeded_index):
    rows, _ = run(seeded_index, "vuln:CVE-2011-2523")
    assert rows and any(
        v["cve"] == "CVE-2011-2523" for r in rows for v in r["vulns"])


def test_rescan_replaces_services(empty_index):
    empty_index.insert_raw({"ip": "10.9.9.9",
                            "services": [{"port": 80, "service": "http"}]})
    assert empty_index.host("10.9.9.9")["services"][0]["port"] == 80
    # re-insert with a different port set; the old one must be gone
    empty_index.insert_raw({"ip": "10.9.9.9",
                            "services": [{"port": 443, "service": "https"}]})
    ports = [s["port"] for s in empty_index.host("10.9.9.9")["services"]]
    assert ports == [443]


def test_map_points_split_located_and_private(seeded_index):
    m = seeded_index.map_points()
    located_ips = {p["ip"] for p in m["located"]}
    assert "8.8.8.8" in located_ips          # has lat/lon
    assert "192.168.1.10" in m["ungeolocated"]   # private, no geo
    for p in m["located"]:
        assert p["lat"] is not None and p["lon"] is not None


def test_missing_host_returns_none(empty_index):
    assert empty_index.host("203.0.113.7") is None


def test_migration_adds_missing_columns(tmp_path):
    import sqlite3
    # Simulate an OLD database: a services table without the later columns.
    path = str(tmp_path / "old.db")
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE hosts(ip TEXT PRIMARY KEY, hostnames TEXT, country TEXT,
            city TEXT, org TEXT, asn TEXT, lat REAL, lon REAL, seen_at TEXT);
        CREATE TABLE services(id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, port INTEGER,
            transport TEXT, service TEXT, product TEXT, version TEXT, os TEXT,
            has_ssl INTEGER, ssl_cn TEXT, ssl_issuer TEXT, banner TEXT,
            search_text TEXT, seen_at TEXT);
    """)
    con.commit()
    con.close()
    # Opening it through Index must add ip_int/vulns/vuln_ids/kev, not raise.
    idx = Index(path)
    cols = {r["name"] for r in idx.conn.execute("PRAGMA table_info(services)")}
    assert {"ip_int", "vulns", "vuln_ids", "kev"} <= cols
    # and a kev-filtered query must now run without error
    rows, total = run(idx, "kev:true")
    assert total == 0
    idx.close()
