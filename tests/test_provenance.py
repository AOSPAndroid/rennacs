"""Inventory requires attributed acquisition; old rows are not retroactive evidence."""
import json
import sqlite3

import pytest

from rennacs.db import Index


def import_doc(ip="127.0.0.1", **extra):
    return {"ip": ip, "services": [{"port": 80, "product": "Apache httpd", "version": "2.4.49"}],
            "provenance": {"kind": "import", "source": "inventory-provider",
                           "retrieved_at": "2026-10-28T12:00:00+00:00",
                           "reference": "https://inventory.example/" + ip,
                           "payload_sha256": "a" * 64}, **extra}


def test_raw_without_explicit_import_evidence_is_rejected_before_write(empty_index):
    with pytest.raises(ValueError, match="provenance"):
        empty_index.insert_raw({"ip": "127.0.0.1", "services": [{"port": 80}]})
    assert empty_index.conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 0
    assert empty_index.stats()["services"] == 0


def test_sourced_import_roundtrips_metadata_without_inventing_measurement_time(empty_index):
    doc = import_doc()
    doc["provenance"]["host_cpes"] = ["cpe:/a:vendor:product:1.0"]
    doc["provenance"]["host_advisories"] = ["CVE-2099-1000"]
    empty_index.insert_raw(doc)
    stored = empty_index.host(doc["ip"])
    assert stored["provenance"] == doc["provenance"]
    assert stored["seen_at"] is None
    assert stored["observed_at"] is None
    assert stored["services"][0]["provenance"] == doc["provenance"]
    assert stored["services"][0]["seen_at"] is None
    assert stored["services"][0]["observed_at"] is None
    rows, total = empty_index.search("1", [])
    assert total == 1
    assert rows[0]["provenance"] == doc["provenance"]
    assert empty_index.data_status() == {
        "policy": "real_only", "sourced_hosts": 1, "quarantined_hosts": 0,
        "sourced_services": 1, "quarantined_services": 0,
    }


def make_legacy(path):
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE hosts(ip TEXT PRIMARY KEY, hostnames TEXT, country TEXT,
            city TEXT, org TEXT, asn TEXT, lat REAL, lon REAL, seen_at TEXT);
        CREATE TABLE services(id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, port INTEGER,
            transport TEXT, service TEXT, product TEXT, version TEXT, os TEXT,
            has_ssl INTEGER, ssl_cn TEXT, ssl_issuer TEXT, banner TEXT,
            search_text TEXT, seen_at TEXT);
        INSERT INTO hosts(ip, hostnames, country, lat, lon, seen_at)
            VALUES('127.0.0.9', '["legacy.invalid"]', 'XX', 10, 20, '2099-01-01T00:00:00Z');
        INSERT INTO services(ip, port, transport, product, version, banner, search_text, seen_at)
            VALUES('127.0.0.9', 22, 'tcp', 'OpenSSH', '9.0', 'legacy banner', 'legacy',
                   '2099-01-01T00:00:00Z');
    """)
    conn.commit()
    conn.close()


def test_migration_quarantines_legacy_without_rewriting_or_deleting_evidence(tmp_path):
    path = str(tmp_path / "legacy.db")
    make_legacy(path)
    for _ in range(2):
        idx = Index(path)
        assert idx.host("127.0.0.9") is None
        assert idx.search("1", []) == ([], 0)
        assert idx.stats()["hosts"] == idx.stats()["services"] == 0
        assert idx.map_points() == {"located": [], "ungeolocated": [], "countries": []}
        assert idx.hosts_without_geo() == []
        assert idx.service_history("127.0.0.9") == []
        assert idx.data_status() == {"policy": "real_only", "sourced_hosts": 0,
            "quarantined_hosts": 1, "sourced_services": 0, "quarantined_services": 1}
        row = idx.conn.execute("SELECT * FROM hosts").fetchone()
        assert row["seen_at"] == "2099-01-01T00:00:00Z"
        assert row["hostnames"] == '["legacy.invalid"]'
        assert json.loads(row["provenance"])["kind"] == "legacy_unverified"
        assert idx.conn.execute("SELECT banner FROM services").fetchone()[0] == "legacy banner"
        idx.close()


def test_scan_stamps_internal_evidence_and_keeps_history_sourced(empty_index):
    import hashlib
    from rennacs.scanner import HostResult, ServiceResult

    measured = "2026-10-28T10:00:00+00:00"
    service = ServiceResult(port=80, banner="HTTP/1.0 200 OK\r\n", seen_at=measured)
    result = HostResult(ip="127.0.0.1", services=[service], scanned_ports=[80], seen_at=measured)
    empty_index.upsert_host(result)
    stored = empty_index.host(result.ip)
    assert stored is not None
    assert stored["provenance"]["kind"] == "scan"
    assert stored["provenance"]["source"] == "rennacs"
    assert stored["provenance"]["observed_at"] == measured
    assert "reference" not in stored["provenance"]
    assert stored["observed_at"] == measured
    evidence = stored["services"][0]
    assert evidence["provenance"]["banner_sha256"] == hashlib.sha256(service.banner.encode()).hexdigest()
    assert evidence["observed_at"] == measured
    assert empty_index.data_status()["sourced_services"] == 1
    result.services = []
    empty_index.upsert_host(result)
    history = empty_index.service_history(result.ip)
    assert [event["state"] for event in history] == ["not_observed", "open"]
    assert all(event["provenance"]["kind"] == "scan" for event in history)


@pytest.mark.parametrize("writer", ["import", "scan"])
def test_sourced_refresh_preserves_quarantined_collision_for_review(tmp_path, writer):
    from rennacs.scanner import HostResult, ServiceResult

    path = str(tmp_path / "collision.db")
    make_legacy(path)
    idx = Index(path)
    idx.conn.execute("UPDATE hosts SET tags='[\"invented-tag\"]'")
    if writer == "import":
        idx.insert_raw(import_doc("127.0.0.9"))
    else:
        idx.upsert_host(HostResult(ip="127.0.0.9", services=[ServiceResult(port=80)]))
    stored = idx.host("127.0.0.9")
    assert [s["port"] for s in stored["services"]] == [80]
    assert stored["tags"] == []
    assert stored["hostnames"] == []
    assert stored["country"] != "XX"
    assert all(event["state"] != "not_observed" for event in idx.service_history("127.0.0.9"))
    archived = [dict(row) for row in idx.conn.execute("SELECT * FROM quarantined_records")]
    assert {row["record_type"] for row in archived} == {"hosts", "services"}
    service = next(json.loads(row["payload"]) for row in archived if row["record_type"] == "services")
    assert service["banner"] == "legacy banner"
    assert service["seen_at"] == "2099-01-01T00:00:00Z"
    expected = {"policy": "real_only", "sourced_hosts": 1, "sourced_services": 1,
                "quarantined_hosts": 1, "quarantined_services": 1}
    assert idx.data_status() == expected
    idx.close()
    reopened = Index(path)
    assert reopened.data_status() == expected
    reopened.close()


def test_quarantined_services_cannot_be_reassessed_through_direct_update(empty_index):
    empty_index.insert_raw(import_doc())
    service_id = empty_index.host("127.0.0.1")["services"][0]["id"]
    empty_index.conn.execute("UPDATE services SET provenance=? WHERE id=?",
                            ('{"kind":"synthetic"}', service_id))
    with pytest.raises(ValueError, match="no such service"):
        empty_index.update_catalog_matches(service_id, [], revision=1)
    assert empty_index.conn.execute("SELECT catalog_revision FROM services").fetchone()[0] == 0


def test_mixed_inventory_does_not_leak_legacy_tags_geo_findings_or_history(empty_index):
    from rennacs.findings import report
    from rennacs.query import compile_query

    idx = empty_index
    idx.insert_raw(import_doc(lat=10.0, lon=20.0, country="US"))
    idx.conn.execute("INSERT INTO hosts(ip, tags, hostnames, country, seen_at) VALUES(?,?,?,?,?)",
        ("127.0.0.9", '["invented-tag"]', '["legacy.invalid"]', "XX", "2099-01-01T00:00:00Z"))
    unknown = {"cve": "CVE-2099-1000", "source": "invented", "kev": True}
    for ip in ("127.0.0.1", "127.0.0.9"):
        idx.conn.execute("""INSERT INTO services(ip, port, transport, product, version, banner,
            vulns, vuln_ids, kev, search_text) VALUES(?,22,'tcp','Legacy','9','invented',?,?,1,?)""",
            (ip, json.dumps([unknown]), unknown["cve"], "invented-tag legacy"))
        idx.conn.execute("""INSERT INTO service_observations(ip,port,transport,state,observed_at,
            details,note) VALUES(?,22,'tcp','open','2099-01-01T00:00:00Z',?,'invented')""",
            (ip, json.dumps(unknown)))
    idx.conn.commit()
    assert idx.host("127.0.0.9") is None
    assert [s["port"] for s in idx.host("127.0.0.1")["services"]] == [80]
    assert idx.search("1", [])[1] == idx.stats()["services"] == 1
    assert idx.stats()["hosts"] == 1
    assert idx.stats()["top_countries"] == [{"country": "US", "n": 1}]
    assert idx.stats()["top_ports"] == [{"port": 80, "n": 1}]
    for query in ("invented-tag", "product:Legacy", "port:22", "vuln:CVE-2099-1000"):
        where, params = compile_query(query)
        assert idx.search(where, params) == ([], 0)
        assert idx.map_points(where, params)["located"] == []
        assert report(idx, query)["total"] == 0
    assert idx.service_history("127.0.0.1") == idx.service_history("127.0.0.9") == []
    assert idx.hosts_without_geo() == []
    assert [point["ip"] for point in idx.map_points()["located"]] == ["127.0.0.1"]
    assert unknown["cve"] not in idx.distinct_cves()

    class CacheOnly:
        def enrich_vuln(self, vuln, version, *, allow_network):
            assert allow_network is False
            assert vuln["cve"] != unknown["cve"]
            return vuln

    assert idx.reenrich(CacheOnly())["services"] == 1
    assert idx.reassess_catalog(limit=1)["processed"] == 1
    assert idx.reassess_catalog(limit=1)["has_more"] is False
    assert all(row[0] is None for row in idx.conn.execute(
        "SELECT catalog_checked_at FROM services WHERE port=22"))
    assert idx.data_status() == {"policy": "real_only", "sourced_hosts": 1,
        "quarantined_hosts": 1, "sourced_services": 1, "quarantined_services": 2}


@pytest.mark.parametrize("existing", [False, True])
def test_empty_provider_response_neither_creates_placeholder_nor_erases_observation(empty_index, existing):
    if existing:
        empty_index.insert_raw(import_doc())
    before = empty_index.host("127.0.0.1")
    empty_index.insert_raw(import_doc(services=[]))
    assert empty_index.host("127.0.0.1") == before
    assert empty_index.data_status()["sourced_hosts"] == int(existing)


def test_scan_history_uses_service_measurement_not_host_completion_time(empty_index):
    from rennacs.scanner import HostResult, ServiceResult

    service = ServiceResult(port=22, seen_at="2026-10-28T10:00:00Z")
    host = HostResult(ip="127.0.0.1", services=[service], seen_at="2026-10-28T11:00:00Z")
    empty_index.upsert_host(host)
    assert empty_index.service_history(host.ip)[0]["observed_at"] == service.seen_at


@pytest.mark.parametrize("change", [
    {"kind": "scan", "source": "rennacs"}, {"kind": "synthetic"},
    {"source": ""}, {"source": " inventory-provider"}, {"source": "synthetic"},
    {"source": "demo"}, {"source": "rennacs"}, {"source": 4},
    {"retrieved_at": "2026-10-28T12:00:00"}, {"retrieved_at": "2026-10-28"},
    {"reference": "http://inventory.example/source"}, {"reference": "https://"},
    {"reference": "https://user:password@inventory.example/"},
    {"payload_sha256": "a" * 63}, {"payload_sha256": "g" * 64},
    {"payload_sha256": "a" * 64 + "\n"},
])
def test_bad_or_self_asserted_scan_import_is_rejected_without_changing_existing_data(empty_index, change):
    doc = import_doc()
    empty_index.insert_raw(doc)
    before = empty_index.host(doc["ip"])
    doc["provenance"].update(change)
    with pytest.raises(ValueError, match="provenance"):
        empty_index.insert_raw(doc)
    assert empty_index.host(doc["ip"]) == before


@pytest.mark.parametrize("table", ["hosts", "services"])
@pytest.mark.parametrize("metadata", ["not json", "null", "{}", '{"kind":"synthetic"}',
    json.dumps(import_doc()["provenance"] | {"retrieved_at": "not-a-time"})])
def test_tampered_persisted_metadata_is_quarantined_on_read_and_reopen(tmp_path, table, metadata):
    path = str(tmp_path / "tampered.db")
    idx = Index(path)
    idx.insert_raw(import_doc())
    idx.conn.execute(f"UPDATE {table} SET provenance=?", (metadata,))
    idx.conn.commit()
    idx.close()
    idx = Index(path)
    assert idx.search("1", []) == ([], 0)
    assert idx.stats()["services"] == 0
    assert idx.data_status()["quarantined_services"] == 1
    assert idx.distinct_cves() == []
    assert idx.map_points() == {"located": [], "ungeolocated": [], "countries": []}
    assert idx.reassess_catalog()["processed"] == 0
    assert idx.service_history("127.0.0.1") == []
    assert idx.conn.execute(f"SELECT provenance FROM {table}").fetchone()[0] == metadata
    idx.close()


def test_fresh_index_is_empty_across_all_inventory_reads(empty_index):
    from rennacs.findings import report

    assert empty_index.data_status() == {"policy": "real_only", "sourced_hosts": 0,
        "quarantined_hosts": 0, "sourced_services": 0, "quarantined_services": 0}
    assert empty_index.stats() == {"hosts": 0, "services": 0, "top_ports": [],
        "top_products": [], "top_countries": [], "top_vulns": [], "vuln_services": 0, "kev_services": 0}
    assert empty_index.search("1", []) == ([], 0)
    assert report(empty_index)["total"] == 0
    assert empty_index.distinct_cves() == []
    assert empty_index.hosts_without_geo() == []
    assert empty_index.service_history("127.0.0.1") == []
    assert empty_index.reassess_catalog()["processed"] == 0


def test_failed_refresh_rolls_back_quarantine_archive_with_original_rows_intact(tmp_path):
    path = str(tmp_path / "rollback.db")
    make_legacy(path)
    idx = Index(path)
    before_host = dict(idx.conn.execute("SELECT * FROM hosts").fetchone())
    before_service = dict(idx.conn.execute("SELECT * FROM services").fetchone())
    doc = import_doc("127.0.0.9")
    doc["services"].append({"product": "missing-port"})
    with pytest.raises(KeyError, match="port"):
        idx.insert_raw(doc)
    assert dict(idx.conn.execute("SELECT * FROM hosts").fetchone()) == before_host
    assert dict(idx.conn.execute("SELECT * FROM services").fetchone()) == before_service
    assert idx.conn.execute("SELECT COUNT(*) FROM quarantined_records").fetchone()[0] == 0
    assert idx.data_status()["quarantined_services"] == 1
    idx.close()


def test_malformed_service_override_cannot_claim_internal_scan(empty_index):
    doc = import_doc()
    doc["services"][0]["provenance"] = {"kind": "scan", "source": "rennacs"}
    with pytest.raises(ValueError, match="provenance"):
        empty_index.insert_raw(doc)
    assert empty_index.conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 0


def test_refresh_of_one_legacy_port_never_promotes_unscanned_ports(tmp_path):
    from rennacs.scanner import HostResult, ServiceResult

    path = str(tmp_path / "partial.db")
    make_legacy(path)
    idx = Index(path)
    idx.upsert_host(HostResult(ip="127.0.0.9", services=[ServiceResult(port=80)], scanned_ports=[80]))
    assert [s["port"] for s in idx.host("127.0.0.9")["services"]] == [80]
    assert idx.data_status()["quarantined_services"] == 1
    assert len(idx.service_history("127.0.0.9")) == 1
    idx.close()


def test_unsuccessful_scan_does_not_promote_existing_legacy_host(tmp_path):
    from rennacs.scanner import HostResult

    path = str(tmp_path / "failed.db")
    make_legacy(path)
    idx = Index(path)
    before = idx.data_status()
    idx.upsert_host(HostResult(ip="127.0.0.9", scanned_ports=[22]))
    assert idx.data_status() == before
    assert idx.host("127.0.0.9") is None
    assert idx.conn.execute("SELECT banner FROM services").fetchone()[0] == "legacy banner"
    idx.close()


def test_geo_updates_do_not_rewrite_quarantined_operator_evidence(tmp_path):
    from rennacs.geoip import Geo

    path = str(tmp_path / "geo-legacy.db")
    make_legacy(path)
    idx = Index(path)
    before = dict(idx.conn.execute("SELECT * FROM hosts").fetchone())
    idx.update_host_geo("127.0.0.9", Geo(country="US", city="Different", lat=30.0, lon=40.0))
    assert dict(idx.conn.execute("SELECT * FROM hosts").fetchone()) == before
    idx.close()


@pytest.mark.parametrize("token", [" CVE-2099-1000", "CVE-2099-1000\n", "cve-2099-1000"])
def test_inventory_never_repairs_advisory_identifier_tokens(empty_index, token):
    doc = import_doc(services=[{"port": 80, "vulns": [{"cve": token}]}])
    empty_index.insert_raw(doc)
    assert empty_index.host(doc["ip"])["services"][0]["vulns"][0]["cve"] == token
    assert empty_index.distinct_cves() == []
    assert empty_index.stats()["top_vulns"] == []
