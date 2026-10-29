"""Catalog storage is separate from legacy/import evidence and scan timestamps."""
from tests.inventory_fixture import with_test_source
import json
import sqlite3

import pytest

from rennacs.findings import report
from rennacs.query import compile_query


@pytest.mark.parametrize("rollback", ["insert_failure", "caller"])
def test_catalog_cache_does_not_reuse_rolled_back_revision(empty_index, rollback):
    raw = {"id": "CVE-2099-80002", "affected": [
        {"product": "Fixture Server", "versions": ["1.5"]}]}
    doc = {"ip": "127.0.0.1", "services": [{"port": 80,
        "product": "Fixture Server", "version": "1.5", "vulns": []}]}
    empty_index.catalog.upsert(raw)
    if rollback == "insert_failure":
        with pytest.raises(sqlite3.IntegrityError):
            empty_index.insert_raw(with_test_source(dict(doc, services=doc["services"] * 2)))
    else:
        matches = empty_index._catalog_matches("Fixture Server", "1.5", revision=1)
        assert [item["cve"] for item in matches] == [raw["id"]]
        assert empty_index.conn.in_transaction
        empty_index.conn.rollback()
    assert empty_index.catalog.revision() == 0

    replacement = "CVE-2099-80003"
    empty_index.catalog.upsert(dict(raw, id=replacement))
    empty_index.conn.commit()
    assert empty_index.catalog.revision() == 1
    empty_index.insert_raw(with_test_source(doc))
    stored = empty_index.host("127.0.0.1")["services"][0]
    assert [item["cve"] for item in stored["catalog_vulns"]] == [replacement]
    assert stored["catalog_vulns"][0]["catalog_provenance"] == empty_index.catalog.provenance(replacement)


@pytest.mark.parametrize("positive_evidence", ["import", "reenrichment"])
def test_duplicate_id_preserves_positive_legacy_kev(empty_index, positive_evidence):
    identifier = "CVE-2099-80004"
    seen = "2026-01-01T00:00:00Z"
    empty_index.catalog.upsert({"id": identifier, "affected": [
        {"product": "Fixture Server", "versions": ["1.5"]}]})
    empty_index.conn.commit()
    empty_index.insert_raw(with_test_source({"ip": "127.0.0.1", "seen_at": seen, "services": [
        {"port": 80, "product": "Fixture Server", "version": "1.5", "vulns": [
            {"cve": identifier, "source": "fixture-import", "kev": positive_evidence == "import"}]},
    ]}))
    before = empty_index.host("127.0.0.1")
    if positive_evidence == "reenrichment":
        class PositiveCache:
            def enrich_vuln(self, vuln, version, *, allow_network):
                assert allow_network is False
                return dict(vuln, enriched=True, kev=True)

        assert empty_index.reenrich(PositiveCache()) == {"services": 1, "enriched": 1, "kev": 1}

    stored = empty_index.host("127.0.0.1")["services"][0]
    assert stored["kev"] == 1
    assert stored["vulns"][0]["kev"] is True
    assert stored["vulns"][0]["correlation_sources"] == ["fixture-import", "cve.now-catalog"]
    assert stored["catalog_vulns"][0]["kev"] is False
    legacy = json.loads(empty_index.conn.execute("SELECT vulns FROM services").fetchone()[0])
    assert legacy[0]["kev"] is True
    assert stored["seen_at"] == before["services"][0]["seen_at"] == seen
    assert empty_index.host("127.0.0.1")["seen_at"] == before["seen_at"] == seen
    where, params = compile_query("kev:true")
    assert empty_index.search(where, params)[1] == 1
    assert report(empty_index)["matches"][0]["advisories"][0]["known_exploited_catalog"] is True


def test_catalog_survives_caller_initialization_rollback_without_committing_host(empty_index):
    empty_index.conn.execute("INSERT INTO hosts(ip) VALUES(?)", ("127.0.0.2",))
    catalog = empty_index.catalog
    assert catalog.status()["stored_details"] == 0
    assert empty_index.conn.in_transaction
    with sqlite3.connect(empty_index.path) as observer:
        assert observer.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 0
    empty_index.conn.rollback()
    assert empty_index.host("127.0.0.2") is None

    empty_index.insert_raw(with_test_source({"ip": "127.0.0.1", "services": [{"port": 80,
        "product": "Fixture Server", "version": "1.5", "vulns": []}]}))
    assert empty_index.host("127.0.0.1")["services"][0]["catalog_vulns"] == []
    assert empty_index.catalog is catalog
    assert catalog.status()["revision"] == 0
    with sqlite3.connect(empty_index.path) as observer:
        assert observer.execute("SELECT ip FROM hosts").fetchall() == [("127.0.0.1",)]


def test_catalog_matches_refresh_without_destroying_legacy_or_observation_time(empty_index):
    seen = "2026-10-28T00:00:00+00:00"
    legacy = {"cve": "CVE-2099-10001", "source": "fixture-import", "severity": "low"}
    match = {"cve": "CVE-2099-10002", "catalog_id": "CVE-2099-10002",
             "source": "cve.now-catalog", "match_status": "affected", "confirmed": "yes",
             "severity": "high", "kev": True}
    empty_index.insert_raw(with_test_source({"ip": "127.0.0.1", "seen_at": seen, "services": [
        {"port": 80, "product": "Fixture Server", "version": "1.5", "vulns": [legacy]},
    ]}))
    service = empty_index.host("127.0.0.1")["services"][0]
    empty_index.update_catalog_matches(service["id"], [match], revision=1)
    stored = empty_index.host("127.0.0.1")["services"][0]
    assert {v["cve"] for v in stored["vulns"]} == {legacy["cve"], match["cve"]}
    assert stored["catalog_vulns"] == [match]
    assert stored["catalog_revision"] == 1
    assert stored["catalog_checked_at"]
    assert stored["seen_at"] == seen
    assert stored["kev"] == 1
    where, params = compile_query("vuln:" + match["cve"])
    assert empty_index.search(where, params)[1] == 1

    empty_index.update_catalog_matches(service["id"], [], revision=2)
    stored = empty_index.host("127.0.0.1")["services"][0]
    assert stored["vulns"] == [legacy]
    assert stored["catalog_vulns"] == []
    assert stored["kev"] == 0
    assert stored["seen_at"] == seen
    assert empty_index.search(where, params)[1] == 0
    where, params = compile_query(match["cve"])
    assert empty_index.search(where, params)[1] == 0


def test_new_scan_automatically_matches_cached_advisories_without_network(empty_index, monkeypatch):
    from rennacs.catalog import Catalog
    from rennacs.scanner import HostResult, ServiceResult
    import socket

    def forbidden(*args, **kwargs):
        raise AssertionError("matching must not access the network")

    catalog = Catalog(connection=empty_index.conn)
    catalog.upsert({"id": "CVE-2099-10003", "status": "published",
                    "affected": [{"product": "Fixture Server", "ranges": [
                        {"introduced": "1.0", "fixed": "2.0"}]}]})
    monkeypatch.setattr(socket, "create_connection", forbidden)
    host = HostResult(ip="127.0.0.1", services=[ServiceResult(
        port=12345, product="Fixture Server", version="1.5")])
    empty_index.upsert_host(host)
    stored = empty_index.host("127.0.0.1")["services"][0]
    assert [v["cve"] for v in stored["catalog_vulns"]] == ["CVE-2099-10003"]
    assert stored["catalog_checked_at"]
    assert stored["catalog_revision"] == catalog.revision()


def test_catalog_reassessment_uses_keyset_without_touching_observations(empty_index):
    empty_index.insert_raw(with_test_source({"ip": "127.0.0.1", "seen_at": "2026-10-28T00:00:00Z",
        "services": [{"port": p, "product": "Fixture Server", "version": "1.5", "vulns": []}
                     for p in (80, 81, 82)]}))
    empty_index.catalog.upsert({"id": "CVE-2099-10004", "affected": [
        {"product": "Fixture Server", "ranges": [{"introduced": "1.0", "fixed": "2.0"}]}]})
    first = empty_index.reassess_catalog(limit=2)
    assert first["processed"] == 2
    assert first["matched_services"] == 2
    assert first["advisory_matches"] == 2
    assert first["has_more"] is True
    second = empty_index.reassess_catalog(limit=2, after_id=first["after_id"])
    assert second["processed"] == 1
    assert second["has_more"] is False
    assert second["after_id"] > first["after_id"]
    for service in empty_index.host("127.0.0.1")["services"]:
        assert service["seen_at"] == "2026-10-28T00:00:00Z"
        assert service["catalog_vulns"][0]["cve"] == "CVE-2099-10004"


def test_raw_inventory_insert_uses_local_catalog_and_keeps_imported_tags(empty_index):
    empty_index.catalog.upsert({"id": "CVE-2099-10005", "affected": [
        {"product": "Fixture Server", "versions": ["1.5"]}]})
    empty_index.insert_raw(with_test_source({"ip": "127.0.0.1", "services": [{"port": 80,
        "product": "Fixture Server", "version": "1.5", "vulns": [
            {"cve": "CVE-2099-10006", "source": "import"}]}]}))
    service = empty_index.host("127.0.0.1")["services"][0]
    assert {v["cve"] for v in service["vulns"]} == {"CVE-2099-10005", "CVE-2099-10006"}
    assert len(service["catalog_vulns"]) == 1


def test_legacy_enrichment_cannot_clear_catalog_kev(empty_index):
    class CacheOnly:
        def enrich_vuln(self, vuln, version, *, allow_network):
            assert allow_network is False
            return dict(vuln, enriched=True, kev=False)

    empty_index.catalog.upsert({"id": "CVE-2099-10007", "exploitation": {"kev": True},
        "affected": [{"product": "Fixture Server", "versions": ["1.5"]}]})
    empty_index.insert_raw(with_test_source({"ip": "127.0.0.1", "services": [{"port": 80,
        "product": "Fixture Server", "version": "1.5", "vulns": [
            {"cve": "CVE-2099-10008", "source": "import"}]}]}))
    empty_index.reenrich(CacheOnly())
    service = empty_index.host("127.0.0.1")["services"][0]
    assert service["kev"] == 1
    assert service["catalog_vulns"][0]["kev"] is True


def test_reassessment_invalidates_cached_match_after_advisory_withdrawal(empty_index):
    raw = {"id": "CVE-2099-10009", "affected": [
        {"product": "Fixture Server", "versions": ["1.5"]}]}
    empty_index.catalog.upsert(raw)
    empty_index.insert_raw(with_test_source({"ip": "127.0.0.1", "services": [{"port": 80,
        "product": "Fixture Server", "version": "1.5", "vulns": []}]}))
    before = empty_index.host("127.0.0.1")["services"][0]
    assert len(before["catalog_vulns"]) == 1
    empty_index.catalog.upsert(dict(raw, status="withdrawn"))
    result = empty_index.reassess_catalog()
    assert result["advisory_matches"] == 0
    after = empty_index.host("127.0.0.1")["services"][0]
    assert after["catalog_vulns"] == []
    assert after["catalog_revision"] > before["catalog_revision"]
    assert after["seen_at"] == before["seen_at"]


def test_persisted_match_records_original_catalog_fetch_provenance(empty_index):
    empty_index.catalog.upsert({"id": "CVE-2099-10010", "affected": [
        {"product": "Fixture Server", "versions": ["1.5"]}]})
    provenance = empty_index.catalog.provenance("CVE-2099-10010")
    empty_index.insert_raw(with_test_source({"ip": "127.0.0.1", "services": [{"port": 80,
        "product": "Fixture Server", "version": "1.5", "vulns": []}]}))
    match = empty_index.host("127.0.0.1")["services"][0]["catalog_vulns"][0]
    assert match["catalog_provenance"] == provenance
