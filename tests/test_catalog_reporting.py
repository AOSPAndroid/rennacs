"""Catalog-report fixtures are synthetic and never contact advisory/host APIs."""
from tests.inventory_fixture import with_test_source
from rennacs.findings import assess_service
import pytest


def test_catalog_finding_keeps_product_bound_evidence_and_fix_provenance():
    affected = [{"vendor": "Fixture Vendor", "product": "Fixture Server",
                 "ranges": [{"introduced": "1.0", "fixed": "2.0"}]}]
    finding = assess_service({
        "ip": "127.0.0.1", "port": 12345, "transport": "tcp",
        "product": "Fixture Server", "version": "1.5", "seen_at": "2026-10-28T00:00:00Z",
        "vulns": [{"cve": "CVE-2099-99999", "source": "cve.now-catalog",
                   "catalog_id": "CVE-2099-99999", "detection_method": "catalog_product_version",
                   "match_status": "affected", "confirmed": "yes", "severity": "high",
                   "matched_affected": affected, "fixed_versions": ["2.0"],
                   "summary": "Synthetic advisory fixture."}],
    })
    advisory = finding["advisories"][0]
    assert advisory["source"] == "cve.now-catalog"
    assert advisory["match_status"] == "affected"
    assert advisory["matched_affected"] == affected
    assert advisory["fixed_versions"] == ["2.0"]
    assert advisory["reference"] == "https://cve.now/CVE-2099-99999"
    assert finding["assessment"]["status"] == "potential"
    assert finding["assessment"]["exploit_tested"] is False


@pytest.mark.parametrize("advisory_id", ["GHSA-4MFG-R38W-W8FG", "GO-2099-1234", "PYSEC-2022-5"])
def test_report_accepts_catalog_identifiers_without_case_repair(advisory_id):
    finding = assess_service({"ip": "127.0.0.1", "port": 80, "vulns": [
        {"cve": advisory_id, "catalog_id": advisory_id, "source": "cve.now-catalog",
         "match_status": "unknown", "confirmed": "unknown"},
    ]})
    assert finding["advisories"][0]["cve"] == advisory_id
    assert finding["advisories"][0]["reference"] == "https://cve.now/" + advisory_id
    assert finding["advisories"][0]["version_range_match"] == "unknown"
    assert finding["assessment"]["status"] == "potential"


@pytest.mark.parametrize("advisory_id", [
    "CVE-2099-99999/../../", "CVE-2099-99999\n", "cve-2099-99999",
    "CVE-2022-123", "GHSA-2022-123",
])
def test_report_rejects_malformed_ids_instead_of_normalizing(advisory_id):
    finding = assess_service({"ip": "127.0.0.1", "port": 80, "vulns": [
        {"cve": advisory_id, "source": "cve.now-catalog"},
    ]})
    assert finding["advisories"] == []


def test_local_report_exposes_catalog_coverage_and_reassessment_time(empty_index):
    from rennacs.findings import report
    empty_index.insert_raw(with_test_source({"ip": "127.0.0.1", "seen_at": "2026-10-28T00:00:00Z",
        "services": [{"port": 80, "product": "Fixture Server", "version": "1.5",
                      "vulns": []}]}))
    empty_index.catalog.upsert({"id": "CVE-2099-19999", "affected": [
        {"product": "Fixture Server", "ranges": [{"introduced": "1.0", "fixed": "2.0"}]}]})
    empty_index.reassess_catalog()
    data = report(empty_index)
    assert data["catalog"]["stored_details"] == 1
    assert data["catalog"]["complete"] is False
    evidence = data["matches"][0]["evidence"]
    assert evidence["observed_at"] == "2026-10-28T00:00:00Z"
    assert evidence["catalog_checked_at"]
    assert evidence["catalog_revision"] == empty_index.catalog.revision()
    advisory = data["matches"][0]["advisories"][0]
    assert advisory["summary_provenance"]["kind"] == "unavailable"
    assert advisory["limitations"]
    assert advisory["catalog_provenance"]["fetched_at"]
    assert advisory["catalog_provenance"]["source"] == "cve.now"
