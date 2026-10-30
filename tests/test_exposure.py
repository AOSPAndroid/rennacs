"""Scope, provenance, uncertainty and operator-state regression tests; no live I/O."""
import copy
import gzip
import json
import urllib.error
from datetime import datetime, timedelta, timezone

import pytest

from rennacs.exposure.cli import csv_export
from rennacs.exposure.engine import assess, report
from rennacs.exposure.scope import Scope, stamp
from rennacs.exposure.sources import (Remote, Shodan, import_shodan, observation,
                                      parse_feed, parse_msrc, sync_microsoft,
                                      trusted_url, validate_advisory)
from rennacs.exposure.store import Store


@pytest.fixture
def setup(tmp_path):
    now = datetime.now(timezone.utc)
    scope = Scope({"engagement": "SYNTHETIC-TEST", "networks": [{"cidr": "192.0.2.0/24",
        "authorization_ref": "synthetic fixture, no real target", "expires_at": (now + timedelta(days=3)).isoformat()}]})
    advisory = {"id": "CVE-2026-9999999", "vendor": "citrix", "title": "SYNTHETIC TEST ONLY",
        "published_at": (now - timedelta(hours=24)).isoformat(), "source_url": "https://support.citrix.com/TEST-ONLY",
        "affected": [{"product": "NetScaler ADC", "ranges": [{"introduced": "14.1.0", "fixed": "14.1.50"}]}],
        "reviewed_by": "test fixture", "range_evidence_ref": "synthetic numeric rule"}
    banner = {"ip_str": "192.0.2.10", "port": 443, "transport": "tcp", "product": "Citrix NetScaler",
        "version": "14.1.40", "timestamp": (now - timedelta(hours=1)).isoformat(), "data": "synthetic banner"}
    return tmp_path, scope, advisory, banner, now.isoformat()


def seed(setup):
    path, scope, advisory, banner, now = setup
    store = Store(str(path / "test.db"))
    store.advisory(validate_advisory(advisory))
    store.observation(observation(banner, scope))
    return store, scope, now


def test_scope_has_no_implicit_private_or_public_access(setup):
    _, scope, _, _, _ = setup
    for ip in ["127.0.0.1", "10.1.1.1", "8.8.8.8", "example.org", "192.0.3.1"]:
        with pytest.raises(ValueError): scope.authorize(ip)
    assert scope.authorize("192.0.2.10")["engagement"] == "SYNTHETIC-TEST"


@pytest.mark.parametrize("change", ["expiry", "empty", "broad", "reference", "timezone"])
def test_invalid_scopes_fail_closed(setup, change):
    data = copy.deepcopy(setup[1].data)
    if change == "expiry": data["networks"][0]["expires_at"] = "2000-01-01T00:00:00Z"
    if change == "empty": data["networks"] = []
    if change == "broad": data["networks"][0]["cidr"] = "0.0.0.0/0"
    if change == "reference": data["networks"][0]["authorization_ref"] = ""
    if change == "timezone": data["networks"][0]["expires_at"] = "2030-01-01T00:00:00"
    with pytest.raises(ValueError): Scope(data)


def test_version_match_never_confirms_and_keeps_provenance(setup):
    store, scope, now = seed(setup)
    with store:
        data = assess(store, scope, now)
        row = data["findings"][0]
        assert row["match_kind"] == "version_match"
        assert row["confirmation"] == "unconfirmed"
        assert "confirmed" not in row
        assert row["fixed_versions"] == ["14.1.50"]
        assert row["observed_at"] < row["ingested_at"]
        assert row["advisory_fetched_at"] and len(row["evidence_hash"]) == 64
        assert row["disclosure_to_remediation_hours"] is None


@pytest.mark.parametrize("version", ["", "14.1-40.1", "unknown"])
def test_unsupported_versions_stay_uncertain(setup, version):
    path, scope, advisory, banner, now = setup
    banner["version"] = version
    with Store(str(path / "test.db")) as store:
        store.advisory(validate_advisory(advisory))
        store.observation(observation(banner, scope))
        assert assess(store, scope, now)["findings"][0]["match_kind"] == "product_match_unknown"


def test_old_and_predisclosure_evidence_is_flagged(setup):
    path, scope, advisory, banner, now = setup
    banner["timestamp"] = "2020-01-01T00:00:00Z"
    with Store(str(path / "test.db")) as store:
        store.advisory(validate_advisory(advisory))
        store.observation(observation(banner, scope))
        row = assess(store, scope, now)["findings"][0]
        assert row["stale"] and row["pre_disclosure_evidence"]
        assert row["first_post_disclosure_observed_at"] is None


def test_new_banner_cannot_auto_remediate(setup):
    store, scope, now = seed(setup)
    with store:
        first = assess(store, scope)["findings"][0]
        banner = dict(setup[3], version="14.1.60", timestamp=stamp())
        store.observation(observation(banner, scope))
        second = assess(store, scope)["findings"][0]
        assert second["finding_id"] == first["finding_id"]
        assert second["status"] == "open" and second["match_kind"] == "not_reproduced"
        assert len(store.history(first["finding_id"])["assessments"]) == 2


def test_owner_decisions_are_explicit_append_only_and_exported(setup):
    store, scope, now = seed(setup)
    with store:
        row = assess(store, scope)["findings"][0]
        with pytest.raises(ValueError): store.decide(row["finding_id"], "remediated", "", "")
        store.decide(row["finding_id"], "owner_confirmed", "owner", "inventory://snapshot/1")
        assert report(store)["findings"][0]["confirmation"] == "owner_attestation"
        store.decide(row["finding_id"], "remediated", "owner", "change://CHG123")
        exported = report(store)["findings"][0]
        assert exported["disclosure_to_remediation_hours"] >= 24
        assert exported["priority"] == 0
        assert len(store.history(row["finding_id"])["decisions"]) == 2
        assert store.history(row["finding_id"])["assessments"][0]["status"] == "open"


def test_revoked_scope_excludes_stored_assets(setup):
    store, scope, now = seed(setup)
    with store:
        assess(store, scope)
        other = Scope({**scope.data, "networks": [{**scope.data["networks"][0], "cidr": "198.51.100.0/24"}]})
        data = assess(store, other)
        assert data["findings"] == [] and data["excluded_observations"] == 1


def test_export_import_is_atomic_and_idempotent(setup):
    path, scope, _, banner, _ = setup
    file = path / "data.json.gz"
    with Store(str(path / "test.db")) as store:
        with gzip.open(file, "wt") as f: f.write(json.dumps(banner) + "\n")
        assert import_shodan(file, scope, store) == 1
        assert import_shodan(file, scope, store) == 0
        with gzip.open(file, "wt") as f:
            f.write(json.dumps(banner) + "\n" + json.dumps({**banner, "ip_str": "8.8.8.8"}))
        with pytest.raises(ValueError): import_shodan(file, scope, store)
        assert len(store.observations()) == 1


@pytest.mark.parametrize("url", ["http://api.shodan.io/api-info", "https://api.shodan.io.evil.test/", "https://user@api.shodan.io/", "https://api.shodan.io:8443/", "https://127.0.0.1/"])
def test_outbound_host_and_scheme_guards(url):
    with pytest.raises(ValueError): trusted_url(url, {"api.shodan.io"})


def test_shodan_only_queries_allowed_ip_database_and_hides_key(setup, monkeypatch):
    calls = []
    class Fake:
        def get(self, url, hosts, **kwargs):
            calls.append(url)
            return {"data": [], "plan": "test", "query_credits": 5, "key": "SENSITIVE"}
    monkeypatch.setenv("SHODAN_API_KEY", "SENSITIVE")
    client = Shodan(Fake())
    with pytest.raises(ValueError): client.host("8.8.8.8", setup[1])
    assert not calls
    client.host("192.0.2.10", setup[1], history=True)
    assert "/shodan/host/192.0.2.10?" in calls[0] and "history=true" in calls[0]
    assert "SENSITIVE" not in json.dumps(client.capabilities())
    assert not any("/scan" in url for url in calls)


def test_network_exception_does_not_leak_query_key():
    class Fail:
        def open(self, request, **kwargs):
            raise urllib.error.HTTPError(request.full_url, 401, "key=SECRET", {}, None)
    remote = Remote(interval=0)
    remote.opener = Fail()
    with pytest.raises(ValueError) as error:
        remote.get("https://api.shodan.io/api-info?key=SECRET", {"api.shodan.io"})
    assert "SECRET" not in str(error.value)


def test_vendor_feed_preserves_original_date_and_does_not_invent_ranges():
    xml = b'''<rss><channel><item><title>CVE-2026-9999999</title>
    <link>https://support.citrix.com/TEST</link><pubDate>Thu, 29 Oct 2026 10:00:00 GMT</pubDate>
    <description>NetScaler before 14.1-50.1; requires Gateway configuration</description>
    </item></channel></rss>'''
    rows = parse_feed(xml, "citrix", "https://support.citrix.com/rss")
    assert len(rows) == 1 and rows[0]["affected"] == []
    assert rows[0]["published_at"] == "2026-10-29T10:00:00+00:00"
    assert "Gateway configuration" in rows[0]["affected_text"]
    with pytest.raises(ValueError): parse_feed(b'<!DOCTYPE x><rss/>', "citrix", "https://support.citrix.com/rss")


def test_review_required_before_using_machine_ranges(setup):
    row = dict(setup[2])
    del row["reviewed_by"]
    with pytest.raises(ValueError): validate_advisory(row)


def test_msrc_keeps_windows_editions_kbs_and_cve_dates():
    raw = {"ProductTree": {"FullProductName": [{"ProductID": "123", "Value": "Windows Server 2022"}]},
           "Vulnerability": [{"CVE": "CVE-2026-9999999", "Title": {"Value": "synthetic"},
               "RevisionHistory": [{"Date": "2026-10-01T10:00:00"}, {"Date": "2026-10-29T10:00:00Z"}],
               "ProductStatuses": [{"Type": 3, "ProductID": ["123"]}, {"Type": 0, "ProductID": ["do-not-use"]}],
               "Remediations": [{"Description": {"Value": "KB9999999"}}]}]}
    rows = parse_msrc(raw, "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Oct")
    assert rows[0]["affected"][0]["product"] == "Windows Server 2022"
    assert len(rows[0]["affected"]) == 1
    assert rows[0]["affected"][0]["ranges"] == []
    assert rows[0]["published_at"].startswith("2026-10-01")
    assert rows[0]["remediations"][0]["Description"]["Value"] == "KB9999999"


def test_msrc_budget_is_honest_about_remaining_documents(tmp_path):
    class Fake:
        def get(self, url, hosts, **kwargs):
            if url.endswith("updates"):
                return {"value": [{"ID": "2026-Oct", "CurrentReleaseDate": "2026-10-29T00:00:00Z"},
                                  {"ID": "2026-Sep", "CurrentReleaseDate": "2026-09-29T00:00:00Z"}]}
            return {"Vulnerability": []}
    with Store(str(tmp_path / "test.db")) as store:
        result = sync_microsoft(store, "2026-01-01", limit=1, remote=Fake())
        assert result["documents"] == 1 and result["remaining_documents"] == 1
        result = sync_microsoft(store, "2026-01-01", limit=1, remote=Fake())
        assert result["documents"] == 1 and result["remaining_documents"] == 0
        assert sync_microsoft(store, "2026-01-01", limit=1, remote=Fake())["documents"] == 0


def test_filter_csv_formula_defence_and_read_only_web(setup, monkeypatch):
    store, scope, now = seed(setup)
    with store:
        assess(store, scope)
        assert len(report(store, {"vendor": "citrix"})["findings"]) == 1
        assert report(store, {"vendor": "microsoft"})["findings"] == []
        with pytest.raises(ValueError): report(store, {"max_evidence_hours": "nan"})
    from rennacs.app import create_app
    def forbidden(*args, **kwargs): raise AssertionError("page views must be offline")
    monkeypatch.setattr(Remote, "get", forbidden)
    client = create_app(str(setup[0] / "test.db")).test_client()
    response = client.get("/exposure")
    assert response.status_code == 200 and b"SYNTHETIC TEST ONLY" in response.data
    assert client.get("/api/exposure?max_disclosure_hours=no").status_code == 400
    assert client.post("/api/exposure").status_code == 405
    assert b"finding_id" in client.get("/api/exposure/export.csv").data
    csv = csv_export({"findings": [{"product": " =cmd()"}]})
    assert "' =cmd()" in csv


def test_advisory_revisions_and_decision_history_survive_restart(setup):
    store, scope, now = seed(setup)
    with store:
        assess(store, scope)
        revised = {**setup[2], "title": "Updated synthetic advisory"}
        store.advisory(validate_advisory(revised))
        assess(store, scope)
    with Store(str(setup[0] / "test.db")) as reopened:
        assert reopened.advisories()[0]["title"] == "Updated synthetic advisory"
        fid = reopened.latest()["findings"][0]["finding_id"]
        assert len(reopened.history(fid)["assessments"]) == 2


def test_advisory_refresh_and_reversion_preserve_all_revisions(setup):
    store, scope, now = seed(setup)
    with store:
        original = validate_advisory(setup[2])
        original_hash = store.advisories()[0]["revision"]
        store.advisory({**original, "title": "Revised"})
        assert store.advisories()[0]["title"] == "Revised"
        store.advisory(original)
        assert store.advisories()[0]["revision"] == original_hash
        assert store.evidence(original_hash)["data"] == original
        assert store.db.execute("SELECT COUNT(*) FROM exposure_advisories").fetchone()[0] == 2
        assert store.db.execute("SELECT COUNT(*) FROM exposure_advisory_fetches").fetchone()[0] == 3


def test_provider_reported_cve_is_never_confirmed(setup):
    path, scope, advisory, banner, now = setup
    banner.update(product="", version="", vulns={advisory["id"]: {"verified": True}})
    with Store(str(path / "test.db")) as store:
        store.advisory(validate_advisory({**advisory, "affected": []}))
        store.observation(observation(banner, scope))
        row = assess(store, scope)["findings"][0]
        assert row["match_kind"] == "provider_reported_unverified"
        assert row["confirmation"] == "unconfirmed"


def test_recent_evidence_after_remediation_requires_review(setup):
    store, scope, now = seed(setup)
    with store:
        first = assess(store, scope)["findings"][0]
        store.decide(first["finding_id"], "remediated", "owner", "CHG1")
        store.observation(observation({**setup[3], "timestamp": stamp()}, scope))
        row = assess(store, scope)["findings"][0]
        assert row["status"] == "remediated" and row["review_after_decision"]
        assert row["priority"] >= 50


def test_disclosure_window_ranks_ahead_of_older_same_match(setup):
    store, scope, now = seed(setup)
    with store:
        older = {**setup[2], "id": "CVE-2026-9999998", "published_at": "2026-01-01T00:00:00Z"}
        store.advisory(validate_advisory(older))
        rows = assess(store, scope)["findings"]
        assert rows[0]["advisory_id"] == setup[2]["id"]
        assert rows[0]["priority"] > rows[1]["priority"]


def test_cli_batch_scope_gate_prevents_any_shodan_request(setup, monkeypatch, capsys):
    import cli
    path, scope, advisory, banner, now = setup
    file = path / "scope.json"
    file.write_text(json.dumps(scope.data))
    def forbidden(*args, **kwargs): raise AssertionError("must gate batch before constructing Shodan")
    monkeypatch.setattr(Shodan, "__init__", forbidden)
    code = cli.main(["--db", str(path / "test.db"), "exposure", "collect", "--scope", str(file),
                     "192.0.2.10", "8.8.8.8"])
    assert code == 2 and "allowlist" in capsys.readouterr().err


def test_malformed_vendor_feed_and_cli_missing_key_fail_cleanly(monkeypatch, capsys):
    import cli
    with pytest.raises(ValueError): parse_feed(b"<rss>", "citrix", "https://support.citrix.com/rss")
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    assert cli.main(["exposure", "account"]) == 2
    assert "SHODAN_API_KEY" in capsys.readouterr().err
