"""Catalog CLI/API/UI exercise real SQLite; only external fetches are mocked."""

import gc
import json
import sqlite3
import sys
import urllib.error
import urllib.request

import pytest

import cli
from rennacs._http import SafeFetcher
from rennacs.catalog import Catalog
from rennacs.cvenow import CVENow


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("unexpected network access")

    monkeypatch.setattr(SafeFetcher, "get_json", forbidden)
    monkeypatch.setattr(CVENow, "_get_json", forbidden)
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", forbidden)


def advisory(identifier="CVE-2099-12345", **changes):
    raw = {"id": identifier, "status": "published", "affected": [
        {"vendor": "Fixture Vendor", "product": "Fixture Server", "ranges": [
            {"introduced": "1.0", "fixed": "2.0"}]}]}
    raw.update(changes)
    return raw


def test_status_json_is_offline_and_does_not_infer_coverage_from_stored_data(tmp_path, capsys):
    path = str(tmp_path / "catalog.db")
    cat = Catalog(path)
    cat.upsert(advisory())
    cat.close()

    assert cli.main(["--db", path, "catalog", "status", "--json"]) == 0
    state = json.loads(capsys.readouterr().out)
    assert state["source"] == "cve.now"
    assert state["stored_details"] == 1
    assert state["traversal"] == "not_started"
    assert state["complete"] is False
    assert state["atomic_snapshot"] is False

    assert cli.main(["--db", path, "catalog", "status"]) == 0
    text = capsys.readouterr().out
    assert "not_started" in text
    assert "not an atomic snapshot" in text


def test_sync_resumes_budgeted_partial_work_through_real_catalog(tmp_path, capsys, monkeypatch):
    path = str(tmp_path / "catalog.db")
    calls = []
    base = "https://cve.now/api/v1/entries"

    def fetch(self, url, **kwargs):
        calls.append(url)
        if url == base:
            return {"entries": [{"id": "CVE-2099-12345"}], "nextCursor": None}
        assert url == base + "/CVE-2099-12345"
        return advisory()

    monkeypatch.setattr(CVENow, "_get_json", fetch)
    argv = ["--db", path, "catalog", "sync", "--max-requests", "1"]
    assert cli.main(argv + ["--json"]) == 0
    first = json.loads(capsys.readouterr().out)
    assert first["requests"] == 1
    assert first["complete"] is False
    assert first["status"]["pending_catalog_details"] == 1
    assert cli.main(argv) == 0
    text = capsys.readouterr().out
    assert "traversal complete: True" in text
    assert "not an atomic snapshot" in text
    assert calls == [base, base + "/CVE-2099-12345"]
    cat = Catalog(path)
    try:
        assert cat.status()["stored_details"] == 1
        assert cat.status()["complete"] is True
    finally:
        cat.close()


@pytest.mark.parametrize("options", [
    ["--max-pages", "0"], ["--max-pages", "-1"], ["--max-pages", "1.5"],
    ["--max-requests", "0"], ["--max-requests", "-1"], ["--max-requests", "1.5"],
    ["--rate", "0"], ["--rate", "-1"], ["--rate", "nan"], ["--rate", "inf"],
])
def test_sync_invalid_budgets_exit_two_without_network_or_database(tmp_path, capsys, options):
    path = tmp_path / "invalid.db"
    try:
        code = cli.main(["--db", str(path), "catalog", "sync", *options])
    except SystemExit as exc:
        code = exc.code
    assert code == 2
    assert not path.exists()
    assert capsys.readouterr().err


def test_catalog_api_is_local_status_only_not_a_sync_trigger(tmp_path):
    from rennacs.app import create_app

    path = str(tmp_path / "api.db")
    cat = Catalog(path)
    cat.upsert(advisory())
    expected = cat.status()
    cat.close()
    app = create_app(path)
    app.config.update(TESTING=True)
    client = app.test_client()

    response = client.get("/api/catalog")
    assert response.status_code == 200
    assert response.get_json() == expected
    assert client.post("/api/catalog").status_code == 405
    assert client.post("/api/catalog/sync").status_code == 404
    assert client.get("/api/catalog/sync").status_code == 404
    cat = Catalog(path)
    try:
        assert cat.status() == expected
    finally:
        cat.close()


def test_findings_ui_shows_catalog_coverage_reassessment_and_escaped_evidence(tmp_path):
    from rennacs.app import create_app
    from rennacs.db import Index

    path = str(tmp_path / "ui.db")
    idx = Index(path)
    seen = "2026-01-02T03:04:05Z"
    hostile = "<script>alert('upstream')</script>"
    try:
        idx.catalog.upsert(advisory())
        idx.conn.commit()
        idx.insert_raw({"ip": "127.0.0.1", "seen_at": seen, "services": [
            {"port": 12345, "product": "Fixture Server", "version": "1.5", "vulns": [
                {"cve": "CVE-2099-22222", "source": hostile}]}]})
        service = idx.host("127.0.0.1")["services"][0]
        idx.update_catalog_matches(service["id"], [{
            "cve": "CVE-2099-12345", "catalog_id": "CVE-2099-12345",
            "source": "cve.now-catalog", "match_status": hostile,
            "fixed_versions": ["2.0", hostile], "summary": hostile,
            "detection_method": "catalog_product_version", "confirmed": "yes",
        }], revision=idx.catalog.revision())
        checked = idx.host("127.0.0.1")["services"][0]["catalog_checked_at"]
    finally:
        idx.close()
    app = create_app(path)
    app.config.update(TESTING=True)
    client = app.test_client()
    response = client.get("/findings")
    assert response.status_code == 200
    text = response.get_data(as_text=True)
    assert "Catalog coverage" in text
    assert "not_started" in text
    assert "not an atomic snapshot" in text
    assert "Catalog assessed:" in text and checked in text
    assert "revision 1" in text
    assert seen in text
    assert "Source: cve.now-catalog" in text
    assert "Range match:" in text
    assert "Source-reported fixed versions" in text and "2.0" in text
    assert hostile not in text
    assert "&lt;script&gt;" in text
    assert "potential" in text and "No exploit test performed" in text

    report = client.get("/api/findings").get_json()
    assert report["catalog"] == client.get("/api/catalog").get_json()
    finding = report["matches"][0]
    assert finding["evidence"]["catalog_checked_at"] == checked
    assert finding["evidence"]["catalog_revision"] == 1
    assert finding["assessment"]["status"] == "potential"


def test_fetch_preserves_ids_and_does_not_claim_full_catalog_coverage(tmp_path, capsys, monkeypatch):
    path = str(tmp_path / "fetch.db")
    ids = ["GHSA-4MFG-R38W-W8FG", "GO-2099-1234"]
    calls = []

    def fetch(self, url, **kwargs):
        calls.append(url)
        return advisory(url.rsplit("/", 1)[1])

    monkeypatch.setattr(CVENow, "_get_json", fetch)
    argv = ["--db", path, "catalog", "fetch", *ids, "--max-requests", "1", "--rate", "3"]
    assert cli.main(argv + ["--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["requests"] == 1
    assert result["status"]["pending_targeted_details"] == 1
    assert result["complete"] is False
    assert cli.main(["--db", path, "catalog", "fetch", "--max-requests", "1"]) == 0
    text = capsys.readouterr().out
    assert "ids_complete" in text
    assert "traversal complete: False" in text
    assert calls == ["https://cve.now/api/v1/entries/" + i for i in ids]
    cat = Catalog(path)
    try:
        assert {r["id"] for r in cat.candidates(["Fixture Server"])} == set(ids)
        assert cat.status()["traversal"] == "not_started"
    finally:
        cat.close()


@pytest.mark.parametrize("token", [
    "cve-2099-12345", " CVE-2099-12345", "CVE-2099-12345\n",
    "CVE-2099-12345/../../x", "CVE-２０９９-12345", "https://example.org",
    "GHSA-4MFG-R38W-W8FG?x=1", "not-an-id",
])
def test_fetch_validates_every_exact_id_before_creating_db_or_requesting(tmp_path, token):
    path = tmp_path / "invalid.db"
    assert cli.main(["--db", str(path), "catalog", "fetch", "CVE-2099-12345", token]) == 2
    assert not path.exists()


@pytest.mark.parametrize("options", [
    ["--max-requests", "0"], ["--max-requests", "-1"],
    ["--rate", "0"], ["--rate", "-1"], ["--rate", "nan"], ["--rate", "inf"],
])
def test_fetch_rejects_invalid_budgets_before_network_or_database(tmp_path, options):
    path = tmp_path / "invalid.db"
    assert cli.main(["--db", str(path), "catalog", "fetch", "CVE-2099-12345", *options]) == 2
    assert not path.exists()


def test_assess_is_offline_keyset_progress_and_preserves_observation_time(tmp_path, capsys):
    from rennacs.db import Index

    path = str(tmp_path / "assess.db")
    idx = Index(path)
    seen = "2026-01-02T03:04:05Z"
    try:
        idx.insert_raw({"ip": "127.0.0.1", "seen_at": seen, "services": [
            {"port": 12345, "product": "Fixture Server", "version": "1.5", "vulns": []},
            {"port": 12346, "product": "Fixture Server", "version": "1.6", "vulns": []},
            {"port": 12347, "product": "Other Server", "version": "1.6", "vulns": []}]})
        idx.catalog.upsert(advisory())
        idx.conn.commit()
        before = idx.host("127.0.0.1")
    finally:
        idx.close()
    query = "product:Fixture"
    argv = ["--db", path, "catalog", "assess", query, "--limit", "1", "--json"]
    assert cli.main(argv) == 0
    first = json.loads(capsys.readouterr().out)
    assert first["processed"] == first["matched_services"] == first["advisory_matches"] == 1
    assert first["has_more"] is True
    assert first["catalog_revision"] == 1
    assert cli.main(argv + ["--after-id", str(first["after_id"])]) == 0
    second = json.loads(capsys.readouterr().out)
    assert second["processed"] == 1
    assert second["has_more"] is False
    assert second["after_id"] > first["after_id"]
    idx = Index(path)
    try:
        after = idx.host("127.0.0.1")
        assert after["seen_at"] == before["seen_at"]
        assert [s["seen_at"] for s in after["services"]] == [s["seen_at"] for s in before["services"]]
        assert all(s["catalog_checked_at"] for s in after["services"][:2])
        assert after["services"][2]["catalog_checked_at"] == before["services"][2]["catalog_checked_at"]
        assert idx.service_history("127.0.0.1") == []
    finally:
        idx.close()
    assert cli.main(["--db", path, "catalog", "assess", query, "--limit", "1"]) == 0
    text = capsys.readouterr().out
    assert "has_more: True" in text
    assert "--after-id" in text
    assert "not a snapshot" in text
    assert cli.main(["--db", path, "catalog", "assess", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["processed"] == 3


@pytest.mark.parametrize("options", [
    ["--limit", "0"], ["--limit", "-1"], ["--limit", "10001"],
    ["--after-id", "-1"], ["bogus:1"],
])
def test_assess_rejects_invalid_limits_cursor_and_query_before_database(tmp_path, options):
    path = tmp_path / "invalid.db"
    assert cli.main(["--db", str(path), "catalog", "assess", *options]) == 2
    assert not path.exists()


@pytest.mark.parametrize("operation", ["sync", "fetch"])
@pytest.mark.parametrize("failure", [urllib.error.URLError("offline fixture"), {"malformed": True}])
def test_network_failures_exit_one_with_json_error_and_closed_sqlite(
        tmp_path, capsys, monkeypatch, operation, failure):
    path = str(tmp_path / "failed.db")
    connections = []

    def fetch(self, url):
        connections.extend(o.conn for o in gc.get_objects()
                           if isinstance(o, Catalog) and o.owns_connection)
        if isinstance(failure, BaseException):
            raise failure
        return failure

    monkeypatch.setattr(CVENow, "_get_json", fetch)
    ids = ["CVE-2099-12345"] if operation == "fetch" else []
    assert cli.main(["--db", path, "catalog", operation, *ids, "--json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["stop_reason"] == "error"
    assert data["last_error"]
    assert data["complete"] is False
    assert connections
    for conn in connections:
        with pytest.raises(sqlite3.ProgrammingError):
            conn.execute("SELECT 1")
    cat = Catalog(path)
    try:
        assert cat.status()["last_error"] == data["last_error"]
        if operation == "fetch":
            assert cat.status()["pending_targeted_details"] == 1
    finally:
        cat.close()


@pytest.mark.parametrize("operation", ["sync", "fetch"])
def test_interrupted_network_batch_returns_130_and_closes_sqlite(
        tmp_path, capsys, monkeypatch, operation):
    path = str(tmp_path / "interrupted.db")
    connections = []

    def fetch(self, url):
        connections.extend(o.conn for o in gc.get_objects()
                           if isinstance(o, Catalog) and o.owns_connection)
        raise KeyboardInterrupt

    monkeypatch.setattr(CVENow, "_get_json", fetch)
    ids = ["CVE-2099-12345"] if operation == "fetch" else []
    assert cli.main(["--db", path, "catalog", operation, *ids, "--json"]) == 130
    data = json.loads(capsys.readouterr().out)
    assert data["interrupted"] is True
    assert data["complete"] is False
    assert data["status"]["complete"] is False
    assert connections
    for conn in connections:
        with pytest.raises(sqlite3.ProgrammingError):
            conn.execute("SELECT 1")


def test_interrupted_offline_assessment_closes_index_and_replays_safe_cursor(tmp_path, capsys):
    path = str(tmp_path / "assess.db")
    connections = []

    def interrupt_at_reassessment(frame, event, arg):
        if event == "call" and frame.f_code.co_name == "reassess_catalog":
            connections.append(frame.f_locals["self"].conn)
            raise KeyboardInterrupt
        return interrupt_at_reassessment

    # Inject Ctrl-C at the real SQLite/CLI seam without replacing Index or its methods.
    previous = sys.gettrace()
    sys.settrace(interrupt_at_reassessment)
    try:
        code = cli.main(["--db", path, "catalog", "assess", "--after-id", "7", "--json"])
    finally:
        sys.settrace(previous)
    assert code == 130
    data = json.loads(capsys.readouterr().out)
    assert data["interrupted"] is True
    assert data["after_id"] == 7
    assert data["has_more"] is True
    assert connections
    for conn in connections:
        with pytest.raises(sqlite3.ProgrammingError):
            conn.execute("SELECT 1")
