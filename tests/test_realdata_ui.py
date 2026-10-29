"""Real-data boundaries use isolated databases; no demo inventory is loaded."""
import socket

from rennacs.app import create_app


def test_data_status_api_is_read_only_local_and_empty_by_default(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("status endpoints must not contact sources or targets")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    app = create_app(str(tmp_path / "empty.db"))
    app.config["TESTING"] = True
    client = app.test_client()
    response = client.get("/api/data-status")
    assert response.status_code == 200
    assert response.get_json() == {"policy": "real_only", "sourced_hosts": 0,
        "quarantined_hosts": 0, "sourced_services": 0, "quarantined_services": 0}
    assert client.post("/api/data-status").status_code == 405
    assert client.get("/api/search").get_json()["total"] == 0
    assert client.get("/api/findings").get_json()["total"] == 0


def test_import_page_displays_source_and_unknown_observation_time(tmp_path):
    from flask import render_template
    app = create_app(str(tmp_path / "render.db"))
    provenance = {"kind": "import", "source": "provider<script>alert(1)</script>",
        "retrieved_at": "2026-10-28T20:00:00Z", "observed_at": None,
        "reference": "https://provider.invalid/127.0.0.1", "payload_sha256": "a" * 64}
    doc = {"ip": "127.0.0.1", "hostnames": [], "tags": [], "seen_at": None,
           "provenance": provenance, "services": [{"port": 443, "transport": "unknown",
           "product": "", "service": "", "version": "", "os": "", "has_ssl": False,
           "vulns": [], "banner": "", "seen_at": None, "provenance": provenance}]}
    with app.test_request_context():
        body = render_template("host.html", doc=doc, ip=doc["ip"])
    assert "not supplied by source" in body.lower()
    assert "2026-10-28T20:00:00Z" in body
    assert "provider&lt;script&gt;" in body
    assert "<script>alert(1)</script>" not in body


def test_import_requires_explicit_targets_not_a_starter_population():
    import cli
    import pytest
    with pytest.raises(SystemExit) as exc:
        cli.build_parser().parse_args(["import", "--starter"])
    assert exc.value.code == 2


def test_finding_preserves_source_attribution_without_inventing_observation_time():
    from rennacs.findings import assess_service
    provenance = {"kind": "import", "source": "provider", "observed_at": None,
        "retrieved_at": "2026-10-28T20:00:00Z", "reference": "https://provider.invalid/host",
        "payload_sha256": "a" * 64, "raw_payload": "not duplicated in every finding"}
    finding = assess_service({"ip": "127.0.0.1", "port": 80, "seen_at": None,
        "provenance": provenance, "vulns": []})
    evidence = finding["evidence"]
    assert evidence["observed_at"] is None
    assert evidence["provenance"]["retrieved_at"] == provenance["retrieved_at"]
    assert evidence["provenance"]["source"] == "provider"
    assert evidence["provenance"]["payload_sha256"] == "a" * 64
    assert "raw_payload" not in evidence["provenance"]


def test_findings_page_labels_unknown_time_and_import_source(tmp_path):
    from flask import render_template
    from rennacs.findings import assess_service
    provenance = {"kind": "import", "source": "provider<script>alert(1)</script>",
        "retrieved_at": "2026-10-28T20:00:00Z", "observed_at": None}
    finding = assess_service({"ip": "127.0.0.1", "port": 80, "seen_at": None,
        "provenance": provenance, "vulns": []})
    app = create_app(str(tmp_path / "render.db"))
    with app.test_request_context():
        body = render_template("findings.html", data={"total": 1, "matches": [finding]},
                               q="", error=None, page=1)
    assert "not supplied by source" in body.lower()
    assert "2026-10-28T20:00:00Z" in body
    assert "provider&lt;script&gt;" in body
    assert "<script>alert(1)</script>" not in body


def test_provider_unknown_tls_remains_unknown_after_storage(empty_index):
    from rennacs.internetdb import normalize
    raw = {"ip": "1.1.1.1", "ports": [443], "hostnames": [], "cpes": [], "tags": [], "vulns": []}
    doc = normalize("1.1.1.1", raw, retrieved_at="2026-10-28T20:00:00Z")
    assert doc["services"][0]["has_ssl"] is None
    empty_index.insert_raw(doc)
    service = empty_index.host("1.1.1.1")["services"][0]
    assert service["has_ssl"] is None
    assert service["transport"] == "unknown"
    assert service["seen_at"] is None
