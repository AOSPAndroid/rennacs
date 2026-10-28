"""Assessment reports must never sell banner correlations as confirmed exploits."""


def test_findings_api_returns_evidence_and_unverified_status(client):
    response = client.get("/api/findings?q=ip:192.168.1.66&limit=2")
    assert response.status_code == 200
    data = response.get_json()
    assert data["count"] == len(data["matches"]) == 2
    assert data["total"] >= data["count"]
    for finding in data["matches"]:
        assert finding["ip"] == "192.168.1.66"
        assert finding["assessment"]["status"] == "potential"
        assert finding["assessment"]["confidence"] == "low"
        assert finding["assessment"]["exploit_tested"] is False
        assert finding["evidence"]["observed_at"]
        assert finding["advisories"]
        assert finding["remediation"]["owner_approval_required"] is True


def test_findings_page_explains_confidence_and_remediation(client):
    response = client.get("/findings?q=ip:192.168.1.66")
    assert response.status_code == 200
    assert b"Potential findings" in response.data
    assert b"Owner approval required" in response.data
    assert b"CVE-2021-41773" in response.data
    assert b"not proof" in response.data


def test_findings_cli_exports_the_same_local_report(seeded_index, capsys):
    import json
    import cli

    assert cli.main(["--db", seeded_index.path, "findings", "ip:192.168.1.66", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["unit"] == "service_assessments"
    assert data["matches"]
    assert all(f["assessment"]["status"] == "potential" for f in data["matches"])


def test_enrichment_does_not_confirm_a_vulnerability_on_this_host(enriched_client):
    data = enriched_client.get("/api/findings?q=ip:192.168.1.66").get_json()
    assert data["matches"]
    assert any(v["metadata_enriched"] for f in data["matches"] for v in f["advisories"])
    assert all(f["assessment"]["status"] == "potential" for f in data["matches"])
    assert all(f["assessment"]["exploit_tested"] is False for f in data["matches"])


def test_findings_reject_invalid_query_and_unbounded_pagination(client):
    for query in ("q=bogus:1", "limit=0", "limit=1001", "limit=oops", "offset=-1"):
        response = client.get("/api/findings?" + query)
        assert response.status_code == 400
        assert "error" in response.get_json()


def test_findings_paginate_service_assessments_without_duplicate_ids(client):
    first = client.get("/api/findings?limit=1").get_json()
    second = client.get("/api/findings?limit=1&offset=1").get_json()
    assert first["total"] == second["total"]
    assert first["matches"][0]["id"] != second["matches"][0]["id"]
