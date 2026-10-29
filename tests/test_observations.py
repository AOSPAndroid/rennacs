"""Current observations must not erase services outside a scan's scope."""
from tests.inventory_fixture import with_test_source
from types import SimpleNamespace

from rennacs.scanner import ServiceResult


def observation(ip, ports, services=()):
    return SimpleNamespace(
        ip=ip, hostnames=[], services=list(services), scanned_ports=ports,
        seen_at="2026-10-28T20:00:00+00:00",
    )


def test_partial_port_rescan_preserves_unscanned_services(empty_index):
    empty_index.insert_raw(with_test_source({"ip": "127.0.0.1", "services": [
        {"port": 22, "service": "ssh"}, {"port": 80, "service": "http"},
    ]}))
    empty_index.upsert_host(observation("127.0.0.1", [80], [ServiceResult(port=80)]))
    assert [s["port"] for s in empty_index.host("127.0.0.1")["services"]] == [22, 80]


def test_lost_observation_is_recorded_as_unknown_not_fixed(empty_index):
    empty_index.upsert_host(observation("127.0.0.1", [80], [
        ServiceResult(port=80, product="Apache httpd", version="2.4.49"),
    ]))
    empty_index.upsert_host(observation("127.0.0.1", [80]))
    assert empty_index.host("127.0.0.1")["services"] == []
    history = empty_index.service_history("127.0.0.1")
    assert [event["state"] for event in history] == ["not_observed", "open"]
    assert history[0]["details"]["version"] == "2.4.49"
    assert "not proof" in history[0]["note"]


def test_unresponsive_new_address_does_not_create_empty_index_rows(empty_index):
    empty_index.upsert_host(observation("127.0.0.9", [22, 80]))
    assert empty_index.host("127.0.0.9") is None
    assert empty_index.service_history("127.0.0.9") == []


def test_history_api_exposes_uncertain_rescan(empty_index):
    from rennacs.app import create_app

    empty_index.upsert_host(observation("127.0.0.1", [80], [ServiceResult(port=80)]))
    empty_index.upsert_host(observation("127.0.0.1", [80]))
    app = create_app(empty_index.path)
    response = app.test_client().get("/api/host/127.0.0.1/history")
    assert response.status_code == 200
    data = response.get_json()
    assert data["count"] == len(data["events"]) == 2
    assert data["events"][0]["state"] == "not_observed"
    assert "not proof" in data["events"][0]["note"]


def test_tls_subject_names_and_trust_survive_index_roundtrip(empty_index):
    service = ServiceResult(port=443, has_ssl=True, ssl_cn="fixture.local",
                            ssl_sans=["fixture.local", "127.0.0.1"], ssl_trust="unverified")
    empty_index.upsert_host(observation("127.0.0.1", [443], [service]))
    stored = empty_index.host("127.0.0.1")["services"][0]
    assert stored["ssl_sans"] == ["fixture.local", "127.0.0.1"]
    assert stored["ssl_trust"] == "unverified"
