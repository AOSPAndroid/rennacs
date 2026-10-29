"""Synthetic inventory must stay in tests, never in the running product."""

import ast
import importlib.util
from pathlib import Path

import pytest

from rennacs.app import create_app
from rennacs.db import Index


ROOT = Path(__file__).resolve().parents[1]


def test_synthetic_inventory_is_only_an_inert_test_fixture():
    assert not (ROOT / "demo_seed.py").exists(), "Remove the runtime seeder"
    assert importlib.util.find_spec("demo_seed") is None

    fixture = ROOT / "tests" / "inventory_fixture.py"
    assert fixture.is_file(), "Keep synthetic inventory under tests only"
    tree = ast.parse(fixture.read_text(encoding="utf-8"))
    datasets = [node.value for node in tree.body if isinstance(node, ast.Assign)
                and any(isinstance(name, ast.Name) and name.id == "TEST_DATA"
                        for name in node.targets)]
    assert len(datasets) == 1
    data = ast.literal_eval(datasets[0])  # no generators, calls or current timestamps
    assert isinstance(data, list) and len(data) == 16
    assert {doc["ip"] for doc in data} >= {"8.8.8.8", "1.1.1.1", "192.168.1.66"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert not (node.module or "").startswith("rennacs")
        elif isinstance(node, ast.Import):
            assert not any(name.name.startswith("rennacs") for name in node.names)
        elif isinstance(node, ast.Name):
            assert node.id not in {"Index", "main", "__name__"}
        elif isinstance(node, ast.Attribute):
            assert node.attr not in {"insert_raw", "upsert_host", "execute", "connect"}
    assert not any(isinstance(node, (ast.For, ast.While, ast.If, ast.With))
                   for node in tree.body), "The fixture is data, not a runnable seeder"


def test_test_source_copies_inventory_with_explicit_deterministic_provenance():
    import copy
    import hashlib
    import json
    from datetime import datetime

    import inventory_fixture

    wrap = getattr(inventory_fixture, "with_test_source", None)
    assert callable(wrap), "Provide the test-only provenance helper"
    original = {"ip": "127.0.0.1", "services": [{"port": 22, "banner": "SSH-2.0-test"}]}
    before = copy.deepcopy(original)
    first, second = wrap(original), wrap(original)
    assert original == before and "provenance" not in original
    assert first == second and first is not original
    provenance = first["provenance"]
    expected_hash = hashlib.sha256(json.dumps(
        original, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")).hexdigest()
    assert provenance == {
        "kind": "import", "source": "test-fixture",
        "retrieved_at": "2026-10-27T00:00:00+00:00",
        "reference": "https://fixtures.invalid/inventory",
        "payload_sha256": expected_hash,
    }
    assert datetime.fromisoformat(provenance["retrieved_at"]).utcoffset() is not None
    first["services"][0]["port"] = 443
    first["provenance"]["source"] = "changed"
    assert original == before and second["services"][0]["port"] == 22
    changed = copy.deepcopy(original)
    changed["services"][0]["banner"] = "different"
    assert wrap(changed)["provenance"]["payload_sha256"] != expected_hash


def test_shared_inventory_uses_test_provenance_before_inserting():
    tree = ast.parse((ROOT / "tests" / "conftest.py").read_text(encoding="utf-8"))
    inserts = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
               and isinstance(node.func, ast.Attribute) and node.func.attr == "insert_raw"]
    assert len(inserts) == 3
    for node in inserts:
        assert isinstance(node.args[0], ast.Call), "Wrap every test inventory document"
        assert isinstance(node.args[0].func, ast.Name)
        assert node.args[0].func.id == "with_test_source"


@pytest.mark.parametrize("route", ["/", "/search?q=port%3A22"])
def test_empty_ui_requests_authorized_observations_not_generated_data(tmp_path, route):
    app = create_app(str(tmp_path / "empty.db"))
    app.config.update(TESTING=True)
    response = app.test_client().get(route)
    assert response.status_code == 200
    text = response.get_data(as_text=True).lower()
    assert "demo" not in text, "Never suggest generating observations"
    assert "authorized" in text and "import" in text
    assert "private / lab hosts only" not in text  # no made-up country explanation
    assert "index is empty" in text if route == "/" else "no matches" in text


def test_fresh_ui_api_stay_empty_without_network_or_fixture_loading(tmp_path, monkeypatch):
    def no_network(*args, **kwargs):
        pytest.fail("Fresh index reads must not acquire external data")

    monkeypatch.setattr("rennacs._http.SafeFetcher.get_json", no_network)
    monkeypatch.setattr("rennacs.cvenow.CVENow._get_json", no_network)
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "fresh.db"
    assert not path.exists()
    app = create_app(str(path))
    app.config.update(TESTING=True)
    client = app.test_client()
    for route in ("/", "/search", "/map", "/findings"):
        assert client.get(route).status_code == 200
    stats = client.get("/api/stats").get_json()
    for key in ("hosts", "services", "vuln_services", "kev_services"):
        assert stats[key] == 0
    for key in ("top_ports", "top_products", "top_countries", "top_vulns"):
        assert stats[key] == []
    for route in ("/api/search", "/api/findings"):
        data = client.get(route).get_json()
        assert data["total"] == data["count"] == 0
        assert data["matches"] == []
    assert client.get("/api/map").get_json() == {
        "located": [], "ungeolocated": [], "countries": [],
    }
    assert client.get("/api/jobs").get_json() == {"jobs": []}
    feed = client.get("/api/cve-feed").get_json()
    assert feed["items"] == [] and not feed["catalog"]
    assert client.get("/api/host/8.8.8.8").status_code == 404
    assert client.get("/host/192.168.1.66").status_code == 404
    idx = Index(str(path))
    try:
        assert idx.stats()["hosts"] == idx.stats()["services"] == 0
        assert idx.search("1=1", [])[1] == 0
    finally:
        idx.close()
    assert not (tmp_path / "rennacs.db").exists()


def test_production_does_not_import_synthetic_inventory():
    paths = [*ROOT.glob("*.py"), *(ROOT / "rennacs").rglob("*.py")]
    assert paths
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or "", *(alias.name for alias in node.names)]
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                # Also catch dynamic import strings and runpy/importlib fixture paths.
                assert "inventory_fixture" not in node.value
                continue
            else:
                continue
            assert not any(name.startswith("tests") or "inventory_fixture" in name
                           or "demo_seed" in name for name in names), str(path)


def test_inventory_database_is_isolated_under_tmp_path(seeded_index, tmp_path):
    paths = [Path(row[2]).resolve() for row in
             seeded_index.conn.execute("PRAGMA database_list") if row[1] == "main"]
    assert paths and all(path.is_relative_to(tmp_path.resolve()) for path in paths)


@pytest.mark.parametrize("identity", ["package", "user_agent", "/", "/search", "/map", "/findings"])
def test_product_identity_describes_observations_not_an_educational_recreation(tmp_path, identity):
    import rennacs
    from rennacs.cvenow import USER_AGENT

    if identity == "package":
        text = rennacs.__doc__
    elif identity == "user_agent":
        text = USER_AGENT
    else:
        app = create_app(str(tmp_path / "identity.db"))
        app.config.update(TESTING=True)
        response = app.test_client().get(identity)
        assert response.status_code == 200
        text = response.get_data(as_text=True)
    assert "educational" not in text.lower()
    assert "re-creation" not in text.lower()
    assert "demo" not in text.lower()


def test_search_discloses_missing_source_measurement_time(tmp_path):
    from inventory_fixture import with_test_source

    path = str(tmp_path / "unknown-observation-time.db")
    idx = Index(path)
    try:
        idx.insert_raw(with_test_source({"ip": "192.0.2.9", "services": [
            {"port": 443, "service": "https"},
        ]}))
    finally:
        idx.close()
    app = create_app(path)
    app.config.update(TESTING=True)
    client = app.test_client()
    data = client.get("/api/search").get_json()
    assert data["total"] == 1 and data["matches"][0]["seen_at"] is None
    response = client.get("/search")
    assert response.status_code == 200
    assert "not supplied by source" in response.get_data(as_text=True).lower()


def test_home_kev_count_describes_advisories_not_host_exploitation(enriched_client):
    response = enriched_client.get("/")
    assert response.status_code == 200
    text = response.get_data(as_text=True).lower()
    assert "services with kev-linked advisories" in text
    assert "not proof of exploitation" in text


def test_home_explains_quarantined_records_without_promoting_them(tmp_path):
    import re
    from inventory_fixture import with_test_source

    path = str(tmp_path / "quarantined.db")
    idx = Index(path)
    try:
        idx.insert_raw(with_test_source({"ip": "192.0.2.11", "services": [{"port": 22}]}))
        # Simulate unsupported legacy rows, not a source-attributed import.
        idx.conn.execute("INSERT INTO hosts(ip) VALUES(?)", ("192.0.2.12",))
        idx.conn.execute("INSERT INTO services(ip, port) VALUES(?,?)", ("192.0.2.12", 80))
        idx.conn.commit()
    finally:
        idx.close()
    app = create_app(path)
    app.config.update(TESTING=True)
    client = app.test_client()
    assert client.get("/api/data-status").get_json() == {
        "policy": "real_only", "sourced_hosts": 1, "sourced_services": 1,
        "quarantined_hosts": 1, "quarantined_services": 1,
    }
    response = client.get("/")
    assert response.status_code == 200
    html = response.get_data(as_text=True).lower()
    text = " ".join(re.sub(r"<[^>]+>", " ", html).split())
    assert "quarantined hosts: 1" in text and "quarantined services: 1" in text
    assert "excluded from search, maps and findings" in text
    assert 'href="/api/data-status"' in html
    assert client.get("/api/search").get_json()["total"] == 1


def test_readme_documents_explicit_acquisition_instead_of_bundled_inventory():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    lower = text.lower()
    for retired in ("educational", "learning purposes", "demo_seed", "--starter"):
        assert retired not in lower
    assert "starts empty" in lower
    assert "fabricated" in lower and "not implemented" in lower
    assert "import @ips.txt" in text
    assert "docs/BUILD.md" in text and "docs/CATALOG.md" in text
