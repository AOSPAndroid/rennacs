"""Tests for the Flask web UI and JSON API."""

import pytest


# -- JSON API -----------------------------------------------------------------

def test_api_search_port(client):
    j = client.get("/api/search?q=port:22").get_json()
    assert j["total"] >= 1
    assert all(m["port"] == 22 for m in j["matches"])


def test_api_search_bad_query_is_400(client):
    r = client.get("/api/search?q=bogus:1")
    assert r.status_code == 400
    assert "error" in r.get_json()


def test_api_search_net(client):
    j = client.get("/api/search?q=net:192.168.1.0/24").get_json()
    assert j["total"] > 0
    assert all(m["ip"].startswith("192.168.1.") for m in j["matches"])


def test_api_has_vuln(client):
    j = client.get("/api/search?q=has_vuln:true").get_json()
    assert j["total"] >= 1
    assert all(m["vulns"] for m in j["matches"])


def test_api_host_document(client):
    j = client.get("/api/host/192.168.1.66").get_json()
    assert j["ip"] == "192.168.1.66"
    assert any(s["vulns"] for s in j["services"])


def test_api_host_404(client):
    r = client.get("/api/host/203.0.113.1")
    assert r.status_code == 404


def test_api_stats_shape(client):
    j = client.get("/api/stats").get_json()
    for key in ("hosts", "services", "top_ports", "top_products",
                "top_vulns", "vuln_services", "kev_services"):
        assert key in j


def test_api_map(client):
    j = client.get("/api/map").get_json()
    assert "located" in j and "ungeolocated" in j and "countries" in j
    assert any(p["ip"] == "8.8.8.8" for p in j["located"])


def test_api_map_query_filter(client):
    j = client.get("/api/map?q=port:53").get_json()
    assert {p["ip"] for p in j["located"]} == {"8.8.8.8", "1.1.1.1"}


def test_api_map_bad_query(client):
    r = client.get("/api/map?q=bogus:1")
    assert r.status_code == 400


def test_map_page_query_box(client):
    r = client.get("/map?q=port:443")
    assert r.status_code == 200
    assert b"Global map" in r.data and b"port:443" in r.data


def test_api_filters_lists_vuln(client):
    j = client.get("/api/filters").get_json()
    assert "vuln" in j and "has_vuln" in j and "net" in j and "kev" in j


def test_kev_filter_compiles_and_runs(client):
    # no enrichment in tests, so kev:true returns nothing but must not error
    r = client.get("/api/search?q=kev:true")
    assert r.status_code == 200
    assert r.get_json()["total"] == 0


def test_api_cve_uncached_is_404(client):
    r = client.get("/api/cve/CVE-2024-6387")
    assert r.status_code == 404   # nothing enriched in the test db


def test_api_cve_feed_shape(client):
    j = client.get("/api/cve-feed").get_json()
    assert "items" in j and "catalog" in j


def test_api_cve_rejects_bad_id(client):
    r = client.get("/api/cve/not-a-cve")
    assert r.status_code == 404


def test_home_shows_cvenow_panel(client):
    r = client.get("/")
    assert b"Latest critical vulnerabilities" in r.data


# -- enriched render paths (fake-fetcher cve.now data, no network) ------------

def test_enriched_host_page_shows_cvss_kev_source(enriched_client):
    r = enriched_client.get("/host/192.168.1.66")
    assert r.status_code == 200
    body = r.data
    assert b"CVSS 7.5" in body or b"CVSS 9.8" in body      # authoritative score
    assert b"KEV" in body                                  # exploited badge
    assert b"in affected range" in body                    # OpenSSH 9.2p1 confirmed
    assert b"cve.now" in body                               # source attribution


def test_enriched_results_show_inline_score(enriched_client):
    r = enriched_client.get("/search?q=kev:true")
    assert r.status_code == 200
    assert b"192.168.1.66" in r.data
    assert b"KEV" in r.data


def test_enriched_home_feed_panel_has_rows(enriched_client):
    r = enriched_client.get("/")
    assert b"CVE-2026-109618" in r.data        # a cached feed row
    assert b"396,719 tracked" in r.data        # catalog line
    assert b"No cve.now data cached yet" not in r.data


def test_enriched_api_cve_returns_entry(enriched_client):
    j = enriched_client.get("/api/cve/CVE-2021-41773").get_json()
    assert j["cvss"] == 7.5 and j["kev"] is True


def test_enriched_kev_stat_tile(enriched_client):
    r = enriched_client.get("/")
    assert b"known exploited" in r.data


# -- HTML pages ---------------------------------------------------------------

def test_home_renders(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"hosts indexed" in r.data


def test_search_page_renders(client):
    r = client.get("/search?q=port:443")
    assert r.status_code == 200
    assert b"443" in r.data


def test_search_page_shows_query_error(client):
    r = client.get("/search?q=port:abc")
    assert r.status_code == 200
    assert b"Query error" in r.data


def test_host_page_renders_with_vulns(client):
    r = client.get("/host/192.168.1.66")
    assert r.status_code == 200
    assert b"CVE-2011-2523" in r.data


def test_host_page_404(client):
    r = client.get("/host/203.0.113.9")
    assert r.status_code == 404


def test_map_page_renders(client):
    r = client.get("/map")
    assert r.status_code == 200
    assert b"id=\"map\"" in r.data
