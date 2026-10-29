"""Tests for the cve.now client — with a fake fetcher so no network is touched."""
from tests.inventory_fixture import with_test_source

import urllib.error

import pytest

from rennacs.cvenow import (CVENow, normalize_entry, severity_from_cvss, tech_slug,
                            valid_id, version_in_ranges)
from rennacs.db import Index

# A realistic cve.now single-entry payload (shape confirmed against the live API).
RAW_REGRESSHION = {
    "id": "CVE-2024-6387",
    "title": "OpenSSH regreSSHion - race condition in sshd allows RCE",
    "summary": {"text": "A signal handler race in OpenSSH sshd allows unauthenticated "
                        "remote code execution.", "model": "anthropic/claude-haiku-5.5"},
    "originalDescription": "sshd race condition ...",
    "severity": {"cvss": 8.1, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                 "source": "cna"},
    "exploitation": {"kev": None, "epssReached": None, "exploitDb": None},
    "ssvc": None,
    "affected": [{"vendor": "OpenSSH", "product": "OpenSSH",
                  "ranges": [{"introduced": "8.5p1", "fixed": ""}]}],
    "references": [{"url": "https://www.openssh.com/txt/release-9.8", "type": "web"}],
    "publishedAt": "2024-07-01T00:00:00Z",
}
RAW_APACHE_KEV = {
    "id": "CVE-2021-41773",
    "title": "Apache HTTP Server 2.4.49 path traversal",
    "summary": {"text": "Path traversal and file disclosure in Apache 2.4.49."},
    "severity": {"cvss": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "exploitation": {"kev": {"dateAdded": "2021-11-03"}},
    "affected": [{"vendor": "Apache", "product": "Apache HTTP Server", "ranges": []}],
    "references": [{"url": "https://httpd.apache.org/security/", "type": "web"}],
    "publishedAt": "2021-10-05T00:00:00Z",
}
LIST_ITEMS = [
    {"id": "CVE-2026-104353", "title": "Adobe Campaign Classic OS command injection",
     "publishedAt": "2026-10-27T17:03:36Z", "cvss": 9.9, "kev": False,
     "product": "Adobe Campaign Classic"},
    {"id": "CVE-2026-109618", "title": "PHP RCE via OOM corruption",
     "publishedAt": "2026-10-26T23:00:00Z", "cvss": 9.8, "kev": True, "product": "PHP"},
]
STATS = {"computedAt": "2026-10-27T19:00:00Z", "vulnerabilitiesTracked": 396719,
         "newThisWeek": 4085, "criticalThisWeek": 38}


class FakeNet:
    """Stand-in for CVENow._get_json; routes by URL, records calls."""

    def __init__(self):
        self.entries = {"CVE-2024-6387": RAW_REGRESSHION,
                        "CVE-2021-41773": RAW_APACHE_KEV}
        self.calls = []

    def __call__(self, url):
        self.calls.append(url)
        if "/api/v1/entries/" in url:
            cve = url.rsplit("/", 1)[1]
            if cve in self.entries:
                return self.entries[cve]
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
        if "/api/v1/entries" in url:
            return {"entries": LIST_ITEMS, "nextCursor": "opaque"}
        if "/api/stats" in url:
            return STATS
        raise ValueError(f"unexpected url {url}")


@pytest.fixture
def client(tmp_path):
    c = CVENow(str(tmp_path / "cve.db"), now_iso="2026-10-27T00:00:00Z")
    c._get_json = FakeNet()
    yield c
    c.close()


# -- pure helpers -------------------------------------------------------------

@pytest.mark.parametrize("cvss,label", [
    (9.8, "critical"), (9.0, "critical"), (8.1, "high"), (7.0, "high"),
    (5.0, "medium"), (4.0, "medium"), (2.0, "low"), (0.0, "none"), (None, ""),
])
def test_severity_from_cvss(cvss, label):
    assert severity_from_cvss(cvss) == label


@pytest.mark.parametrize("cve,ok", [
    ("CVE-2024-6387", True), ("GHSA-vg84-c5mg-76xh", True),
    ("cve-2024-6387", False), ("../../etc/passwd", False),
    ("CVE-2024-6387;rm -rf", False), ("", False), ("http://evil", False),
])
def test_valid_id_guards_url(cve, ok):
    assert valid_id(cve) is ok


def test_version_in_ranges_open_ended():
    aff = [{"ranges": [{"introduced": "8.5p1", "fixed": ""}]}]
    assert version_in_ranges("9.2p1", aff) == "yes"
    assert version_in_ranges("8.9p1", aff) == "yes"
    assert version_in_ranges("7.9", aff) == "no"      # below introduced


def test_version_in_ranges_bounded():
    aff = [{"ranges": [{"introduced": "2.4.0", "fixed": "2.4.50"}]}]
    assert version_in_ranges("2.4.49", aff) == "yes"
    assert version_in_ranges("2.4.50", aff) == "no"   # fixed is exclusive
    assert version_in_ranges("2.4.52", aff) == "no"


def test_version_in_ranges_unknown_when_no_ranges():
    assert version_in_ranges("2.3.4", [{"ranges": []}]) == "unknown"
    assert version_in_ranges("", [{"ranges": [{"introduced": "1.0"}]}]) == "unknown"


def test_tech_slug_map():
    assert tech_slug("nginx") == "nginx"
    assert tech_slug("Apache httpd") == "apache-httpd"
    assert tech_slug("OpenSSH") == ""   # no cve.now tech slug


def test_normalize_entry_shapes_fields():
    n = normalize_entry(RAW_APACHE_KEV)
    assert n["cve"] == "CVE-2021-41773"
    assert n["cvss"] == 7.5 and n["severity"] == "high"
    assert n["kev"] is True
    assert n["url"] == "https://cve.now/CVE-2021-41773"


# -- client behavior ----------------------------------------------------------

def test_entry_fetches_then_caches(client):
    e = client.entry("CVE-2024-6387")
    assert e["cvss"] == 8.1 and e["summary"].startswith("A signal handler")
    n_calls = len(client._get_json.calls)
    client.entry("CVE-2024-6387")               # second call served from cache
    assert len(client._get_json.calls) == n_calls


def test_force_refetches_despite_cache(client):
    client.entry("CVE-2024-6387")
    calls = len(client._get_json.calls)
    client.entry("CVE-2024-6387", force=True)   # bypass cache
    assert len(client._get_json.calls) == calls + 1


def test_stale_cache_refetches(tmp_path):
    # TTL of 1 hour; cache stamped 'now', then a client whose clock is 2h later.
    c1 = CVENow(str(tmp_path / "t.db"), ttl_hours=1, now_iso="2026-10-27T00:00:00Z")
    c1._get_json = FakeNet()
    c1.entry("CVE-2024-6387")
    c1.close()
    c2 = CVENow(str(tmp_path / "t.db"), ttl_hours=1, now_iso="2026-10-27T02:00:00Z")
    fake = FakeNet()
    c2._get_json = fake
    c2.entry("CVE-2024-6387")                    # stale -> refetch
    assert len(fake.calls) == 1
    c2.close()


def test_fresh_cache_not_refetched(tmp_path):
    c1 = CVENow(str(tmp_path / "f.db"), ttl_hours=24, now_iso="2026-10-27T00:00:00Z")
    c1._get_json = FakeNet()
    c1.entry("CVE-2024-6387")
    c1.close()
    c2 = CVENow(str(tmp_path / "f.db"), ttl_hours=24, now_iso="2026-10-27T01:00:00Z")
    fake = FakeNet()
    c2._get_json = fake
    c2.entry("CVE-2024-6387")                    # within TTL -> cache
    assert fake.calls == []
    c2.close()


def test_entry_absent_is_cached(client):
    assert client.entry("CVE-2000-0001") is None
    calls = len(client._get_json.calls)
    assert client.entry("CVE-2000-0001") is None   # not re-fetched
    assert len(client._get_json.calls) == calls


def test_entry_rejects_bad_id_without_network(client):
    assert client.entry("../../secret") is None
    assert client._get_json.calls == []


def test_offline_never_calls_network(tmp_path):
    c = CVENow(str(tmp_path / "o.db"), offline=True, now_iso="2026-10-27T00:00:00Z")
    c._get_json = FakeNet()
    assert c.entry("CVE-2024-6387") is None
    assert c._get_json.calls == []
    c.close()


def test_enrich_vuln_merges_and_confirms(client):
    v = {"cve": "CVE-2024-6387", "severity": "high", "summary": "heuristic text"}
    out = client.enrich_vuln(v, "9.2p1")
    assert out["enriched"] is True
    assert out["cvss"] == 8.1
    assert out["confirmed"] == "yes"            # 9.2p1 in [8.5p1, ∞)
    assert out["summary"].startswith("A signal handler")   # authoritative wins
    assert out["url"] == "https://cve.now/CVE-2024-6387"


def test_enrich_vuln_sets_kev(client):
    out = client.enrich_vuln({"cve": "CVE-2021-41773", "severity": "high",
                              "summary": "x"}, "2.4.49")
    assert out["kev"] is True
    assert out["confirmed"] == "unknown"        # no ranges published


def test_enrich_vuln_unknown_cve_is_passthrough(client):
    v = {"cve": "CVE-2000-0001", "severity": "low", "summary": "s"}
    out = client.enrich_vuln(v, "1.0")
    assert out["enriched"] is False
    assert out["confirmed"] == "unknown"


def test_refresh_feed_and_latest(client):
    n = client.refresh_feed(limit=10)
    assert n == 2
    items = client.latest(10)
    kev = {i["cve"]: i["kev"] for i in items}
    assert kev["CVE-2026-109618"] == 1 and kev["CVE-2026-104353"] == 0


def test_refresh_stats(client):
    s = client.refresh_stats()
    assert s["vulnerabilitiesTracked"] == 396719
    assert client.catalog_stats()["criticalThisWeek"] == 38


# -- integration with the index ----------------------------------------------

def test_version_in_ranges_unparseable_bounds_not_yes():
    # bounds present but non-numeric -> cannot compare -> must NOT confirm 'yes'
    aff = [{"ranges": [{"introduced": "v1.0.0", "fixed": "v2.0.0"}]}]
    assert version_in_ranges("1.5.0", aff) == "unknown"
    aff2 = [{"ranges": [{"introduced": "deadbeef", "fixed": "cafebabe"}]}]
    assert version_in_ranges("3.1.4", aff2) == "unknown"


def test_version_in_ranges_mixed_comparable_and_incomparable():
    # one numeric range excludes v, one unparseable range -> 'unknown', not 'no'
    aff = [{"ranges": [{"introduced": "9.0", "fixed": "9.5"},
                       {"introduced": "vX", "fixed": "vY"}]}]
    assert version_in_ranges("8.0", aff) == "unknown"


# -- regression tests for review findings -------------------------------------

def test_malformed_200_does_not_overwrite_cache(client):
    """HIGH finding: an ambiguous 200 must not mark a good entry absent."""
    good = client.entry("CVE-2024-6387")
    assert good and good["cvss"] == 8.1
    # now make the fetcher return a structurally-valid-but-not-an-entry 200
    client._get_json.entries["CVE-2024-6387"] = {"error": "maintenance"}
    again = client.entry("CVE-2024-6387", force=True)   # force refresh
    assert again is not None and again["cvss"] == 8.1    # cached entry preserved
    # and the cache row is still 'present', not 'absent'
    assert client.entry("CVE-2024-6387", allow_network=False)["cvss"] == 8.1


def test_transient_error_falls_back_to_cache(client):
    import urllib.error
    client.entry("CVE-2024-6387")                        # populate cache
    def boom(url):
        raise urllib.error.URLError("network down")
    client._get_json = boom
    # stale-forcing client: ttl passed, but even a normal lookup during an outage
    # must return the cached entry, never None.
    got = client.entry("CVE-2024-6387", force=True)
    assert got is not None and got["cvss"] == 8.1


def test_redirect_guard_blocks_private_and_foreign_hosts():
    from rennacs.cvenow import _redirect_host_ok
    assert _redirect_host_ok("https://cve.now/x") is True
    assert _redirect_host_ok("https://f9g.public.blob.vercel-storage.com/x") is True
    assert _redirect_host_ok("http://cve.now/x") is False          # not https
    assert _redirect_host_ok("https://169.254.169.254/latest") is False
    assert _redirect_host_ok("https://127.0.0.1/") is False
    assert _redirect_host_ok("https://evil.example.com/") is False
    assert _redirect_host_ok("ftp://cve.now/x") is False


def test_reenrich_with_network_uses_two_phase(tmp_path):
    """LOW finding: reenrich(allow_network=True) must not deadlock on its own DB."""
    idx = Index(str(tmp_path / "r.db"))
    idx.insert_raw(with_test_source({"ip": "10.0.0.1", "services": [
        {"port": 80, "service": "http", "product": "Apache httpd", "version": "2.4.49"},
        {"port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.2p1"},
    ]}))
    c = CVENow(str(tmp_path / "r.db"), now_iso="2026-10-27T00:00:00Z")
    c._get_json = FakeNet()
    counts = idx.reenrich(c, allow_network=True)   # must complete, not lock up
    assert counts["enriched"] >= 2
    c.close()
    idx.close()


def test_reenrich_updates_services_and_kev(tmp_path):
    idx = Index(str(tmp_path / "s.db"))
    idx.insert_raw(with_test_source({"ip": "10.0.0.9", "services": [
        {"port": 80, "service": "http", "product": "Apache httpd", "version": "2.4.49"},
    ]}))
    c = CVENow(str(tmp_path / "s.db"), now_iso="2026-10-27T00:00:00Z")
    c._get_json = FakeNet()
    # populate cache first (network), then merge from cache
    for cve in idx.distinct_cves():
        c.entry(cve)
    counts = idx.reenrich(c, allow_network=False)
    assert counts["enriched"] >= 1 and counts["kev"] >= 1
    doc = idx.host("10.0.0.9")
    kevs = [v for s in doc["services"] for v in s["vulns"] if v.get("kev")]
    assert any(v["cve"] == "CVE-2021-41773" for v in kevs)
    assert doc["services"][0]["kev"] == 1
    c.close()
    idx.close()
