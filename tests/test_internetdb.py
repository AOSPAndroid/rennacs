"""Synthetic provider-shaped fixtures test imports without public network access."""

import copy
import hashlib
import json
from datetime import datetime

import pytest

from rennacs.db import Index
from rennacs.internetdb import InternetDB, _parse_cpe, normalize
from rennacs.query import compile_query

# Synthetic test input modeled on the provider's response shape, not a live capture.
RAW_SCANME = {
    "cpes": ["cpe:/o:canonical:ubuntu_linux", "cpe:/a:ntp:ntp:3",
             "cpe:/a:openbsd:openssh:6.6.1p1", "cpe:/a:apache:http_server:2.4.7"],
    "hostnames": ["scanme.nmap.org"],
    "ip": "45.33.32.156",
    "ports": [22, 80, 123, 31337],
    "tags": ["cloud", "self-signed"],
    "vulns": ["CVE-2017-9798", "CVE-2021-26691", "CVE-2013-6438"],
}


def test_parse_cpe_uri_and_formatted():
    assert _parse_cpe("cpe:/a:openbsd:openssh:6.6.1p1") == ("a", "openssh", "6.6.1p1")
    assert _parse_cpe("cpe:/o:canonical:ubuntu_linux") == ("o", "ubuntu_linux", "")
    assert _parse_cpe("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*") == ("a", "nginx", "1.18.0")
    assert _parse_cpe("garbage") == ("", "", "")


def test_normalize_retains_ports_without_inventing_service_bindings():
    doc = normalize("45.33.32.156", RAW_SCANME, retrieved_at="2026-10-27T00:00:00Z")
    assert doc["ip"] == "45.33.32.156"
    assert doc["hostnames"] == ["scanme.nmap.org"]
    assert doc["tags"] == ["cloud", "self-signed"]
    by_port = {s["port"]: s for s in doc["services"]}
    assert set(by_port) == {22, 80, 123, 31337}
    assert all(s["product"] == s["version"] == s["os"] == "" for s in by_port.values())
    assert doc["provenance"]["host_cpes"] == RAW_SCANME["cpes"]


def test_normalize_retains_host_advisories_without_service_attribution():
    doc = normalize("45.33.32.156", RAW_SCANME, retrieved_at="2026-10-27T00:00:00Z")
    by_port = {s["port"]: s for s in doc["services"]}
    assert all(s["vulns"] == [] for s in by_port.values())
    advisories = doc["provenance"]["host_advisories"]
    assert [v["cve"] for v in advisories] == RAW_SCANME["vulns"]
    assert all(v["source"] == "shodan-internetdb" and v["scope"] == "host"
               and v["service_attribution"] == "unknown"
               and v["assessment_state"] == "unverified" for v in advisories)


def test_imported_ports_do_not_imply_tls_transport_or_measured_protocol():
    doc = normalize("45.33.32.156", {**RAW_SCANME, "ports": [443, 8443, 123]},
                    retrieved_at="2026-10-27T00:00:00Z")
    assert all(s["has_ssl"] is None and s["transport"] == "unknown"
               and s["service"] == "" and s["observed_at"] is None
               and s["seen_at"] == "" for s in doc["services"])
    assert doc["services"][1]["service_hint"] == "https"


def test_normalize_filters_bad_data():
    doc = normalize("1.2.3.4", {**RAW_SCANME, "ip": "1.2.3.4",
                                "ports": [80, 99999, "x"], "vulns": ["not-a-cve"],
                                "hostnames": ["a"], "tags": []},
                    retrieved_at="2026-10-27T00:00:00Z")
    assert [s["port"] for s in doc["services"]] == [80]     # bad ports dropped
    assert all(not s["vulns"] for s in doc["services"])     # bad CVE dropped


def test_exact_valid_tokens_only_without_repairing_provider_values():
    raw = {**RAW_SCANME,
           "ports": [80, 80, 443, True, False, 22.9, 23.0, "53", " 25 ", 0, 65536],
           "vulns": ["CVE-2021-41773", "cve-2021-42013", "CVE-2021-41773\n",
                     " CVE-2021-41773", "CVE-２０２１-４１７７３", None, 17],
           "cpes": ["cpe:/a:openbsd:openssh:6.6.1p1",
                    "cpe:/a:apache:http_server:2.4.7\n", " cpe:/a:ntp:ntp:3",
                    "cpe:2.3:a:nginx:nginx:1.18.0:*:*", None, {"cpe": "fake"}],
           "hostnames": ["scanme.nmap.org", None, {"name": "fake"}],
           "tags": ["cloud", None, 17, {"tag": "fake"}]}
    doc = normalize("45.33.32.156", raw, retrieved_at="2026-10-27T00:00:00Z")
    assert [s["port"] for s in doc["services"]] == [80, 443]
    assert [v["cve"] for v in doc["provenance"]["host_advisories"]] == ["CVE-2021-41773"]
    assert doc["provenance"]["host_cpes"] == ["cpe:/a:openbsd:openssh:6.6.1p1"]
    assert doc["hostnames"] == ["scanme.nmap.org"]
    assert doc["tags"] == ["cloud"]
    assert doc["provenance"]["raw_payload"] == raw


@pytest.mark.parametrize("bad", [None, 12, " cpe:/a:ntp:ntp:3", "cpe:/a:ntp:ntp:3\n",
                                "cpe:/a:ntp:ntp:3:too:many:fields:extra",
                                "cpe:/a:vendor:product%ZZ:1", "cpe:2.3:x:v:p:1:*:*:*:*:*:*:*"])
def test_parse_cpe_rejects_invalid_exact_tokens(bad):
    assert _parse_cpe(bad) == ("", "", "")


@pytest.mark.parametrize("stamp", ["", None, "not-a-date", "2026-10-27T00:00:00",
                                    "2026-10-27 00:00:00+00:00"])
def test_normalize_cannot_invent_unknown_provider_retrieval_time(stamp):
    assert normalize("45.33.32.156", RAW_SCANME, retrieved_at=stamp) is None


@pytest.mark.parametrize("ip", [True, 134744072, None, "8.8.8.8\n", "008.8.8.8", "::1"])
def test_lookup_invalid_exact_ip_never_fetches(idb, ip):
    assert idb.lookup(ip) is None
    assert idb._fetcher.calls == []


@pytest.mark.parametrize("ports", [[True], [80.0], ["443"], [0, 65536], []])
def test_invalid_only_port_inventory_does_not_become_observation(idb, ports):
    idb._fetcher.data["45.33.32.156"] = {**RAW_SCANME, "ports": ports}
    assert idb.lookup("45.33.32.156") is None


def test_non_json_provider_payload_cannot_be_hashed_as_real_data(idb):
    idb._fetcher.data["45.33.32.156"] = {**RAW_SCANME, "unexpected": float("nan")}
    assert idb.lookup("45.33.32.156") is None


class FakeIDB:
    def __init__(self):
        self.calls = []
        self.data = {"45.33.32.156": RAW_SCANME}

    def get_json(self, url, timeout=8.0):
        self.calls.append(url)
        ip = url.rstrip("/").rsplit("/", 1)[-1]
        if ip in self.data:
            return self.data[ip]
        return {"detail": "No information available"}     # InternetDB 404 shape


@pytest.fixture
def idb(tmp_path):
    c = InternetDB(str(tmp_path / "i.db"), now_iso="2026-10-27T00:00:00Z")
    c._fetcher = FakeIDB()
    yield c
    c.close()


def test_lookup_retains_raw_provenance_across_reopened_cache(idb):
    original = copy.deepcopy(RAW_SCANME)
    original["provider_note"] = "Evidence: café"
    idb._fetcher.data["45.33.32.156"] = original
    doc = idb.lookup("45.33.32.156")
    provenance = doc["provenance"]
    assert provenance["kind"] == "import"
    assert provenance["source"] == "shodan-internetdb"
    assert provenance["reference"] == "https://internetdb.shodan.io/45.33.32.156"
    assert provenance["retrieved_at"] == "2026-10-27T00:00:00Z"
    assert datetime.fromisoformat(provenance["retrieved_at"]).utcoffset() is not None
    canonical = json.dumps(original, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False).encode("utf-8")
    assert provenance["payload_sha256"] == hashlib.sha256(canonical).hexdigest()
    assert provenance["raw_payload"] == original
    assert provenance["observed_at"] is None
    cached = InternetDB(idb.db_path, offline=True, now_iso="2026-10-29T12:00:00Z")
    try:
        assert cached.lookup("45.33.32.156") == doc
        assert cached.conn.execute("SELECT fetched_at FROM idb_cache").fetchone()[0] == provenance["retrieved_at"]
    finally:
        cached.close()


@pytest.mark.parametrize("offline", [True, False])
def test_legacy_normalized_cache_without_raw_evidence_is_not_trusted(idb, offline):
    legacy = {"ip": "45.33.32.156", "services": [{"port": 22, "product": "Invented"}]}
    idb.conn.execute("INSERT INTO idb_cache VALUES(?,1,?,?)",
                     (legacy["ip"], json.dumps(legacy), "2026-10-01T00:00:00Z"))
    idb.conn.commit()
    idb.offline = offline
    doc = idb.lookup(legacy["ip"])
    if offline:
        assert doc is None
        assert idb._fetcher.calls == []
    else:
        assert doc["provenance"]["raw_payload"] == RAW_SCANME
        assert idb._fetcher.calls == ["https://internetdb.shodan.io/45.33.32.156"]


@pytest.mark.parametrize("corruption", ["hash", "raw_ip", "timestamp", "cache_timestamp"])
def test_corrupted_cache_evidence_is_not_trusted_offline(idb, corruption):
    doc = idb.lookup("45.33.32.156")
    stamp = doc["provenance"]["retrieved_at"]
    if corruption == "hash":
        doc["provenance"]["payload_sha256"] = "0" * 64
    elif corruption == "raw_ip":
        doc["provenance"]["raw_payload"]["ip"] = "1.1.1.1"
    elif corruption == "timestamp":
        doc["provenance"]["retrieved_at"] = "2026-10-27T00:00:00"
    else:
        stamp = "2026-10-28T00:00:00Z"
    idb.conn.execute("UPDATE idb_cache SET json=?, fetched_at=?", (json.dumps(doc), stamp))
    idb.conn.commit()
    assert idb.lookup("45.33.32.156", allow_network=False) is None


def test_lookup_and_cache(idb):
    doc = idb.lookup("45.33.32.156")
    assert doc and len(doc["services"]) == 4
    n = len(idb._fetcher.calls)
    idb.lookup("45.33.32.156")                 # cache hit
    assert len(idb._fetcher.calls) == n


@pytest.mark.parametrize("raw", [
    None, [], {}, {"ports": [80]},
    {**RAW_SCANME, "ip": "1.1.1.1"},
    {**RAW_SCANME, "ports": "80"},
    {**RAW_SCANME, "ports": []},
    {**RAW_SCANME, "hostnames": "scanme.nmap.org"},
    {**RAW_SCANME, "tags": {"cloud": True}},
    {**RAW_SCANME, "cpes": None},
    {**RAW_SCANME, "vulns": "CVE-2017-9798"},
    {**RAW_SCANME, "detail": "provider error"},
    {**RAW_SCANME, "success": False},
    {**RAW_SCANME, "success": "false"},
])
def test_provider_structure_failure_is_not_an_import_observation(idb, raw):
    idb._fetcher.data["45.33.32.156"] = raw
    assert idb.lookup("45.33.32.156") is None
    assert idb.lookup("45.33.32.156", allow_network=False) is None


def test_internetdb_network_failure_does_not_create_observation(idb):
    def fail(*args, **kwargs):
        raise TimeoutError("provider unavailable")
    idb._fetcher.get_json = fail
    assert idb.lookup("45.33.32.156") is None
    assert idb.conn.execute("SELECT COUNT(*) FROM idb_cache WHERE success=1").fetchone()[0] == 0


def test_lookup_unknown_is_cached_absent(idb):
    assert idb.lookup("203.0.113.200") is None  # (also private in 3.12, returns None)
    assert idb.lookup("8.8.8.8") is None        # not in fake data -> absent
    calls = len(idb._fetcher.calls)
    idb.lookup("8.8.8.8")                        # not re-fetched
    assert len(idb._fetcher.calls) == calls


def test_offline_no_network(tmp_path):
    c = InternetDB(str(tmp_path / "o.db"), offline=True)
    c._fetcher = FakeIDB()
    assert c.lookup("45.33.32.156") is None
    assert c._fetcher.calls == []
    c.close()


def test_import_targets_indexes_provider_evidence(tmp_path):
    idx = Index(str(tmp_path / "x.db"))
    c = InternetDB(str(tmp_path / "x.db"), now_iso="2026-10-27T00:00:00Z")
    c._fetcher = FakeIDB()
    counts = c.import_targets(["45.33.32.156", "8.8.8.8"], idx, rate=0)
    assert counts["requested"] == 2 and counts["found"] == 1
    doc = idx.host("45.33.32.156")
    assert doc["tags"] == ["cloud", "self-signed"]
    assert all(s["product"] == "" and s["vulns"] == [] for s in doc["services"])
    c.close()
    idx.close()


def test_cached_reimport_keeps_original_retrieval_and_unknown_observation(idb, tmp_path):
    idx = Index(str(tmp_path / "roundtrip.db"))
    try:
        idb.import_targets(["45.33.32.156"], idx, rate=0)
        idb._now = "2026-10-29T12:00:00Z"
        idb.import_targets(["45.33.32.156"], idx, rate=0)
        doc = idx.host("45.33.32.156")
        assert doc["provenance"]["retrieved_at"] == "2026-10-27T00:00:00Z"
        assert doc["provenance"]["raw_payload"] == RAW_SCANME
        assert doc["provenance"]["host_cpes"] == RAW_SCANME["cpes"]
        assert doc["observed_at"] is None
        assert all(s["observed_at"] is None and s["transport"] == "unknown"
                   and s["ssl_trust"] == "not_observed" for s in doc["services"])
        assert idx.service_history("45.33.32.156") == []
        assert idb._fetcher.calls == ["https://internetdb.shodan.io/45.33.32.156"]
    finally:
        idx.close()


def test_tag_filter(tmp_path):
    idx = Index(str(tmp_path / "t.db"))
    idx.insert_raw(normalize("45.33.32.156", RAW_SCANME, retrieved_at="2026-10-27T00:00:00Z"))
    where, params = compile_query("tag:self-signed")
    rows, total = idx.search(where, params)
    assert total >= 1 and all(r["ip"] == "45.33.32.156" for r in rows)
    # a tag that isn't present returns nothing
    where2, p2 = compile_query("tag:honeypot")
    assert idx.search(where2, p2)[1] == 0
    idx.close()
