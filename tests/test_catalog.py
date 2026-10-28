"""Offline catalog contracts; payloads are data, never network fixtures."""

import json
import sqlite3
import urllib.error
import urllib.request

import pytest

from rennacs.catalog import Catalog


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("catalog tests must never contact the network")
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", forbidden)


def detail(identifier="CVE-2024-6387", **changes):
    raw = {
        "id": identifier,
        "feedId": identifier,
        "aliases": [],
        "status": "published",
        "affected": [{"vendor": "Example Vendor", "product": "  OpenSSH\t Server ",
                      "package": "OpenSSH", "ecosystem": "native",
                      "ranges": [{"introduced": "8.5p1", "lastAffected": "9.7p1",
                                  "futureBound": {"value": "unknown"}}]}],
        "sources": [{"name": "CVE", "url": "https://example.org/advisory"}],
        "unknownSourceField": {"keep": True},
    }
    raw.update(changes)
    return raw


def test_owned_catalog_persists_lossless_raw_and_normalized_identities(tmp_path):
    path = tmp_path / "catalog.db"
    cat = Catalog(path)
    raw = detail()
    assert cat.upsert(raw) == raw["id"]
    cat.close()
    reopened = Catalog(path)
    try:
        assert reopened.candidates([" OPENSSH  SERVER ", "openssh"]) == [raw]
        assert reopened.candidates(["example vendor"]) == []
        assert reopened.candidates([]) == []
        row = reopened.conn.execute(
            "SELECT source, source_url, fetched_at FROM advisory_catalog"
        ).fetchone()
        assert row[0] == "cve.now"
        assert row[1] == "https://cve.now/api/v1/entries/CVE-2024-6387"
        assert row[2]
    finally:
        reopened.close()
    with pytest.raises(sqlite3.ProgrammingError):
        reopened.conn.execute("SELECT 1")


@pytest.mark.parametrize("changes", [
    {"id": " CVE-2024-6387"}, {"id": "CVE-2024-6387\n"},
    {"id": "CVE-2024-6387/../../x"}, {"id": "cve-2024-6387"},
    {"id": "CVE-２０２４-6387"}, {"id": None},
    {"affected": None}, {"affected": {}}, {"affected": [None]},
    {"affected": [{"product": {"name": "OpenSSH"}}]},
    {"affected": [{"package": 3}]},
    {"affected": [{"product": "OpenSSH", "ranges": "bad"}]},
    {"affected": [{"product": "OpenSSH", "ranges": [None]}]},
    {"feedId": "../../x"}, {"aliases": ["https://example.org"]},
    {"severity": float("nan")},
])
def test_upsert_rejects_malformed_details_without_replacing_good_data(tmp_path, changes):
    cat = Catalog(tmp_path / "catalog.db")
    try:
        raw = detail()
        cat.upsert(raw)
        with pytest.raises(ValueError):
            cat.upsert(detail(**changes))
        assert cat.candidates(["openssh"]) == [raw]
    finally:
        cat.close()


def test_upsert_failure_rolls_back_raw_and_identity_changes(tmp_path):
    cat = Catalog(tmp_path / "catalog.db")
    try:
        raw = detail()
        cat.upsert(raw)
        cat.conn.execute("""CREATE TRIGGER deny_identity BEFORE INSERT ON advisory_identities
            BEGIN SELECT RAISE(ABORT, 'disk fixture'); END""")
        with pytest.raises(sqlite3.IntegrityError):
            cat.upsert(detail(affected=[{"product": "Changed"}]))
        assert cat.candidates(["openssh"]) == [raw]
    finally:
        cat.close()


def test_revision_changes_only_on_success_and_survives_reopen(tmp_path):
    path = tmp_path / "catalog.db"
    cat = Catalog(path)
    assert cat.revision() == 0
    cat.upsert(detail())
    assert cat.revision() == 1
    cat.upsert(detail(affected=[]))
    assert cat.revision() == 2
    with pytest.raises(ValueError):
        cat.upsert({"id": "bad"})
    assert cat.revision() == 2
    cat.close()
    cat = Catalog(path)
    assert cat.revision() == 2
    cat.close()


def test_shared_connection_never_commits_or_closes_caller_transaction(tmp_path):
    path = tmp_path / "catalog.db"
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE caller_data (value TEXT)")
    conn.execute("INSERT INTO caller_data VALUES('uncommitted')")
    cat = Catalog(connection=conn)
    assert conn.in_transaction
    assert conn.row_factory is sqlite3.Row
    cat.upsert(detail())
    assert cat.revision() == 1
    assert conn.in_transaction
    cat.close()
    assert conn.execute("SELECT count(*) FROM caller_data").fetchone()[0] == 1
    conn.rollback()
    assert conn.execute("SELECT count(*) FROM caller_data").fetchone()[0] == 0
    conn.close()


def test_provenance_is_exposed_separately_without_mutating_raw(tmp_path):
    cat = Catalog(tmp_path / "catalog.db")
    raw = detail()
    cat.upsert(raw)
    provenance = cat.provenance(raw["id"])
    assert provenance["source"] == "cve.now"
    assert provenance["source_url"].endswith(raw["id"])
    assert provenance["fetched_at"]
    assert cat.provenance("CVE-2000-0001") is None
    assert cat.candidates(["openssh"]) == [raw]
    cat.close()


def test_populated_cache_is_not_complete_catalog_coverage(tmp_path):
    cat = Catalog(tmp_path / "catalog.db")
    cat.upsert(detail())
    state = cat.status()
    assert state["stored_details"] == 1
    assert state["pending_details"] == 0
    assert state["traversal"] == "not_started"
    assert state["complete"] is False
    assert state["listing_exhausted"] is False
    assert state["atomic_snapshot"] is False
    assert state["last_error"] is None
    json.dumps(state, allow_nan=False)
    cat.close()


class Fetcher:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, url):
        self.calls.append(url)
        result = self.routes[url]
        if isinstance(result, BaseException):
            raise result
        return result


BASE = "https://cve.now/api/v1/entries"


def test_sync_durably_queues_whole_page_before_budgeted_details(tmp_path):
    path = tmp_path / "catalog.db"
    first, second = "CVE-2024-6387", "GHSA-4MFG-R38W-W8FG"
    cursor = "opaque +/&?="
    fetcher = Fetcher({BASE: {"entries": [{"id": first}, {"id": second}],
                              "nextCursor": cursor},
                       f"{BASE}/{first}": detail(first),
                       f"{BASE}/{second}": detail(second),
                       BASE + "?cursor=opaque+%2B%2F%26%3F%3D": {
                           "entries": [], "nextCursor": None}})
    cat = Catalog(path)
    summary = cat.sync(max_pages=1, max_requests=1, rate=100000, fetcher=fetcher)
    assert summary["requests"] == 1
    assert summary["pages"] == 1
    assert summary["stored"] == 0
    assert summary["stop_reason"] == "request_budget"
    assert summary["complete"] is False
    assert cat.status()["pending_details"] == 2
    assert cat.status()["cursor"] == cursor
    cat.close()
    cat = Catalog(path)
    summary = cat.sync(max_pages=1, max_requests=3, rate=100000, fetcher=fetcher)
    assert summary["requests"] == 3
    assert summary["stored"] == 2
    assert summary["complete"] is True
    assert summary["stop_reason"] == "complete"
    assert cat.status()["traversal"] == "complete"
    assert cat.status()["pending_details"] == 0
    assert cat.candidates(["openssh"]) == [detail(first), detail(second)]
    assert fetcher.calls == [BASE, f"{BASE}/{first}", f"{BASE}/{second}",
                             BASE + "?cursor=opaque+%2B%2F%26%3F%3D"]
    cat.close()


@pytest.mark.parametrize("failure", [
    urllib.error.HTTPError(BASE, 429, "slow down", {}, None),
    urllib.error.HTTPError(BASE, 503, "unavailable", {}, None),
    TimeoutError("timed out"), urllib.error.URLError("offline"),
    {"id": "CVE-2024-9999", "affected": []},
    {"id": "CVE-2024-6388"}, [],
    detail("CVE-2024-6388", affected=[{"ranges": [None]}]),
])
def test_failed_detail_is_never_skipped_and_successes_are_independent(tmp_path, failure):
    path = tmp_path / "catalog.db"
    ids = ["CVE-2024-6387", "CVE-2024-6388", "CVE-2024-6389"]
    routes = {BASE: {"entries": [{"id": i} for i in ids], "nextCursor": None},
              **{f"{BASE}/{i}": detail(i) for i in ids}}
    routes[f"{BASE}/{ids[1]}"] = failure
    fetcher = Fetcher(routes)
    cat = Catalog(path)
    summary = cat.sync(max_requests=10, rate=100000, fetcher=fetcher)
    assert (summary["requests"], summary["stored"]) == (3, 1)
    assert summary["stop_reason"] == "error"
    assert summary["complete"] is False
    state = cat.status()
    assert state["pending_details"] == 2
    assert state["stored_details"] == 1
    assert state["listing_exhausted"] is True
    assert state["last_error"]["url"] == f"{BASE}/{ids[1]}"
    cat.close()
    fetcher.routes[f"{BASE}/{ids[1]}"] = detail(ids[1])
    cat = Catalog(path)
    assert cat.status()["last_error"]
    summary = cat.sync(max_requests=1, rate=100000, fetcher=fetcher)
    assert summary["stored"] == 1
    assert summary["complete"] is False
    assert cat.status()["pending_details"] == 1
    assert fetcher.calls[-1] == f"{BASE}/{ids[1]}"
    summary = cat.sync(max_requests=1, rate=100000, fetcher=fetcher)
    assert summary["complete"] is True
    assert cat.status()["last_error"] is None
    cat.close()


@pytest.mark.parametrize("page", [
    {}, [], {"entries": [], "nextCursor": ""},
    {"entries": "bad", "nextCursor": None},
    {"entries": [], "nextCursor": 123},
    {"entries": [], "nextCursor": {"opaque": True}},
    {"entries": [], "cursor": None},
    {"entries": [{"id": "CVE-2024-6387"}, None], "nextCursor": "later"},
    {"entries": [{"id": "CVE-2024-6387"}, {"id": " CVE-2024-6388"}],
     "nextCursor": "later"},
    {"entries": [{"id": "CVE-2024-6387"}, {"feedId": "CVE-2024-6388"}],
     "nextCursor": "later"},
])
def test_malformed_page_cannot_advance_cursor_or_partially_enqueue(tmp_path, page):
    cat = Catalog(tmp_path / "catalog.db")
    fetcher = Fetcher({BASE: page})
    summary = cat.sync(max_requests=1, rate=100000, fetcher=fetcher)
    assert summary["stop_reason"] == "error"
    assert summary["requests"] == 1
    assert summary["pages"] == 0
    assert summary["complete"] is False
    state = cat.status()
    assert state["cursor"] is None
    assert state["pending_details"] == 0
    assert state["pages"] == 0
    assert not state["listing_exhausted"]
    assert state["last_error"]
    cat.close()


def test_repeated_cursor_cycles_are_detected_across_batches(tmp_path):
    path = tmp_path / "catalog.db"
    fetcher = Fetcher({BASE: {"entries": [], "nextCursor": "one"},
                       BASE + "?cursor=one": {"entries": [], "nextCursor": "two"},
                       BASE + "?cursor=two": {"entries": [], "nextCursor": "one"}})
    cat = Catalog(path)
    for expected in ("one", "two"):
        summary = cat.sync(max_requests=1, rate=100000, fetcher=fetcher)
        assert summary["stop_reason"] == "request_budget"
        assert cat.status()["cursor"] == expected
        cat.close()
        cat = Catalog(path)
    summary = cat.sync(max_requests=5, rate=100000, fetcher=fetcher)
    assert summary["requests"] == 1
    assert summary["stop_reason"] == "error"
    assert "repeated cursor" in summary["last_error"]["message"]
    assert cat.status()["cursor"] == "two"
    assert cat.status()["complete"] is False
    cat.close()


def test_rate_limit_covers_lists_details_failures_and_consecutive_batches(tmp_path, monkeypatch):
    import rennacs.catalog as module

    class Clock:
        now = 0.0

        def monotonic(self):
            return self.now

        def sleep(self, seconds):
            assert seconds >= 0
            self.now += seconds

    clock = Clock()
    monkeypatch.setattr(module, "time", clock, raising=False)
    times = []
    identifier = "CVE-2024-6387"
    routes = Fetcher({BASE: {"entries": [{"id": identifier}], "nextCursor": "next"},
                      f"{BASE}/{identifier}": detail(),
                      BASE + "?cursor=next": TimeoutError("timeout")})

    def fetcher(url):
        times.append(clock.now)
        return routes(url)

    cat = Catalog(tmp_path / "catalog.db")
    cat.sync(max_requests=2, rate=2, fetcher=fetcher)
    result = cat.sync(max_requests=1, rate=2, fetcher=fetcher)
    assert result["stop_reason"] == "error"
    assert times == [0.0, 0.5, 1.0]
    cat.close()


@pytest.mark.parametrize("limits", [
    {"max_requests": -1}, {"max_requests": 1.5}, {"max_requests": True},
    {"max_pages": -1}, {"max_pages": 1.5}, {"max_pages": False},
    {"rate": 0}, {"rate": -1}, {"rate": float("nan")},
    {"rate": float("inf")}, {"rate": "1"}, {"rate": True},
])
def test_invalid_sync_limits_are_rejected_before_any_request(tmp_path, limits):
    cat = Catalog(tmp_path / "catalog.db")
    fetcher = Fetcher({BASE: {"entries": [], "nextCursor": None}})
    with pytest.raises(ValueError):
        cat.sync(fetcher=fetcher, **limits)
    assert fetcher.calls == []
    assert cat.status()["traversal"] == "not_started"
    cat.close()


def test_targeted_fetches_resume_without_implying_catalog_traversal(tmp_path):
    path = tmp_path / "catalog.db"
    ids = ["GHSA-4MFG-R38W-W8FG", "GO-2024-1234"]
    fetcher = Fetcher({f"{BASE}/{i}": detail(i) for i in ids})
    cat = Catalog(path)
    summary = cat.fetch_ids([ids[0], ids[0], ids[1]], max_requests=1, rate=100000, fetcher=fetcher)
    assert summary["requests"] == summary["stored"] == 1
    assert summary["stop_reason"] == "request_budget"
    assert summary["complete"] is False
    assert cat.status()["traversal"] == "not_started"
    assert cat.status()["pending_targeted_details"] == 1
    cat.close()
    cat = Catalog(path)
    summary = cat.fetch_ids([], max_requests=1, rate=100000, fetcher=fetcher)
    assert summary["requests"] == summary["stored"] == 1
    assert summary["stop_reason"] == "ids_complete"
    assert summary["complete"] is False
    assert cat.status()["stored_details"] == 2
    assert cat.status()["pending_details"] == 0
    assert cat.status()["traversal"] == "not_started"
    assert fetcher.calls == [f"{BASE}/{i}" for i in ids]
    cat.close()


@pytest.mark.parametrize("identifier, expected", [
    ("CVE-2024-6387", True), ("GHSA-4MFG-R38W-W8FG", True),
    ("GHSA-abcd-1234-wxyz", True), ("GO-2024-1234", True),
    ("PYSEC-2024-1", True), ("RUSTSEC-2023-0001", True),
    (" CVE-2024-6387", False), ("CVE-2024-6387\n", False),
    ("CVE-２０２４-6387", False), ("CVE-2024-123", False),
    ("cve-2024-6387", False), ("GHSA-ABCD-1234", False),
    ("CVE-2024-6387#fragment", False), ("../../etc/passwd", False),
    ("https://evil.invalid", False), (None, False), (1, False),
])
def test_exported_id_validator_accepts_source_tokens_without_repair(identifier, expected):
    from rennacs.catalog import valid_id
    assert valid_id(identifier) is expected


@pytest.mark.parametrize("operation", ["sync", "fetch_ids"])
def test_network_batches_require_owned_idle_connection(tmp_path, operation):
    conn = sqlite3.connect(tmp_path / "catalog.db")
    cat = Catalog(connection=conn)
    fetcher = Fetcher({BASE: {"entries": [], "nextCursor": None}})
    args = (["CVE-2024-6387"],) if operation == "fetch_ids" else ()
    with pytest.raises(RuntimeError, match="owned"):
        getattr(cat, operation)(*args, fetcher=fetcher)
    assert fetcher.calls == []
    assert not conn.in_transaction
    cat.close()
    assert conn.execute("SELECT 1").fetchone()[0] == 1
    conn.close()
    owned = Catalog(tmp_path / "owned.db")
    owned.conn.execute("BEGIN")
    with pytest.raises(RuntimeError, match="transaction"):
        getattr(owned, operation)(*args, fetcher=fetcher)
    assert owned.conn.in_transaction
    assert fetcher.calls == []
    owned.close()


@pytest.mark.parametrize("operation", ["sync", "fetch_ids"])
@pytest.mark.parametrize("failed", [False, True])
def test_default_fetcher_uses_and_closes_fresh_memory_safe_client(tmp_path, monkeypatch, operation, failed):
    from rennacs.cvenow import CVENow
    clients = []

    def getter(client, url):
        clients.append(client)
        assert client.db_path == ":memory:"
        assert not client.conn.execute("SELECT name FROM sqlite_master WHERE name='hosts'").fetchone()
        if failed:
            raise TimeoutError("default getter fixture")
        return detail() if operation == "fetch_ids" else {"entries": [], "nextCursor": None}

    monkeypatch.setattr(CVENow, "_get_json", getter)
    cat = Catalog(tmp_path / "catalog.db")
    args = (["CVE-2024-6387"],) if operation == "fetch_ids" else ()
    summary = getattr(cat, operation)(*args)
    assert summary["requests"] == 1
    assert summary["stop_reason"] == ("error" if failed else "ids_complete" if operation == "fetch_ids" else "complete")
    assert len(clients) == 1
    with pytest.raises(sqlite3.ProgrammingError):
        clients[0].conn.execute("SELECT 1")
    cat.close()


def test_restart_begins_new_traversal_without_erasing_cache_or_pending_work(tmp_path):
    cat = Catalog(tmp_path / "catalog.db")
    identifier = "CVE-2024-6387"
    fetcher = Fetcher({BASE: {"entries": [{"id": identifier}], "nextCursor": "old"},
                       f"{BASE}/{identifier}": detail()})
    cat.sync(max_requests=1, rate=100000, fetcher=fetcher)
    assert cat.status()["pending_catalog_details"] == 1
    cat.sync(max_requests=0, rate=100000, fetcher=fetcher, restart=True)
    assert cat.status()["cursor"] is None
    assert cat.status()["pages"] == 0
    assert cat.status()["pending_catalog_details"] == 1
    assert cat.status()["complete"] is False
    fetcher.routes[BASE] = {"entries": [], "nextCursor": None}
    result = cat.sync(max_requests=2, rate=100000, fetcher=fetcher)
    assert result["complete"] is True
    assert fetcher.calls[-2:] == [f"{BASE}/{identifier}", BASE]
    assert cat.status()["stored_details"] == 1
    result = cat.sync(max_requests=0, rate=100000, fetcher=fetcher, restart=True)
    assert result["complete"] is False
    assert cat.status()["stored_details"] == 1
    assert cat.status()["traversal"] == "partial"
    cat.close()


def test_status_exposes_current_revision(tmp_path):
    cat = Catalog(tmp_path / "catalog.db")
    assert cat.status()["revision"] == 0
    cat.upsert(detail())
    assert cat.status()["revision"] == cat.revision() == 1
    cat.close()


def test_budgeted_targeted_batch_does_not_claim_complete_work(tmp_path):
    cat = Catalog(tmp_path / "catalog.db")
    fetcher = Fetcher({BASE: {"entries": [], "nextCursor": None},
                       f"{BASE}/CVE-2024-6387": detail(),
                       f"{BASE}/CVE-2024-6388": detail("CVE-2024-6388")})
    assert cat.sync(max_requests=1, fetcher=fetcher)["complete"]
    result = cat.fetch_ids(["CVE-2024-6387", "CVE-2024-6388"], max_requests=1,
                           rate=100000, fetcher=fetcher)
    assert result["stop_reason"] == "request_budget"
    assert result["complete"] is False
    # A previously finished traversal is independent from targeted-refresh work.
    assert result["status"]["complete"] is True
    assert result["status"]["pending_targeted_details"] == 1
    cat.close()


def test_alias_lookup_preserves_raw_ids_and_actual_fetch_provenance(tmp_path):
    requested = "GHSA-4MFG-R38W-W8FG"
    raw = detail(aliases=["GHSA-4mfg-r38w-w8fg"])
    fetcher = Fetcher({f"{BASE}/{requested}": raw})
    cat = Catalog(tmp_path / "catalog.db")
    result = cat.fetch_ids([requested], max_requests=1, fetcher=fetcher)
    assert result["stored"] == 1
    assert cat.candidates(["openssh"]) == [raw]
    assert cat.provenance(raw["id"])["source_url"] == f"{BASE}/{requested}"
    assert fetcher.calls == [f"{BASE}/{requested}"]
    cat.close()


@pytest.mark.parametrize("operation", ["sync", "fetch_ids"])
def test_cancel_preserves_completed_details_and_durable_unfinished_queue(tmp_path, operation):
    path = tmp_path / "catalog.db"
    ids = ["CVE-2024-6387", "CVE-2024-6388"]
    routes = {BASE: {"entries": [{"id": i} for i in ids], "nextCursor": None},
              f"{BASE}/{ids[0]}": detail(ids[0]),
              f"{BASE}/{ids[1]}": KeyboardInterrupt()}
    fetcher = Fetcher(routes)
    cat = Catalog(path)
    args = (ids,) if operation == "fetch_ids" else ()
    with pytest.raises(KeyboardInterrupt):
        getattr(cat, operation)(*args, rate=100000, fetcher=fetcher)
    assert not cat.conn.in_transaction
    cat.close()
    cat = Catalog(path)
    assert cat.revision() == 1
    assert cat.status()["stored_details"] == cat.status()["pending_details"] == 1
    assert cat.status()["complete"] is False
    fetcher.routes[f"{BASE}/{ids[1]}"] = detail(ids[1])
    args = ([],) if operation == "fetch_ids" else ()
    result = getattr(cat, operation)(*args, max_requests=1, rate=100000, fetcher=fetcher)
    assert result["stored"] == 1
    assert cat.status()["pending_details"] == 0
    assert cat.revision() == 2
    cat.close()


def test_page_enqueue_and_cursor_checkpoint_rollback_as_one_unit(tmp_path):
    path = tmp_path / "catalog.db"
    cat = Catalog(path)
    cat.conn.execute("""CREATE TRIGGER deny_second BEFORE INSERT ON catalog_pending
        WHEN NEW.id='CVE-2024-6388' BEGIN SELECT RAISE(ABORT, 'queue fixture'); END""")
    fetcher = Fetcher({BASE: {"entries": [{"id": "CVE-2024-6387"}, {"id": "CVE-2024-6388"}],
                              "nextCursor": "later"}})
    with pytest.raises(sqlite3.IntegrityError):
        cat.sync(max_requests=1, fetcher=fetcher)
    cat.close()
    cat = Catalog(path)
    state = cat.status()
    assert state["pending_details"] == state["pages"] == state["revision"] == 0
    assert state["cursor"] is None
    assert cat.conn.execute("SELECT count(*) FROM catalog_cursors").fetchone()[0] == 0
    cat.close()


@pytest.mark.parametrize("unknown", [("tuple would become a list",), {1: "key would change"}])
def test_raw_validation_rejects_lossy_non_json_values(tmp_path, unknown):
    cat = Catalog(tmp_path / "catalog.db")
    with pytest.raises(ValueError, match="JSON"):
        cat.upsert(detail(unknownSourceField=unknown))
    assert cat.revision() == 0
    assert cat.status()["stored_details"] == 0
    cat.close()


def test_whitespace_only_affected_names_are_not_candidate_identities(tmp_path):
    cat = Catalog(tmp_path / "catalog.db")
    cat.upsert(detail(affected=[{"product": " \t ", "package": "\n"}]))
    assert cat.candidates(["", " \t "]) == []
    assert cat.conn.execute("SELECT count(*) FROM advisory_identities").fetchone()[0] == 0
    cat.close()
