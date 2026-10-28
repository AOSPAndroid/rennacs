"""Bounded, resumable cve.now advisory ingestion, separate from scan acquisition.

``candidates`` returns unchanged validated source JSON; ``provenance(id)`` exposes
its source URL and UTC fetch timestamp separately. Product/package names alone
are indexed; vendor, ecosystem and every version-bound field remain in raw JSON.

Owned connections durably commit each page checkpoint/detail independently. Shared
connections never commit or close caller work; only owned, idle connections may
run network batches. KeyboardInterrupt propagates with committed progress intact.

Batch summaries contain requests/pages/stored, stop_reason, complete, last_error
and status. Budgets count attempted list AND detail endpoint calls (including
failures); the default safe getter may follow its constrained CDN redirects.
max_pages limits new pages, not draining existing pending details. fetch_ids([])
resumes targeted work without traversing the catalog. Request spacing applies to
one Catalog instance, including consecutive batches, not concurrent processes.

Status distinguishes stored/pending details, cursor, revision, traversal progress
and last error. ``complete`` means the last unfiltered traversal reached its end
and all its queued details succeeded, NOT an atomic snapshot, source-wide matching
coverage or fresh data. Retained old details are not purged. A failed/404/malformed
detail blocks its queue until the source recovers; there is no automatic bypass.
restart resets pagination/cursor history, retaining cache AND unfinished details.
"""

from __future__ import annotations

import json
import math
import http.client
import urllib.error
import re
import sqlite3
import time
from datetime import datetime, timezone
from contextlib import contextmanager
from urllib.parse import urlencode

BASE = "https://cve.now/api/v1/entries"

_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS advisory_catalog (
        id TEXT PRIMARY KEY, raw_json TEXT NOT NULL, source TEXT NOT NULL,
        source_url TEXT NOT NULL, fetched_at TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS advisory_identities (
        identity TEXT NOT NULL, advisory_id TEXT NOT NULL,
        PRIMARY KEY(identity, advisory_id))""",
    "CREATE TABLE IF NOT EXISTS catalog_meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS catalog_state (id INTEGER PRIMARY KEY CHECK(id=1), json TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS catalog_cursors (cursor TEXT PRIMARY KEY)",
    """CREATE TABLE IF NOT EXISTS catalog_pending (
        seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL,
        catalog INTEGER NOT NULL DEFAULT 0, targeted INTEGER NOT NULL DEFAULT 0)""",
)


def _stamp():
    return datetime.now(timezone.utc).isoformat()


def _identity(value):
    return " ".join(value.casefold().split())


# ASCII-only, exact tokens. GHSA source casing is preserved, not repaired.
_ID = re.compile(
    r"(?:CVE-[0-9]{4}-[0-9]{4,}|"
    r"GHSA-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}|"
    r"(?!CVE-|GHSA-)[A-Z]{2,}-[0-9]{4}-[0-9]+)"
)


def valid_id(value):
    """Whether an exact source token is an accepted CVE/GHSA/year-number OSV ID."""
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _identifier(value):
    if not valid_id(value):
        raise ValueError("invalid advisory ID")
    return value


def _json_value(value):
    # json.dumps silently coerces tuples and non-string object keys. Reject those
    # rather than claim a lossless raw record after a SQLite roundtrip.
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError("JSON object keys must be strings")
            _json_value(child)
    elif isinstance(value, list):
        for child in value:
            _json_value(child)
    elif type(value) not in (str, int, float, bool, type(None)):
        raise ValueError("value is not JSON")


def _validated(raw):
    if not isinstance(raw, dict):
        raise ValueError("detail must be a JSON object")
    identifier = _identifier(raw.get("id"))
    if "feedId" in raw:
        _identifier(raw["feedId"])
    for key in ("aliases", "supersededBy"):
        if key in raw:
            if not isinstance(raw[key], list):
                raise ValueError(f"{key} must be a list")
            for value in raw[key]:
                _identifier(value)
    if not isinstance(raw.get("affected"), list):
        raise ValueError("detail must contain an affected list (not a list summary)")
    for affected in raw["affected"]:
        if not isinstance(affected, dict):
            raise ValueError("affected item must be an object")
        for key in ("vendor", "product", "package", "ecosystem"):
            if key in affected and affected[key] is not None and not isinstance(affected[key], str):
                raise ValueError(f"affected {key} must be a string or null")
        if "ranges" in affected:
            if not isinstance(affected["ranges"], list) or any(
                    not isinstance(r, dict) for r in affected["ranges"]):
                raise ValueError("affected ranges must be a list of objects")
    try:
        _json_value(raw)
        encoded = json.dumps(raw, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("detail is not finite JSON") from exc
    return identifier, encoded


def _limits(max_requests, rate, max_pages=0):
    if any(type(value) is not int or value < 0 for value in (max_requests, max_pages)):
        raise ValueError("request/page budgets must be nonnegative integers")
    if type(rate) not in (int, float) or not math.isfinite(rate) or rate <= 0:
        raise ValueError("rate must be a finite positive number")


def _page(raw):
    if not isinstance(raw, dict) or not isinstance(raw.get("entries"), list):
        raise ValueError("list response must contain an entries list")
    if "nextCursor" not in raw:
        raise ValueError("list response is missing nextCursor")
    cursor = raw["nextCursor"]
    if cursor is not None and (not isinstance(cursor, str) or not cursor):
        raise ValueError("nextCursor must be a nonempty opaque string or null")
    identifiers = []
    for item in raw["entries"]:
        if not isinstance(item, dict):
            raise ValueError("list entry must be an object")
        identifiers.append(_identifier(item.get("id")))
    return identifiers, cursor


class Catalog:
    """Own a SQLite connection, or borrow one without closing/committing it."""

    def __init__(self, path="rennacs.db", *, connection=None):
        self.owns_connection = connection is None
        self._last_request = None
        self.conn = sqlite3.connect(path) if self.owns_connection else connection
        for statement in _SCHEMA:
            self.conn.execute(statement)

    def close(self):
        if self.owns_connection:
            self.conn.close()

    @contextmanager
    def _atomic(self):
        # A shared connection leaves its transaction entirely caller-owned.
        if not self.owns_connection and not self.conn.in_transaction:
            self.conn.execute("BEGIN")
        self.conn.execute("SAVEPOINT catalog_write")
        try:
            yield
        except BaseException:
            self.conn.execute("ROLLBACK TO catalog_write")
            self.conn.execute("RELEASE catalog_write")
            raise
        else:
            self.conn.execute("RELEASE catalog_write")

    def revision(self):
        """Cheap, transactional cache-invalidation token; increments even on refresh."""
        row = self.conn.execute("SELECT value FROM catalog_meta WHERE key='revision'").fetchone()
        return row[0] if row else 0

    def upsert(self, raw):
        identifier, encoded = _validated(raw)
        with self._atomic():
            self._store(raw, identifier, encoded)
        return identifier

    def _store(self, raw, identifier, encoded, source_url=None):
        self.conn.execute(
            "INSERT INTO advisory_catalog VALUES(?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET raw_json=excluded.raw_json, "
            "source=excluded.source, source_url=excluded.source_url, "
            "fetched_at=excluded.fetched_at",
            (identifier, encoded, "cve.now", source_url or f"{BASE}/{identifier}", _stamp()),
        )
        self.conn.execute("DELETE FROM advisory_identities WHERE advisory_id=?", (identifier,))
        identities = {_identity(a[k]) for a in raw["affected"]
                      for k in ("product", "package") if a.get(k)} - {""}
        self.conn.executemany("INSERT INTO advisory_identities VALUES(?,?)",
                              ((key, identifier) for key in identities))
        self.conn.execute("INSERT INTO catalog_meta VALUES('revision',1) "
                          "ON CONFLICT(key) DO UPDATE SET value=value+1")

    def _state(self):
        row = self.conn.execute("SELECT json FROM catalog_state WHERE id=1").fetchone()
        return json.loads(row[0]) if row else {
            "cursor": None, "started_at": None, "listing_exhausted": False,
            "pages": 0, "last_error": None, "updated_at": None,
        }

    def _save_state(self, state):
        state["updated_at"] = _stamp()
        self.conn.execute("INSERT INTO catalog_state VALUES(1,?) "
                          "ON CONFLICT(id) DO UPDATE SET json=excluded.json", (json.dumps(state),))

    def status(self):
        """Local storage is not source coverage, nor an atomic source snapshot."""
        state = self._state()
        pending = self.conn.execute("SELECT count(*), coalesce(sum(catalog),0), "
                                    "coalesce(sum(targeted),0) FROM catalog_pending").fetchone()
        complete = bool(state["listing_exhausted"] and not pending[1] and not state["last_error"])
        return dict(state, source="cve.now", revision=self.revision(), stored_details=self.conn.execute(
            "SELECT count(*) FROM advisory_catalog").fetchone()[0],
            pending_details=pending[0], pending_catalog_details=pending[1],
            pending_targeted_details=pending[2], complete=complete, atomic_snapshot=False,
            traversal="complete" if complete else "partial" if state["started_at"] else "not_started")

    def _enqueue(self, identifiers, kind):
        for identifier in identifiers:
            self.conn.execute(f"INSERT INTO catalog_pending(id,{kind}) VALUES(?,1) "
                              f"ON CONFLICT(id) DO UPDATE SET {kind}=1", (identifier,))

    def _summary(self, requests, pages, stored, reason):
        state = self.status()
        return {"requests": requests, "pages": pages, "stored": stored,
                "stop_reason": reason,
                "complete": state["complete"] and reason in ("complete", "ids_complete"),
                "last_error": state["last_error"], "status": state}

    def _require_owned_idle(self):
        if not self.owns_connection:
            raise RuntimeError("network batches require an owned Catalog connection")
        if self.conn.in_transaction:
            raise RuntimeError("network batches cannot run inside an existing transaction")

    def _request(self, url, fetcher, rate):
        if self._last_request is not None:
            wait = self._last_request + 1 / rate - time.monotonic()
            if wait > 0:
                time.sleep(wait)
        self._last_request = time.monotonic()
        if fetcher is not None:
            return fetcher(url)
        # Reuse only the redirect-constrained, response-capped HTTP getter. Its
        # SQLite cache is fresh memory, never a scanner/customer database.
        from .cvenow import CVENow
        client = CVENow(":memory:")
        try:
            return client._get_json(url)
        finally:
            client.close()

    def sync(self, max_pages=1, max_requests=50, rate=1, fetcher=None, restart=False):
        """Resume pending details first, then at most max_pages unfiltered list pages."""
        _limits(max_requests, rate, max_pages)
        self._require_owned_idle()
        requests = pages = stored = 0
        state = self._state()
        if restart:
            # Restart pagination, not the durable unfinished-detail queue. Cached
            # historical details are retained: a traversal is not a source snapshot.
            state.update(cursor=None, listing_exhausted=False, pages=0,
                         started_at=_stamp(), last_error=None)
            with self._atomic():
                self.conn.execute("DELETE FROM catalog_cursors")
                self._save_state(state)
        while True:
            pending = self.conn.execute("SELECT id FROM catalog_pending WHERE catalog=1 "
                                        "ORDER BY seq LIMIT 1").fetchone()
            if not pending and state["listing_exhausted"]:
                return self._summary(requests, pages, stored, "complete")
            if requests >= max_requests:
                return self._summary(requests, pages, stored, "request_budget")
            if not pending and pages >= max_pages:
                return self._summary(requests, pages, stored, "page_budget")
            url = BASE + ("?" + urlencode({"cursor": state["cursor"]}) if state["cursor"] is not None else "")
            if pending:
                identifier = _identifier(pending[0])
                url = f"{BASE}/{identifier}"
            requests += 1
            try:
                raw = self._request(url, fetcher, rate)
                if pending:
                    self._receive_detail(raw, identifier)
                    stored += 1
                    state = self._state()
                else:
                    identifiers, cursor = _page(raw)
                    if cursor is not None and (cursor == state["cursor"] or self.conn.execute(
                            "SELECT 1 FROM catalog_cursors WHERE cursor=?", (cursor,)).fetchone()):
                        raise ValueError("repeated cursor in catalog traversal; restart required if persistent")
                    state["cursor"] = cursor
                    state["listing_exhausted"] = cursor is None
                    state["started_at"] = state["started_at"] or _stamp()
                    state["pages"] += 1
                    state["last_error"] = None
                    with self._atomic():
                        self._enqueue(identifiers, "catalog")
                        if cursor is not None:
                            self.conn.execute("INSERT INTO catalog_cursors VALUES(?)", (cursor,))
                        self._save_state(state)
                    pages += 1
            except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
                self._record_error(exc, url)
                return self._summary(requests, pages, stored, "error")

    def fetch_ids(self, ids, max_requests=50, rate=1, fetcher=None):
        """Queue/retry explicit IDs; this never starts or advances the list traversal."""
        _limits(max_requests, rate)
        self._require_owned_idle()
        identifiers = [_identifier(value) for value in ids]
        with self._atomic():
            self._enqueue(identifiers, "targeted")
        requests = stored = 0
        while True:
            pending = self.conn.execute("SELECT id FROM catalog_pending WHERE targeted=1 "
                                        "ORDER BY seq LIMIT 1").fetchone()
            if not pending:
                return self._summary(requests, 0, stored, "ids_complete")
            if requests >= max_requests:
                return self._summary(requests, 0, stored, "request_budget")
            identifier = _identifier(pending[0])
            url = f"{BASE}/{identifier}"
            requests += 1
            try:
                raw = self._request(url, fetcher, rate)
                self._receive_detail(raw, identifier)
                stored += 1
            except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
                self._record_error(exc, url)
                return self._summary(requests, 0, stored, "error")

    def _receive_detail(self, raw, requested):
        canonical, encoded = _validated(raw)
        identities = [canonical, raw.get("feedId"), *raw.get("aliases", [])]
        if not any(requested == value or (
                requested.startswith("GHSA-") and isinstance(value, str) and
                value.startswith("GHSA-") and requested.casefold() == value.casefold())
                for value in identities):
            raise ValueError("detail identity does not match requested advisory")
        state = self._state()
        state["last_error"] = None
        with self._atomic():
            self._store(raw, canonical, encoded, source_url=f"{BASE}/{requested}")
            self.conn.execute("DELETE FROM catalog_pending WHERE id=?", (requested,))
            self._save_state(state)

    def _record_error(self, exc, url):
        state = self._state()
        state["last_error"] = {"type": type(exc).__name__, "message": str(exc)[:1000],
                               "url": url, "at": _stamp()}
        if isinstance(exc, urllib.error.HTTPError):
            state["last_error"]["http_status"] = exc.code
        with self._atomic():
            self._save_state(state)

    def provenance(self, identifier):
        """Read fetched/source metadata separately; candidate raw JSON is untouched."""
        _identifier(identifier)
        row = self.conn.execute(
            "SELECT source, source_url, fetched_at FROM advisory_catalog WHERE id=?",
            (identifier,)).fetchone()
        return dict(zip(("source", "source_url", "fetched_at"), row)) if row else None

    def candidates(self, keys):
        identifiers = set()
        for key in keys:
            identifiers.update(row[0] for row in self.conn.execute(
                "SELECT advisory_id FROM advisory_identities WHERE identity=?", (_identity(key),)))
        return [json.loads(self.conn.execute(
            "SELECT raw_json FROM advisory_catalog WHERE id=?", (identifier,)).fetchone()[0])
                for identifier in sorted(identifiers)]
