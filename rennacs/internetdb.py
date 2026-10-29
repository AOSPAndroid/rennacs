"""Passive imports from Shodan InternetDB, with retained provider evidence.

The provider reports host-level ports, hostnames, CPEs, CVEs and tags. It supplies
neither per-port product/advisory bindings nor transport, TLS or observation times.
Keep these unknown: host assertions are not measured service vulnerabilities.

Successful imports retain the raw JSON, its canonical UTF-8 SHA256 and the actual
retrieval timestamp. Cache hits revalidate that evidence and preserve its time;
legacy normalized-only entries must be fetched again, never relabeled as fresh.
No targets or synthetic fallback records are loaded automatically. Provider access
uses a host-allowlisted, size-capped fetcher. Redistribution terms remain separate
from technical access to the API.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import sqlite3
import time
from datetime import datetime, timezone

from ._http import FETCH_ERRORS, SafeFetcher
from .ports import SERVICE_NAMES

BASE = "https://internetdb.shodan.io"

_CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
_CPE_URI = re.compile(r"cpe:/[aoh](?::(?:[A-Za-z0-9._~*-]|%[0-9A-Fa-f]{2})*){2,6}")
_CPE_FORMATTED = re.compile(r"cpe:2\.3:[aoh](?::(?:[A-Za-z0-9._?*-]|\\[^\s])+){10}")


_SCHEMA = """
CREATE TABLE IF NOT EXISTS idb_cache (
    ip         TEXT PRIMARY KEY,
    success    INTEGER,
    json       TEXT,
    fetched_at TEXT
);
"""


def _parse_cpe(cpe: str):
    """Parse supported, complete CPE tokens; never repair malformed source IDs."""
    if not isinstance(cpe, str):
        return "", "", ""
    if _CPE_FORMATTED.fullmatch(cpe):
        parts = re.findall(r"(?:\\[^\s]|[^:\\\s])+", cpe)
        return parts[2], parts[4], (parts[5] if parts[5] != "*" else "")
    if _CPE_URI.fullmatch(cpe):
        parts = cpe[5:].split(":")
        if parts[1] and parts[2]:
            return parts[0], parts[2], parts[3] if len(parts) > 3 else ""
    return "", "", ""


def _text_token(value) -> bool:
    return (isinstance(value, str) and bool(value) and value == value.strip()
            and value.isprintable())


def _aware_stamp(value) -> bool:
    if not isinstance(value, str) or "T" not in value or value != value.strip():
        return False
    try:
        return datetime.fromisoformat(value).utcoffset() is not None
    except ValueError:
        return False


def _ipv4_literal(value) -> bool:
    if not isinstance(value, str):
        return False
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def normalize(ip: str, raw: dict, *, retrieved_at: str = "") -> dict | None:
    """Normalize provider evidence with its known retrieval time, or fail closed.

    ``retrieved_at`` must come from the fetch or its validated cache entry, not
    from normalization time. The digest covers the entire unmodified raw JSON:
    sorted keys, compact separators, ensure_ascii=False, allow_nan=False, UTF-8.
    Unsupported CPE syntax remains in raw_payload, never a repaired assertion.
    """
    if (not _ipv4_literal(ip) or not _aware_stamp(retrieved_at)
            or not isinstance(raw, dict) or raw.get("ip") != ip
            or "detail" in raw or "error" in raw
            or ("success" in raw and raw["success"] is not True)
            or any(not isinstance(raw.get(key), list)
                   for key in ("ports", "hostnames", "tags", "cpes", "vulns"))):
        return None
    ports = sorted({p for p in raw["ports"] if _is_port(p)})
    if not ports:
        return None
    hostnames = [h for h in raw["hostnames"] if _text_token(h)][:12]
    tags = [t for t in raw["tags"] if _text_token(t)][:16]
    vulns = [c for c in raw["vulns"] if isinstance(c, str) and _CVE_RE.fullmatch(c)]

    services = [
        {"port": p, "transport": "unknown", "service": "",
         "service_hint": SERVICE_NAMES.get(p, ""), "product": "", "version": "",
         "os": "", "has_ssl": None, "vulns": [], "observed_at": None, "seen_at": ""}
        for p in ports
    ]
    host_advisories = [
        {"cve": c, "source": "shodan-internetdb", "scope": "host",
         "service_attribution": "unknown", "assessment_state": "unverified"}
        for c in vulns
    ]

    try:
        canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False, allow_nan=False)
        payload_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    except (TypeError, ValueError):
        return None
    provenance = {
        "kind": "import", "source": "shodan-internetdb",
        "retrieved_at": retrieved_at, "reference": f"{BASE}/{ip}",
        "payload_sha256": payload_hash,
        "raw_payload": json.loads(canonical), "observed_at": None,
        "host_cpes": [c for c in raw["cpes"] if _parse_cpe(c)[0]],
        "host_advisories": host_advisories,
    }
    return {"ip": ip, "hostnames": hostnames, "tags": tags, "services": services,
            "provenance": provenance}


def _is_port(p) -> bool:
    return type(p) is int and 1 <= p <= 65535


class InternetDB:
    """Cached client for Shodan InternetDB (free, no key)."""

    def __init__(self, db_path: str = "rennacs.db", *, timeout: float = 8.0,
                 offline: bool = False, now_iso: str = ""):
        self.db_path = db_path
        self.offline = offline
        self.timeout = timeout
        self._now = now_iso
        self._fetcher = SafeFetcher(allowed_hosts=("internetdb.shodan.io",),
                                    user_agent="Rennacs/0.3 internetdb")
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def _stamp(self) -> str:
        if self._now:
            return self._now
        return datetime.now(timezone.utc).isoformat()

    def _cached(self, ip: str):
        row = self.conn.execute(
            "SELECT success, json, fetched_at FROM idb_cache WHERE ip=?", (ip,)).fetchone()
        if row is None:
            return None
        if row["success"] == 0:
            return {"__absent__": True}
        try:
            cached = json.loads(row["json"])
            provenance = cached.get("provenance") if isinstance(cached, dict) else None
            if (row["success"] != 1 or not isinstance(provenance, dict)
                    or provenance.get("kind") != "import"
                    or provenance.get("source") != "shodan-internetdb"
                    or provenance.get("reference") != f"{BASE}/{ip}"
                    or not _aware_stamp(provenance.get("retrieved_at"))
                    or provenance["retrieved_at"] != row["fetched_at"]):
                return None
            # Re-normalize the evidence, never legacy/invented per-port claims.
            doc = normalize(ip, provenance.get("raw_payload"),
                            retrieved_at=provenance["retrieved_at"])
            if doc and doc["provenance"]["payload_sha256"] == provenance.get("payload_sha256"):
                return doc
        except (TypeError, ValueError):
            pass
        return None

    def lookup(self, ip: str, *, allow_network: bool = True) -> dict | None:
        """Return a normalized host doc for ``ip`` (real data), or None. Cache-first."""
        if not _ipv4_literal(ip):
            return None
        cached = self._cached(ip)
        if cached is not None:
            return None if cached.get("__absent__") else cached
        if self.offline or not allow_network:
            return None
        try:
            raw = self._fetcher.get_json(f"{BASE}/{ip}", timeout=self.timeout)
        except FETCH_ERRORS:
            return None
        # InternetDB returns {"detail":"No information available"} (404) for unknown IPs.
        if not isinstance(raw, dict) or "ports" not in raw:
            self._store_absent(ip)
            return None
        doc = normalize(ip, raw, retrieved_at=self._stamp())
        if doc is None:
            return None
        self._store(ip, doc)
        return doc

    def _store(self, ip: str, doc: dict) -> None:
        self.conn.execute(
            """INSERT INTO idb_cache(ip, success, json, fetched_at) VALUES(?,1,?,?)
               ON CONFLICT(ip) DO UPDATE SET success=1, json=excluded.json,
                   fetched_at=excluded.fetched_at""",
            (ip, json.dumps(doc), doc["provenance"]["retrieved_at"]))
        self.conn.commit()

    def _store_absent(self, ip: str) -> None:
        self.conn.execute(
            """INSERT INTO idb_cache(ip, success, json, fetched_at) VALUES(?,0,NULL,?)
               ON CONFLICT(ip) DO UPDATE SET success=0, json=NULL,
                   fetched_at=excluded.fetched_at""",
            (ip, self._stamp()))
        self.conn.commit()

    def import_targets(self, ips: list[str], idx, *, rate: float = 1.0,
                       on_result=None) -> dict:
        """Look up each ip and index the real data it returns.

        ``rate`` throttles lookups/second (InternetDB's free tier is ~1/s). Returns
        {requested, found, services} counts.
        """
        counts = {"requested": 0, "found": 0, "services": 0}
        min_gap = 1.0 / rate if rate else 0.0
        last = 0.0
        for ip in ips:
            counts["requested"] += 1
            if min_gap and self._cached(ip) is None and not self.offline:
                wait = min_gap - (time.monotonic() - last)
                if wait > 0:
                    time.sleep(wait)
                last = time.monotonic()
            doc = self.lookup(ip)
            if doc and doc.get("services"):
                idx.insert_raw(doc)
                counts["found"] += 1
                counts["services"] += len(doc["services"])
            if on_result:
                on_result(ip, doc, counts)
        return counts
