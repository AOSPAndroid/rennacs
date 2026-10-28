"""SQLite-backed index — the 'search engine' storage layer.

Two tables:

* ``hosts``    — one row per host (the indexed document + geo enrichment).
* ``services`` — one row per open port, with the banner and fingerprint fields the
                 query language filters on.

Keeping services in their own table makes ``port:``/``product:`` filters a plain JOIN,
which is exactly how a filter query engine wants to work. A flattened ``search_text``
column on each service powers free-text matching.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone

from .geoip import enrich

SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    ip        TEXT PRIMARY KEY,
    hostnames TEXT,            -- json list
    country   TEXT,
    city      TEXT,
    org       TEXT,
    asn       TEXT,
    lat       REAL,            -- for the map view; NULL == not geolocated
    lon       REAL,
    tags      TEXT,            -- json list (e.g. from Shodan InternetDB: cloud, self-signed)
    seen_at   TEXT
);
CREATE TABLE IF NOT EXISTS services (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT NOT NULL,
    ip_int      INTEGER,       -- IPv4 as 32-bit int, for net: CIDR filtering
    port        INTEGER NOT NULL,
    transport   TEXT,
    service     TEXT,
    product     TEXT,
    version     TEXT,
    os          TEXT,
    has_ssl     INTEGER DEFAULT 0,
    ssl_cn      TEXT,
    ssl_issuer  TEXT,
    ssl_sans    TEXT DEFAULT '[]',
    ssl_trust   TEXT DEFAULT 'not_observed',
    banner      TEXT,
    vulns       TEXT,          -- json list of {cve, severity, summary, ...enrichment}
    vuln_ids    TEXT,          -- space-joined CVE ids, for vuln:/has_vuln: filters
    kev         INTEGER DEFAULT 0,  -- 1 if any vuln is a CISA Known-Exploited (cve.now)
    search_text TEXT,          -- lower-cased blob for free-text matching
    seen_at     TEXT,
    UNIQUE(ip, port, transport),
    FOREIGN KEY(ip) REFERENCES hosts(ip) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS service_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    transport TEXT NOT NULL,
    state TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    details TEXT NOT NULL,
    note TEXT NOT NULL,
    FOREIGN KEY(ip) REFERENCES hosts(ip) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS scan_jobs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scope       TEXT,              -- the CIDR / comma list swept
    ports       TEXT,              -- ports spec
    seed        INTEGER,           -- permutation seed (for deterministic resume)
    total       INTEGER,           -- total hosts in scope
    scanned     INTEGER DEFAULT 0, -- hosts visited so far (the resume cursor)
    resume_at   INTEGER DEFAULT 0, -- contiguous completed prefix, safe to resume
    config      TEXT,              -- effective traversal and probe configuration
    hosts_up    INTEGER DEFAULT 0,
    services    INTEGER DEFAULT 0,
    rate        REAL,
    concurrency INTEGER,
    status      TEXT,              -- running | done | interrupted
    started_at  TEXT,
    updated_at  TEXT,
    finished_at TEXT
);
"""

# Indexes are created AFTER the column migration, so an old DB (missing ip_int) gets
# the column added before we try to index it.
INDEXES = """
CREATE INDEX IF NOT EXISTS idx_services_port    ON services(port);
CREATE INDEX IF NOT EXISTS idx_services_product ON services(product);
CREATE INDEX IF NOT EXISTS idx_services_ip      ON services(ip);
CREATE INDEX IF NOT EXISTS idx_services_ip_int  ON services(ip_int);
CREATE INDEX IF NOT EXISTS idx_observations_host ON service_observations(ip, id);
"""


def ip_to_int(ip: str) -> int | None:
    """IPv4 dotted string -> 32-bit int, or None for IPv6/invalid (net: is v4-only)."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return int(addr) if addr.version == 4 else None


class Index:
    def __init__(self, path: str = "rennacs.db"):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)
        self._migrate()                     # add any columns an old DB is missing
        self.conn.executescript(INDEXES)    # then index them
        self.conn.commit()

    def _migrate(self) -> None:
        """Add columns that newer versions introduced to an older database file.

        CREATE TABLE IF NOT EXISTS never alters an existing table, so a rennacs.db from
        a previous release lacks later columns (ip_int, vulns, vuln_ids, kev). Add any
        that are missing so queries referencing them don't fail with 'no such column'.
        """
        have = {r["name"] for r in self.conn.execute("PRAGMA table_info(services)")}
        for name, ddl in (("ip_int", "INTEGER"), ("vulns", "TEXT"),
                          ("vuln_ids", "TEXT"), ("kev", "INTEGER DEFAULT 0"),
                          ("ssl_sans", "TEXT DEFAULT '[]'"),
                          ("ssl_trust", "TEXT DEFAULT 'not_observed'")):
            if name not in have:
                self.conn.execute(f"ALTER TABLE services ADD COLUMN {name} {ddl}")
        have_h = {r["name"] for r in self.conn.execute("PRAGMA table_info(hosts)")}
        if "tags" not in have_h:
            self.conn.execute("ALTER TABLE hosts ADD COLUMN tags TEXT")
        have_j = {r["name"] for r in self.conn.execute("PRAGMA table_info(scan_jobs)")}
        for name, ddl in (("resume_at", "INTEGER DEFAULT 0"), ("config", "TEXT")):
            if name not in have_j:
                self.conn.execute(f"ALTER TABLE scan_jobs ADD COLUMN {name} {ddl}")

    def close(self) -> None:
        self.conn.close()

    @contextmanager
    def _tx(self):
        try:
            yield
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    # -- writing -----------------------------------------------------------------

    def upsert_host(self, host) -> None:
        """Refresh attempted services and retain an explicit observation trail.

        A missing response is not proof of closure, remediation, or security.
        ``scanned_ports=None`` preserves the legacy full-snapshot behavior.
        """
        if not host.services and not self.conn.execute(
            "SELECT 1 FROM hosts WHERE ip=?", (host.ip,)
        ).fetchone():
            return  # do not store billions of empty/unknown address documents
        geo = enrich(host.ip)
        with self._tx():
            previous = self.conn.execute(
                "SELECT * FROM services WHERE ip=?", (host.ip,)
            ).fetchall()
            self.conn.execute(
                """INSERT INTO hosts(ip, hostnames, country, city, org, asn,
                       lat, lon, seen_at)
                   VALUES(?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(ip) DO UPDATE SET
                       hostnames=excluded.hostnames, country=excluded.country,
                       city=excluded.city, org=excluded.org, asn=excluded.asn,
                       lat=excluded.lat, lon=excluded.lon, seen_at=excluded.seen_at""",
                (host.ip, json.dumps(host.hostnames), geo.country, geo.city,
                 geo.org, geo.asn, geo.lat, geo.lon, host.seen_at),
            )
            # Only replace ports this observation actually attempted. A partial
            # web scan must not silently erase a previously observed SSH service.
            scanned_ports = getattr(host, "scanned_ports", None)
            touched = set(scanned_ports) if scanned_ports is not None else None
            live = {(s.port, s.transport) for s in host.services}
            for old in previous:
                selected = touched is None or (old["transport"] == "tcp" and old["port"] in touched)
                if selected and (old["port"], old["transport"]) not in live:
                    self.conn.execute(
                        """INSERT INTO service_observations
                           (ip,port,transport,state,observed_at,details,note)
                           VALUES(?,?,?,'not_observed',?,?,?)""",
                        (host.ip, old["port"], old["transport"], host.seen_at,
                         json.dumps(dict(old)),
                         "Not observed on rescan; not proof of closure or remediation."),
                    )
            if scanned_ports is None:  # legacy callers supply a full-host snapshot
                self.conn.execute("DELETE FROM services WHERE ip=?", (host.ip,))
            else:
                self.conn.executemany(
                    "DELETE FROM services WHERE ip=? AND port=? AND transport=?",
                    ((host.ip, old["port"], old["transport"]) for old in previous
                     if old["transport"] == "tcp" and old["port"] in touched),
                )
            ip_int = ip_to_int(host.ip)
            for s in host.services:
                vuln_ids = " ".join(v["cve"] for v in s.vulns)
                search = " ".join(filter(None, [
                    s.banner, s.product, s.version, s.service, s.os, s.ssl_cn,
                    s.ssl_issuer, geo.org, geo.country, geo.city, vuln_ids,
                ])).lower()
                self.conn.execute(
                    """INSERT INTO services(ip, ip_int, port, transport, service,
                           product, version, os, has_ssl, ssl_cn, ssl_issuer, banner,
                           vulns, vuln_ids, search_text, seen_at, ssl_sans, ssl_trust)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (host.ip, ip_int, s.port, s.transport, s.service, s.product,
                     s.version, s.os, 1 if s.has_ssl else 0, s.ssl_cn, s.ssl_issuer,
                     s.banner, json.dumps(s.vulns), vuln_ids, search, s.seen_at,
                     json.dumps(s.ssl_sans), "unverified" if s.has_ssl else "not_observed"),
                )
                self.conn.execute(
                    """INSERT INTO service_observations
                       (ip,port,transport,state,observed_at,details,note)
                       VALUES(?,?,?,'open',?,?,?)""",
                    (host.ip, s.port, s.transport, host.seen_at, json.dumps(asdict(s)),
                     "Service answered; vulnerability status remains unverified."),
                )

    def service_history(self, ip: str, *, limit: int = 100, offset: int = 0) -> list[dict]:
        """Bounded newest-first observation events, including missing responses."""
        if not 1 <= limit <= 1000 or offset < 0:
            raise ValueError("history limit must be 1..1000 and offset nonnegative")
        rows = self.conn.execute(
            "SELECT * FROM service_observations WHERE ip=? ORDER BY id DESC LIMIT ? OFFSET ?",
            (ip, limit, offset),
        ).fetchall()
        return [dict(row, details=json.loads(row["details"])) for row in rows]

    def insert_raw(self, doc: dict) -> None:
        """Insert a plain dict document (used by the demo seeder).

        Vulns are computed from (product, version) via :mod:`rennacs.vulns` unless the
        document already supplies a ``vulns`` list for a service.
        """
        from .vulns import check as vulncheck

        geo = enrich(doc["ip"])
        seen = doc.get("seen_at") or datetime.now(timezone.utc).isoformat()
        lat = doc.get("lat", geo.lat)
        lon = doc.get("lon", geo.lon)
        tags = doc.get("tags", [])
        tag_text = " ".join(tags)
        with self._tx():
            self.conn.execute(
                """INSERT INTO hosts(ip, hostnames, country, city, org, asn,
                       lat, lon, tags, seen_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(ip) DO UPDATE SET
                       hostnames=excluded.hostnames, country=excluded.country,
                       city=excluded.city, org=excluded.org, asn=excluded.asn,
                       lat=excluded.lat, lon=excluded.lon, tags=excluded.tags,
                       seen_at=excluded.seen_at""",
                (doc["ip"], json.dumps(doc.get("hostnames", [])),
                 doc.get("country") or geo.country, doc.get("city") or geo.city,
                 doc.get("org") or geo.org, doc.get("asn") or geo.asn, lat, lon,
                 json.dumps(tags), seen),
            )
            self.conn.execute("DELETE FROM services WHERE ip=?", (doc["ip"],))
            ip_int = ip_to_int(doc["ip"])
            for s in doc.get("services", []):
                vulns = s.get("vulns")
                if vulns is None:
                    vulns = [v.as_dict()
                             for v in vulncheck(s.get("product", ""),
                                                s.get("version", ""))]
                vuln_ids = " ".join(v["cve"] for v in vulns)
                search = " ".join(filter(None, [
                    s.get("banner", ""), s.get("product", ""), s.get("version", ""),
                    s.get("service", ""), s.get("os", ""), s.get("ssl_cn", ""),
                    doc.get("org", "") or geo.org, doc.get("country", "") or geo.country,
                    vuln_ids, tag_text,
                ])).lower()
                self.conn.execute(
                    """INSERT INTO services(ip, ip_int, port, transport, service,
                           product, version, os, has_ssl, ssl_cn, ssl_issuer, banner,
                           vulns, vuln_ids, search_text, seen_at, ssl_sans, ssl_trust)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (doc["ip"], ip_int, s["port"], s.get("transport", "tcp"),
                     s.get("service", ""), s.get("product", ""), s.get("version", ""),
                     s.get("os", ""), 1 if s.get("has_ssl") else 0,
                     s.get("ssl_cn", ""), s.get("ssl_issuer", ""),
                     s.get("banner", ""), json.dumps(vulns), vuln_ids, search, seen,
                     json.dumps(s.get("ssl_sans", [])),
                     "unverified" if s.get("has_ssl") else "not_observed"),
                )

    # -- scan jobs (crawler history + resumability) ------------------------------

    def start_job(self, scope: str, ports: str, total: int, *, rate: float = 0,
                  concurrency: int = 0, seed: int = 0, config: dict | None = None) -> int:
        now = datetime.now(timezone.utc).isoformat()
        cur = self.conn.execute(
            """INSERT INTO scan_jobs(scope, ports, seed, total, scanned, status,
                   rate, concurrency, started_at, updated_at, resume_at, config)
               VALUES(?,?,?,?,0,'running',?,?,?,?,0,?)""",
            (scope, ports, seed, total, rate, concurrency, now, now,
             json.dumps(config or {}, sort_keys=True)))
        self.conn.commit()
        return cur.lastrowid

    def checkpoint_job(self, job_id: int, *, scanned: int, hosts_up: int,
                       services: int, seed: int = 0, resume_at: int | None = None) -> None:
        self.conn.execute(
            """UPDATE scan_jobs SET scanned=?, hosts_up=?, services=?, seed=?, resume_at=?,
                   updated_at=? WHERE id=?""",
            (scanned, hosts_up, services, seed, scanned if resume_at is None else resume_at,
             datetime.now(timezone.utc).isoformat(), job_id))
        self.conn.commit()

    def finish_job(self, job_id: int, status: str = "done") -> None:
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "UPDATE scan_jobs SET status=?, finished_at=?, updated_at=? WHERE id=?",
            (status, now, now, job_id))
        self.conn.commit()

    def get_job(self, job_id: int) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM scan_jobs WHERE id=?", (job_id,)).fetchone()
        return dict(row, config=json.loads(row["config"] or "{}")) if row else None

    def list_jobs(self, limit: int = 20) -> list[dict]:
        return [dict(r, config=json.loads(r["config"] or "{}")) for r in self.conn.execute(
            "SELECT * FROM scan_jobs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]

    def resumable_jobs(self) -> list[dict]:
        """Running/interrupted jobs that haven't finished their scope."""
        return [dict(r, config=json.loads(r["config"] or "{}")) for r in self.conn.execute(
            "SELECT * FROM scan_jobs WHERE status IN ('running','interrupted','failed') "
            "AND resume_at < total ORDER BY id DESC").fetchall()]

    # -- reading -----------------------------------------------------------------

    def host(self, ip: str) -> dict | None:
        row = self.conn.execute("SELECT * FROM hosts WHERE ip=?", (ip,)).fetchone()
        if not row:
            return None
        services = self.conn.execute(
            "SELECT * FROM services WHERE ip=? ORDER BY port", (ip,)
        ).fetchall()
        doc = dict(row)
        doc["hostnames"] = json.loads(doc.get("hostnames") or "[]")
        doc["tags"] = json.loads(doc.get("tags") or "[]")
        svc = []
        for s in services:
            d = dict(s)
            d["vulns"] = json.loads(d.get("vulns") or "[]")
            d["ssl_sans"] = json.loads(d.get("ssl_sans") or "[]")
            svc.append(d)
        doc["services"] = svc
        doc["vuln_count"] = sum(len(s["vulns"]) for s in svc)
        return doc

    # -- cve.now enrichment ------------------------------------------------------

    def distinct_cves(self) -> list[str]:
        """Every CVE id currently referenced by the index (for a refresh pass)."""
        ids: set[str] = set()
        for (vids,) in self.conn.execute(
                "SELECT vuln_ids FROM services WHERE vuln_ids<>''").fetchall():
            ids.update(vids.split())
        return sorted(ids)

    def reenrich(self, cvenow, *, allow_network: bool = False) -> dict:
        """Re-merge every stored vuln with cve.now data (from cache by default).

        Rewrites each service's ``vulns`` JSON in place and sets the ``kev`` flag.
        Does not re-scan anything. Returns {services, enriched, kev} counts.

        When ``allow_network`` is True the network fetches happen FIRST, outside the
        write transaction: the cvenow client writes its cache on a separate connection,
        and doing that while this connection holds a write lock would self-deadlock.
        The merge pass below always reads cache-only.
        """
        if allow_network:
            for cve in self.distinct_cves():
                cvenow.entry(cve, allow_network=True)   # warm cache, no lock held
        counts = {"services": 0, "enriched": 0, "kev": 0}
        rows = self.conn.execute(
            "SELECT id, version, vulns FROM services WHERE vuln_ids<>''").fetchall()
        with self._tx():
            for row in rows:
                try:
                    vulns = json.loads(row["vulns"] or "[]")
                except (TypeError, ValueError):
                    continue
                if not vulns:
                    continue
                merged = [cvenow.enrich_vuln(v, row["version"] or "",
                                             allow_network=False)  # cache-only in tx
                          for v in vulns]
                kev = 1 if any(v.get("kev") for v in merged) else 0
                counts["services"] += 1
                counts["enriched"] += sum(1 for v in merged if v.get("enriched"))
                counts["kev"] += kev
                self.conn.execute(
                    "UPDATE services SET vulns=?, kev=? WHERE id=?",
                    (json.dumps(merged), kev, row["id"]))
        return counts

    def stats(self) -> dict:
        from collections import Counter
        c = self.conn.execute
        vc: Counter = Counter()
        for (ids,) in c("SELECT vuln_ids FROM services WHERE vuln_ids<>''").fetchall():
            vc.update(ids.split())
        return {
            "hosts": c("SELECT COUNT(*) FROM hosts").fetchone()[0],
            "services": c("SELECT COUNT(*) FROM services").fetchone()[0],
            "top_ports": [dict(r) for r in c(
                "SELECT port, COUNT(*) n FROM services GROUP BY port "
                "ORDER BY n DESC LIMIT 10").fetchall()],
            "top_products": [dict(r) for r in c(
                "SELECT product, COUNT(*) n FROM services "
                "WHERE product<>'' GROUP BY product ORDER BY n DESC LIMIT 10"
            ).fetchall()],
            "top_countries": [dict(r) for r in c(
                "SELECT country, COUNT(DISTINCT ip) n FROM services "
                "JOIN hosts USING(ip) WHERE country<>'' GROUP BY country "
                "ORDER BY n DESC LIMIT 10").fetchall()],
            "top_vulns": [{"cve": cve, "n": n} for cve, n in vc.most_common(10)],
            "vuln_services": c(
                "SELECT COUNT(*) FROM services WHERE vuln_ids<>''").fetchone()[0],
            "kev_services": c(
                "SELECT COUNT(*) FROM services WHERE kev=1").fetchone()[0],
        }

    def map_points(self, where_sql: str = "1", params: list | None = None) -> dict:
        """Hosts for the world map, optionally filtered by a compiled search query.

        ``where_sql``/``params`` come from :func:`rennacs.query.compile_query`, so the
        map can show only the hosts matching a query (Shodan's "View on Map"). Each
        located point carries its open-port count and whether any matching service has a
        suggested vuln, so markers can be coloured. Also returns the ungeolocated hosts
        and a country breakdown of the located set.
        """
        params = params or []
        located = []
        for r in self.conn.execute(
            f"""SELECT h.ip, h.lat, h.lon, h.city, h.country, h.org,
                       COUNT(s.id) ports,
                       SUM(CASE WHEN s.vuln_ids<>'' THEN 1 ELSE 0 END) vulns
                FROM hosts h JOIN services s ON s.ip = h.ip
                WHERE h.lat IS NOT NULL AND h.lon IS NOT NULL AND ({where_sql})
                GROUP BY h.ip""", params
        ).fetchall():
            d = dict(r)
            d["vulns"] = int(d["vulns"] or 0)
            located.append(d)
        ungeo = [row[0] for row in self.conn.execute(
            f"""SELECT DISTINCT h.ip FROM hosts h JOIN services s ON s.ip = h.ip
                WHERE (h.lat IS NULL OR h.lon IS NULL) AND ({where_sql})
                ORDER BY h.ip""", params
        ).fetchall()]
        countries = [dict(r) for r in self.conn.execute(
            f"""SELECT h.country, COUNT(DISTINCT h.ip) n
                FROM hosts h JOIN services s ON s.ip = h.ip
                WHERE h.lat IS NOT NULL AND h.country<>'' AND ({where_sql})
                GROUP BY h.country ORDER BY n DESC LIMIT 12""", params
        ).fetchall()]
        return {"located": located, "ungeolocated": ungeo, "countries": countries}

    # -- geolocation enrichment --------------------------------------------------

    def hosts_without_geo(self) -> list[str]:
        """IPs in the index that have no coordinates yet (candidates for geolocation)."""
        return [r[0] for r in self.conn.execute(
            "SELECT ip FROM hosts WHERE lat IS NULL OR lon IS NULL "
            "ORDER BY ip").fetchall()]

    def update_host_geo(self, ip: str, geo) -> None:
        """Write a located host's coordinates/country/city/org back to the index."""
        self.conn.execute(
            """UPDATE hosts SET lat=?, lon=?, country=COALESCE(NULLIF(?,''),country),
                   city=COALESCE(NULLIF(?,''),city), org=COALESCE(NULLIF(?,''),org),
                   asn=COALESCE(NULLIF(?,''),asn) WHERE ip=?""",
            (geo.lat, geo.lon, geo.country, geo.city, geo.org, geo.asn, ip))
        self.conn.commit()

    def search(self, where_sql: str, params: list, *, limit: int = 100,
               offset: int = 0) -> tuple[list[dict], int]:
        """Run a compiled query. Returns (rows, total_matching_services).

        Each result row is a service joined to its host — the same granularity Shodan
        shows in a results list (one banner per row).
        """
        base = ("FROM services s JOIN hosts h ON h.ip = s.ip "
                f"WHERE {where_sql}")
        total = self.conn.execute(
            f"SELECT COUNT(*) {base}", params).fetchone()[0]
        rows = self.conn.execute(
            f"""SELECT s.*, h.hostnames, h.country, h.city, h.org, h.asn {base}
                ORDER BY s.ip, s.port LIMIT ? OFFSET ?""",
            params + [limit, offset],
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["hostnames"] = json.loads(d.get("hostnames") or "[]")
            d["vulns"] = json.loads(d.get("vulns") or "[]")
            d["ssl_sans"] = json.loads(d.get("ssl_sans") or "[]")
            out.append(d)
        return out, total
