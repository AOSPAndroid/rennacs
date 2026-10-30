"""Append-only evidence, advisory revisions, and operator decision history."""
import hashlib
import json
import sqlite3
from contextlib import AbstractContextManager

from .scope import stamp


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)


def digest(value):
    return hashlib.sha256(encoded(value).encode()).hexdigest()


class Store(AbstractContextManager):
    def __init__(self, path):
        self.db = sqlite3.connect(path, timeout=15)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS exposure_advisories (
          hash TEXT PRIMARY KEY, advisory_id TEXT NOT NULL, fetched_at TEXT NOT NULL,
          data TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS exposure_advisory_ids ON exposure_advisories(advisory_id);
        CREATE TABLE IF NOT EXISTS exposure_advisory_fetches (
          id INTEGER PRIMARY KEY, hash TEXT NOT NULL, fetched_at TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS exposure_advisory_fetch_hash ON exposure_advisory_fetches(hash,id);
        CREATE TABLE IF NOT EXISTS exposure_observations (
          hash TEXT PRIMARY KEY, ip TEXT NOT NULL, port INTEGER NOT NULL,
          transport TEXT NOT NULL, observed_at TEXT NOT NULL, ingested_at TEXT NOT NULL,
          data TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS exposure_services ON exposure_observations(ip,port,transport,observed_at);
        CREATE TABLE IF NOT EXISTS exposure_assessments (
          id INTEGER PRIMARY KEY, assessed_at TEXT NOT NULL, data TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS exposure_decisions (
          id INTEGER PRIMARY KEY, finding_id TEXT NOT NULL, recorded_at TEXT NOT NULL,
          effective_at TEXT NOT NULL, status TEXT NOT NULL, actor TEXT NOT NULL,
          evidence_ref TEXT NOT NULL, note TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS exposure_runs (
          id INTEGER PRIMARY KEY, recorded_at TEXT NOT NULL, data TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS exposure_source_documents (
          source_id TEXT PRIMARY KEY, revision TEXT NOT NULL, fetched_at TEXT NOT NULL);
        """)
        self.db.execute("""INSERT INTO exposure_advisory_fetches(hash,fetched_at)
            SELECT hash,fetched_at FROM exposure_advisories AS a WHERE NOT EXISTS (
              SELECT 1 FROM exposure_advisory_fetches AS f WHERE f.hash=a.hash)""")
        self.db.commit()

    def __exit__(self, *args):
        self.db.close()

    def advisory(self, data):
        h = digest(data)
        now = stamp()
        self.db.execute("INSERT OR IGNORE INTO exposure_advisories VALUES(?,?,?,?)",
                        (h, data["id"], now, encoded(data)))
        self.db.execute("INSERT INTO exposure_advisory_fetches(hash,fetched_at) VALUES(?,?)", (h, now))
        self.db.commit()
        return h

    def advisories(self):
        rows = self.db.execute("""SELECT a.hash,a.advisory_id,a.data,f.fetched_at
            FROM exposure_advisories AS a JOIN exposure_advisory_fetches AS f ON f.hash=a.hash
            WHERE f.id=(SELECT MAX(f2.id) FROM exposure_advisory_fetches AS f2 WHERE f2.hash=f.hash)
            ORDER BY f.id""")
        latest = {}
        for row in rows:
            data = json.loads(row["data"])
            latest[(data["vendor"], row["advisory_id"])] = {**data, "revision": row["hash"],
                                                          "fetched_at": row["fetched_at"]}
        return list(latest.values())

    def observation(self, data):
        h = digest(data)
        cur = self.db.execute("INSERT OR IGNORE INTO exposure_observations VALUES(?,?,?,?,?,?,?)",
                        (h, data["ip"], data["port"], data["transport"], data["observed_at"],
                         stamp(), encoded(data)))
        self.db.commit()
        return cur.rowcount

    def observations(self):
        return [{**json.loads(r["data"]), "evidence_hash": r["hash"],
                 "ingested_at": r["ingested_at"]} for r in self.db.execute(
                     "SELECT * FROM exposure_observations ORDER BY observed_at, rowid")]

    def record_assessment(self, data):
        cur = self.db.execute("INSERT INTO exposure_assessments(assessed_at,data) VALUES(?,?)",
                              (data["assessed_at"], encoded(data)))
        self.db.commit()
        return cur.lastrowid

    def latest(self):
        row = self.db.execute("SELECT data FROM exposure_assessments ORDER BY id DESC LIMIT 1").fetchone()
        return json.loads(row[0]) if row else {"findings": [], "advisories": [], "assessed_at": None}

    def history(self, finding_id):
        return {"assessments": [f for row in self.db.execute(
            "SELECT data FROM exposure_assessments ORDER BY id")
            for f in json.loads(row[0])["findings"] if f["finding_id"] == finding_id],
            "decisions": [dict(r) for r in self.db.execute(
                "SELECT * FROM exposure_decisions WHERE finding_id=? ORDER BY id", (finding_id,))]}

    def evidence(self, content_hash):
        for kind, table in (("observation", "exposure_observations"), ("advisory", "exposure_advisories")):
            row = self.db.execute(f"SELECT * FROM {table} WHERE hash=?", (content_hash,)).fetchone()
            if row:
                return {"kind": kind, "sha256": content_hash, "record": dict(row), "data": json.loads(row["data"])}
        return None

    def decisions(self):
        return {r["finding_id"]: dict(r) for r in self.db.execute(
            "SELECT * FROM exposure_decisions ORDER BY id")}

    def decide(self, finding_id, status, actor, evidence_ref, note="", effective_at=None):
        if status not in {"open", "owner_confirmed", "remediated", "false_positive", "accepted_risk"}:
            raise ValueError("unsupported decision status")
        if not actor.strip() or not evidence_ref.strip():
            raise ValueError("actor and evidence_ref are required")
        if not self.history(finding_id)["assessments"]:
            raise ValueError("unknown finding ID; assess first")
        now = stamp()
        effective = stamp(effective_at) if effective_at else now
        if effective > now:
            raise ValueError("decision cannot be effective in the future")
        self.db.execute("""INSERT INTO exposure_decisions
            (finding_id,recorded_at,effective_at,status,actor,evidence_ref,note) VALUES(?,?,?,?,?,?,?)""",
            (finding_id, now, effective, status, actor, evidence_ref, note))
        self.db.commit()

    def run(self, data):
        self.db.execute("INSERT INTO exposure_runs(recorded_at,data) VALUES(?,?)", (stamp(), encoded(data)))
        self.db.commit()

    def runs(self):
        return [{"recorded_at": r["recorded_at"], **json.loads(r["data"])} for r in self.db.execute(
            "SELECT * FROM exposure_runs ORDER BY id DESC LIMIT 20")]

    def source_revision(self, source_id):
        row = self.db.execute("SELECT revision FROM exposure_source_documents WHERE source_id=?", (source_id,)).fetchone()
        return row[0] if row else None

    def checkpoint_source(self, source_id, revision):
        self.db.execute("INSERT OR REPLACE INTO exposure_source_documents VALUES(?,?,?)", (source_id, revision, stamp()))
        self.db.commit()
