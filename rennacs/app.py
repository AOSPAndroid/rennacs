"""Flask web UI + JSON API — the Shodan-like front end.

Routes:
    GET /                     landing page with stats and example queries
    GET /search?q=...         results list (one row per service/banner)
    GET /host/<ip>            per-host detail page
    GET /api/search?q=...     JSON results
    GET /api/host/<ip>        JSON host document
    GET /api/stats            JSON index stats

The web layer is intentionally thin: it parses a query with :mod:`rennacs.query`,
hands the compiled WHERE clause to :mod:`rennacs.db`, and renders. All the "search
engine" logic lives in those modules.
"""

from __future__ import annotations

import os

from flask import Flask, jsonify, render_template, request

from .cvenow import CVENow
from .db import Index
from .query import QueryError, compile_query, describe

EXAMPLES = [
    ("port:22", "hosts with SSH open"),
    ("product:nginx", "fingerprinted as nginx"),
    ("port:443 has_ssl:true", "TLS services on 443"),
    ("has_vuln:true", "services with a suggested CVE"),
    ("kev:true", "CISA known-exploited (cve.now)"),
    ("net:192.168.1.0/24", "everything in a subnet"),
    ('org:"Google LLC"', "by organization"),
    ("vuln:CVE-2024-6387", "a specific CVE"),
]


def create_app(db_path: str | None = None) -> Flask:
    app = Flask(__name__)
    app.config["DB_PATH"] = db_path or os.environ.get("RENNACS_DB", "rennacs.db")

    def index() -> Index:
        # One connection per request keeps SQLite happy across Flask's threads.
        return Index(app.config["DB_PATH"])

    @app.route("/")
    def home():
        idx = index()
        cvenow = CVENow(app.config["DB_PATH"], offline=True)  # read cache only
        try:
            stats = idx.stats()
            feed = cvenow.latest(10)
            catalog = cvenow.catalog_stats()
            feed_at = cvenow.feed_fetched_at()
            jobs = idx.list_jobs(6)
        finally:
            idx.close()
            cvenow.close()
        return render_template("index.html", stats=stats, examples=EXAMPLES,
                               cve_feed=feed, catalog=catalog, feed_at=feed_at,
                               jobs=jobs)

    @app.route("/search")
    def search():
        q = request.args.get("q", "").strip()
        page = max(1, int(request.args.get("page", 1) or 1))
        per = 25
        idx = index()
        error = None
        rows: list = []
        total = 0
        try:
            where, params = compile_query(q)
            rows, total = idx.search(where, params, limit=per, offset=(page - 1) * per)
        except QueryError as e:
            error = str(e)
        finally:
            idx.close()
        pages = (total + per - 1) // per if total else 0
        return render_template(
            "results.html", q=q, rows=rows, total=total, page=page, pages=pages,
            error=error, examples=EXAMPLES,
        )

    @app.route("/map")
    def map_view():
        q = request.args.get("q", "").strip()
        idx = index()
        error = None
        data = {"located": [], "ungeolocated": [], "countries": []}
        try:
            where, params = compile_query(q)
            data = idx.map_points(where, params)
        except QueryError as e:
            error = str(e)
        finally:
            idx.close()
        return render_template("map.html", data=data, q=q, error=error)

    @app.route("/host/<ip>")
    def host(ip: str):
        idx = index()
        try:
            doc = idx.host(ip)
        finally:
            idx.close()
        if not doc:
            return render_template("host.html", doc=None, ip=ip), 404
        return render_template("host.html", doc=doc, ip=ip)

    # -- JSON API ---------------------------------------------------------------

    @app.route("/findings")
    def findings_view():
        from .findings import report

        q = request.args.get("q", "").strip()
        data, error = {"matches": [], "total": 0}, None
        idx = index()
        try:
            page = int(request.args.get("page", "1"))
            if page < 1:
                raise ValueError("page must be positive")
            data = report(idx, q, limit=25, offset=(page - 1) * 25)
        except (ValueError, QueryError) as exc:
            page, error = 1, str(exc)
        finally:
            idx.close()
        return render_template("findings.html", q=q, data=data, error=error, page=page)

    @app.get("/api/catalog")
    def api_catalog():
        """Local coverage metadata only; no web-triggered catalog acquisition."""
        idx = index()
        try:
            return jsonify(idx.catalog.status())
        finally:
            idx.close()

    @app.route("/api/findings")
    def api_findings():
        from .findings import report

        try:
            limit = int(request.args.get("limit", "100"))
            offset = int(request.args.get("offset", "0"))
            if not 1 <= limit <= 1000 or offset < 0:
                raise ValueError("limit must be 1..1000 and offset nonnegative")
            idx = index()
            try:
                data = report(idx, request.args.get("q", ""), limit=limit, offset=offset)
            finally:
                idx.close()
        except (ValueError, QueryError) as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(data)

    @app.route("/api/search")
    def api_search():
        q = request.args.get("q", "").strip()
        try:
            limit = min(1000, int(request.args.get("limit", 100) or 100))
            offset = max(0, int(request.args.get("offset", 0) or 0))
            where, params = compile_query(q)
        except QueryError as e:
            return jsonify(error=str(e)), 400
        idx = index()
        try:
            rows, total = idx.search(where, params, limit=limit, offset=offset)
        finally:
            idx.close()
        return jsonify(query=q, total=total, count=len(rows), matches=rows)

    @app.route("/api/host/<ip>/history")
    def api_host_history(ip: str):
        try:
            limit = int(request.args.get("limit", "100"))
            offset = int(request.args.get("offset", "0"))
            if not 1 <= limit <= 1000 or offset < 0:
                raise ValueError("limit must be 1..1000 and offset nonnegative")
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        idx = index()
        try:
            if idx.host(ip) is None:
                return jsonify(error="not found", ip=ip), 404
            events = idx.service_history(ip, limit=limit, offset=offset)
        finally:
            idx.close()
        return jsonify(ip=ip, count=len(events), offset=offset, events=events)

    @app.route("/api/host/<ip>")
    def api_host(ip: str):
        idx = index()
        try:
            doc = idx.host(ip)
        finally:
            idx.close()
        if not doc:
            return jsonify(error="not found", ip=ip), 404
        return jsonify(doc)

    @app.route("/api/map")
    def api_map():
        q = request.args.get("q", "").strip()
        try:
            where, params = compile_query(q)
        except QueryError as e:
            return jsonify(error=str(e)), 400
        idx = index()
        try:
            return jsonify(idx.map_points(where, params))
        finally:
            idx.close()

    @app.route("/api/cve/<cve>")
    def api_cve(cve: str):
        # Cache-first; the web layer never blocks on the network for a page view.
        cvenow = CVENow(app.config["DB_PATH"], offline=True)
        try:
            entry = cvenow.entry(cve, allow_network=False)
        finally:
            cvenow.close()
        if not entry:
            return jsonify(error="not cached; run 'cli.py enrich'", cve=cve), 404
        return jsonify(entry)

    @app.route("/api/cve-feed")
    def api_cve_feed():
        cvenow = CVENow(app.config["DB_PATH"], offline=True)
        try:
            return jsonify(items=cvenow.latest(30), fetched_at=cvenow.feed_fetched_at(),
                           catalog=cvenow.catalog_stats())
        finally:
            cvenow.close()

    @app.route("/api/jobs")
    def api_jobs():
        idx = index()
        try:
            return jsonify(jobs=idx.list_jobs(50))
        finally:
            idx.close()

    @app.route("/api/stats")
    def api_stats():
        idx = index()
        try:
            return jsonify(idx.stats())
        finally:
            idx.close()

    @app.route("/api/filters")
    def api_filters():
        return jsonify(describe())

    return app
