"""Read-only local review surfaces. No acquisition or mutation on page views."""
from flask import Blueprint, Response, current_app, jsonify, render_template, request

from .cli import csv_export
from .engine import report
from .store import Store

bp = Blueprint("exposure", __name__)


@bp.get("/exposure", endpoint="page")
@bp.get("/api/exposure", endpoint="api")
@bp.get("/api/exposure/export.csv", endpoint="export")
def review():
    try:
        with Store(current_app.config["DB_PATH"]) as store:
            data = report(store, request.args)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    if request.path.endswith(".csv"):
        return Response(csv_export(data), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=exposure-findings.csv",
                                 "Cache-Control": "no-store"})
    if request.path.startswith("/api/"):
        return jsonify(data)
    return render_template("exposure.html", data=data)


@bp.get("/api/exposure/<finding_id>/history")
def history(finding_id):
    with Store(current_app.config["DB_PATH"]) as store:
        return jsonify(store.history(finding_id))


@bp.get("/api/exposure/evidence/<sha256>")
def evidence(sha256):
    with Store(current_app.config["DB_PATH"]) as store:
        data = store.evidence(sha256)
    return (jsonify(data), 200) if data else (jsonify(error="evidence not found"), 404)
