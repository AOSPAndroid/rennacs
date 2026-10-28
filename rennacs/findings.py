"""Evidence-backed, explicitly unverified service-level assessment reports.

Advisory enrichment/version ranges describe a CVE, not proof about a host. This
module performs no network requests, exploit checks or system changes.
"""
from __future__ import annotations

import hashlib
import re

_CVE = re.compile(r"CVE-\d{4}-\d{4,}\Z", re.ASCII)


def assess_service(row: dict) -> dict:
    """Produce one stable assessment per observed service with reported CVEs."""
    ip, port = row["ip"], row["port"]
    transport = row.get("transport") or "tcp"
    identity = f"{ip}|{port}|{transport}".encode("utf-8")
    advisories = []
    for vuln in row.get("vulns") or []:
        if not isinstance(vuln, dict):
            continue
        cve = vuln.get("cve", "")
        if not isinstance(cve, str) or not _CVE.fullmatch(cve):
            continue
        advisories.append({
            "cve": cve,
            "severity": vuln.get("severity", "unknown"),
            "summary": str(vuln.get("summary") or "")[:2000],
            "cvss": vuln.get("cvss"),
            "known_exploited_catalog": bool(vuln.get("kev")),
            "reference": f"https://www.cve.org/CVERecord?id={cve}",
            "metadata_enriched": bool(vuln.get("enriched")),
            # Historical 'confirmed' means only version-range membership.
            "version_range_match": vuln.get("confirmed", "unknown"),
        })
    return {
        "id": hashlib.sha256(identity).hexdigest()[:24],
        "ip": ip,
        "port": port,
        "transport": transport,
        "assessment": {
            "status": "potential",
            "confidence": "low",
            "method": "reported_product_version_cve_correlation",
            "exploit_tested": False,
            "limitations": [
                "A reported version or imported CVE is not proof of vulnerability.",
                "Distribution backports, platform and configuration are not verified.",
                "KEV identifies exploitation of a CVE elsewhere, not this host.",
            ],
        },
        "evidence": {
            "observed_at": row.get("seen_at"),
            "product": row.get("product") or "",
            "version": row.get("version") or "",
            "service": row.get("service") or "",
            "ssl_cn": row.get("ssl_cn") or "",
            "banner_sha256": hashlib.sha256(
                (row.get("banner") or "").encode("utf-8")
            ).hexdigest(),
        },
        "advisories": advisories,
        "remediation": {
            "owner_approval_required": True,
            "automatic_changes": False,
            "steps": [
                "Verify asset control, installed package/build and applicable vendor advisory.",
                "Check distribution backports and the advisory's configuration prerequisites.",
                "With owner approval, back up and apply the vendor-supported fix or mitigation.",
                "Retest the affected condition; a changed banner alone does not prove a fix.",
            ],
        },
    }


def report(index, query: str = "", *, limit: int = 100, offset: int = 0) -> dict:
    """Paginate service assessments, not individual CVEs; cache/local DB only."""
    from .query import compile_query

    if not 1 <= limit <= 1000 or offset < 0:
        raise ValueError("limit must be 1..1000 and offset nonnegative")
    where, params = compile_query(query)
    rows, total = index.search(f"({where}) AND s.vuln_ids<>''", params,
                               limit=limit, offset=offset)
    matches = [assess_service(row) for row in rows]
    return {
        "query": query, "unit": "service_assessments", "total": total,
        "count": len(matches), "offset": offset, "matches": matches,
        "notice": "Potential findings only; no exploit verification or remediation performed.",
    }
