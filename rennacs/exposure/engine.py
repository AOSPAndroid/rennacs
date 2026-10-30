"""Offline correlation. Banner evidence can never confirm vulnerability or fixes."""
from copy import deepcopy

from ..matching import match_advisory
from .scope import age_hours, stamp
from .store import digest

LIMITATION = ("Passive service evidence does not prove vulnerability, missing patches, "
              "exploitability or remediation. Backports, editions, prerequisites and "
              "asset identity must be verified using authorized owner evidence.")

ALIASES = {
    "citrix netscaler": "netscaler adc", "citrix netscaler adc": "netscaler adc",
    "netscaler": "netscaler adc", "netscaler adc": "netscaler adc",
    "citrix netscaler gateway": "netscaler gateway", "netscaler gateway": "netscaler gateway",
}


def product(value):
    key = " ".join(value.casefold().split())
    return ALIASES.get(key, key)


def correlate(observation, advisory):
    translated = {"id": advisory["id"], "status": advisory.get("status"),
                  "affected": [{**row, "product": product(row["product"])} for row in advisory["affected"]]}
    # Reuse the repository's conservative product/range evaluator. Its legacy
    # `confirmed` field refers to ranges, so NEVER carry it into exposure results.
    match = match_advisory(product(observation["product"]), observation["version"], translated)
    if match:
        return ("version_match" if match["match_status"] == "affected" else "product_match_unknown",
                match["fixed_versions"])
    vulns = observation["raw"].get("vulns", {})
    if isinstance(vulns, (dict, list)) and advisory["id"] in vulns:
        return "provider_reported_unverified", []
    return None


def finding_id(engagement, ip, port, transport, cve, vendor):
    return digest([engagement, ip, port, transport, cve, vendor])[:24]


def decorate(row, decision, now):
    row = deepcopy(row)
    row["disclosure_age_hours"] = round(max(0, age_hours(row["published_at"], now)), 2)
    row["evidence_age_hours"] = round(max(0, age_hours(row["observed_at"], now)), 2)
    row["stale"] = row["evidence_age_hours"] > 72
    row["pre_disclosure_evidence"] = row["observed_at"] < row["published_at"]
    row["scope_expired"] = row["authorization"]["expires_at"] <= now
    row["status"] = decision["status"] if decision else "open"
    row["decision"] = decision
    row["confirmation"] = "owner_attestation" if row["status"] == "owner_confirmed" else "unconfirmed"
    row["disclosure_to_remediation_hours"] = None
    row["review_after_decision"] = bool(decision and row["observed_at"] > decision["effective_at"]
                                         and row["status"] in {"remediated", "false_positive"})
    if row["status"] == "remediated":
        elapsed = age_hours(row["published_at"], decision["effective_at"])
        row["disclosure_to_remediation_hours"] = round(elapsed, 2) if elapsed >= 0 else None
    # Triage order targets an actionable recent disclosure, not CVSS.
    score = (40 if row["disclosure_age_hours"] <= 72 else
             25 if row["disclosure_age_hours"] <= 168 else 10)
    score += 25 if not row["stale"] and not row["pre_disclosure_evidence"] else 0
    score += 20 if row["match_kind"] == "version_match" else 5
    score += 15 if row.get("fixed_versions") or row.get("remediations") else 0
    reasons = ["recent disclosure" if row["disclosure_age_hours"] <= 168 else "older disclosure",
               "stale evidence" if row["stale"] else "recent observation",
               "observation predates disclosure" if row["pre_disclosure_evidence"] else "post-disclosure observation",
               row["match_kind"]]
    if row["scope_expired"] or row["match_kind"] == "not_reproduced":
        score = 0
    if row["status"] in {"remediated", "false_positive", "accepted_risk"}:
        score = 0
    if row["review_after_decision"]:
        score = max(score, 50)
        reasons.append("new passive evidence after operator decision; revalidate")
    row["priority"] = score
    row["priority_reasons"] = reasons
    row["limitation"] = LIMITATION
    return row


def assess(store, scope, now=None):
    now = stamp(now)
    advisories = store.advisories()
    observations = []
    excluded = 0
    for obs in store.observations():
        try:
            authorization = scope.authorize(obs["ip"], now)
            if obs["authorization"]["engagement"] != scope.data["engagement"]:
                raise ValueError("other engagement")
        except ValueError:
            excluded += 1
            continue
        observations.append({**obs, "authorization": authorization})
    latest = {}
    for obs in observations:
        latest[(obs["ip"], obs["port"], obs["transport"])] = obs
    previous = {f["finding_id"]: f for f in store.latest()["findings"]}
    decisions = store.decisions()
    findings = []
    for (ip, port, transport), obs in latest.items():
        for advisory in advisories:
            fid = finding_id(scope.data["engagement"], ip, port, transport, advisory["id"], advisory["vendor"])
            match = correlate(obs, advisory)
            prior = previous.get(fid)
            if not match and not prior:
                continue
            kind, fixed = match or ("not_reproduced", [])
            supporting = [o for o in observations if (o["ip"], o["port"], o["transport"]) == (ip, port, transport)
                          and correlate(o, advisory)]
            post = [o["observed_at"] for o in supporting if o["observed_at"] >= advisory["published_at"]]
            row = {"finding_id": fid, "advisory_id": advisory["id"], "title": advisory.get("title", advisory["id"]),
                   "vendor": advisory["vendor"], "ip": ip, "port": port, "transport": transport,
                   "product": obs["product"], "version": obs["version"],
                   "published_at": advisory["published_at"], "date_basis": advisory.get("date_basis", "reviewed vendor disclosure"),
                   "source_url": advisory["source_url"], "advisory_revision": advisory["revision"],
                   "advisory_fetched_at": advisory["fetched_at"], "affected": advisory["affected"],
                   "range_evidence_ref": advisory.get("range_evidence_ref"), "reviewed_by": advisory.get("reviewed_by"),
                   "remediations": advisory.get("remediations", []), "fixed_versions": fixed,
                   "match_kind": kind, "observed_at": obs["observed_at"], "ingested_at": obs["ingested_at"],
                   "first_observed_at": min((o["observed_at"] for o in supporting), default=prior["first_observed_at"] if prior else obs["observed_at"]),
                   "first_post_disclosure_observed_at": min(post) if post else None,
                   "evidence_hash": obs["evidence_hash"], "authorization": obs["authorization"], "assessed_at": now}
            findings.append(decorate(row, decisions.get(fid), now))
    findings.sort(key=lambda f: (-f["priority"], f["published_at"], f["finding_id"]))
    summaries = [{k: a.get(k) for k in ("id", "title", "vendor", "published_at", "source_url", "revision", "fetched_at")}
                 | {"affected_count": len(a["affected"]), "requires_range_review": not bool(a.get("reviewed_by"))}
                 for a in advisories]
    result = {"assessed_at": now, "engagement": scope.data["engagement"], "findings": findings,
              "advisories": summaries, "excluded_observations": excluded,
              "coverage": {"advisories": len(advisories), "observations": len(observations), "services": len(latest)},
              "limitation": LIMITATION}
    store.record_assessment(result)
    return result


def report(store, filters=None, now=None):
    filters = filters or {}
    now = stamp(now)
    result = store.latest()
    decisions = store.decisions()
    rows = [decorate(f, decisions.get(f["finding_id"]), now) for f in result["findings"]]
    for name in ("vendor", "status", "match_kind", "ip", "advisory_id"):
        if filters.get(name):
            rows = [r for r in rows if r[name] == filters[name]]
    for field, key in (("max_disclosure_hours", "disclosure_age_hours"), ("max_evidence_hours", "evidence_age_hours")):
        if filters.get(field) not in (None, ""):
            value = float(filters[field])
            if not 0 <= value <= 1e8:
                raise ValueError("age filter must be between 0 and 100000000 hours")
            rows = [r for r in rows if r[key] <= value]
    rows.sort(key=lambda r: (-r["priority"], r["finding_id"]))
    return {**result, "findings": rows, "reported_at": now, "recent_runs": store.runs()}
