"""CLI entry points; all network acquisition is explicit and budgeted."""
import csv
import io
import ipaddress
import json
import sys

from .engine import assess, report
from .scope import Scope
from .sources import (CAP, Remote, Shodan, VENDOR_HOSTS, import_shodan,
                      observation, parse_feed, sync_microsoft, validate_advisory)
from .store import Store

CSV_FIELDS = ["finding_id", "advisory_id", "vendor", "ip", "port", "transport", "product", "version",
              "status", "confirmation", "match_kind", "priority", "published_at", "observed_at",
              "ingested_at", "assessed_at", "disclosure_age_hours", "evidence_age_hours", "stale",
              "pre_disclosure_evidence", "scope_expired", "review_after_decision",
              "disclosure_to_remediation_hours", "source_url", "evidence_hash", "limitation"]


def csv_export(data):
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for row in data["findings"]:
        # Protect spreadsheet consumers from formula injection in external strings.
        writer.writerow({k: ("'" + v if isinstance(v, str) and v.lstrip().startswith(("=", "+", "-", "@")) else v)
                         for k, v in row.items() if k in CSV_FIELDS})
    return output.getvalue()


def run(args):
    try:
        cmd = args.exposure_cmd
        if cmd == "account":
            print(json.dumps(Shodan().capabilities(), indent=2))
            return 0
        with Store(args.db) as store:
            if cmd == "advisories":
                with open(args.file, "rb") as f:
                    body = f.read(CAP + 1)
                if len(body) > CAP:
                    raise ValueError("advisory import exceeds 16 MiB")
                rows = json.loads(body)
                if not isinstance(rows, list) or len(rows) > 10000:
                    raise ValueError("advisory import must be a list of at most 10000 records")
                rows = [validate_advisory(row) for row in rows]
                for row in rows:
                    store.advisory(row)
                result = {"advisories_imported": len(rows)}
            elif cmd == "sync":
                if args.vendor == "microsoft":
                    if args.url:
                        raise ValueError("Microsoft uses the built-in MSRC CVRF adapter; omit --url")
                    result = sync_microsoft(store, args.since, args.limit)
                else:
                    if not args.url:
                        raise ValueError("provide the vendor's official RSS/Atom URL with --url")
                    rows = parse_feed(Remote().get(args.url, VENDOR_HOSTS[args.vendor], json_body=False),
                                      args.vendor, args.url)
                    for row in rows:
                        store.advisory(row)
                    result = {"advisories_imported": len(rows), "coverage": "one RSS/Atom response; ranges require review"}
                store.run({"kind": "vendor_sync", "vendor": args.vendor, **result})
            elif cmd == "import":
                result = {"observations_imported": import_shodan(args.file, Scope.load(args.scope), store)}
            elif cmd == "collect":
                scope = Scope.load(args.scope)
                ips = list(dict.fromkeys(str(ipaddress.ip_address(ip)) for ip in args.ips))
                if not 1 <= len(ips) <= args.max_hosts <= 256:
                    raise ValueError("provide 1..max-hosts explicit IPs; max-hosts cannot exceed 256")
                for ip in ips:
                    scope.authorize(ip)  # validate ALL targets before any API request
                shodan = Shodan()
                result = {"hosts_requested": len(ips), "observations_imported": 0, "errors": []}
                for ip in ips:
                    try:
                        raw = shodan.host(ip, scope, args.history)
                        banners = raw.get("data")
                        if not isinstance(banners, list) or len(banners) > 10000:
                            raise ValueError("unexpected Shodan host response")
                        rows = [observation(b, scope) for b in banners]
                        if any(row["ip"] != ip for row in rows):
                            raise ValueError("host response contains a different address")
                        result["observations_imported"] += sum(store.observation(row) for row in rows)
                    except (ValueError, KeyError, TypeError) as exc:
                        result["errors"].append({"ip": ip, "error": str(exc)})
                store.run({"kind": "shodan_collect", **result})
            elif cmd == "assess":
                result = assess(store, Scope.load(args.scope))
            elif cmd == "decision":
                store.decide(args.finding_id, args.status, args.actor, args.evidence_ref,
                             args.note, args.effective_at)
                result = {"decision_recorded": args.finding_id, "status": args.status}
            elif cmd == "history":
                result = store.history(args.finding_id)
            elif cmd == "evidence":
                result = store.evidence(args.sha256)
                if result is None:
                    raise ValueError("evidence hash not found")
            else:
                filters = {k: getattr(args, k, None) for k in (
                    "vendor", "status", "match_kind", "ip", "advisory_id", "max_disclosure_hours", "max_evidence_hours")}
                result = report(store, filters)
                if args.format == "csv":
                    print(csv_export(result), end="")
                    return 0
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 1 if result.get("errors") else 0
    except (OSError, ValueError, TypeError, KeyError) as exc:
        if args.exposure_cmd in {"sync", "collect", "import"}:
            with Store(args.db) as store:
                store.run({"kind": args.exposure_cmd, "status": "failed", "error": str(exc)})
        print(f"exposure: {exc}", file=sys.stderr)
        return 2


def register(sub):
    p = sub.add_parser("exposure", help="explicitly scoped passive disclosure-to-remediation tracker")
    commands = p.add_subparsers(dest="exposure_cmd", required=True)
    p = commands.add_parser("account", help="read Shodan API entitlements; no scanning")
    p.set_defaults(func=run)
    p = commands.add_parser("advisories", help="import reviewed normalized vendor advisories")
    p.add_argument("file")
    p.set_defaults(func=run)
    p = commands.add_parser("sync", help="ingest vendor publications with a bounded request budget")
    p.add_argument("--vendor", choices=sorted(VENDOR_HOSTS), required=True)
    p.add_argument("--since", default="2026-01-01", help="MSRC monthly update cutoff (YYYY-MM-DD)")
    p.add_argument("--limit", type=int, default=2, help="MSRC monthly document budget (1..12)")
    p.add_argument("--url", help="official RSS/Atom URL for Citrix or Aruba")
    p.set_defaults(func=run)
    p = commands.add_parser("import", help="import scoped Shodan JSON/NDJSON/JSON.gz exports")
    p.add_argument("file")
    p.add_argument("--scope", required=True)
    p.set_defaults(func=run)
    p = commands.add_parser("collect", help="passive Shodan host database lookups for explicit IPs")
    p.add_argument("ips", nargs="+")
    p.add_argument("--scope", required=True)
    p.add_argument("--max-hosts", type=int, default=32)
    p.add_argument("--history", action="store_true", help="request available Shodan history; plan dependent")
    p.set_defaults(func=run)
    p = commands.add_parser("assess", help="correlate local authorized evidence without networking")
    p.add_argument("--scope", required=True)
    p.set_defaults(func=run)
    p = commands.add_parser("decision", help="append an owner/evidence-backed decision")
    p.add_argument("finding_id")
    p.add_argument("--status", required=True, choices=["open", "owner_confirmed", "remediated", "false_positive", "accepted_risk"])
    p.add_argument("--actor", required=True)
    p.add_argument("--evidence-ref", required=True)
    p.add_argument("--note", default="")
    p.add_argument("--effective-at")
    p.set_defaults(func=run)
    p = commands.add_parser("history", help="assessment and decision history")
    p.add_argument("finding_id")
    p.set_defaults(func=run)
    p = commands.add_parser("evidence", help="export immutable local evidence by SHA-256")
    p.add_argument("sha256")
    p.set_defaults(func=run)
    p = commands.add_parser("report", help="filter or export last offline assessment")
    p.add_argument("--format", choices=["json", "csv"], default="json")
    for key in ("vendor", "status", "match-kind", "ip", "advisory-id"):
        p.add_argument("--" + key)
    p.add_argument("--max-disclosure-hours", type=float)
    p.add_argument("--max-evidence-hours", type=float)
    p.set_defaults(func=run)
