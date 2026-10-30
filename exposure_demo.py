#!/usr/bin/env python3
"""Create a synthetic passive-tracker demo. No network requests or real targets."""
import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

from rennacs.exposure.engine import assess
from rennacs.exposure.scope import Scope
from rennacs.exposure.sources import observation, validate_advisory
from rennacs.exposure.store import Store


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="exposure-demo.db")
    args = parser.parse_args()
    if Path(args.db).exists():
        parser.error("demo database already exists; choose a new --db path")
    now = datetime.now(timezone.utc)
    scope = Scope({"engagement": "SYNTHETIC-DEMO-NO-REAL-ASSETS", "networks": [{
        "cidr": "192.0.2.0/24", "authorization_ref": "synthetic documentation addresses only",
        "expires_at": (now + timedelta(days=7)).isoformat()}]})
    advisory = validate_advisory({"id": "CVE-2099-9999999", "vendor": "citrix",
        "title": "SYNTHETIC DEMO — not a real vulnerability",
        "source_url": "https://support.citrix.com/", "published_at": (now - timedelta(hours=20)).isoformat(),
        "date_basis": "synthetic example, not a vendor disclosure",
        "reviewed_by": "synthetic fixture", "range_evidence_ref": "synthetic rule; not vendor guidance",
        "affected": [{"product": "NetScaler ADC", "ranges": [{"introduced": "14.1.0", "fixed": "14.1.50"}]}]})
    with Store(args.db) as store:
        store.advisory(advisory)
        for ip, version, hours in [("192.0.2.10", "14.1.40", 1), ("192.0.2.11", "14.1-40.1", 96)]:
            store.observation(observation({"ip_str": ip, "port": 443, "transport": "tcp",
                "product": "Citrix NetScaler", "version": version,
                "timestamp": (now - timedelta(hours=hours)).isoformat(),
                "data": "SYNTHETIC fixture; not a real Shodan observation"}, scope))
        result = assess(store, scope)
    print(f"Created {args.db}: {len(result['findings'])} synthetic findings. No network access.")
    print(f"Review: python cli.py --db {args.db} web")
    print("Then open http://127.0.0.1:5000/exposure")


if __name__ == "__main__":
    main()
