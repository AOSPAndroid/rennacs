# Passive disclosure-to-remediation tracker

This extends Rennacs's CLI, Flask app, SQLite database and conservative matcher.
It is a **single-engagement local prototype**, not a production SaaS or a claim
that an externally visible system is vulnerable. The `exposure` commands never
call Rennacs's scanners, connect to target services, submit Shodan scans, or make
global Shodan searches. The existing `scan`/`sweep` commands are separate tools;
their older authorization policy does not grant access to this workflow.

## Run the working demo

```bash
python -m pip install -r requirements-dev.txt
python exposure_demo.py
python cli.py --db exposure-demo.db web
# http://127.0.0.1:5000/exposure
```

The demo is entirely synthetic: documentation IPs, a fabricated CVE ID, fake
banner evidence and fake version rules. It performs no network requests and
refuses to overwrite an existing database. The second finding illustrates a stale,
pre-disclosure observation with an unsupported NetScaler build syntax.

## Configure an actual engagement

Use **one separate database per engagement/customer**. Keep the database, WAL,
scope, imports and exports out of Git and restrict local filesystem access.
On POSIX set `umask 077` before creating files; on Windows use restrictive ACLs.
The database contains service evidence and authorization references in plaintext.

Copy `examples/exposure-scope.example.json` to `scope.json`. It intentionally
contains no authorized networks and refuses acquisition until completed. Each
entry needs an exact CIDR, an authorization reference and an expiry timestamp:

```json
{
  "engagement": "SIGNED-ENGAGEMENT-IDENTIFIER",
  "networks": [{
    "cidr": "192.0.2.10/32",
    "authorization_ref": "CONTRACT-OR-OWNERSHIP-RECORD",
    "expires_at": "2026-12-01T00:00:00Z"
  }]
}
```

Replace the documentation address with infrastructure actually covered by that
authorization. The tracker does not infer authority from a company name,
employer, ASN, hostname, private address, existing Rennacs inventory or Shodan
visibility. Hostnames are not resolved. Networks broader than IPv4 /16 or IPv6
/48 are rejected. Collection takes **explicit individual IPs**, at most 256 per
batch; it does not expand CIDRs. Expired scope fails closed. An offline assessment
rechecks current scope and excludes prior observations from another engagement.
Scope changes require a new assessment; reports remain historical snapshots.

Set `SHODAN_API_KEY` through your process environment or secret manager. Do not
paste it into commands with literal values, repository files, screenshots or PRs.
`.env.example` is a template; this application does **not** automatically load it.
For example, inject the environment using your preferred credential manager, then:

```bash
python cli.py exposure account
```

This calls Shodan `/api-info` and prints only plan/credit fields. Membership alone
does not prove specific current quotas or host-history entitlement. This build
does not provision Shodan Monitor alerts or use scan credits. Existing Terminal
or Monitor-derived banner exports can be imported if they use the documented
Shodan banner JSON shape. Do not enable active testing through other tools unless
your engagement explicitly authorizes it.

## Workflow

Root `--db` comes **before** `exposure` in every command.

1. Ingest official vendor publications. Microsoft has a built-in, live-verified
   CVRF adapter. It fetches the MSRC update list plus at most `--limit` monthly
   documents, choosing the most recently revised documents since `--since` whose
   source revision has not been ingested. Successful document revisions are
   checkpointed; repeat the command to drain the remaining queue. Failed documents
   are retried. Remaining documents and index pagination are reported; a bounded
   batch is not complete coverage.

   ```bash
   python cli.py --db customer.db exposure sync --vendor microsoft --since 2026-10-01 --limit 2
   ```

   CVE revision history supplies the earliest available vulnerability publication
   date, **not** the monthly document's date or the fetch date. MSRC timestamps
   lacking a timezone are interpreted as UTC and explicitly labelled as such.
   Known-affected product IDs/names, individual revision dates and remediation/KB
   records are preserved with raw vendor evidence. Windows edition/KB inventory
   cannot be inferred from an IIS banner, so there is no automatic IIS → Windows
   vulnerability mapping. No Microsoft API credential is needed for this adapter.

   Citrix/NetScaler and Aruba support official-domain RSS/Atom ingestion using
   `--vendor citrix|aruba --url OFFICIAL_FEED_URL`. There is **no bundled verified
   Citrix/Aruba feed URL**, no automatic bulletin-page scraping and no claim of
   complete feed coverage. Supply an official feed that has original publication
   dates and CVE IDs in its entries. Feeds with only update dates fail rather than
   inventing a disclosure date. Feed publication can differ from original vendor
   disclosure; this provenance is labelled and must be reviewed.

2. Review source applicability and affected versions. Import normalized advisory
   JSON when the vendor feed has prose-only ranges or when a bulletin needs
   explicit product/version rules. All imports preserve full records as revisions.
   An import file is an array of records with this shape:

   ```json
   [{
     "id": "CVE-2099-9999999",
     "vendor": "citrix",
     "title": "SYNTHETIC SCHEMA EXAMPLE — not a real bulletin",
     "published_at": "2026-10-29T10:00:00Z",
     "source_url": "https://support.citrix.com/",
     "reviewed_by": "reviewer identity",
     "range_evidence_ref": "bulletin revision / affected-table row / retained evidence",
     "affected": [{
       "product": "NetScaler ADC",
       "ranges": [{"introduced": "14.1.0", "fixed": "14.1.50"}]
     }],
     "affected_text": "Retain configuration prerequisites and original build syntax here"
   }]
   ```

   This is synthetic schema documentation, not real patch advice. Replace it with
   reviewed vendor records, including configuration/platform prerequisites.
   Machine-matchable ranges/exact versions require a reviewer and evidence ref.
   Use separate records for different product editions and branches. Matching
   reuses Rennacs's numeric/OpenSSH evaluator: inclusive `introduced` and
   `lastAffected`, exclusive `fixed`, exact `versions`, conservative unsupported
   schemes. **NetScaler strings such as `14.1-40.1` stay unknown**; do not remove
   punctuation or infer branch ordering to force a match. Range applicability does
   not verify configuration prerequisites, backports, firmware bundles or patches.

   ```bash
   python cli.py --db customer.db exposure advisories reviewed-advisories.local.json
   ```

3. Collect passive evidence via Shodan host lookups, or import existing exports.
   All requested IPs are checked before the first API request. Responses and each
   imported banner are checked again; a mixed-scope import is rejected before any
   records from that batch are stored. No credentials are sent to asset addresses.

   ```bash
   python cli.py --db customer.db exposure collect --scope scope.json YOUR_AUTHORIZED_IP
   # Optional, subject to your Shodan entitlement:
   python cli.py --db customer.db exposure collect --scope scope.json --history YOUR_AUTHORIZED_IP
   python cli.py --db customer.db exposure import evidence/shodan-export.json.gz --scope scope.json
   ```

   Imports accept Shodan NDJSON, gzip NDJSON, banner arrays, a single banner,
   `{ "matches": [...] }`, or `{ "data": [...] }` host responses. Each banner must
   contain `ip_str`, `port`, `timestamp`, and optional `product`, `version`,
   `transport`, `vulns`. UTC is assumed for Shodan's timezone-omitted timestamps.
   Observation time comes from **each banner**, never the host `last_update` field
   or local ingestion time. Identical records are deduplicated; changed timestamps
   or content create separate evidence. Missing/404/empty responses and disappearing
   services do not establish remediation. Exports are capped at 16 MiB uncompressed
   and 10,000 banners; split larger files. API fetches are spaced at least one second
   apart with 15-second socket timeouts, no redirects and bounded response bodies.
   Failed/partial collection returns a nonzero exit status and recorded errors.

4. Assess locally and review at `/exposure`:

   ```bash
   python cli.py --db customer.db exposure assess --scope scope.json
   python cli.py --db customer.db web
   ```

   Browser views and exports are offline. Review filters include vendor, CVE, IP,
   status, match kind, disclosure age and evidence age. Acquisition runs, source
   revisions, raw observations, timestamps and hashes are inspectable. Prior
   assessments survive restart. Scope expiry and evidence age are recalculated
   at report time; applicability only changes on explicit reassessment.

5. Append owner-backed decisions. Copy the stable finding ID from the report:

   ```bash
   python cli.py --db customer.db exposure decision FINDING_ID --status owner_confirmed --actor OWNER_ID --evidence-ref INVENTORY_OR_ASSESSMENT_REFERENCE
   python cli.py --db customer.db exposure decision FINDING_ID --status remediated --actor OWNER_ID --evidence-ref CHANGE_RECORD --effective-at 2026-10-30T16:00:00Z
   python cli.py --db customer.db exposure history FINDING_ID
   python cli.py --db customer.db exposure evidence SHA256_HASH
   ```

   Other statuses: `open`, `false_positive`, `accepted_risk`. Confirmation means
   **an explicit owner attestation**, not an independent technical verification by
   this application. An actor and evidence reference are mandatory; reference
   contents are not automatically retrieved or validated. Decisions are appended,
   not substituted into old assessment snapshots. New observations after a closed
   decision prompt review; a passive observation cannot silently clear a finding.

6. Export audit findings:

   ```bash
   mkdir -p exports
   python cli.py --db customer.db exposure report --max-disclosure-hours 168 --max-evidence-hours 72 > exports/findings.json
   python cli.py --db customer.db exposure report --vendor citrix --format csv > exports/findings.csv
   ```

   JSON carries rule evidence, timestamps, limitations and operator decisions.
   CSV carries identifiers, match/confirmation states, ages, evidence hashes and
   disclosure-to-remediation measurements, and neutralizes spreadsheet formulas.
   Export raw observations/advisory revisions separately with `exposure evidence`
   when an audit requires the underlying records. Treat exports as customer data.

## Triage semantics

| Field | Meaning |
|---|---|
| `version_match` | Banner version falls in a reviewed supported range; asset vulnerability unconfirmed |
| `product_match_unknown` | Product identity matches; version/range membership remains unknown |
| `provider_reported_unverified` | Shodan associates this CVE with the banner; the tracker has not verified it |
| `not_reproduced` | A prior finding is absent from the latest service evidence; no automatic remediation |
| `owner_confirmed` | Explicit operator-recorded owner attestation with evidence reference |
| `stale` | Latest service observation is over 72 hours old |
| `pre_disclosure_evidence` | Latest service observation predates the recorded disclosure |
| `disclosure_to_remediation_hours` | Owner-attested remediation time minus disclosure date; null until recorded |

The displayed priority is a transparent **triage score**, not a calibrated exploit
probability: recent disclosure (40/25/10 points for ≤72/≤168/>168 hours), fresh
post-disclosure observation (25), supported version match (20; other matches 5),
and explicit fix/remediation guidance (15). CVSS is not used. Closed decisions,
expired scope and non-reproduced matches score zero; new observations after closed
decisions receive a revalidation flag. The disclosure-to-remediation measure is
not proof the system was vulnerable throughout that interval. First observed
exposure and first post-disclosure observation are separate fields.

## Repeated operation and commercial development

The workflow is repeatable: sync overlapping vendor windows, collect/import scoped
evidence, assess, then export. No schedule, global inventory search, alert
subscription, outbound sales message, background scan or hosted service is enabled
by this change. Use a local scheduler only after providing the actual scope and
credentials. Failed sources remain visible in acquisition run history. Repeated
MSRC batches resume pending document revisions; increase the document budget
or choose a cutoff appropriate to your coverage. There is no all-vendor coverage,
update-index pagination or automatic HTML/CVSS/KEV ingestion in this prototype.

SQLite evidence/revisions and decisions are append-only **through the application**,
with SHA-256 content references. They are not signed, WORM storage, or tamper-proof
against a database administrator. Storage/retention is operator-managed. Keep the
Flask server on its default localhost binding and debug off; it has no customer
authentication or role isolation. Before commercial hosting, add authenticated
engagement access, tenant isolation, encryption/key management, retention and
deletion policy, reviewed vendor feed adapters and build comparators, entitlement
and data-redistribution review, source health alerts, and authorized owner-inventory
verification. This implementation does not establish redistribution rights over
Shodan/vendor data or replace the assessment authorization contract.

Official integration references:

- [Shodan API](https://developer.shodan.io/api): `/api-info`, `/shodan/host/{ip}`;
  [Terminal exports](https://help.shodan.io/guides/how-to-download-data-with-api).
- [Microsoft MSRC API source and schema](https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API),
  [live update index](https://api.msrc.microsoft.com/cvrf/v3.0/updates).

## Validation

```bash
python -m pytest -q
```

Tests use mocked APIs and synthetic evidence. They cover scope/expiry/revocation,
uncertain versions, stale/pre-disclosure evidence, safe exports, credential
redaction, vendor publication parsing, request budgets, deduplication, provenance,
append-only history, operator remediation and offline UI/API behavior. Live MSRC
index/document parsing was also checked during implementation; Shodan account and
host endpoints require a configured key for live validation.
