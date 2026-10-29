# Local advisory catalog

The catalog caches cve.now advisory **details** in SQLite and correlates them with
recorded service product/version evidence offline. It is separate from the recent
critical/KEV homepage feed and the legacy `enrich` metadata cache. Feed counts and
source aggregate counts do not establish local catalog coverage.

This adds potential advisory detection, not exploit verification, asset ownership
verification, a production service, or any change to scan scope or authorization.
No catalog operation probes observed hosts. Only explicit `catalog sync` and
`catalog fetch` commands contact cve.now; page views, status, reports and reassessment
use local data. No HTTP endpoint starts a sync or reassessment.

## Commands

Run from the checkout; the root `--db` option goes **before** the command. All four
subcommands accept `--json`, which writes one JSON object to stdout.

```bash
# Offline: inspect this database, not the source's aggregate statistics.
python cli.py --db rennacs.db catalog status --json

# Explicit network access: a bounded first batch, not a full download.
python cli.py --db rennacs.db catalog sync --max-pages 1 --max-requests 50 --rate 1 --json

# Resume saved pending details/cursor with another independently bounded batch.
python cli.py --db rennacs.db catalog sync --max-pages 2 --max-requests 100 --rate 1 --json

# Explicit network access: exact advisory IDs; casing is preserved.
python cli.py --db rennacs.db catalog fetch CVE-2024-6387 GHSA-4MFG-R38W-W8FG --max-requests 50 --rate 1 --json

# Resume only the pending targeted-detail queue without re-enqueuing fetched IDs.
python cli.py --db rennacs.db catalog fetch --max-requests 50 --rate 1 --json

# Offline: reassess at most 1000 already-recorded services.
python cli.py --db rennacs.db catalog assess --json
python cli.py --db rennacs.db catalog assess 'product:OpenSSH' --limit 100 --after-id 0 --json

# Read local results; these commands do not sync or reassess.
python cli.py --db rennacs.db findings 'product:OpenSSH' --json
python cli.py --db rennacs.db web
```

| Operation | Defaults and validation |
| --- | --- |
| `status` | Offline; no network options. An empty database is not complete coverage. |
| `sync` | `--max-pages 1`, `--max-requests 50`, `--rate 1`, `--restart` off. Page/request budgets must be positive integers; rate must be finite and positive. |
| `fetch [IDs ...]` | `--max-requests 50`, `--rate 1`, with the same request/rate validation. All IDs are validated before any request. Omit IDs to drain the durable targeted queue; repeating IDs deliberately queues a refresh. |
| `assess [query]` | Empty query selects all recorded services; `--limit 1000` (valid range 1..10000), `--after-id 0` (nonnegative integer). Offline; the normal service query language applies. |

IDs must be exact accepted ASCII CVE/GHSA/year-number source tokens. Spaces,
trailing newlines, URL/path fragments and malformed tokens are rejected, not
trimmed, uppercased or otherwise repaired. Format acceptance is not proof that an
ID exists upstream. Numeric and ID validation happens before outbound requests.

Exit codes: **0** for a successful local operation or budget-limited batch,
**2** for invalid input, **1** for a failed network/response batch, **130** for
interruption. Exit 0 does **not** mean the catalog or reassessment pass is complete.
Inspect the JSON progress fields. Connections close on success, handled failure
and interruption. Unexpected programming errors are not silently converted into
successful partial results.

## Sync, budgets and recovery

Sync walks the unfiltered `/api/v1/entries` list using its opaque `nextCursor` and
fetches individual `/api/v1/entries/<id>` details. A list summary is not stored as
an advisory detail. A validated page queues **all** of its IDs durably before
budgeted detail requests; pending catalog details are retried before new pages.
The rate covers list and detail requests, including failures, within one Catalog
instance. It is not a global limiter across concurrent processes.

`--max-pages` bounds newly fetched list pages in that invocation, not pending-detail
work. `--max-requests` bounds both list and detail requests. A small request budget
can leave an entire page's details pending. Each invocation is separately bounded;
there is no automatic unbounded loop, scheduler or background download.

Sync JSON includes `requests`, `pages`, `stored`, `stop_reason`, `complete`,
`last_error` and nested `status`. `stored` is successful detail upserts in this
batch, not necessarily distinct new IDs. Stops include `request_budget`,
`page_budget`, `complete` and `error`; targeted fetch uses `ids_complete` for an
exhausted targeted queue. Targeted queue exhaustion is not full catalog coverage.

Status includes `source`, `stored_details`, `pending_details`,
`pending_catalog_details`, `pending_targeted_details`, `revision`, `cursor`,
`pages`, `started_at`, `updated_at`, `listing_exhausted`, `last_error`, `traversal`,
`complete` and `atomic_snapshot`. `updated_at` describes catalog-state activity,
including recorded errors, not necessarily a successful fetch. `traversal` is
`not_started`, `partial` or `complete`. A populated cache can still be `not_started`.

A failed, malformed or mismatched detail remains pending. Even a **404 for an ID
returned by a fresh list page** can occur upstream; it is recorded as a failure,
not skipped or counted as downloaded. Retry a later bounded batch after the source
recovers. An unrecoverable detail can block traversal completion; there is no
silent bypass. Previously stored successful details remain available offline.

To deliberately start a fresh traversal:

```bash
python cli.py --db rennacs.db catalog sync --restart --max-pages 1 --max-requests 50 --rate 1 --json
```

`--restart` resets pagination/cursor history while retaining cached details **and
unfinished detail work**; it is not a way to bypass a failed ID. Use it once to
start a new pass, then omit it on subsequent resume batches. Repeated cursors are
errors, not evidence of successful exhaustion. A previously completed traversal
is not automatically refreshed: starting a new pass requires `--restart`.

`complete: true` means the list traversal reached its end and its queued catalog
details succeeded. It does **not** mean an atomic source snapshot, current data,
all vulnerabilities known, or every observed product matchable. The source may
change while pages are traversed; retained old records are not automatically
purged. `atomic_snapshot` remains false. Neither source totals nor local row
counts prove completeness.

## Offline reassessment and keyset resume

New scan/raw-inventory ingestion uses locally cached candidates automatically.
Fetching new advisories does not itself rewrite all existing services. Use
`catalog assess` to refresh those correlations without acquiring observations.

A successful page returns `processed`, `matched_services`, `advisory_matches`,
`after_id`, `has_more` and `catalog_revision`. Counts are for that page, not global
coverage. Continue with the **returned** service `after_id` and the same database
and query until `has_more` is false. For example, if a page returns `after_id: 275`:

```bash
python cli.py --db rennacs.db catalog assess 'product:OpenSSH' --limit 100 --after-id 275 --json
```

The cursor is a service primary key, **not** a processed count or offset. Filtering
by mutable match fields such as `has_vuln:true` can change membership during a pass;
use stable inventory filters when traversing a fixed intended population. Avoid
concurrent inventory changes, sync or reassessment for a consistent pass. Keyset
traversal is not a database snapshot. If the catalog revision changes, restart
assessment from `--after-id 0` for consistent evidence against that revision.
An interrupted assessment returns the invocation's original safe `after_id` with
`has_more: true`; replaying that page may repeat work but avoids claiming an
unverified last-processed cursor.

Reassessment updates catalog correlation evidence and its `catalog_checked_at`
and `catalog_revision`. It does not update service/host observation timestamps,
create scan history, probe hosts or overwrite legacy/imported advisory evidence.
No matches, unsupported version schemes, empty coverage or an exhausted local
pass are not proof that an asset is secure.

## Read-only UI and API

- `GET /api/catalog` returns local catalog status, independently of the homepage's
  separate recent-feed/source statistics. POST is not a sync interface.
- `GET /api/findings` includes catalog status, each finding's
  `evidence.catalog_checked_at`/`catalog_revision`, and advisory source, catalog ID,
  detection method, match status, matched affected records, fixed versions and
  provenance fields. These are local reports, not live reassessments.
- `/findings` shows coverage and progress timestamps separately from observation
  and assessment timestamps. Upstream strings are HTML-escaped, including source,
  match status, summaries and fixed-version evidence. There is no sync button.

All asset assessments remain **potential / low confidence**, with no exploit test
or automatic remediation. `match_status: affected` (and the legacy advisory
`confirmed: yes`) describes version-range membership only, never a confirmed
vulnerability on the host. `unknown` is not a clean bill of health.

## Matching and data limitations

Candidate lookup uses exact normalized product/package identities plus a small
explicit product-alias table, not fuzzy matching or a lookup per host. Range
comparison is bound to compatible affected product/package records, not every
range in a multi-product advisory. Supported numeric releases and OpenSSH portable
versions have conservative comparisons; ambiguous bounds, unsupported suffixes,
package ecosystems and distribution/backport semantics are not general-purpose
package-version resolution. Rejected/withdrawn or provably outside records do not
become catalog matches; superseded/ambiguous evidence can remain unknown.

Fixed versions are only source-reported supported fixed bounds from potentially
applicable matched records. They are not generated upgrade commands, a guarantee
that a particular distribution package is patched, or proof of remediation.
Verify installed builds, platform and configuration against the applicable vendor
advisory, with owner approval before any changes or deeper testing. KEV identifies
exploitation of an advisory elsewhere, not compromise of this host.

Raw detail JSON and catalog source/fetch metadata are retained separately from
matching output. Summaries may be model-written; summary provenance is retained
rather than calling all prose vendor-authored. There is no demonstrated
Internet-scale matching/ingestion capacity, production SaaS readiness, weekly
coverage guarantee or changed scan permission implied by this feature.

## Source terms

Review [cve.now's current API/reference and licensing information](https://cve.now/llms.txt)
and every relevant upstream dataset's terms before commercial reuse or
redistribution. cve.now identifies its summaries as CC-BY 4.0; preserve required
attribution and verify the applicable terms. That is **not** a blanket license for
all merged CVE/OSV/GitHub/NVD/CISA data, third-party references or imported host
inventories. A free no-key endpoint does not automatically authorize resale.

Deterministic catalog CLI/API/UI tests use synthetic advisory data and mocked
outbound fetches over real SQLite, Index, Flask and command-line seams. They do
not establish upstream availability or production performance.

## Attacker workflow: hunt

`hunt` chains the recon modules into one pass and leaves a ranked report:

```bash
python cli.py hunt example.com -p web          # CT -> origins -> prove -> scan -> rank
python cli.py findings --rank                  # KEV first, then CVSS, then confirmed kernel
python cli.py probe 203.0.113.9 --host www.example.com --edge 104.16.1.1
python cli.py udp 203.0.113.9                  # SNMP sysDescr -> kernel -> kernel CVEs
```

`probe` presents the vhost over SNI and Host and compares identity (title, favicon,
server) against the edge. An origin is only "confirmed" when it answers the vhost;
everything else is a DNS guess. Kernel CVEs only match when a kernel string was read
(`confirmed`) or a distro revision was inferred — never from a bare product version.
