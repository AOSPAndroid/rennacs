# Rennacs — network observations and exposure search

Rennacs collects TCP service observations from assets you are authorized to assess,
imports source-attributed inventory, and stores the results in a local SQLite index.
The CLI, Flask UI and JSON API expose recorded services, banners, TLS metadata,
observation history and **potential** advisory correlations.

**A new index starts empty.** Rennacs does not generate fabricated host records,
service banners, locations or inventory statistics. A scan may find no responding
services, and an import may return no data. Neither outcome is filled with invented
records. Synthetic inventory exists only in isolated automated tests, never loaded
by the application.

This is a working local TCP acquisition/search foundation, **not** a production SaaS
or a verified Internet-scale crawler. See [the build guide](docs/BUILD.md) for current
capabilities and remaining work, and [the catalog guide](docs/CATALOG.md) for advisory
acquisition, coverage and matching limits.

## Scope and authorization

Only scan assets you own or have explicit permission to assess. Applicable law,
network-owner consent and ISP/provider policy still apply.

- The default scan policy permits loopback and RFC1918 private addresses. Address
  class is a technical boundary, **not evidence of permission**: private networks can
  belong to other people.
- Public scan targets require `--i-am-authorized`. That flag is an operator assertion;
  it does not grant permission, verify ownership or establish engagement scope.
- Hostnames resolve to checked destination addresses; probes connect to those same
  addresses. The original hostname supplies HTTP Host/TLS SNI.
- InternetDB imports are provider database lookups, not active scans of the targets.
  Check provider terms, permitted use, attribution and commercial redistribution
  rights before importing or publishing data.
- Intrusive validation, exploitation and system-changing remediation are not part of
  discovery. They require separate owner-approved scope and safeguards.

No installation command, page view or offline planner starts a public scan or installs
a recurring schedule. Do not expose the development Flask server or your personal PC
directly to customers.

## Install and open an empty index

From the checkout, in Windows Git Bash:

```bash
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt

.venv/Scripts/python.exe cli.py --db rennacs.db stats
.venv/Scripts/python.exe cli.py --db rennacs.db web --host 127.0.0.1
```

Open <http://127.0.0.1:5000>. A fresh database shows zero hosts and services until
you deliberately acquire observations. On Linux/macOS, substitute `.venv/bin/python`
for `.venv/Scripts/python.exe`.

The root `--db` option must precede the command. Reuse the same path for acquisition,
search, enrichment and serving; `RENNACS_DB` can also configure the Flask app factory.
Back up an existing database before upgrading or reacquiring old inventory.

## Acquire real observations

### Authorized active TCP collection

These commands contact only your own loopback interface:

```bash
.venv/Scripts/python.exe cli.py --db rennacs.db scan 127.0.0.1 -p multiservice
.venv/Scripts/python.exe cli.py --db rennacs.db sweep 127.0.0.1/32 -p multiservice --rate 50 --checkpoint-every 1
.venv/Scripts/python.exe cli.py --db rennacs.db jobs
```

If nothing is listening, there may be no host/service records to search. For other
scopes, select actual authorized targets, ports and a measured resource budget;
public targets additionally require the authorization assertion described above.

The default `multiservice` profile spans web, remote access, mail, databases and
infrastructure. Other profiles include `web`, `remote`, `mail`, `databases`,
`infrastructure`, `top20` and `top100`; combine profiles and port ranges as needed.
`all-tcp` selects TCP ports 1 through 65535. Enumerating ports does **not** identify
every protocol, cover UDP or test every vulnerability.

Sweeps use bounded workers, a connection-attempt token bucket, permuted traversal
and persisted job configuration. Resume an interrupted job using its actual ID:

```bash
.venv/Scripts/python.exe cli.py --db rennacs.db sweep --resume JOB_ID
```

Resume restores saved ports, timeout, rate, concurrency, shuffle and checkpoint
configuration. Its cursor is a safe contiguous prefix; out-of-order work beyond it
may replay. Legacy jobs without safe configuration cannot be exactly resumed.
Partial-port refreshes preserve unscanned services. A previously observed service
that does not answer records `not_observed`, not a claim of closure or remediation.

`--repeat 0 --interval N` repeats after a completed round plus the requested delay.
It is **not** a fixed weekly start time, a production scheduler or an overlap lock.

### Explicit provider imports

Put actual IP addresses you have selected and are permitted to use in `ips.txt`,
one per line. Import only those targets, with an explicit lookup budget:

```bash
.venv/Scripts/python.exe cli.py --db rennacs.db import @ips.txt --max 25 --rate 1
.venv/Scripts/python.exe cli.py --db rennacs.db geo --limit 25 --rate 1
.venv/Scripts/python.exe cli.py --db rennacs.db enrich
```

`import` reads [Shodan InternetDB](https://internetdb.shodan.io). Imported ports,
hostnames, CPEs, tags and CVE associations are **provider reports**, not observations
made by Rennacs and not independently confirmed findings. No inventory or geographic
spread is guaranteed. Lookup failures and missing fields remain missing; responses
and acquisition metadata are cached locally. `--offline` uses existing cache only.

Source acquisition time and service measurement time are different. InternetDB may
not supply a measurement timestamp; Rennacs does not invent one from the fetch time.
Supported acquisition provenance includes source identity, retrieval time, reference
and payload digest. It supports attribution, not proof that a provider is correct.

Existing rows without supported acquisition provenance are quarantined from search,
statistics, maps and findings, rather than silently relabeled as real. The homepage
and `GET /api/data-status` show sourced and quarantined host/service counts. Reacquire
legacy inventory through authorized observation or a validated provider import; do
not promote it by editing a label.

### Geolocation

Indexing performs no network geolocation. Public locations come from an optional
MaxMind GeoLite2 database (`geoip2` and `RENNACS_GEOLITE2`/`GeoLite2-City.mmdb`) or an
explicit `geo` lookup through ipwho.is. Public IPs have no hard-coded geographic
fallback. Private/loopback labels classify address scope, not a physical location.
Missing coordinates stay unknown and do not acquire a map marker. Geolocation is
approximate provider metadata, not proof of ownership or physical presence.

## Search and local reports

```bash
.venv/Scripts/python.exe cli.py --db rennacs.db search 'port:22 product:OpenSSH'
.venv/Scripts/python.exe cli.py --db rennacs.db findings 'product:OpenSSH' --json
```

The query language supports free text and combined `filter:value` expressions:

| Query | Meaning within recorded inventory |
|---|---|
| `port:22` | Recorded services on port 22 |
| `product:OpenSSH` | Services identified as OpenSSH |
| `port:443 has_ssl:true` | Recorded TLS services on port 443 |
| `net:192.168.1.0/24` | Restrict to an indexed subnet; does not scan it |
| `country:US` | Services with that sourced country code |
| `has_vuln:true` | Services with advisory associations |
| `kev:true` | Services with a KEV-linked advisory; not proof of host exploitation |

Other filters include `version`, `hostname`, `ip`, `org`, `city`, `os`, `tag`,
`ssl.cn`, `vuln`, `before` and `after`; `-filter:value` negates a filter.

UI routes include `/search`, `/host/<ip>`, `/map` and `/findings`. JSON routes include
`/api/search`, `/api/host/<ip>`, `/api/host/<ip>/history`, `/api/stats`, `/api/map`,
`/api/findings`, `/api/jobs`, `/api/catalog` and `/api/data-status`. Page views read
local inventory/advisory caches; they do not initiate scans or advisory syncs.
Findings totals count **service assessments**, not individual CVEs.

The map shows only records with available coordinates and respects the search query.
Map assets/tiles can require external browser requests; offline inventory reads do
not mean the browser has a fully offline basemap.

## Advisory catalog and enrichment

Product/version correlations from banners, imported CVE tags and cached advisories
are **potential / low-confidence assessments**, not proof of vulnerability,
compromise, exploitation, a working fix or asset security. Banner matching cannot
resolve all vendor editions, distribution backports, configurations or prerequisites.
Unknown and untested do not mean secure. Review vendor guidance and original evidence
before making remediation decisions.

[cve.now](https://cve.now) supplies advisory metadata and a separately cached recent
critical/KEV feed. `enrich` refreshes metadata for already associated CVE IDs and that
feed; feed size or source-wide statistics are **not local catalog coverage**. Scanning,
status, reassessment and page views use locally cached advisories. Acquisition is an
explicit, budgeted CLI operation:

```bash
.venv/Scripts/python.exe cli.py --db rennacs.db catalog status --json
.venv/Scripts/python.exe cli.py --db rennacs.db catalog sync --max-pages 1 --max-requests 50 --rate 1 --json
.venv/Scripts/python.exe cli.py --db rennacs.db catalog fetch CVE-2024-6387 --max-requests 50 --rate 1 --json
.venv/Scripts/python.exe cli.py --db rennacs.db catalog assess 'product:OpenSSH' --limit 1000 --after-id 0 --json
```

Repeat bounded sync batches to resume pending details and pagination. One successful
batch is not a complete catalog. Failed/malformed details remain pending. A completed
source traversal is not an atomic/current snapshot or complete vulnerability coverage.
For reassessment, continue with returned `after_id` while `has_more` is true, keeping
the query/database and catalog revision consistent. Observation times do not become
reassessment times. Source summaries may be model-written; check source provenance,
vendor references, attribution and redistribution terms.

See [docs/CATALOG.md](docs/CATALOG.md) for defaults, matching boundaries, restart/resume
semantics, source-license caveats and exit codes.

## Production limits and future SaaS

The goal is broad IPv4 service coverage operated from the local scanner, with a
separate customer-facing service. That architecture is not implemented as a SaaS.
The offline `plan public-ipv4` command estimates TCP workloads; it never probes
targets or grants authorization. Its static candidate policy is not a live BGP
routability or executable opt-out-aware scan manifest.

Weekly exhaustive global TCP coverage has not been demonstrated and is not enabled.
The all-port traffic budget in [docs/BUILD.md](docs/BUILD.md) exceeds the current
PC/link operating assumptions; local tests are not Internet-scale benchmarks.

Not implemented:

- Protocol-aware broad UDP discovery, exhaustive protocol/vulnerability identification
  or a fast native global discovery backend.
- An executable routing/exclusion/opt-out manifest, verified ISP operating policy,
  measured global capacity, production scheduler or no-overlap enforcement.
- Production-scale retention, sharded ingestion/search, an outbound authenticated
  worker upload queue or a hosted customer deployment.
- SaaS authentication, tenant isolation, verified asset ownership, consent records,
  quotas, billing, monitoring and operational abuse/opt-out handling.
- Intrusive confirmation, automatic patching, remote system modification or
  remediation workflows with owner approval, rollback and scoped retesting.

Responsible disclosure and opt-out handling must not depend on purchasing a service.
Do not turn an advisory correlation into a claim of compromise or a demand for payment.

## Tests

```bash
.venv/Scripts/python.exe -m pip install -r requirements-dev.txt
.venv/Scripts/python.exe -m pytest
.venv/Scripts/python.exe -m pytest tests/test_multiservice_e2e.py -s
```

The suite uses temporary databases, synthetic inventory, mocked provider responses
and explicitly loopback HTTP/TLS/SSH/SMTP/Redis fixtures. Those inputs are not public
host findings and never populate a user index. Regression tests cover acquisition
provenance, quarantine, fresh zero-data UI/API behavior, authorization, query safety,
fingerprinting, refresh/resume, geolocation and advisory caching/matching. No public
scan or recurring task is required to run the test suite.
