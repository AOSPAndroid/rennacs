# Rennacs — an educational "Shodan-style" device search engine

Rennacs is a small, self-contained project that recreates the core ideas behind
[Shodan](https://www.shodan.io/) for **learning purposes**. It scans hosts you are
authorized to scan, grabs service banners, fingerprints what's running, indexes the
results in a local database, and gives you a Shodan-like web UI with a filter query
language and per-host detail pages.

## Multi-service foundation build

The current development branch adds multi-service TCP profiles, an offline IPv4
coverage planner, reliable resume/refresh behavior, TLS metadata and evidence-backed
potential-finding reports. See [the build guide](docs/BUILD.md) for working commands,
verification and explicit production/UDP limitations. It does not start a global scan
or install a weekly schedule.

It was built to understand *how* a device search engine works end-to-end:

```
  target ──► scanner ──► fingerprinter ──► indexer (SQLite) ──► search API ──► web UI
            (TCP connect   (banner → product   (one document      (filter query    (results +
             + banner)      / version guess)    per host)          language)        host pages)
```

## ⚠️ Scope & authorization

Shodan continuously scans the entire public Internet. **Rennacs deliberately does
not.** Mass-scanning hosts you don't own is, depending on jurisdiction, abusive or
illegal, so Rennacs refuses to scan anything outside an allow-list by default:

- `localhost` / `127.0.0.1` and your own machine are always allowed.
- **Private / lab ranges** (RFC1918: `10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16`) are allowed.
- Any **public** address requires you to pass `--i-am-authorized`, which prints a
  reminder that you must have explicit permission for that target (e.g. your own
  VPS, or a sanctioned lab such as `scanme.nmap.org`).

This keeps the project useful for a classroom lab (scan the VMs on your own subnet)
while making the "don't point this at the Internet" lesson a first-class feature.

## Quick start

```bash
pip install -r requirements.txt

# 0. REAL DATA, no scanning: import real hosts from Shodan's free InternetDB,
#    geolocate them, and pull real CVE severities — then browse a real global map
python cli.py import --starter    # real ports/CVEs/tags for well-known public hosts
python cli.py geo                 # real worldwide coordinates
python cli.py enrich              # real CVSS + CISA-KEV from cve.now
python cli.py web                 # open http://127.0.0.1:5000  (and /map)

# 1. Scan your own machine
python cli.py scan 127.0.0.1

# 2. Sweep a WHOLE network you control — the Shodan-style crawler
python cli.py sweep 192.168.0.0/16 --ports top20 --rate 500

# 2b. Or scan one subnet
python cli.py scan 192.168.1.0/24 --ports top100

# 3. Or just load the bundled demo dataset to explore the UI with no scanning
python demo_seed.py

# 4. (Optional) pull real CVSS scores + CISA-KEV flags from cve.now
python cli.py enrich

# 5. Launch the web UI
python cli.py web
# open http://127.0.0.1:5000
```

## Real data — without scanning the internet

You don't have to scan the internet to populate Rennacs with real device data (you
shouldn't — see the authorization boundary below). Instead, **import** it from an
existing, authorized, legal source: Shodan's free, no-key
[InternetDB](https://internetdb.shodan.io) API, which returns a summary of what Shodan
already crawled for an IP — open ports, hostnames, CPEs (product/version), CVEs and tags.

```bash
python cli.py import --starter             # a curated set of real public hosts
python cli.py import 45.33.32.156 1.1.1.1  # specific IPs
python cli.py import 192.0.2.0/28          # a CIDR (one lookup per host, ~1/s)
python cli.py import @ips.txt              # a file of IPs
```

[rennacs/internetdb.py](rennacs/internetdb.py) maps each response into real host
records: ports → services, CPEs → product/version + OS, the CVE list → real vuln tags
(then enriched with CVSS/KEV by `cli.py enrich`), and Shodan's `tags` (e.g. `cloud`,
`self-signed`, `honeypot`) — searchable with the new `tag:` filter. Every lookup is
cached and hardened (allow-listed redirects, size cap, graceful fallback). Reading
InternetDB is a passive database lookup, **not** a scan, so it isn't gated.

Example: `import`-ing `scanme.nmap.org` pulls its real Apache 2.4.7 with ~140 real CVEs;
`geo` places it in San Francisco; the world map and `has_vuln:true` light up with it.

## Network-wide sweeping — the crawler

Shodan's defining capability is a crawler that continuously sweeps huge address spaces.
[rennacs/sweep.py](rennacs/sweep.py) is the small, readable version of that engine,
using the same techniques real internet scanners (zmap, masscan) rely on:

```bash
# Sweep a /16 (65k hosts) — streams with O(1) memory
python cli.py sweep 10.0.0.0/16 -p top20 --rate 500 -c 300

# Continuous re-crawl: sweep forever, 10 min between rounds (keeps the index fresh)
python cli.py sweep 192.168.0.0/16 --repeat 0 --interval 600

# Resume an interrupted sweep exactly where it stopped
python cli.py sweep --resume 7

python cli.py jobs                 # sweep / crawl history
```

- **Permuted scan order.** Addresses are visited in a pseudo-random permutation
  (`(a·i + b) mod N`, `gcd(a,N)=1`) so load spreads evenly across the scope instead of
  hammering one subnet — and it needs no host list in memory, so a /16 or larger streams
  through fine.
- **Global rate limiting.** A token bucket caps new connections/second across the whole
  sweep (`--rate`), so you stay polite.
- **Bounded concurrency** (`--concurrency`): a fixed worker pool, not a task per host.
- **Resumable jobs.** A sweep is deterministic given `(scope, ports, seed)`, so resume =
  "skip the first K permuted indices" — checkpointed to the DB and shown on the homepage
  **Crawler activity** panel and `python cli.py jobs`.

### The authorization boundary

"Network-wide" means *the networks you're allowed to scan*. The gate
([rennacs/authz.py](rennacs/authz.py)) checks the **whole scope up front**: localhost and
private (RFC1918) ranges sweep freely; a public range is refused unless you pass
`--i-am-authorized` to assert you own it or have explicit permission (your own fleet /
VPC, a sanctioned lab). Rennacs deliberately has no "scan the whole internet" mode and no
way to disable the gate — mass-scanning hosts you don't own is abusive and, in many
places, illegal. The engine shows you *how* crawling at scale works; the boundary keeps
it pointed at scope you control.

## Search query language

Mirrors Shodan's `filter:value` syntax. Examples:

| Query                         | Meaning                                        |
|-------------------------------|------------------------------------------------|
| `nginx`                       | free text across banners                       |
| `port:22`                     | hosts with SSH open                            |
| `product:OpenSSH`             | fingerprinted as OpenSSH                       |
| `port:443 has_ssl:true`       | TLS services on 443                            |
| `country:US org:"Google LLC"` | combine filters (quotes for spaces)            |
| `net:192.168.1.0/24`          | everything in a subnet                         |
| `-port:80 http`               | has "http" in a banner but NOT on port 80      |

Supported filters: `port`, `product`, `version`, `hostname`, `ip`, `net`, `org`,
`country`, `city`, `os`, `tag`, `has_ssl`, `ssl.cn`, `vuln`, `has_vuln`, `kev`,
`before`, `after`, plus free text.

## Vulnerability tags

Each fingerprinted `(product, version)` is run through a small, hand-written CVE
rule set ([rennacs/vulns.py](rennacs/vulns.py)). Matches show as CVE tags in the
results list and an "⚠ Possible vulnerabilities" box on the host page, and are
searchable with `has_vuln:true` or `vuln:CVE-2024-6387`.

**This is a heuristic, advisory only.** It matches *version ranges* from a banner and
cannot see backported patches or distro versioning, so it both misses real issues and
flags patched hosts. It's here to show the *mechanism* (fingerprint → known-CVE
lookup), not to be a scanner you'd act on.

## Live CVE data — cve.now integration

The heuristic above only *guesses* CVE IDs. [cve.now](https://cve.now) — a free,
no-auth public feed merging CVE List, OSV, GitHub Advisories, NVD and CISA KEV — turns
those guesses into sourced facts. Run:

```bash
python cli.py enrich          # pulls authoritative data for your flagged CVEs
python cli.py cve CVE-2024-6387   # look up a single CVE
```

`enrich` does three things, then caches everything locally:

1. **Enriches every flagged CVE** with the real CVSS score + vector, the CISA-KEV
   *exploited-in-the-wild* flag, a sourced summary, and reference links. These show on
   the results list and host pages, with a `cve.now ↗` source link.
2. **Validates the version match** against cve.now's authoritative affected ranges. If
   the detected version falls inside the affected window it's marked *✓ in affected
   range*; if clearly outside, *version may be patched*; if the version schemes can't
   be compared, it stays heuristic-only (we never *hide* a finding on a disagreement).
3. **Caches the latest Critical/KEV feed** for the homepage "Latest critical
   vulnerabilities" panel, plus catalog stats (total tracked, critical this week).

New `kev:true` filter finds services with a CISA Known-Exploited CVE.

**Design guarantees** (see [rennacs/cvenow.py](rennacs/cvenow.py)):

- **Offline-first.** Scanning and page views *never* hit the network — they read the
  local cache only. Talking to cve.now is the explicit `enrich` step.
- **Graceful degradation.** Any network error falls back to cache, then to the
  heuristic. cve.now being down never breaks Rennacs.
- **Sends nothing sensitive.** Only public CVE IDs leave the machine — never scan data,
  host info, or credentials. No API key, no account.
- **No new dependencies, SSRF-aware.** Uses only the stdlib `urllib`. Every CVE ID is
  validated before it enters a request URL; redirects are constrained to the cve.now
  host set (never an arbitrary or private host); responses are size-capped; and every
  read/parse/redirect failure degrades to cache, then heuristic — cve.now being down,
  slow, or hostile never breaks or hangs Rennacs.

> This integration was hardened after an adversarial multi-agent review of the network,
> SQL, caching and offline-fallback paths; the regression tests in `tests/test_cvenow.py`
> lock in those fixes (cache not clobbered by a malformed `200`, stale-cache fallback on
> transient errors, redirect/size guards, version-range validation).

## Global map

`/map` is a world map of the index with **clustered** markers (Leaflet + OpenStreetMap,
theme-darkened), coloured red when a host has a flagged service, plus a country
breakdown. It's **query-filtered** — `/map?q=port:443 country:US` (Shodan's "View on
Map", linked from every results page) — and lists private / lab hosts separately since
they have no public location.

Real geolocation comes in two layers ([rennacs/geoip.py](rennacs/geoip.py)):

- **Offline** (`enrich`, used at index time, never blocks a sweep): loopback/private
  labels, a few known IPs, and an optional **MaxMind GeoLite2** DB if present
  (`RENNACS_GEOLITE2` or `GeoLite2-City.mmdb`).
- **Network** (`cli.py geo`): real coordinates for every public host via a free, keyless
  API (ipwho.is), cached and hardened, updating each host's lat/lon/country/city/org.
  Private/loopback addresses are never geolocated (they have no public location).

```bash
python cli.py geo          # place the public hosts in the index on the world map
```

## How it maps to Shodan

| Shodan concept            | Rennacs equivalent                          |
|---------------------------|---------------------------------------------|
| Global crawlers           | `scanner.py` + `sweep.py` (scale engine)    |
| Continuous re-crawl       | `sweep --repeat 0 --interval` + scan jobs   |
| Service fingerprint DB    | `fingerprint.py` (regex rules → product)    |
| Banner / host "document"  | one JSON row per host in `db.py`            |
| `shodan.io/host/<ip>`     | `/host/<ip>` detail page                    |
| Filter reference          | `query.py` parser                           |
| `vuln:` tags / CVEs       | `vulns.py` (version-range heuristics)       |
| Real CVSS / CVE data      | `cvenow.py` (live cve.now enrichment)       |
| CISA-KEV / `vuln:` detail | `cve.now` exploited flag + sourced summary  |
| Shodan Maps + View on Map | `/map?q=` (clustered, query-filtered)       |
| GeoIP enrichment          | `geoip.py` (ipwho.is live + MaxMind option) |
| Real device data / import | `internetdb.py` (Shodan InternetDB, free)   |
| `tag:` filter             | tags from InternetDB (`cloud`, `honeypot`…) |

## Files

- `rennacs/scanner.py` — async scanner + banner grabber with the authorization gate
- `rennacs/sweep.py` — network-wide sweep engine (permuted order, rate limit, resume)
- `rennacs/fingerprint.py` — turns raw banners into product/version/os guesses
- `rennacs/db.py` — SQLite-backed index (the "search engine" storage)
- `rennacs/query.py` — Shodan-style filter query → SQL
- `rennacs/geoip.py` — geo enrichment: offline (MaxMind) + live geolocation (ipwho.is)
- `rennacs/internetdb.py` — import real host data from Shodan InternetDB (no scanning)
- `rennacs/_http.py` — shared hardened HTTP helper (redirect allowlist, size cap)
- `rennacs/app.py` — Flask web UI + JSON API
- `cli.py` — command-line entry point (`scan`, `web`, `search`)
- `rennacs/vulns.py` — heuristic CVE tagging from (product, version)
- `rennacs/cvenow.py` — live cve.now client (enrichment, feed, cache, offline fallback)
- `demo_seed.py` — loads a realistic demo dataset so the UI works with no scanning
- `tests/` — pytest suite (query, authz, fingerprint, vulns, cvenow, db, API)

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

174 tests cover the query compiler (including SQL-injection safety), the authorization
gate (per-host and whole-network), fingerprinting, the vuln heuristics, the cve.now
client, the geolocation client and the Shodan-InternetDB importer (CPE parsing, real-CVE
mapping, caching — all with mocked fetchers, no live network in CI), the sweep engine
(addressing, permutation bijection, rate limiting, resume, job history), the
query-filtered world map, enriched page rendering, the index/search layer, schema
migration, and the web API.

For educational use only. See the authorization notes above.
