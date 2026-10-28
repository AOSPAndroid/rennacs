# Multi-service TCP foundation

This branch is the first working increment toward a locally operated IPv4 exposure-monitoring and remediation SaaS. It is **not** an Internet-scale production crawler or a production SaaS deployment.

## Working now

- CLI `scan` and `sweep` default to a curated **120-port TCP `multiservice` profile** spanning web, remote access, mail, databases and infrastructure.
- Individual profiles: `web`, `remote`, `mail`, `databases`, `infrastructure`; existing `top20` and `top100` remain available. Combine profiles and ranges, e.g. `mail,remote,8000-8010`.
- `all-tcp` / `all` selects every TCP port from 1 through 65535. Port enumeration is not exhaustive protocol identification or vulnerability assessment.
- Offline IPv4 interval planning supports scope unions, exclusions, exact counts, duration lower bounds and required attempt rates. It never contacts targets.
- Correct sustained token-bucket limiting, bounded worker/dispatch memory and cancellation cleanup.
- Crash-safe contiguous-prefix checkpoints, persisted effective traversal/probe configuration, safe resumed counters and failed/interrupted job history.
- Hostnames are resolved, all destinations are checked before probing, and connections are pinned to checked IPs. Original names supply HTTP Host/TLS SNI. Shared-IP aliases are metadata, not separate virtual-host coverage.
- DER certificate CN, issuer and SAN collection, persisted with explicit **unverified** trust status.
- Partial scans preserve unscanned services. A missing previously observed service leaves an explicit `not_observed` event; it is **not** claimed closed, fixed or secure.
- Service-level potential-vulnerability reports with observation time, evidence hash, advisory links, low confidence, caveats and owner-approved remediation guidance. Enriched CVE metadata never becomes proof about the host.

## Local usage (Windows Git Bash)

```bash
uv venv --python python .venv
uv pip install --python .venv/Scripts/python.exe -r requirements-dev.txt

# OFFLINE: address/port arithmetic only. No scan or authorization implied.
.venv/Scripts/python.exe cli.py plan public-ipv4 -p multiservice
.venv/Scripts/python.exe cli.py plan public-ipv4 -p all-tcp
.venv/Scripts/python.exe cli.py plan 127.0.0.0/29 -p mail,remote --exclude 127.0.0.1/32 --json

# Explicitly local scans. Only scan other scopes you are permitted to assess.
.venv/Scripts/python.exe cli.py scan 127.0.0.1 -p multiservice
.venv/Scripts/python.exe cli.py sweep 127.0.0.1/32 -p multiservice --rate 50 --checkpoint-every 1
.venv/Scripts/python.exe cli.py jobs
.venv/Scripts/python.exe cli.py sweep --resume JOB_ID

# Local evidence-backed reports and UI; these commands do not perform exploits.
.venv/Scripts/python.exe cli.py findings 'product:OpenSSH' --json
.venv/Scripts/python.exe cli.py web --host 127.0.0.1
```

The UI has a **Findings** navigation entry at `/findings`. JSON endpoints:

- `/api/findings?q=product:OpenSSH&limit=25&offset=0`
- `/api/host/127.0.0.1/history?limit=25&offset=0`

A report's `total` counts **service assessments**, not individual CVEs. Pagination is bounded. History events expose their exact observation state and notes.

The `public-ipv4` alias is **planner-only**. It uses a disclosed conservative static special-use exclusion policy, not live BGP/routability data. Planner counts include network/broadcast addresses; traditional `sweep` CIDRs use host-address semantics, so a plan is not an executable sweep manifest.

Do not point the development Flask server at the public Internet. Authentication, tenant isolation and billing are not implemented. `--i-am-authorized` remains an operator assertion, not evidence of permission. Private networks can also belong to other people; their address class does not establish authorization.

## Recovery semantics

`scan_jobs.scanned` is a completed-work count; **`resume_at`** is the contiguous prefix safe to skip. Out-of-order results beyond that prefix can replay. Current service writes are replacement/idempotent in effect; the observation trail intentionally records repeated observations.

A resumed job restores the saved selected ports, shuffle mode, seed, timeout, rate, concurrency and checkpoint frequency. Changing CLI values does not silently change a resumed job's traversal. Prefix-consistent host/service counters avoid double-counting replayed holes. Old jobs without version-2 configuration are refused for exact resume; start a new sweep instead.

`--repeat 0 --interval N` still waits after completion; it is **not** a calendar-week scheduler. No Windows scheduled task or Hermes cron job is installed by this build.

## Verification

```bash
.venv/Scripts/python.exe -m pytest
.venv/Scripts/python.exe -m pytest tests/test_multiservice_e2e.py -s
```

Agent runs use an explicit Hermes scratch `--basetemp`, and fixture keys stay there. The loopback end-to-end test creates synthetic HTTP, SSH, SMTP and Redis fixtures, then actually connects, fingerprints, indexes, serves assessment reports and checks a partial rescan. These banners are test fixtures, not Internet findings. A separate real local TLS regression verifies certificate parsing, Host and SNI.

## Capacity and remaining work

The offline conservative public candidate set contains 3,702,257,664 addresses. Scanning all 65,535 TCP ports once per week would require **401,169,735.47 attempts/s**, before retries, replies, TLS/HTTP and indexing. Minimum outbound IPv4/TCP headers alone would be about **128.37 Gbit/s**, excluding link overhead. That is not viable over the PC's currently observed 520 Mbit/s Wi-Fi link, regardless of Python optimization. A weekly popular-service refresh plus a longer rolling full-port discovery cycle is a different, more practical product promise; do not advertise it as weekly exhaustive coverage.

Not implemented in this increment:

- UDP/protocol-specific discovery, all application protocols, exhaustive vulnerability checks or zero-day discovery.
- Fast raw-packet/native discovery backend, production sharding and an executable BGP/exclusion/opt-out-aware global manifest.
- A validated weekly global schedule, process overlap lock, operational resource/traffic budgets or measured Internet-scale throughput.
- Production observation retention/compaction, scalable ingest/search storage or worker-to-SaaS upload queue.
- Tenant identity, verified asset ownership, consent records, customer credentials, payments or cloud deployment.
- Intrusive validation, automatic fixes, remote system modification or remediation work orders.

Broad service-family coverage remains the product goal. This TCP foundation does not claim that all services or all vulnerabilities are now covered.
