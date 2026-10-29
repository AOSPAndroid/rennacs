#!/usr/bin/env python3
"""Rennacs command-line interface.

    python cli.py scan 127.0.0.1                 scan one host (multiservice TCP)
    python cli.py sweep 192.168.0.0/16 -p top20  sweep a whole network (Shodan-style)
    python cli.py sweep 10.0.0.0/24 --repeat 0 --interval 600   continuous re-crawl
    python cli.py sweep --resume 7               resume an interrupted sweep
    python cli.py jobs                           show crawl/sweep history
    python cli.py search "port:22 product:OpenSSH"
    python cli.py enrich                         pull real CVE data from cve.now
    python cli.py web                            launch the web UI
    python cli.py stats                          print index stats

Scanning only touches localhost and private (RFC1918) ranges unless you pass
--i-am-authorized, which asserts you have permission for a public target.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import math
import random
import sys
import time

from rennacs.authz import NotAuthorized, Policy
from rennacs.db import Index
from rennacs.query import QueryError, compile_query
from rennacs import scanner


def cmd_scan(args) -> int:
    policy = Policy(authorized=args.i_am_authorized)
    if args.i_am_authorized:
        print("[!] --i-am-authorized set: you assert you have permission to scan "
              "these targets.\n    Only scan hosts you own or are explicitly "
              "allowed to test.\n")
    idx = Index(args.db)

    count = {"hosts": 0, "services": 0}

    def on_host(hr: scanner.HostResult):
        idx.upsert_host(hr)
        if not hr.services:
            return  # the callback also carries unknown/no-response refreshes
        count["hosts"] += 1
        count["services"] += len(hr.services)
        ports = ", ".join(f"{s.port}"
                          f"{'(' + s.product + ')' if s.product else ''}"
                          for s in hr.services)
        print(f"  {hr.ip:<16} {len(hr.services):>3} open  [{ports}]")

    try:
        print(f"Scanning {args.target}  ports={args.ports}  timeout={args.timeout}s")
        asyncio.run(scanner.scan(
            args.target, args.ports, policy=policy, timeout=args.timeout,
            on_host=on_host,
        ))
    except NotAuthorized as e:
        print(f"\n[REFUSED] {e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"\n[FAILED] {e}", file=sys.stderr)
        return 1
    finally:
        idx.close()

    print(f"\nDone. {count['hosts']} host(s), {count['services']} service(s) indexed "
          f"into {args.db}.")
    if count["hosts"] == 0:
        print("No open ports found (host down, firewalled, or nothing listening).")
    return 0


def cmd_origin(args) -> int:
    """Certificate-transparency harvest, then split edge from origin candidates.

    Pure DNS plus one CT lookup: no packets reach the target, so this needs no
    authorization assertion even for a public domain.
    """
    from rennacs import ct
    from rennacs.cdn import EdgeMap

    edges = EdgeMap(path=args.cache)
    if args.refresh or edges.stale:
        got = edges.refresh()
        if got:
            print(f"[edge] refreshed ranges: {got}")
        elif args.refresh:
            print("[edge] refresh failed; using cached/seed ranges", file=sys.stderr)

    print(f"Harvesting certificate transparency for {args.domain} ...")
    try:
        names = ct.harvest(args.domain)
    except Exception as exc:  # noqa: BLE001 - crt.sh is frequently slow or down
        print(f"[FAILED] CT harvest: {exc}", file=sys.stderr)
        return 1
    if not names:
        print("No names found.")
        return 0
    print(f"{len(names)} name(s) in CT logs; resolving ...")

    classes = ct.classify(names, edges)
    origins, protected = ct.split(classes)
    unresolved = [c for c in classes if not c.addresses]

    print(f"\n=== ORIGIN CANDIDATES ({len(origins)}) — no edge in front ===")
    for c in sorted(origins, key=lambda c: c.name):
        print(f"  {c.name:<45} {', '.join(c.addresses)}")
    print(f"\n=== EDGE-PROTECTED ({len(protected)}) ===")
    by_provider: dict[str, int] = {}
    for c in protected:
        by_provider[c.edge or "?"] = by_provider.get(c.edge or "?", 0) + 1
    for provider, n in sorted(by_provider.items(), key=lambda kv: -kv[1]):
        print(f"  {provider:<14} {n} host(s)")
    if unresolved:
        print(f"\n{len(unresolved)} name(s) did not resolve (dead or internal-only).")

    if args.index and origins:
        idx = Index(args.db)
        try:
            for c in origins:
                idx.upsert_host(scanner.HostResult(ip=c.addresses[0], hostnames=[c.name]))
        finally:
            idx.close()
        print(f"\nIndexed {len(origins)} origin host(s) into {args.db}.")
    print("\nNext: scan an origin IP directly — it has no WAF in front of it.")
    return 0


def cmd_udp(args) -> int:
    """UDP probes: SNMP sysDescr, NTP, DNS version.bind, mDNS."""
    from rennacs import kernel as kernelmod
    from rennacs import udp as udpmod

    policy = Policy(authorized=args.i_am_authorized)
    try:
        policy.check(args.target)
    except NotAuthorized as e:
        print(f"\n[REFUSED] {e}", file=sys.stderr)
        return 2

    ports = [int(p) for p in args.ports.split(",")] if args.ports else None
    answers = udpmod.scan(args.target, ports, timeout=args.timeout)
    if not answers:
        print("No UDP answers (lossy protocol; a miss is not a closed port).")
        return 0

    idx = Index(args.db)
    services = []
    try:
        for a in answers:
            hint = kernelmod.from_sysdescr(a.text) if a.service == "snmp" else None
            svc = scanner.ServiceResult(
                port=a.port, transport="udp", service=a.service, banner=a.text[:2000],
            )
            if hint is not None:
                svc.kernel = hint.kernel
                svc.kernel_distro = hint.distro
                svc.kernel_confidence = hint.confidence
                svc.kernel_source = hint.source
            services.append(svc)
            print(f"  udp/{a.port:<6} {a.service:<6} {a.text[:110].strip()!r}")
            if hint is not None:
                print(f"           kernel={hint.kernel or '-'} distro={hint.distro or '-'} "
                      f"({hint.confidence})")
        idx.upsert_host(scanner.HostResult(ip=args.target, services=services))
    finally:
        idx.close()
    print(f"\n{len(answers)} UDP service(s) indexed into {args.db}.")
    return 0


def cmd_probe(args) -> int:
    """Prove an origin IP serves a vhost, and identify what is on it."""
    from rennacs import attack

    ident = attack.fetch(args.ip, args.host, args.port, args.path, tls=not args.no_tls)
    print(f"{args.ip}:{args.port} Host: {args.host}")
    print(f"  status   {ident.status or '-'}  {ident.error}")
    if ident.server:
        print(f"  server   {ident.server}")
    if ident.title:
        print(f"  title    {ident.title}")
    if ident.favicon:
        print(f"  favicon  {ident.favicon}")
    if ident.tls_cn:
        print(f"  tls cn   {ident.tls_cn}")
    if ident.location:
        print(f"  location {ident.location}")
    if args.edge:
        edge = attack.fetch(args.edge, args.host, args.port, args.path, tls=not args.no_tls)
        verdict = attack.compare(edge, ident)
        print(f"\n  vs edge {args.edge}: {'SAME APP' if verdict['same'] else 'different'}"
              f" — {', '.join(verdict['reasons'])}")
    return 0 if ident.reachable else 1


def cmd_hunt(args) -> int:
    """One-shot: CT harvest -> origin split -> prove -> scan -> rank."""
    from rennacs import attack, ct
    from rennacs.cdn import EdgeMap

    edges = EdgeMap(path=args.cache)
    if edges.stale:
        edges.refresh()

    print(f"[1/4] harvesting CT for {args.domain}")
    names = ct.harvest(args.domain)
    classes = ct.classify(names, edges)
    origins, protected = ct.split(classes)
    print(f"      {len(names)} names, {len(origins)} origin candidate(s), "
          f"{len(protected)} edge-protected")

    if not origins:
        print("No origin candidates; nothing to hunt.")
        return 0

    print("[2/4] proving candidates against the apex vhost")
    confirmed = []
    for c in origins:
        for ip in c.addresses[:2]:
            if ":" in ip and not args.ipv6:
                continue
            ident = attack.fetch(ip, args.domain, args.port, tls=not args.no_tls,
                                 timeout=args.timeout)
            if ident.serves_vhost:
                confirmed.append((c.name, ip, ident))
                print(f"      LIVE {c.name} -> {ip} [{ident.status}] {ident.title[:60]}")
    if not confirmed:
        print("      none answered for the apex vhost (they may be separate apps).")
        if not args.force:
            return 0

    targets = sorted({ip for _, ip, _ in confirmed})
    print(f"[3/4] scanning {len(targets)} confirmed origin(s), ports={args.ports}")
    policy = Policy(authorized=True)
    idx = Index(args.db)
    total = {"services": 0}
    found_ids: set[str] = set()

    def on_host(hr):
        idx.upsert_host(hr)
        total["services"] += len(hr.services)
        for s in hr.services:
            for v in s.vulns:
                if v.get("cve"):
                    found_ids.add(v["cve"])
            print(f"      {hr.ip:<16} {s.port:<6} {s.product or s.service or '?'}"
                  f"{' ' + s.version if s.version else ''}")

    try:
        for ip in targets:
            asyncio.run(scanner.scan(ip, args.ports, policy=policy,
                                     timeout=args.timeout, on_host=on_host))
    finally:
        idx.close()

    print(f"[4/4] {total['services']} service(s) indexed into {args.db}")

    # Pull advisories for the CVEs the fingerprint rules already flagged, so the
    # ranked report has something to rank. Bounded and best-effort.
    if found_ids and not args.no_enrich:
        print(f"[+] fetching {len(found_ids)} advisory record(s) from cve.now")
        idx2 = Index(args.db)
        try:
            idx2.catalog.fetch_ids(sorted(found_ids), max_requests=args.enrich_limit)
            idx2.reassess_catalog("")
        except Exception as exc:  # noqa: BLE001 - enrichment is optional
            print(f"    enrichment failed: {exc}", file=sys.stderr)
        finally:
            idx2.close()
    print("      next: python cli.py findings --rank")
    return 0


def cmd_scope(args) -> int:
    """Resolve a country/region scope from RIPE delegated statistics."""
    from pathlib import Path as _P

    from rennacs import regions

    try:
        countries = regions.resolve(args.region, args.country)
    except ValueError as exc:
        print(f"scope error: {exc}", file=sys.stderr)
        return 2
    path = regions.fetch(_P(args.cache))
    scope = regions.parse(path, countries)
    info = scope.summary()
    if args.json:
        print(json.dumps({"countries": scope.countries, **info,
                          "ipv4": [str(n) for n in scope.ipv4][:args.limit],
                          "ipv6": [str(n) for n in scope.ipv6][:args.limit]}, indent=2))
    else:
        print(f"{info['countries']} countries, {info['ipv4_blocks']} IPv4 block(s), "
              f"{info['ipv4_addresses']:,} addresses, {info['ipv6_prefixes']} IPv6 prefix(es)")
        print(f"~{info['estimated_days_at_500cps']} day(s) at 500 conn/s")
        print("countries: " + " ".join(scope.countries))
    if args.out:
        _P(args.out).write_text("\n".join(str(n) for n in scope.ipv4) + "\n", encoding="utf-8")
        print(f"wrote {len(scope.ipv4)} IPv4 block(s) to {args.out}")
    return 0


def cmd_sweep(args) -> int:
    """Network-wide sweep: the Shodan-style crawler, bounded to authorized scope."""
    from rennacs import sweep as sweepmod

    policy = Policy(authorized=args.i_am_authorized)
    idx = Index(args.db)

    scope, seed, start_at, job_id = args.scope, None, 0, None
    base_hosts_up, base_services = 0, 0
    if args.resume:
        job = idx.get_job(args.resume)
        if not job:
            print(f"no such job: {args.resume}", file=sys.stderr)
            idx.close()
            return 1
        config = job["config"]
        if config.get("version") != 2 or not config.get("ports"):
            print("Legacy job has no safe traversal configuration; start a fresh sweep.", file=sys.stderr)
            idx.close()
            return 2
        if job["status"] == "done":
            print("Job is already complete; start a fresh sweep.", file=sys.stderr)
            idx.close()
            return 2
        scope, seed, start_at, job_id = (job["scope"], job["seed"],
                                         job["resume_at"], job["id"])
        args.ports = ",".join(str(port) for port in config["ports"])
        args.no_shuffle = not config["shuffle"]
        args.timeout = config["timeout"]
        args.rate = config["rate"]
        args.concurrency = config["concurrency"]
        args.checkpoint_every = config.get("progress_every", 50)
        base_hosts_up, base_services = job["hosts_up"], job["services"]
        print(f"Resuming job {job_id}: {scope} from host {start_at}/{job['total']}")
    if not scope:
        print("sweep needs a SCOPE (CIDR) or --resume <job>", file=sys.stderr)
        idx.close()
        return 1

    # Gate the WHOLE scope up front — never start a job we can't run.
    try:
        from rennacs.ports import resolve
        selected_ports = resolve(args.ports)
        sweepmod.RateLimiter(args.rate)
        scanner._check_timeout(args.timeout)
        if args.concurrency <= 0 or args.checkpoint_every <= 0:
            raise ValueError("concurrency and checkpoint interval must be positive")
        if args.repeat < 0 or args.interval < 0:
            raise ValueError("repeat and interval must be nonnegative")
        for part in scope.split(","):
            if part.strip():
                policy.check_network(ipaddress.ip_network(part.strip(), strict=False))
        space = sweepmod.TargetSpace.from_scope(scope)
        if not space.total or not 0 <= start_at <= space.total:
            raise ValueError("scope must be nonempty and resume cursor within scope")
    except (NotAuthorized, ValueError, TypeError) as e:
        print(f"[REFUSED] {e}", file=sys.stderr)
        idx.close()
        return 2
    if args.i_am_authorized:
        print("[!] --i-am-authorized set: you assert you have permission to sweep "
              "this scope. Only sweep networks you own or may test.\n")

    shuffle = not args.no_shuffle
    config = {"version": 2, "ports": selected_ports, "shuffle": shuffle,
              "timeout": args.timeout, "rate": args.rate,
              "concurrency": args.concurrency, "progress_every": args.checkpoint_every}
    rounds, rnd = args.repeat, 0
    rc = 0
    try:
        while True:
            rnd += 1
            if job_id is None:
                use_seed = (seed if seed is not None
                            else (random.randrange(1, 2**31) if shuffle else 0))
                job_id = idx.start_job(scope, args.ports, space.total,
                                       rate=args.rate, concurrency=args.concurrency,
                                       seed=use_seed, config=config)
            else:
                use_seed = seed if seed is not None else 0
            print(f"[job {job_id}] sweeping {scope}  hosts={space.total}  "
                  f"ports={args.ports}  rate={args.rate or 'unlimited'}/s  "
                  f"concurrency={args.concurrency}  shuffle={shuffle}")
            t0 = time.monotonic()

            def on_host(hr):
                idx.upsert_host(hr)

            def on_progress(stats, sd):
                idx.checkpoint_job(job_id, scanned=stats.scanned,
                                   hosts_up=base_hosts_up + stats.resume_hosts_up,
                                   services=base_services + stats.resume_services,
                                   seed=sd, resume_at=stats.resume_at)
                el = time.monotonic() - t0
                r = (stats.scanned - start_at) / el if el > 0 else 0
                sys.stdout.write(
                    f"\r  {stats.scanned}/{stats.total} hosts  up={stats.hosts_up}  "
                    f"services={stats.services}  {r:.0f} hosts/s   ")
                sys.stdout.flush()

            stats = asyncio.run(sweepmod.sweep(
                scope, args.ports, policy=policy, rate=args.rate,
                concurrency=args.concurrency, timeout=args.timeout, shuffle=shuffle,
                seed=use_seed, start_at=start_at, on_host=on_host,
                on_progress=on_progress, progress_every=args.checkpoint_every))
            idx.finish_job(job_id, "done")
            print(f"\n[job {job_id}] done: {base_hosts_up + stats.hosts_up} host(s) up, "
                  f"{base_services + stats.services} service(s) across {stats.scanned} scanned.")
            job_id, seed, start_at = None, None, 0   # next round is a fresh sweep
            base_hosts_up, base_services = 0, 0

            if rounds and rnd >= rounds:
                break
            wait = args.interval
            print(f"next crawl in {wait}s (Ctrl-C to stop) ...")
            time.sleep(wait)
    except KeyboardInterrupt:
        if job_id is not None:
            idx.finish_job(job_id, "interrupted")
            print(f"\n[interrupted] resume with:  python cli.py sweep --resume {job_id}")
        rc = 130
    except Exception as exc:
        if job_id is not None:
            idx.finish_job(job_id, "failed")
        print(f"[FAILED] {exc}", file=sys.stderr)
        rc = 1
    finally:
        idx.close()
    return rc


def cmd_jobs(args) -> int:
    idx = Index(args.db)
    jobs = idx.list_jobs(args.limit)
    idx.close()
    if not jobs:
        print("No sweeps yet. Run e.g.:  python cli.py sweep 192.168.1.0/24 -p top20")
        return 0
    print(f"{'ID':>3}  {'STATUS':<11} {'SCOPE':<22} {'SCANNED':>12}  UP   SVC  WHEN")
    for j in jobs:
        prog = f"{j['scanned']}/{j['total']}"
        when = (j.get("finished_at") or j.get("updated_at") or "")[:19].replace("T", " ")
        print(f"{j['id']:>3}  {j['status']:<11} {j['scope']:<22} {prog:>12}  "
              f"{j['hosts_up']:>3}  {j['services']:>4}  {when}")
    return 0


def cmd_plan(args) -> int:
    """Compute address/port workload locally; never authorize or execute a scan."""
    from rennacs.planner import build_plan

    try:
        data = build_plan(args.scope, args.ports, rate=args.rate,
                          days=args.days, exclude=args.exclude)
    except ValueError as exc:
        print(f"plan error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print(f"OFFLINE TCP PLAN — {data['scope']}")
        print(f"Addresses: {data['address_count']:,}  Ports: {data['port_count']:,}")
        print(f"Attempts: {data['attempt_count']:,}")
        print(f"Required for {data['days']:g} days: {data['required_rate']:,.2f} attempts/s")
        print(f"At {data['rate']:g}/s: at least {data['duration_lower_bound_days']:,.2f} days")
        for warning in data["warnings"]:
            print(f"[!] {warning}")
    return 0


def cmd_findings(args) -> int:
    """Export local, evidence-backed assessments without network requests."""
    from rennacs.findings import report

    idx = Index(args.db)
    try:
        data = report(idx, args.query, limit=args.limit, offset=args.offset,
                      ranked=args.rank)
    except (ValueError, QueryError) as exc:
        print(f"report error: {exc}", file=sys.stderr)
        return 2
    finally:
        idx.close()
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print(data["notice"])
        print(f"{data['total']} service assessment(s); showing {data['count']}.")
        for finding in data["matches"]:
            cves = ", ".join(v["cve"] for v in finding["advisories"])
            kev = " [KEV]" if any(v.get("known_exploited_catalog")
                                  for v in finding["advisories"]) else ""
            cvss = max((v.get("cvss") or 0 for v in finding["advisories"]), default=0)
            print(f"  {finding['ip']}:{finding['port']}/{finding['transport']} "
                  f"potential / low confidence  cvss={cvss or '-'}{kev}  {cves}")
    return 0


def cmd_catalog(args) -> int:
    """Explicit catalog operations; local reads never contact the source."""
    from rennacs.catalog import Catalog, valid_id

    try:
        if args.catalog_cmd in {"sync", "fetch"}:
            if (args.max_requests < 1 or not math.isfinite(args.rate) or args.rate <= 0
                    or (args.catalog_cmd == "sync" and args.max_pages < 1)):
                raise ValueError("page/request budgets and finite rate must be positive")
        if args.catalog_cmd == "fetch":
            for identifier in args.ids:
                if not valid_id(identifier):  # Never strip or repair source tokens.
                    raise ValueError("invalid advisory ID")
    except ValueError as exc:
        print(f"catalog error: {exc}", file=sys.stderr)
        return 2
    catalog = Catalog(args.db)
    rc = 0
    try:
        if args.catalog_cmd == "sync":
            data = catalog.sync(max_pages=args.max_pages, max_requests=args.max_requests,
                                rate=args.rate, restart=args.restart)
        elif args.catalog_cmd == "fetch":
            data = catalog.fetch_ids(args.ids, max_requests=args.max_requests, rate=args.rate)
        else:
            data = catalog.status()
        if args.catalog_cmd in {"sync", "fetch"} and data['stop_reason'] == 'error':
            rc = 1
    except KeyboardInterrupt:
        rc = 130
        data = {"interrupted": True, "complete": False, "stop_reason": "interrupted",
                "status": catalog.status()}
    finally:
        catalog.close()
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        state = data.get("status", data)
        if data.get("interrupted"):
            print("Interrupted; this batch is incomplete. Resume the explicit CLI operation.")
        elif args.catalog_cmd in {"sync", "fetch"}:
            print(f"Requests: {data['requests']}; pages: {data['pages']}; "
                  f"stored: {data['stored']}; stopped: {data['stop_reason']}")
        print(f"Local advisory catalog ({state['source']}): {state['traversal']}")
        print(f"Stored details: {state['stored_details']}; pending: {state['pending_details']}")
        print(f"Listing exhausted: {state['listing_exhausted']}; traversal complete: {state['complete']}")
        print("Coverage describes a traversal, not an atomic snapshot or proof of asset security.")
        if state['last_error']:
            print(f"Last catalog error: {state['last_error']['message']}", file=sys.stderr)
    return rc


def cmd_catalog_assess(args) -> int:
    """Reassess one keyset page of recorded services without network probes."""
    try:
        if not 1 <= args.limit <= 10000 or args.after_id < 0:
            raise ValueError("limit must be 1..10000 and after-id nonnegative")
        compile_query(args.query)
    except (ValueError, QueryError) as exc:
        print(f"catalog assessment error: {exc}", file=sys.stderr)
        return 2
    idx = Index(args.db)
    interrupted = False
    try:
        data = idx.reassess_catalog(args.query, limit=args.limit, after_id=args.after_id)
    except KeyboardInterrupt:
        interrupted = True
        # Replaying the original page is safe; never guess the last committed service.
        data = {"interrupted": True, "after_id": args.after_id, "has_more": True}
    finally:
        idx.close()
    if args.json:
        print(json.dumps(data, indent=2))
    elif interrupted:
        print(f"Interrupted; replay this page with the same query and --after-id {args.after_id}.")
    else:
        print(f"Offline catalog reassessment: {data['processed']} service(s); "
              f"{data['matched_services']} matched; {data['advisory_matches']} advisory match(es).")
        print(f"catalog revision: {data['catalog_revision']}; after_id: {data['after_id']}; "
              f"has_more: {data['has_more']}")
        if data['has_more']:
            print(f"Partial pass. Continue with the same database/query and --after-id {data['after_id']}.")
        else:
            print("Selected service traversal exhausted at this point; not proof of security.")
        print("Keyset progress is not a snapshot; avoid concurrent scans/catalog changes during a pass.")
    return 130 if interrupted else 0


def cmd_search(args) -> int:
    idx = Index(args.db)
    try:
        where, params = compile_query(args.query)
    except QueryError as e:
        print(f"query error: {e}", file=sys.stderr)
        idx.close()
        return 1
    rows, total = idx.search(where, params, limit=args.limit)
    idx.close()
    print(f"{total} result(s) for: {args.query or '(all)'}\n")
    for r in rows:
        tag = r["product"] or r["service"] or ""
        ver = f" {r['version']}" if r["version"] else ""
        ssl = " [SSL]" if r["has_ssl"] else ""
        print(f"  {r['ip']:<16} {r['port']:>5}/{r['transport']}  {tag}{ver}{ssl}")
        if r["banner"]:
            first = r["banner"].splitlines()[0][:80] if r["banner"].strip() else ""
            if first:
                print(f"       {first}")
    return 0


def cmd_enrich(args) -> int:
    """Pull authoritative CVE data from cve.now into the local cache and merge it."""
    from rennacs.cvenow import CVENow
    idx = Index(args.db)
    cvenow = CVENow(args.db, ttl_hours=args.ttl, offline=args.offline)
    cves = idx.distinct_cves()
    print(f"Enriching {len(cves)} distinct CVE(s) from cve.now "
          f"({'offline/cache-only' if args.offline else 'https://cve.now'}) ...")
    found = 0
    for cve in cves:
        # force=True so re-running enrich refreshes, rather than returning stale cache.
        entry = cvenow.entry(cve, allow_network=not args.offline,
                             force=not args.offline)
        if entry:
            found += 1
            kev = " [KEV]" if entry.get("kev") else ""
            score = f" CVSS {entry['cvss']}" if entry.get("cvss") is not None else ""
            print(f"  [ok] {cve:<16}{score}{kev}  {entry.get('title','')[:60]}")
        else:
            print(f"  [--] {cve:<16} (not in cve.now / offline)")
    counts = idx.reenrich(cvenow, allow_network=False)
    feed_n = cvenow.refresh_feed(limit=args.feed_limit)
    cvenow.refresh_stats()
    idx.close()
    cvenow.close()
    print(f"\nEnriched {found}/{len(cves)} CVEs; updated {counts['enriched']} "
          f"service tag(s) across {counts['services']} service(s); "
          f"{counts['kev']} service(s) flagged CISA-KEV.")
    print(f"Latest-critical feed: {feed_n} entries cached. "
          f"Run 'python cli.py web' to see enriched tags and the feed panel.")
    return 0


def cmd_import(args) -> int:
    """Import REAL host data from Shodan InternetDB (free, no key, no scanning)."""
    from rennacs.internetdb import InternetDB, STARTER

    targets: list[str] = []
    if args.starter:
        targets = list(STARTER)
    for t in args.targets:
        if t.startswith("@"):
            try:
                with open(t[1:], encoding="utf-8") as fh:
                    targets += [ln.strip() for ln in fh if ln.strip()
                                and not ln.startswith("#")]
            except OSError as e:
                print(f"cannot read {t[1:]}: {e}", file=sys.stderr)
                return 1
        else:
            targets += scanner.expand_targets(t)
    # de-dup, keep order
    seen, ips = set(), []
    for ip in targets:
        if ip not in seen:
            seen.add(ip)
            ips.append(ip)
    if not ips:
        print("nothing to import. Give IPs/CIDRs, @file, or --starter.", file=sys.stderr)
        return 1
    if len(ips) > args.max:
        print(f"[!] {len(ips)} targets > --max {args.max}; importing the first "
              f"{args.max}. InternetDB's free tier is ~1 req/s.")
        ips = ips[:args.max]

    idx = Index(args.db)
    idb = InternetDB(args.db, offline=args.offline)
    print(f"Importing real data for {len(ips)} host(s) from Shodan InternetDB "
          f"(rate={args.rate}/s) ...")

    def on_result(ip, doc, counts):
        if doc and doc.get("services"):
            ports = ",".join(str(s["port"]) for s in doc["services"][:12])
            vn = sum(len(s.get("vulns", [])) for s in doc["services"])
            tags = ("  tags=" + ",".join(doc.get("tags", []))) if doc.get("tags") else ""
            print(f"  [{counts['requested']}/{len(ips)}] {ip:<16} ports[{ports}]  "
                  f"{vn} CVE(s){tags}")
        else:
            print(f"  [{counts['requested']}/{len(ips)}] {ip:<16} (no data)")

    counts = idb.import_targets(ips, idx, rate=args.rate, on_result=on_result)
    idx.close()
    idb.close()
    print(f"\nImported {counts['found']}/{counts['requested']} host(s), "
          f"{counts['services']} service(s) of real data.")
    print("Next:  python cli.py geo     (place them on the world map)")
    print("       python cli.py enrich  (real CVSS + CISA-KEV from cve.now)")
    print("       python cli.py web     (browse + /map)")
    return 0


def cmd_geo(args) -> int:
    """Geolocate public hosts in the index so they appear on the world map."""
    from rennacs.geoip import GeoLocator
    idx = Index(args.db)
    geo = GeoLocator(args.db, offline=args.offline)
    pending = len([ip for ip in idx.hosts_without_geo()])
    print(f"Geolocating public hosts (provider: ipwho.is, free; rate={args.rate}/s) ...")

    def on_progress(i, counts):
        sys.stdout.write(f"\r  {i}/{counts['candidates']}  located="
                         f"{counts['located']}  unresolved={counts['failed']}   ")
        sys.stdout.flush()

    counts = geo.locate_missing(idx, limit=args.limit, rate=args.rate,
                                on_progress=on_progress)
    idx.close()
    geo.close()
    if counts["candidates"] == 0:
        print("No public hosts needing geolocation (private/lab hosts have no public "
              "location). Sweep a public range you're authorized for to populate the map.")
        return 0
    print(f"\nGeolocated {counts['located']}/{counts['candidates']} public host(s); "
          f"{counts['failed']} unresolved.")
    print("See them worldwide:  python cli.py web   then open  /map")
    return 0


def cmd_cve(args) -> int:
    """Look up a single CVE via cve.now and print it."""
    from rennacs.cvenow import CVENow
    cvenow = CVENow(args.db, offline=args.offline)
    entry = cvenow.entry(args.id, allow_network=not args.offline)
    cvenow.close()
    if not entry:
        print(f"{args.id}: not found in cve.now (or offline with empty cache).")
        return 1
    print(f"{entry['cve']}  {entry.get('title','')}")
    if entry.get("cvss") is not None:
        print(f"  severity: {entry.get('severity','')} (CVSS {entry['cvss']})  "
              f"{entry.get('vector','')}")
    if entry.get("kev"):
        print("  CISA KEV: known exploited in the wild")
    if entry.get("summary"):
        print(f"  summary: {entry['summary'][:300]}")
    for a in entry.get("affected", [])[:5]:
        rng = ", ".join(f"{r.get('introduced','?')}->{r.get('fixed') or 'unfixed'}"
                        for r in a.get("ranges", [])) or "(no ranges)"
        print(f"  affected: {a.get('product','')} [{rng}]")
    for u in entry.get("references", [])[:4]:
        print(f"  ref: {u}")
    print(f"  source: {entry.get('url','')}")
    return 0


def cmd_web(args) -> int:
    from rennacs.app import create_app
    app = create_app(args.db)
    print(f"Rennacs UI: http://{args.host}:{args.port}   (db={args.db})")
    app.run(host=args.host, port=args.port, debug=args.debug)
    return 0


def cmd_stats(args) -> int:
    idx = Index(args.db)
    s = idx.stats()
    idx.close()
    print(f"hosts:    {s['hosts']}")
    print(f"services: {s['services']}")
    print("top ports:")
    for p in s["top_ports"]:
        print(f"   {p['port']:>6}  {p['n']}")
    print("top products:")
    for p in s["top_products"]:
        print(f"   {p['product']:<20} {p['n']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="rennacs", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default="rennacs.db", help="index database path")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("scan", help="scan a target and index the results")
    p.add_argument("target", help="IP, CIDR, hostname, or comma list")
    p.add_argument("-p", "--ports", default="multiservice",
                   help="TCP: multiservice | web | remote | mail | databases | infrastructure | all-tcp | ports/ranges")
    p.add_argument("-t", "--timeout", type=float, default=2.0,
                   help="per-connection timeout in seconds")
    p.add_argument("--i-am-authorized", action="store_true",
                   help="assert permission to scan public targets")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("origin", help="CT harvest + edge/origin split for a domain")
    p.add_argument("domain", help="apex domain, e.g. example.com")
    p.add_argument("--refresh", action="store_true",
                   help="force-refresh the CDN range cache from provider lists")
    p.add_argument("--cache", default="cdn-ranges.json",
                   help="CDN range cache file (default: cdn-ranges.json)")
    p.add_argument("--index", action="store_true",
                   help="index the origin candidates as hosts")
    p.set_defaults(func=cmd_origin)

    p = sub.add_parser("udp", help="UDP probes: SNMP sysDescr, NTP, DNS, mDNS")
    p.add_argument("target", help="IP or hostname")
    p.add_argument("-p", "--ports", default="", help="comma list (default: 161,123,53,5353)")
    p.add_argument("-t", "--timeout", type=float, default=2.5)
    p.add_argument("--i-am-authorized", action="store_true",
                   help="assert permission to probe a public target")
    p.set_defaults(func=cmd_udp)

    p = sub.add_parser("probe", help="prove an origin IP serves a vhost (Host/SNI)")
    p.add_argument("ip", help="origin IP")
    p.add_argument("--host", required=True, help="vhost to present as Host and SNI")
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--path", default="/")
    p.add_argument("--no-tls", action="store_true", help="plain HTTP instead of HTTPS")
    p.add_argument("--edge", help="edge IP to compare identity against")
    p.set_defaults(func=cmd_probe)

    p = sub.add_parser("hunt", help="one-shot: CT -> origins -> prove -> scan -> rank")
    p.add_argument("domain", help="apex domain")
    p.add_argument("-p", "--ports", default="web", help="TCP port set (default: web)")
    p.add_argument("--port", type=int, default=443, help="port used while proving")
    p.add_argument("-t", "--timeout", type=float, default=4.0)
    p.add_argument("--no-tls", action="store_true")
    p.add_argument("--ipv6", action="store_true", help="also try IPv6 candidates")
    p.add_argument("--force", action="store_true", help="scan even if no candidate proves")
    p.add_argument("--cache", default="cdn-ranges.json")
    p.add_argument("--no-enrich", action="store_true",
                   help="skip pulling advisories for flagged CVEs")
    p.add_argument("--enrich-limit", type=int, default=60,
                   help="max advisory lookups after a hunt")
    p.set_defaults(func=cmd_hunt)

    p = sub.add_parser("scope", help="country/region scope from RIPE delegated stats")
    p.add_argument("--region", nargs="+", default=["western", "eastern"],
                   choices=["western", "eastern"])
    p.add_argument("--country", nargs="*", help="narrow to country codes, e.g. FR DE")
    p.add_argument("--out", help="write the IPv4 blocks to a file")
    p.add_argument("--limit", type=int, default=50, help="blocks shown with --json")
    p.add_argument("--cache", default="ripe-delegated.txt")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_scope)

    p = sub.add_parser("sweep", help="network-wide sweep (Shodan-style crawler)")
    p.add_argument("scope", nargs="?", default="",
                   help="CIDR or comma list, e.g. 192.168.0.0/16 (omit with --resume)")
    p.add_argument("-p", "--ports", default="multiservice",
                   help="TCP: multiservice | web | remote | mail | databases | infrastructure | all-tcp | ports/ranges")
    p.add_argument("-t", "--timeout", type=float, default=2.0)
    p.add_argument("--rate", type=float, default=500,
                   help="max new connections per second across the whole sweep "
                        "(0 = unlimited); keep it polite")
    p.add_argument("-c", "--concurrency", type=int, default=200,
                   help="number of concurrent workers")
    p.add_argument("--no-shuffle", action="store_true",
                   help="scan in sequential order instead of a random permutation")
    p.add_argument("--repeat", type=int, default=1,
                   help="re-crawl this many rounds (0 = forever) — continuous scanning")
    p.add_argument("--interval", type=int, default=300,
                   help="seconds to wait between re-crawl rounds")
    p.add_argument("--resume", type=int, metavar="JOB",
                   help="resume an interrupted sweep by job id")
    p.add_argument("--checkpoint-every", type=int, default=50,
                   help="persist safe resume state every N completed hosts")
    p.add_argument("--i-am-authorized", action="store_true",
                   help="assert permission to sweep a public scope you own")
    p.set_defaults(func=cmd_sweep)

    p = sub.add_parser("jobs", help="list sweep / crawl history")
    p.add_argument("-n", "--limit", type=int, default=20)
    p.set_defaults(func=cmd_jobs)

    p = sub.add_parser("plan", help="offline IPv4/TCP workload estimate; does not scan")
    p.add_argument("scope", nargs="?", default="public-ipv4")
    p.add_argument("-p", "--ports", default="multiservice")
    p.add_argument("--rate", type=float, default=500)
    p.add_argument("--days", type=float, default=7)
    p.add_argument("--exclude", action="append", default=[], help="IPv4/CIDR exclusions")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_plan)

    p = sub.add_parser("findings", help="local potential-vulnerability assessment reports")
    p.add_argument("query", nargs="?", default="")
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--offset", type=int, default=0)
    p.add_argument("--json", action="store_true", help="machine-readable local report")
    p.add_argument("--rank", action="store_true",
                   help="order by attack priority: KEV, then CVSS, then confirmed kernel")
    p.set_defaults(func=cmd_findings)

    p = sub.add_parser("catalog", help="local advisory catalog and offline reassessment")
    catalog_sub = p.add_subparsers(dest="catalog_cmd", required=True)
    p = catalog_sub.add_parser("status", help="offline local coverage status")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_catalog)
    p = catalog_sub.add_parser("sync", help="explicit bounded, resumable source traversal")
    p.add_argument("--max-pages", type=int, default=1)
    p.add_argument("--max-requests", type=int, default=50)
    p.add_argument("--rate", type=float, default=1.0)
    p.add_argument("--restart", action="store_true")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_catalog)
    p = catalog_sub.add_parser("fetch", help="fetch explicit advisory IDs, not full coverage")
    p.add_argument("ids", nargs="*", help="exact source IDs; omit to resume pending targeted details")
    p.add_argument("--max-requests", type=int, default=50)
    p.add_argument("--rate", type=float, default=1.0)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_catalog)
    p = catalog_sub.add_parser("assess", help="offline reassessment of one service keyset page")
    p.add_argument("query", nargs="?", default="")
    p.add_argument("--limit", type=int, default=1000)
    p.add_argument("--after-id", type=int, default=0)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_catalog_assess)

    p = sub.add_parser("search", help="query the index from the terminal")
    p.add_argument("query", nargs="?", default="", help="filter query string")
    p.add_argument("-n", "--limit", type=int, default=50)
    p.set_defaults(func=cmd_search)

    p = sub.add_parser("web", help="launch the web UI")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--debug", action="store_true")
    p.set_defaults(func=cmd_web)

    p = sub.add_parser("stats", help="print index statistics")
    p.set_defaults(func=cmd_stats)

    p = sub.add_parser("enrich", help="pull authoritative CVE data from cve.now")
    p.add_argument("--offline", action="store_true",
                   help="use only the local cache, make no network calls")
    p.add_argument("--ttl", type=int, default=24, help="cache TTL in hours")
    p.add_argument("--feed-limit", type=int, default=30,
                   help="how many latest-critical entries to cache")
    p.set_defaults(func=cmd_enrich)

    p = sub.add_parser("cve", help="look up one CVE via cve.now")
    p.add_argument("id", help="e.g. CVE-2024-6387")
    p.add_argument("--offline", action="store_true")
    p.set_defaults(func=cmd_cve)

    p = sub.add_parser("import", help="import REAL host data from Shodan InternetDB")
    p.add_argument("targets", nargs="*", default=[],
                   help="IPs / CIDRs / @file of IPs to look up")
    p.add_argument("--starter", action="store_true",
                   help="import a curated set of real public hosts (great for the map)")
    p.add_argument("--rate", type=float, default=1.0,
                   help="lookups per second (InternetDB free tier is ~1/s)")
    p.add_argument("--max", type=int, default=512, help="cap number of targets")
    p.add_argument("--offline", action="store_true", help="use only the local cache")
    p.set_defaults(func=cmd_import)

    p = sub.add_parser("geo", help="geolocate public hosts for the world map")
    p.add_argument("--rate", type=float, default=2.0,
                   help="geolocation lookups per second (free provider is limited)")
    p.add_argument("--limit", type=int, default=0, help="cap how many to locate (0=all)")
    p.add_argument("--offline", action="store_true",
                   help="use only the geo cache, make no network calls")
    p.set_defaults(func=cmd_geo)

    return ap


def main(argv=None) -> int:
    # Windows consoles default to cp1252; make our output UTF-8 tolerant.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
