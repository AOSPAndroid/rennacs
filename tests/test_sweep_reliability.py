"""Deterministic sweep correctness regressions; never contact the network."""

import asyncio
import importlib
import math
from types import SimpleNamespace

import pytest

from rennacs import scanner
from rennacs.sweep import RateLimiter, sweep

sweep_module = importlib.import_module("rennacs.sweep")


@pytest.fixture
def clock(monkeypatch):
    now = [0.0]
    real_sleep = asyncio.sleep
    sleeps = []

    async def sleep(delay):
        assert delay >= 0
        sleeps.append(delay)
        assert len(sleeps) < 1000, "token bucket never permits the waiting acquisition"
        now[0] = max(math.nextafter(now[0], math.inf), now[0] + delay)
        await real_sleep(0)

    monkeypatch.setattr(sweep_module, "time", SimpleNamespace(monotonic=lambda: now[0]))
    monkeypatch.setattr(sweep_module.asyncio, "sleep", sleep)
    return now


@pytest.mark.parametrize("workers", [1, 8])
def test_rate_limiter_does_not_credit_sleep_twice(clock, workers):
    acquired = []

    async def run():
        limiter = RateLimiter(10)

        async def acquire(count):
            for _ in range(count):
                await limiter.acquire()
                acquired.append(clock[0])

        await asyncio.gather(*(acquire(100 // workers + (i < 100 % workers))
                               for i in range(workers)))

    asyncio.run(run())
    assert len(acquired) == 100
    for count, elapsed in enumerate(acquired, 1):
        assert count <= 10 + 10 * elapsed + 1e-9
    assert clock[0] == pytest.approx(9.0)


@pytest.mark.parametrize("rate", [0.25, 0.5, 1.5])
def test_fractional_rate_has_one_token_minimum_burst(clock, rate):
    acquired = []

    async def run():
        limiter = RateLimiter(rate)
        for _ in range(4):
            await limiter.acquire()
            acquired.append(clock[0])

    asyncio.run(run())
    capacity = max(1.0, rate)
    assert acquired[0] == 0
    assert clock[0] == pytest.approx((4 - capacity) / rate)
    for count, elapsed in enumerate(acquired, 1):
        assert count <= capacity + rate * elapsed + 1e-9


@pytest.mark.parametrize("rate", [-1, -0.25, math.inf, -math.inf, math.nan])
def test_rate_limiter_rejects_negative_or_nonfinite_rates(rate):
    with pytest.raises(ValueError, match="rate"):
        RateLimiter(rate)


@pytest.mark.parametrize("rate", [None, "", [], {}, "not-a-rate", object()])
def test_rate_limiter_does_not_treat_invalid_input_as_unlimited(rate):
    with pytest.raises(ValueError, match="rate"):
        RateLimiter(rate)


@pytest.mark.parametrize("some_observed", [False, True])
def test_every_completed_host_reaches_callback(monkeypatch, some_observed):
    hosts = []

    async def grab(ip, port, timeout):
        if some_observed and int(ip.rsplit(".", 1)[1]) % 2 == 0 and port == 80:
            return scanner.ServiceResult(port=port)
        return None

    monkeypatch.setattr(scanner, "_grab", grab)
    stats = asyncio.run(sweep("127.0.0.0/29", "80,443", shuffle=False,
                              concurrency=3, rate=0, on_host=hosts.append))
    assert sorted(hr.ip for hr in hosts) == [f"127.0.0.{i}" for i in range(1, 7)]
    assert stats.scanned == 6
    assert stats.hosts_up == (3 if some_observed else 0)
    assert stats.services == (3 if some_observed else 0)


@pytest.mark.parametrize("failure", ["grab", "on_host", "on_progress", "worker_cancel"])
def test_failure_cancels_and_awaits_sibling_workers(monkeypatch, failure):
    async def run():
        first_started = asyncio.Event()
        first_cleaned = asyncio.Event()
        before = asyncio.all_tasks()

        async def grab(ip, port, timeout):
            if ip == "127.0.0.1":
                first_started.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    await asyncio.sleep(0)
                    first_cleaned.set()
            await first_started.wait()
            if failure == "grab":
                raise RuntimeError("injected grab failure")
            if failure == "worker_cancel":
                raise asyncio.CancelledError()
            return scanner.ServiceResult(port=port)

        def on_host(hr):
            if failure == "on_host":
                raise RuntimeError("injected host callback failure")

        def on_progress(stats, seed):
            if failure == "on_progress":
                raise RuntimeError("injected progress callback failure")

        monkeypatch.setattr(scanner, "_grab", grab)
        error = asyncio.CancelledError if failure == "worker_cancel" else RuntimeError
        try:
            with pytest.raises(error):
                await sweep("127.0.0.0/30", "80", shuffle=False, rate=0,
                            concurrency=2, on_host=on_host, on_progress=on_progress,
                            progress_every=1)
            cleaned_before_return = first_cleaned.is_set()
            leaked = [task for task in asyncio.all_tasks() - before if not task.done()]
        finally:
            # Avoid leaving the intentionally broken implementation's tasks behind.
            pending = list(asyncio.all_tasks() - before)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
        assert cleaned_before_return, "sweep returned before its sibling finished cleanup"
        assert leaked == []

    asyncio.run(run())


@pytest.mark.parametrize("shuffle", [False, True])
@pytest.mark.parametrize("start_at", [0, 2])
def test_resume_retries_holes_after_out_of_order_completion(monkeypatch, shuffle, start_at):
    space = sweep_module.TargetSpace.from_scope("127.0.0.0/29")
    perm = sweep_module.permutation(space.total, 17) if shuffle else lambda i: i
    first_ip = space.addr(perm(start_at))
    completed = []
    checkpoints = []

    class Interrupted(Exception):
        pass

    async def interrupted_grab(ip, port, timeout):
        if ip == first_ip:
            await asyncio.Event().wait()
        return scanner.ServiceResult(port=port)

    def checkpoint(stats, seed):
        checkpoints.append((stats.scanned, getattr(stats, "resume_at", stats.scanned), seed))
        raise Interrupted()

    monkeypatch.setattr(scanner, "_grab", interrupted_grab)
    with pytest.raises(Interrupted):
        asyncio.run(sweep("127.0.0.0/29", "80", rate=0, concurrency=2,
                          seed=17, shuffle=shuffle, start_at=start_at,
                          on_host=lambda hr: completed.append(hr.ip),
                          on_progress=checkpoint, progress_every=1))

    count, cursor, seed = checkpoints[-1]

    async def resumed_grab(ip, port, timeout):
        return scanner.ServiceResult(port=port)

    monkeypatch.setattr(scanner, "_grab", resumed_grab)
    final = asyncio.run(sweep("127.0.0.0/29", "80", rate=0, concurrency=2,
                              seed=seed, shuffle=shuffle, start_at=cursor,
                              on_host=lambda hr: completed.append(hr.ip)))
    assert set(completed) == {space.addr(perm(i)) for i in range(start_at, space.total)}
    assert count == start_at + 1
    assert cursor == start_at, "completion count must not checkpoint past an unfinished host"
    assert final.scanned == final.resume_at == space.total


@pytest.mark.parametrize("concurrency", [1, 3, 8])
def test_dispatch_stays_within_bounded_window_of_resume_prefix(monkeypatch, concurrency):
    async def run():
        release_first = asyncio.Event()
        first_started = asyncio.Event()
        visited = []
        saved = []
        cursors = []
        original_addr = sweep_module.TargetSpace.addr

        def addr(space, index):
            visited.append(index)
            return original_addr(space, index)

        async def grab(ip, port, timeout):
            if ip == "127.0.0.1":
                first_started.set()
                await release_first.wait()
            else:
                await asyncio.sleep(0)
            if int(ip.rsplit(".", 1)[1]) % 2 == 0:
                return scanner.ServiceResult(port=port)
            return None

        monkeypatch.setattr(sweep_module.TargetSpace, "addr", addr)
        monkeypatch.setattr(scanner, "_grab", grab)
        task = asyncio.create_task(sweep(
            "127.0.0.0/24", "80", shuffle=False, concurrency=concurrency, rate=0,
            on_host=lambda hr: saved.append(hr.ip), progress_every=1,
            on_progress=lambda stats, seed: cursors.append(stats.resume_at)))
        try:
            await first_started.wait()
            for _ in range(30):
                await asyncio.sleep(0)
            assert len(visited) <= concurrency, "completed holes grew past the dispatch window"
            assert not task.done()
            release_first.set()
            stats = await asyncio.wait_for(task, 2)
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        assert len(visited) == len(set(visited)) == 254
        assert len(saved) == len(set(saved)) == 254
        assert stats.scanned == stats.resume_at == 254
        expected_up = sum(i % 2 == 0 for i in range(1, 255))
        assert (stats.hosts_up, stats.services) == (expected_up, expected_up)
        assert (stats.resume_hosts_up, stats.resume_services) == (expected_up, expected_up)
        assert cursors == sorted(cursors)

    asyncio.run(run())


@pytest.mark.parametrize("observed", [False, True])
def test_host_result_records_attempted_ports_even_without_observations(monkeypatch, observed):
    attempted = []
    hosts = []

    async def grab(ip, port, timeout):
        attempted.append((ip, port, timeout))
        if observed and port == 80:
            return scanner.ServiceResult(port=80)
        return None

    monkeypatch.setattr(scanner, "_grab", grab)
    asyncio.run(sweep("127.0.0.1", "443,80,22", rate=0, timeout=0.25,
                      on_host=hosts.append))
    assert len(hosts) == 1
    assert hosts[0].scanned_ports == [22, 80, 443]
    assert [service.port for service in hosts[0].services] == ([80] if observed else [])
    assert attempted == [("127.0.0.1", port, 0.25) for port in [22, 80, 443]]


@pytest.mark.parametrize("start_at", [0, 2])
def test_resume_counters_only_include_the_completed_prefix(monkeypatch, start_at):
    first_ip = f"127.0.0.{start_at + 1}"
    second_ip = f"127.0.0.{start_at + 2}"
    snapshot = []

    class Interrupted(Exception):
        pass

    async def grab(ip, port, timeout, *, interrupted):
        if interrupted and ip == first_ip:
            await asyncio.Event().wait()
        if ip == second_ip or (ip == first_ip and port == 80):
            return scanner.ServiceResult(port=port)
        return None

    async def interrupted_grab(ip, port, timeout):
        return await grab(ip, port, timeout, interrupted=True)

    def checkpoint(stats, seed):
        if stats.scanned == start_at + 2:
            snapshot.append((stats.resume_at, stats.hosts_up, stats.services,
                             getattr(stats, "resume_hosts_up", stats.hosts_up),
                             getattr(stats, "resume_services", stats.services)))
            raise Interrupted()

    monkeypatch.setattr(scanner, "_grab", interrupted_grab)
    with pytest.raises(Interrupted):
        asyncio.run(sweep("127.0.0.0/29", "80,443", shuffle=False, rate=0,
                          start_at=start_at, concurrency=3,
                          on_progress=checkpoint, progress_every=1))
    cursor, completed_hosts, completed_services, prefix_hosts, prefix_services = snapshot[0]
    assert (completed_hosts, completed_services) == (1, 2)
    assert (cursor, prefix_hosts, prefix_services) == (start_at, 0, 0)

    async def resumed_grab(ip, port, timeout):
        return await grab(ip, port, timeout, interrupted=False)

    monkeypatch.setattr(scanner, "_grab", resumed_grab)
    final = asyncio.run(sweep("127.0.0.0/29", "80,443", shuffle=False, rate=0,
                              start_at=cursor, concurrency=3))
    assert (final.hosts_up, final.services) == (2, 3)
    assert (final.resume_hosts_up, final.resume_services) == (2, 3)
    assert final.resume_at == 6


def test_callback_mutation_cannot_change_prefix_accounting(monkeypatch):
    async def grab(ip, port, timeout):
        return scanner.ServiceResult(port=port)

    def consume(hr):
        hr.services.clear()

    monkeypatch.setattr(scanner, "_grab", grab)
    stats = asyncio.run(sweep("127.0.0.0/30", "80,443", rate=0, shuffle=False,
                              on_host=consume))
    assert (stats.hosts_up, stats.services) == (2, 4)
    assert (stats.resume_hosts_up, stats.resume_services) == (2, 4)


@pytest.mark.parametrize("pause", ["grab", "dispatch", "limiter"])
def test_parent_cancellation_drains_workers_at_each_wait_point(monkeypatch, pause):
    """Characterize caller cancellation as well as worker-origin cancellation."""
    async def run():
        ready = asyncio.Event()
        cleaned = asyncio.Event()
        baseline = asyncio.all_tasks()
        real_sleep = asyncio.sleep

        async def grab(ip, port, timeout):
            if ip == "127.0.0.1":
                if pause == "grab":
                    ready.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    await real_sleep(0)
                    cleaned.set()
            return None

        async def sleep(delay):
            if pause == "limiter" and delay > 0:
                ready.set()
                await asyncio.Event().wait()
            else:
                await real_sleep(delay)

        def progress(stats, seed):
            if pause == "dispatch":
                ready.set()

        monkeypatch.setattr(scanner, "_grab", grab)
        monkeypatch.setattr(sweep_module.asyncio, "sleep", sleep)
        task = asyncio.create_task(sweep(
            "127.0.0.0/29", "80", shuffle=False, rate=1 if pause == "limiter" else 0,
            concurrency=2, on_progress=progress, progress_every=1))
        try:
            await asyncio.wait_for(ready.wait(), 2)
            # Let the other worker enter the limiter or bounded-dispatch wait.
            await real_sleep(0)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert cleaned.is_set()
            assert not [worker for worker in asyncio.all_tasks() - baseline
                        if not worker.done()]
        finally:
            pending = list(asyncio.all_tasks() - baseline)
            for worker in pending:
                worker.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

    asyncio.run(run())
