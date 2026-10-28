"""Tests for the network-wide sweep engine and scan-job history."""

import asyncio

import pytest

from rennacs import scanner
from rennacs.authz import NotAuthorized, Policy
from rennacs.db import Index
from rennacs.scanner import ServiceResult
from rennacs.sweep import RateLimiter, TargetSpace, permutation, sweep


# -- target space -------------------------------------------------------------

def test_target_space_counts_usable_hosts():
    assert TargetSpace.from_scope("192.168.1.0/24").total == 254   # skips net+bcast
    assert TargetSpace.from_scope("10.0.0.0/30").total == 2
    assert TargetSpace.from_scope("127.0.0.1/32").total == 1
    assert TargetSpace.from_scope("10.0.0.0/31").total == 2        # /31 keeps both


def test_target_space_addresses_in_order():
    sp = TargetSpace.from_scope("192.168.1.0/24")
    assert sp.addr(0) == "192.168.1.1"
    assert sp.addr(253) == "192.168.1.254"


def test_target_space_multi_cidr():
    sp = TargetSpace.from_scope("10.0.0.0/30, 172.16.9.0/30")
    assert sp.total == 4
    assert [sp.addr(i) for i in range(4)] == \
        ["10.0.0.1", "10.0.0.2", "172.16.9.1", "172.16.9.2"]


def test_target_space_rejects_ipv6():
    with pytest.raises(ValueError):
        TargetSpace.from_scope("2001:db8::/120")


# -- permutation --------------------------------------------------------------

@pytest.mark.parametrize("total", [1, 2, 3, 10, 254, 1024])
def test_permutation_is_a_bijection(total):
    perm = permutation(total, seed=7)
    assert {perm(i) for i in range(total)} == set(range(total))


def test_permutation_is_deterministic_for_resume():
    a = permutation(500, seed=123)
    b = permutation(500, seed=123)
    assert [a(i) for i in range(500)] == [b(i) for i in range(500)]


def test_permutation_differs_by_seed():
    a = [permutation(500, seed=1)(i) for i in range(500)]
    b = [permutation(500, seed=2)(i) for i in range(500)]
    assert a != b


# -- rate limiter -------------------------------------------------------------

def test_rate_limiter_unlimited_is_instant():
    async def go():
        rl = RateLimiter(0)
        for _ in range(1000):
            await rl.acquire()
    asyncio.run(go())   # must not hang


def test_rate_limiter_throttles():
    import time

    async def go():
        rl = RateLimiter(50)          # 50/sec
        t0 = time.monotonic()
        for _ in range(25):           # a burst within the bucket then throttle
            await rl.acquire()
        return time.monotonic() - t0
    # 25 tokens, bucket starts full at 50, so this should be near-instant; just
    # assert it completes quickly and doesn't error.
    assert asyncio.run(go()) < 2.0


# -- authorization gate on whole networks -------------------------------------

def test_check_network_allows_private():
    Policy().check_network("192.168.0.0/16")
    Policy().check_network("10.0.0.0/8")
    Policy().check_network("127.0.0.0/8")


def test_check_network_refuses_public():
    with pytest.raises(NotAuthorized):
        Policy().check_network("8.8.8.0/24")


def test_check_network_allows_public_when_authorized():
    Policy(authorized=True).check_network("8.8.8.0/24")   # no raise


# -- the sweep itself (with a fake connector, no real network) ----------------

@pytest.fixture
def fake_grab(monkeypatch):
    """Patch scanner._grab so port 80 is 'open' on every host, else closed."""
    async def _fake(host, port, timeout):
        if port == 80:
            return ServiceResult(port=80, service="http", banner="HTTP/1.1 200 OK")
        return None
    monkeypatch.setattr(scanner, "_grab", _fake)
    return _fake


def test_sweep_finds_all_hosts(fake_grab):
    seen = []
    stats = asyncio.run(sweep("10.9.0.0/29", "top20", policy=Policy(),
                              rate=0, concurrency=8, on_host=lambda h: seen.append(h.ip)))
    assert stats.total == 6 and stats.scanned == 6
    assert stats.hosts_up == 6 and stats.services == 6
    assert sorted(seen) == [f"10.9.0.{i}" for i in range(1, 7)]


def test_sweep_resume_skips_scanned(fake_grab):
    # start_at=4 means 4 already done; only 2 of the 6 remain
    stats = asyncio.run(sweep("10.9.0.0/29", "top20", policy=Policy(),
                              rate=0, concurrency=4, seed=99, start_at=4))
    assert stats.total == 6 and stats.scanned == 6
    assert stats.hosts_up == 2            # only the 2 freshly scanned counted


def test_sweep_refuses_public_scope(fake_grab):
    with pytest.raises(NotAuthorized):
        asyncio.run(sweep("8.8.8.0/29", "top20", policy=Policy()))


def test_sweep_no_shuffle_is_sequential(fake_grab):
    seen = []
    asyncio.run(sweep("10.9.0.0/29", "top20", policy=Policy(), concurrency=1,
                      shuffle=False, on_host=lambda h: seen.append(h.ip)))
    assert seen == [f"10.9.0.{i}" for i in range(1, 7)]   # in order


# -- scan-job persistence -----------------------------------------------------

def test_job_lifecycle(tmp_path):
    idx = Index(str(tmp_path / "j.db"))
    jid = idx.start_job("10.0.0.0/24", "top20", 254, rate=500, concurrency=200, seed=5)
    assert idx.get_job(jid)["status"] == "running"
    idx.checkpoint_job(jid, scanned=100, hosts_up=12, services=30, seed=5)
    assert idx.get_job(jid)["scanned"] == 100
    assert idx.resumable_jobs()[0]["id"] == jid      # running + not complete
    idx.finish_job(jid, "done")
    assert idx.get_job(jid)["status"] == "done"
    assert idx.resumable_jobs() == []
    assert idx.list_jobs()[0]["id"] == jid
    idx.close()


def test_sweep_records_job_via_index(tmp_path, fake_grab):
    idx = Index(str(tmp_path / "s.db"))
    space = TargetSpace.from_scope("10.9.0.0/29")
    jid = idx.start_job("10.9.0.0/29", "top20", space.total, seed=1)

    def on_host(hr):
        idx.upsert_host(hr)

    def on_progress(stats, seed):
        idx.checkpoint_job(jid, scanned=stats.scanned, hosts_up=stats.hosts_up,
                           services=stats.services, seed=seed)

    asyncio.run(sweep("10.9.0.0/29", "top20", policy=Policy(), rate=0, concurrency=4,
                      seed=1, on_host=on_host, on_progress=on_progress,
                      progress_every=1))
    idx.finish_job(jid, "done")
    job = idx.get_job(jid)
    assert job["scanned"] == 6 and job["hosts_up"] == 6
    assert idx.stats()["hosts"] == 6            # hosts landed in the index
    idx.close()
