"""Reject invalid runtime budgets before any connector can run."""
import asyncio

import pytest

from rennacs import scanner
from rennacs.sweep import sweep


@pytest.mark.parametrize("option", [
    {"start_at": -2}, {"start_at": 7}, {"start_at": True},
    {"concurrency": 0}, {"concurrency": -1},
    {"progress_every": 0}, {"progress_every": -1},
    {"timeout": 0}, {"timeout": float("nan")},
])
def test_sweep_rejects_invalid_budget_before_connect(option, monkeypatch):
    attempted = []

    async def fake(host, port, timeout):
        attempted.append(host)
        return None

    monkeypatch.setattr(scanner, "_grab", fake)
    with pytest.raises(ValueError):
        asyncio.run(sweep("127.0.0.0/29", "80", rate=0, **option))
    assert attempted == []
