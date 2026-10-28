"""Offline TCP coverage and exact IPv4 workload planning contracts."""

import pytest

from rennacs import ports


def test_named_tcp_profiles_cover_service_families():
    expected = {
        "web": {80, 443, 8000, 8080, 8443},
        "remote": {21, 22, 23, 3389, 5900, 5985, 5986},
        "mail": {25, 110, 143, 465, 587, 993, 995},
        "databases": {1433, 1521, 3306, 5432, 5984, 6379, 9042, 9200, 27017},
        "infrastructure": {53, 111, 135, 139, 389, 445, 636, 2049, 2375, 2376, 6443},
    }
    combined = set(ports.TOP_100)
    for name, required in expected.items():
        resolved = ports.resolve(name)
        assert required <= set(resolved)
        assert resolved == sorted(set(resolved))
        assert all(1 <= port <= 65535 for port in resolved)
        combined.update(resolved)
    assert ports.resolve("multiservice") == sorted(combined)
    assert ports.resolve("top20") == sorted(set(ports.TOP_20))
    assert ports.resolve("top100") == sorted(set(ports.TOP_100))


def test_all_tcp_alias_and_mixed_profiles_are_sorted_unique():
    assert ports.resolve("all-tcp") == ports.resolve("all") == list(range(1, 65536))
    assert ports.resolve(" WEB ,22,80,443,8000-8002") == sorted(
        set(ports.WEB) | {22, 80, 443, 8000, 8001, 8002}
    )


@pytest.mark.parametrize("spec", [
    "", " ", ",", "22,", "22,,80", "0", "65536", "-1", "1-0", "80-22",
    "1-99999999999999999999999999999", "1-2,unknown", "all-tcp,0",
    "22/udp", "1-2-3", "+22", "1_000", None, 22,
])
def test_invalid_port_specs_are_rejected_before_any_expansion(spec, monkeypatch):
    def no_expansion(*args):
        pytest.fail("invalid specification expanded a range before validation")

    monkeypatch.setattr(ports, "range", no_expansion, raising=False)
    with pytest.raises(ValueError):
        ports.resolve(spec)


def test_small_plan_reports_exact_tcp_workload_and_lower_bounds():
    from rennacs.planner import build_plan
    import json

    plan = build_plan("192.0.2.0/30", "22,80,80", rate=2, days=0.5)
    assert plan["transport"] == "tcp"
    assert plan["offline"] is True
    assert plan["scope"] == "192.0.2.0/30"
    assert plan["scope_cidrs"] == ["192.0.2.0/30"]
    assert plan["effective_scope_cidrs"] == ["192.0.2.0/30"]
    assert plan["exclusions"] == []
    assert plan["ports"] == [22, 80]
    assert plan["address_count"] == 4  # address-space coverage, including boundaries
    assert plan["port_count"] == 2
    assert plan["attempt_count"] == 8
    assert plan["duration_lower_bound_seconds"] == 4
    assert plan["duration_lower_bound_days"] == 4 / 86400
    assert plan["required_rate"] == 8 / 43200
    assert plan["rate"] == 2
    assert plan["days"] == 0.5
    assert any("UDP" in warning and "unsupported" in warning for warning in plan["warnings"])
    assert any("retries" in warning and "overhead" in warning for warning in plan["warnings"])
    assert json.loads(json.dumps(plan, allow_nan=False)) == plan


@pytest.mark.parametrize(("scope", "cidrs", "count"), [
    ("192.0.2.3/30,192.0.2.0/31,192.0.2.3", ["192.0.2.0/30"], 4),
    ("192.0.2.2/31,192.0.2.0/31", ["192.0.2.0/30"], 4),
    ("192.0.2.5,192.0.2.0/31", ["192.0.2.0/31", "192.0.2.5/32"], 3),
    ("0.0.0.0/0,192.0.2.0/24", ["0.0.0.0/0"], 4294967296),
])
def test_scope_union_counts_addresses_once_without_hosts_expansion(scope, cidrs, count, monkeypatch):
    import ipaddress
    from rennacs.planner import build_plan

    def no_addresses(*args):
        pytest.fail("planner must not enumerate addresses")

    monkeypatch.setattr(ipaddress.IPv4Network, "hosts", no_addresses)
    monkeypatch.setattr(ipaddress.IPv4Network, "__iter__", no_addresses)
    plan = build_plan(scope, "53")
    assert plan["scope_cidrs"] == cidrs
    assert plan["effective_scope_cidrs"] == cidrs
    assert plan["address_count"] == plan["attempt_count"] == count


@pytest.mark.parametrize(("scope", "exclude", "effective", "count"), [
    ("192.0.2.0/29", ("192.0.2.2/31", "192.0.2.3", "192.0.2.4/31", "198.51.100.1"),
     ["192.0.2.0/31", "192.0.2.6/31"], 4),
    ("192.0.2.0/29", "192.0.2.0/31,192.0.2.7",
     ["192.0.2.2/31", "192.0.2.4/31", "192.0.2.6/32"], 5),
    ("192.0.2.0/29", ("0.0.0.0/0",), [], 0),
    ("0.0.0.0/0", ("0.0.0.0/1", "128.0.0.0/1"), [], 0),
    ("192.0.2.0/31,192.0.2.4/31", ("192.0.2.0/29",), [], 0),
])
def test_exclusions_subtract_union_once_and_report_effective_scope(scope, exclude, effective, count):
    from rennacs.planner import build_plan

    plan = build_plan(scope, "22,53", exclude=exclude)
    assert plan["effective_scope_cidrs"] == effective
    assert plan["address_count"] == count
    assert plan["attempt_count"] == count * 2
    assert plan["exclusions"]
    assert plan["requested_exclusions"] == plan["exclusions"]
    if count == 0:
        assert plan["duration_lower_bound_seconds"] == plan["required_rate"] == 0


def test_public_ipv4_all_tcp_is_static_exact_and_completely_offline(monkeypatch):
    import ipaddress
    import json
    import socket
    from rennacs.planner import build_plan

    special_use = [
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
        "192.31.196.0/24", "192.52.193.0/24", "192.88.99.0/24", "192.168.0.0/16",
        "192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
        "224.0.0.0/4", "240.0.0.0/4",
    ]

    def forbidden(*args, **kwargs):
        pytest.fail("offline planning attempted networking or address enumeration")

    for name in ("socket", "create_connection", "getaddrinfo", "gethostbyname"):
        monkeypatch.setattr(socket, name, forbidden)
    monkeypatch.setattr(ipaddress.IPv4Network, "hosts", forbidden)
    monkeypatch.setattr(ipaddress.IPv4Network, "__iter__", forbidden)
    plan = build_plan("public-ipv4", "all-tcp", exclude=("8.8.8.0/24", "10.0.0.0/8"))
    assert plan["scope"] == "public-ipv4"
    assert plan["scope_kind"] == "static-public-ipv4-candidates"
    assert plan["exclusion_policy"] == "static-special-use-v1"
    assert plan["scope_cidrs"] == ["0.0.0.0/0"]
    assert plan["requested_exclusions"] == ["8.8.8.0/24", "10.0.0.0/8"]
    expected = 2**32 - sum(ipaddress.ip_network(net).num_addresses for net in special_use) - 256
    assert plan["address_count"] == expected
    assert plan["port_count"] == 65535
    assert plan["attempt_count"] == expected * 65535
    assert plan["duration_lower_bound_seconds"] == expected * 65535 / 500
    assert plan["required_rate"] == expected * 65535 / (7 * 86400)
    remaining = [ipaddress.IPv4Network(cidr) for cidr in plan["effective_scope_cidrs"]]
    assert sum(net.num_addresses for net in remaining) == expected
    assert any(ipaddress.IPv4Address("8.8.4.4") in net for net in remaining)
    for excluded in special_use + ["8.8.8.0/24"]:
        assert not any(net.overlaps(ipaddress.IPv4Network(excluded)) for net in remaining)
    warning = " ".join(plan["warnings"])
    assert "static" in warning and "BGP" in warning and "routability" in warning
    assert "UDP" in warning and "unsupported" in warning
    assert json.loads(json.dumps(plan, allow_nan=False)) == plan


@pytest.mark.parametrize("field", ["rate", "days"])
@pytest.mark.parametrize("value", [0, -1, float("nan"), float("inf"), float("-inf"),
                                   True, "500", None, 10**400, 5e-324])
def test_rate_and_window_require_finite_positive_numbers(field, value):
    from rennacs.planner import build_plan

    with pytest.raises(ValueError):
        build_plan("192.0.2.0/30", **{field: value})


def test_window_overflow_is_rejected_instead_of_serializing_infinity():
    from rennacs.planner import build_plan

    with pytest.raises(ValueError):
        build_plan("192.0.2.0/30", days=1e308)


@pytest.mark.parametrize(("field", "value"), [
    ("scope", None), ("scope", 123), ("scope", True), ("scope", []),
    ("scope", ""), ("scope", " "), ("scope", "localhost"),
    ("scope", "192.0.2.0/33"), ("scope", "::/0"),
    ("scope", "192.0.2.1,"), ("scope", "public-ipv4,8.8.8.8"),
    ("exclude", None), ("exclude", 80), ("exclude", b"8.8.8.8"),
    ("exclude", {"8.8.8.8": "ignored"}), ("exclude", ""),
    ("exclude", (None,)), ("exclude", ("::/0",)), ("exclude", ("8.8.8.8,",)),
])
def test_invalid_scopes_or_exclusions_raise_value_error_without_dns(field, value, monkeypatch):
    import socket
    from rennacs.planner import build_plan

    def no_dns(*args, **kwargs):
        pytest.fail("planning attempted hostname resolution")

    monkeypatch.setattr(socket, "getaddrinfo", no_dns)
    args = {"scope": "192.0.2.0/24", field: value}
    with pytest.raises(ValueError):
        build_plan(**args)


def test_defaults_expose_address_space_not_host_or_protocol_completeness():
    from rennacs.planner import build_plan

    plan = build_plan("10.0.0.0/30")
    assert plan["ports"] == ports.resolve("multiservice")
    assert plan["port_spec"] == "multiservice"
    assert plan["rate"] == 500
    assert plan["days"] == 7
    assert plan["address_count"] == 4
    assert plan["address_semantics"] == "all-addresses-including-network-and-broadcast"
    warning = " ".join(plan["warnings"])
    assert "service identification" in warning and "not" in warning
    assert "network/broadcast" in warning


def test_public_plan_runs_without_site_packages_or_scanner_imports():
    import json
    from pathlib import Path
    import subprocess
    import sys

    source = '''
import sys, json

def deny_network(event, args):
    if event.startswith("socket."):
        raise AssertionError("offline planner attempted networking: " + event)

sys.addaudithook(deny_network)
from rennacs.planner import build_plan
plan = build_plan("public-ipv4", "all-tcp")
for name in ("rennacs.scanner", "rennacs.sweep", "rennacs.db", "requests", "flask"):
    assert name not in sys.modules, name
print(json.dumps({key: plan[key] for key in (
    "offline", "transport", "address_count", "port_count", "attempt_count"
)}, allow_nan=False))
'''
    result = subprocess.run(
        [sys.executable, "-S", "-c", source], cwd=Path(__file__).resolve().parents[1],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output["offline"] is True
    assert output["transport"] == "tcp"
    assert output["port_count"] == 65535
    assert output["attempt_count"] == output["address_count"] * 65535


def test_interval_subtraction_matches_small_independent_set_oracle():
    import ipaddress
    import random
    from rennacs.planner import build_plan

    rng = random.Random(2026)

    def expand(networks):
        return {address for net in networks for address in
                range(int(net.network_address), int(net.broadcast_address) + 1)}

    for _ in range(100):
        included = [ipaddress.IPv4Network(f"10.0.0.{rng.randrange(256)}/{rng.randrange(28, 33)}",
                                         strict=False) for _ in range(8)]
        excluded = [ipaddress.IPv4Network(f"10.0.0.{rng.randrange(256)}/{rng.randrange(28, 33)}",
                                         strict=False) for _ in range(8)]
        expected = expand(included) - expand(excluded)
        plan = build_plan(",".join(map(str, included)), "53,22,53",
                          exclude=(str(net) for net in excluded))
        assert expand(map(ipaddress.IPv4Network, plan["effective_scope_cidrs"])) == expected
        assert plan["address_count"] == len(expected)
        assert plan["attempt_count"] == len(expected) * 2
