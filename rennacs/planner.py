"""Offline TCP workload arithmetic; never resolves names or contacts targets."""

from __future__ import annotations

import ipaddress
import math
from collections.abc import Iterable, Mapping

from .ports import resolve

# Deliberately static, conservative special-use policy, NOT a live IANA/BGP feed.
# Entire special-use blocks are removed, including globally reachable exceptions
# (e.g. 192.0.0.9/.10 and AS112/AMT services). Change the policy ID on revision.
PUBLIC_IPV4_EXCLUSIONS = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.31.196.0/24", "192.52.193.0/24", "192.88.99.0/24", "192.168.0.0/16",
    "192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4",
)


def _union(intervals):
    """Merge inclusive integer intervals, including adjacent ranges."""
    merged = []
    for lo, hi in sorted(intervals):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(hi, merged[-1][1]))
        else:
            merged.append((lo, hi))
    return merged


def _parse_networks(spec):
    if not isinstance(spec, str) or not spec.strip():
        raise ValueError("scope and exclusions must be nonempty IPv4/CIDR strings")
    intervals = []
    for part in spec.split(","):
        network = ipaddress.IPv4Network(part.strip(), strict=False)
        intervals.append((int(network.network_address), int(network.broadcast_address)))
    return _union(intervals)


def _subtract(intervals, exclusions):
    """Subtract sorted disjoint exclusion intervals with a monotone cursor."""
    remaining = []
    index = 0
    for lo, hi in intervals:
        while index < len(exclusions) and exclusions[index][1] < lo:
            index += 1
        cursor = lo
        cut = index
        while cut < len(exclusions) and exclusions[cut][0] <= hi:
            cut_lo, cut_hi = exclusions[cut]
            if cursor < cut_lo:
                remaining.append((cursor, cut_lo - 1))
            cursor = max(cursor, cut_hi + 1)
            if cursor > hi:
                break
            cut += 1
        index = cut
        if cursor <= hi:
            remaining.append((cursor, hi))
    return remaining


def _cidrs(intervals):
    return [str(network) for lo, hi in intervals
            for network in ipaddress.summarize_address_range(
                ipaddress.IPv4Address(lo), ipaddress.IPv4Address(hi))]


def _positive_number(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite positive number")
    try:
        number = float(value)
    except OverflowError:
        raise ValueError(f"{name} is too large") from None
    if not math.isfinite(number) or number <= 0:
        raise ValueError(f"{name} must be a finite positive number")
    return number


def build_plan(
    scope: str,
    port_spec: str = "multiservice",
    rate: float = 500,
    days: float = 7,
    exclude: Iterable[str] | str = (),
) -> dict:
    """Return an offline, JSON-serializable IPv4/TCP workload estimate.

    ``scope`` is comma-separated IPv4 literals/CIDRs or exactly ``public-ipv4``.
    CIDRs normalize host bits (``strict=False``); overlaps/duplicates count once.
    ``exclude`` is a comma-separated string or iterable of such strings. Explicit
    scopes get only these exclusions; public-ipv4 additionally gets the versioned
    conservative PUBLIC_IPV4_EXCLUSIONS policy, never a live routing lookup.

    ``address_count``, ``port_count`` and ``attempt_count`` are exact integers.
    Duration lower bounds are attempts/rate, required_rate is attempts/(days*86400),
    all in attempts/second and seconds/days as named. Rate/days must be finite,
    positive int/float values; invalid inputs/non-finite estimates raise ValueError.
    scope_cidrs, exclusions, requested_exclusions and effective_scope_cidrs are
    sorted canonical CIDR unions, so the arithmetic's actual target set is visible.

    Counts include every address in each CIDR (network/broadcast included), not
    only ``hosts()``. One attempt per address/port, no retries or measurements.
    This is planning, never authorization or an executable scanner scope. Memory
    scales with CIDRs/exclusions plus at most 65535 ports, never address count.
    """
    rate = _positive_number(rate, "rate")
    days = _positive_number(days, "days")
    window_seconds = days * 86400
    if not math.isfinite(window_seconds):
        raise ValueError("days produces a non-finite planning window")
    public_scope = scope == "public-ipv4"
    intervals = _parse_networks("0.0.0.0/0" if public_scope else scope)
    if isinstance(exclude, (bytes, Mapping)) or not isinstance(exclude, Iterable):
        raise ValueError("exclude must be an IPv4/CIDR string or an iterable of such strings")
    exclusion_specs = [exclude] if isinstance(exclude, str) else exclude
    requested_exclusions = _union([
        interval for spec in exclusion_specs for interval in _parse_networks(spec)
    ])
    static_exclusions = _parse_networks(",".join(PUBLIC_IPV4_EXCLUSIONS)) if public_scope else []
    exclusions = _union(requested_exclusions + static_exclusions)
    effective = _subtract(intervals, exclusions)
    selected_ports = resolve(port_spec)
    address_count = sum(hi - lo + 1 for lo, hi in effective)
    attempt_count = address_count * len(selected_ports)
    seconds = attempt_count / rate
    required_rate = attempt_count / window_seconds
    if not math.isfinite(seconds) or not math.isfinite(required_rate):
        raise ValueError("rate or days produces a non-finite workload estimate")
    return {
        "offline": True,
        "transport": "tcp",
        "scope": scope,
        "scope_kind": "static-public-ipv4-candidates" if public_scope else "explicit-ipv4",
        "exclusion_policy": "static-special-use-v1" if public_scope else "explicit-only",
        "scope_cidrs": _cidrs(intervals),
        "effective_scope_cidrs": _cidrs(effective),
        "exclusions": _cidrs(exclusions),
        "requested_exclusions": _cidrs(requested_exclusions),
        "port_spec": port_spec,
        "ports": selected_ports,
        "address_count": address_count,
        "address_semantics": "all-addresses-including-network-and-broadcast",
        "port_count": len(selected_ports),
        "attempt_count": attempt_count,
        "rate": rate,
        "days": days,
        "duration_lower_bound_seconds": seconds,
        "duration_lower_bound_days": seconds / 86400,
        "required_rate": required_rate,
        "warnings": [
            "TCP only; UDP and other transports are unsupported.",
            "Port coverage is not complete service identification or vulnerability assessment, "
            "even with all-tcp. Counts include network/broadcast addresses; "
            "this is address-space arithmetic, not an executable scanner target list.",
            "Lower bounds exclude retries, timeouts, handshake/banner overhead, "
            "indexing and resource limits; not measured throughput or a weekly capacity guarantee.",
        ] + ([
            "public-ipv4 is a static special-use-excluded candidate space, not live BGP "
            "or routability proof; unannounced and unreachable addresses can remain. "
            "The conservative policy excludes entire special-use blocks including globally "
            "reachable exceptions; permission and provider policy must be checked separately.",
        ] if public_scope else []),
    }
