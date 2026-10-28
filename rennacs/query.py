"""Shodan-style filter query language -> parameterised SQL.

A query is a space-separated list of terms:

    free text        -> substring match against the flattened search_text
    filter:value     -> a structured constraint (port:22, product:nginx, ...)
    filter:"a b"     -> quoted value with spaces
    -term            -> negate the term (NOT)

All terms are ANDed together, which matches Shodan's default behaviour. Values always
go into SQL as bound parameters, never string-interpolated, so a query can't inject SQL.

The compiler returns (where_sql, params). ``where_sql`` is always a valid boolean
expression (defaults to "1" for an empty query) suitable for the WHERE clause in
:meth:`rennacs.db.Index.search`.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

# Map a filter name to the SQL column it constrains and how it compares.
# kind: "eq" exact, "like" substring, "bool", "net" CIDR, "date_before"/"date_after".
_FILTERS = {
    "port":      ("s.port", "eq_int"),
    "product":   ("s.product", "like"),
    "version":   ("s.version", "like"),
    "service":   ("s.service", "like"),
    "os":        ("s.os", "like"),
    "ip":        ("s.ip", "eq"),
    "hostname":  ("h.hostnames", "like"),
    "org":       ("h.org", "like"),
    "tag":       ("h.tags", "like"),
    "country":   ("h.country", "eq_ci"),
    "city":      ("h.city", "like"),
    "asn":       ("h.asn", "eq_ci"),
    "has_ssl":   ("s.has_ssl", "bool"),
    "ssl.cn":    ("s.ssl_cn", "like"),
    "vuln":      ("s.vuln_ids", "like"),
    "has_vuln":  ("s.vuln_ids", "notempty"),
    "kev":       ("s.kev", "bool"),
    "net":       ("s.ip", "net"),
    "before":    ("s.seen_at", "date_before"),
    "after":     ("s.seen_at", "date_after"),
}

ALIASES = {"has_screenshot": None}  # reserved / unsupported filters -> ignored


@dataclass
class Term:
    raw: str
    negate: bool
    filt: str | None     # filter name, or None for free text
    value: str


class QueryError(ValueError):
    pass


def tokenize(q: str) -> list[Term]:
    terms: list[Term] = []
    # shlex keeps quoted groups together but splits filter:"..." awkwardly, so we
    # pre-split on whitespace while honouring quotes manually.
    try:
        parts = _split(q)
    except ValueError as e:
        raise QueryError(str(e))
    for p in parts:
        if not p:
            continue
        negate = False
        if p.startswith("-") and len(p) > 1:
            negate = True
            p = p[1:]
        if ":" in p and not p.startswith(":"):
            filt, value = p.split(":", 1)
            filt = filt.lower()
            value = value.strip().strip('"')
            terms.append(Term(raw=p, negate=negate, filt=filt, value=value))
        else:
            terms.append(Term(raw=p, negate=negate, filt=None, value=p.strip('"')))
    return terms


def _split(q: str) -> list[str]:
    """Whitespace split that keeps double-quoted substrings (incl. filter:"a b")
    intact. Only the double quote is special, so values may freely contain
    apostrophes (e.g. a banner fragment like ``O'Brien``)."""
    out, buf, in_quote = [], [], False
    for ch in q.strip():
        if in_quote:
            if ch == '"':
                in_quote = False
            else:
                buf.append(ch)
        elif ch == '"':
            in_quote = True
        elif ch.isspace():
            if buf:
                out.append("".join(buf))
                buf = []
        else:
            buf.append(ch)
    if in_quote:
        raise ValueError("unbalanced quote in query")
    if buf:
        out.append("".join(buf))
    return out


def compile_query(q: str) -> tuple[str, list]:
    terms = tokenize(q or "")
    clauses: list[str] = []
    params: list = []

    for t in terms:
        if t.filt is None:
            sql, p = _free_text(t.value)
        elif t.filt in ALIASES:
            continue
        elif t.filt in _FILTERS:
            sql, p = _filter_clause(t.filt, t.value)
        else:
            raise QueryError(f"unknown filter: {t.filt!r}")
        if t.negate:
            sql = f"NOT ({sql})"
        clauses.append(sql)
        params.extend(p)

    if not clauses:
        return "1", []
    return " AND ".join(clauses), params


def _free_text(value: str) -> tuple[str, list]:
    return "s.search_text LIKE ?", [f"%{value.lower()}%"]


def _filter_clause(name: str, value: str) -> tuple[str, list]:
    col, kind = _FILTERS[name]

    if kind == "eq_int":
        if not value.isdigit():
            raise QueryError(f"{name}: expected a number, got {value!r}")
        return f"{col} = ?", [int(value)]

    if kind == "eq":
        return f"{col} = ?", [value]

    if kind == "eq_ci":
        return f"UPPER({col}) = UPPER(?)", [value]

    if kind == "like":
        return f"{col} LIKE ?", [f"%{value}%"]

    if kind == "bool":
        truthy = value.lower() in ("1", "true", "yes", "y")
        return f"{col} = ?", [1 if truthy else 0]

    if kind == "notempty":
        # has_vuln:true -> column is non-empty; has_vuln:false -> empty/NULL.
        truthy = value.lower() in ("1", "true", "yes", "y")
        if truthy:
            return f"({col} IS NOT NULL AND {col} <> '')", []
        return f"({col} IS NULL OR {col} = '')", []

    if kind == "net":
        return _net_clause(value)

    if kind in ("date_before", "date_after"):
        op = "<" if kind == "date_before" else ">"
        return f"{col} {op} ?", [value]

    raise QueryError(f"unhandled filter kind: {kind}")


def _net_clause(cidr: str) -> tuple[str, list]:
    """Match s.ip inside an IPv4 CIDR.

    The index stores each IPv4 address as a 32-bit integer (``ip_int``), so a CIDR is
    just a BETWEEN over the network/broadcast bounds — fast, index-friendly, and
    injection-safe because the bounds are bound parameters.
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        raise QueryError(f"net: invalid CIDR {cidr!r}: {e}")
    if net.version != 4:
        raise QueryError("net: only IPv4 CIDRs are supported")
    lo, hi = int(net.network_address), int(net.broadcast_address)
    return "(s.ip_int BETWEEN ? AND ?)", [lo, hi]


def describe() -> dict:
    """Return the supported filters, for the UI's filter-reference panel."""
    return {name: kind for name, (col, kind) in _FILTERS.items()}
