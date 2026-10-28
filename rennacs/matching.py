"""Conservative product-bound matching of raw, cached cve.now advisories.

No I/O, exploits, runtime dependencies or imports from the lossy legacy matcher.
Affected-range membership is advisory evidence, never asset confirmation. The
caller owns caching, catalog revision/coverage/freshness and asset assessment.
"""
from __future__ import annotations

import math
import re
from copy import deepcopy

_ID = re.compile(
    r"(?:CVE-[0-9]{4}-[0-9]{4,}|"
    r"GHSA-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}|"
    r"(?!(?:CVE|GHSA)-)[A-Z]{2,}-[0-9]{4}-[0-9]+)"
)

# Product aliases, not CVE rules. Edition names must remain separate identities.
_ALIAS_GROUPS = (
    ("apache http server", "apache httpd", "httpd"),
    ("nginx", "nginx open source"),
    ("dropbear", "dropbear ssh"),
    ("microsoft iis", "iis", "internet information services",
     "microsoft internet information services"),
)

_VENDORS = {
    "apache httpd": {"apache", "apache software foundation", "the apache software foundation"},
    "nginx": {"f5", "f5 networks", "nginx", "nginx inc.", "nginx, inc."},
    "nginx plus": {"f5", "f5 networks", "nginx", "nginx inc.", "nginx, inc."},
    "openssh": {"openbsd", "openbsd project", "openssh"},
    "microsoft iis": {"microsoft", "microsoft corporation"},
}


def _identity(value: object) -> str:
    return " ".join(value.casefold().split()) if isinstance(value, str) else ""


def product_keys(product: str) -> tuple[str, ...]:
    """Return sorted exact lookup keys, expanding only explicit product aliases.

    Every key uses precisely ``' '.join(value.casefold().split())``, matching
    catalog product/package indexes. Unknown names retain their exact normalized
    spelling; there is no punctuation removal, substring search or fuzzy match.
    """
    key = _identity(product)
    for aliases in _ALIAS_GROUPS:
        if key in aliases:
            return tuple(sorted(aliases))
    return (key,) if key else ()


def _compatible(row: dict, keys: tuple[str, ...]) -> bool:
    """Require a coherent upstream identity, not a similarly named component."""
    if not isinstance(row, dict):
        return False
    if any(row.get(field) is not None and not isinstance(row[field], str)
           for field in ("product", "vendor", "ecosystem", "edition")):
        return False
    package = row.get("package")
    package_name = package.get("name") if isinstance(package, dict) else package
    name = _identity(row.get("product"))
    if name not in keys and _identity(package_name) not in keys:
        return False
    # A package nested under a different product/edition is not that upstream service.
    if name and name not in keys:
        return False
    if _identity(package_name) and _identity(package_name) not in keys:
        return False
    vendor = _identity(row.get("vendor"))
    for family, vendors in _VENDORS.items():
        if family in keys and vendor and vendor not in vendors:
            return False
    ecosystems = [row.get("ecosystem")]
    if isinstance(package, dict):
        ecosystems.append(package.get("ecosystem"))
    if any(value is not None and not isinstance(value, str) for value in ecosystems):
        return False
    if any(_identity(value) not in ("", "generic") for value in ecosystems):
        return False
    edition = _identity(row.get("edition"))
    if edition and not (("nginx" in keys and edition in {"open source", "oss"})
                        or ("nginx plus" in keys and edition == "plus")):
        return False
    return True


def _version(value: object, openssh: bool = False) -> tuple | None:
    """Keep numeric and OpenSSH portable releases in separate order domains."""
    if not isinstance(value, str) or len(value) > 256:
        return None
    pattern = r"([0-9]+(?:\.[0-9]+)*)(?:p([0-9]+))?" if openssh else r"([0-9]+(?:\.[0-9]+)*)"
    match = re.fullmatch(pattern, value)
    if not match:
        return None
    parts = tuple(int(part) for part in match[1].split("."))
    while len(parts) > 1 and parts[-1] == 0:
        parts = parts[:-1]
    portable = match[2] if openssh else None
    return ("portable" if portable is not None else "numeric", parts,
            int(portable) if portable is not None else 0)


def _bounds(bounds: dict, openssh: bool) -> dict | None:
    """Reject unsupported shapes/schemes and contradictory known bounds."""
    if (not isinstance(bounds, dict) or not bounds
            or set(bounds) - {"introduced", "fixed", "lastAffected", "type", "versionType"}
            or not _supported_scheme(bounds)):
        return None
    parsed = {name: _version(bounds[name], openssh)
              for name in ("introduced", "fixed", "lastAffected") if name in bounds}
    lower = parsed.get("introduced")
    for name in ("fixed", "lastAffected"):
        upper = parsed.get(name)
        if lower and upper and lower[0] == upper[0]:
            if lower > upper or (name == "fixed" and lower == upper):
                return None
    return parsed or None


def _range_state(version: tuple | None, bounds: dict, openssh: bool) -> str:
    """A known excluding bound can prove outside; wildcard/text cannot prove in."""
    parsed = _bounds(bounds, openssh)
    if version is None or parsed is None:
        return "unknown"
    unknown = False
    for name, bound in parsed.items():
        if name == "introduced" and bounds[name] == "0":
            continue  # OSV's explicit beginning-of-history sentinel, not a p release.
        if bound is None or version[0] != bound[0]:
            unknown = True
        elif ((name == "introduced" and version < bound)
              or (name == "fixed" and version >= bound)
              or (name == "lastAffected" and version > bound)):
            return "outside"
    return "unknown" if unknown else "affected"


def _supported_scheme(value: dict) -> bool:
    return isinstance(value, dict) and all(
        (value.get(field) is None or isinstance(value[field], str))
        and _identity(value.get(field)) in {"", "semver", "numeric"}
        for field in ("type", "versionType"))


def _union(states: list[str]) -> str:
    """One proven affected interval wins; outside requires every interval outside."""
    return ("affected" if "affected" in states else "unknown"
            if not states or "unknown" in states else "outside")


def _record_state(version: tuple | None, row: dict, openssh: bool) -> str:
    if version is None or not _supported_scheme(row):
        return "unknown"
    ranges, versions = row.get("ranges", []), row.get("versions", [])
    states = ([_range_state(version, bounds, openssh) for bounds in ranges]
              if isinstance(ranges, list) else ["unknown"])
    if not isinstance(versions, list):
        versions = []
        states.append("unknown")
    for item in versions:
        exact = _version(item, openssh)
        states.append("unknown" if exact is None or exact[0] != version[0] else
                      "affected" if exact == version else "outside")
    return _union(states)


def _summary(raw: dict) -> tuple[str, dict]:
    summary = raw.get("summary")
    text = summary.get("text") if isinstance(summary, dict) else summary
    if isinstance(text, str) and text:
        metadata = ({key: deepcopy(value) for key, value in summary.items() if key != "text"}
                    if isinstance(summary, dict) else {})
        return text, {"field": "summary", "kind": "catalog_summary_may_be_model_written",
                      "metadata": metadata}
    for field, kind in (("originalDescription", "sourced_description"), ("title", "catalog_title")):
        text = raw.get(field)
        if isinstance(text, str) and text:
            return text, {"field": field, "kind": kind, "metadata": {}}
    return "", {"field": "", "kind": "unavailable", "metadata": {}}


def _severity(raw: dict) -> tuple[float | None, str]:
    metadata = raw.get("severity")
    score = metadata.get("cvss") if isinstance(metadata, dict) else None
    try:
        score = None if isinstance(score, bool) else float(score)
    except (TypeError, ValueError, OverflowError):
        score = None
    if score is not None and (not math.isfinite(score) or not 0 <= score <= 10):
        score = None
    if score is not None:
        label = ("critical" if score >= 9 else "high" if score >= 7 else
                 "medium" if score >= 4 else "low" if score > 0 else "none")
    else:
        label = _identity(raw.get("statedSeverity"))
        if label not in {"critical", "high", "medium", "low", "none"}:
            label = "unknown"
    return score, label


def match_advisory(product: str, version: str, raw_advisory: dict) -> dict | None:
    """Return one low-confidence potential finding from a raw cached advisory.

    ``match_status`` is affected/unknown; legacy ``confirmed`` is yes/unknown
    ONLY for range membership, never confirmation of a vulnerable host. Numeric
    releases and OpenSSH p releases support inclusive introduced/lastAffected,
    exclusive fixed, and exact string versions. Unsupported schemes, missing
    evidence and ambiguous bounds remain unknown, not proof of security.

    ``matched_affected`` (also ``affected`` for compatibility) contains deep-copied
    compatible product/package records, with original bounds intact. Fixes are
    explicit supported fixed bounds from potentially applicable matched ranges;
    none are inferred from lastAffected or another product/edition/branch.

    Return None only for no compatible identity, rejection/withdrawal, or every
    matching interval/version proven outside. A malformed or missing advisory
    ID raises ValueError: CVE/GHSA/OSV-style ASCII tokens are never repaired,
    case-normalized, stripped, or replaced with feedId. Input is never mutated.
    """
    identifier = raw_advisory.get("id")
    if not isinstance(identifier, str) or not _ID.fullmatch(identifier):
        raise ValueError("invalid advisory ID")
    if (_identity(raw_advisory.get("status")) in {"rejected", "withdrawn"}
            or raw_advisory.get("withdrawn") or raw_advisory.get("withdrawnAt")):
        return None
    keys = product_keys(product)
    matched = [row for row in raw_advisory.get("affected", []) if _compatible(row, keys)]
    if not matched:
        return None
    openssh = "openssh" in keys
    parsed = _version(version, openssh)
    superseded = (_identity(raw_advisory.get("status")) == "superseded"
                  or bool(raw_advisory.get("supersededBy")))
    state = "unknown" if superseded else _union(
        [_record_state(parsed, row, openssh) for row in matched])
    if state == "outside":
        return None
    fixed_versions = sorted({bounds["fixed"] for row in matched
                             if not superseded and _supported_scheme(row)
                             and isinstance(row.get("ranges"), list)
                             for bounds in row.get("ranges", [])
                             if _bounds(bounds, openssh) is not None
                             and _range_state(parsed, bounds, openssh) != "outside"
                             and _version(bounds.get("fixed"), openssh) is not None})

    cvss, label = _severity(raw_advisory)
    summary, summary_provenance = _summary(raw_advisory)
    exploitation = raw_advisory.get("exploitation")
    kev_metadata = exploitation.get("kev") if isinstance(exploitation, dict) else None
    kev = kev_metadata is True or (isinstance(kev_metadata, dict) and bool(kev_metadata))
    matched = deepcopy(matched)
    return {
        "cve": identifier, "catalog_id": identifier, "source": "cve.now-catalog",
        "source_url": f"https://cve.now/{identifier}",
        "detection_method": "catalog_product_version", "match_status": state,
        "confirmed": "yes" if state == "affected" else "unknown", "confidence": "low",
        "summary": summary, "summary_provenance": summary_provenance,
        "original_description": raw_advisory.get("originalDescription") or "",
        "sources": deepcopy(raw_advisory.get("sources") or []),
        "superseded_by": deepcopy(raw_advisory.get("supersededBy") or []),
        "severity": label, "cvss": cvss,
        "kev": kev,
        "fixed_versions": fixed_versions, "matched_affected": matched, "affected": matched,
        "limitations": [
            "A product/version match is not proof of vulnerability or exploitation.",
            "Distribution backports, platform, build and configuration are not verified.",
            "Unknown version-range membership is not proof of security.",
            "The legacy confirmed field describes version-range membership only.",
            "Catalog summaries may be model-written; summary provenance is preserved.",
            "KEV describes exploitation elsewhere, not exploitation of this host.",
        ] + (["Advisory is superseded; replacement applicability was not evaluated."]
             if superseded else []),
    }
