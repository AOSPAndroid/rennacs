"""Acquisition attribution, not a cryptographic claim that a provider is truthful.

Raw inventory must carry explicit import evidence. Only the active-observation
write path may attribute data to Rennacs itself. Tokens are validated verbatim.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import re
from urllib.parse import urlsplit


_SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z", re.ASCII)


def valid_timestamp(value) -> bool:
    """Require an explicit timezone; never normalize or repair a source token."""
    if not isinstance(value, str) or "T" not in value or value != value.strip():
        return False
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None


def validate_import(value) -> dict:
    """Return a detached, lossless provenance object or reject before any write."""
    if not isinstance(value, dict) or value.get("kind") != "import":
        raise ValueError("import provenance is required")
    source = value.get("source")
    if (not isinstance(source, str) or not source or source != source.strip()
            or source.casefold() in {"demo", "synthetic", "legacy_unverified", "rennacs"}):
        raise ValueError("provenance source must identify an import provider")
    if not valid_timestamp(value.get("retrieved_at")):
        raise ValueError("provenance retrieved_at must be a timezone-aware ISO8601 timestamp")
    reference = value.get("reference")
    try:
        url = urlsplit(reference) if isinstance(reference, str) else None
        valid_url = (url is not None and url.scheme == "https" and url.hostname
                     and not url.username and not url.password
                     and not any(c.isspace() or ord(c) < 32 for c in reference))
        if url is not None:
            url.port  # reject malformed ports as well
    except ValueError:
        valid_url = False
    if not valid_url:
        raise ValueError("provenance reference must be an HTTPS URL")
    digest = value.get("payload_sha256")
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise ValueError("provenance payload_sha256 must be exactly 64 hex characters")
    return deepcopy(value)


def is_sourced(value) -> bool:
    """Fail closed for absent, malformed or unsupported persisted attribution."""
    try:
        parsed = json.loads(value)
        if isinstance(parsed, dict) and parsed.get("kind") == "scan":
            return (parsed.get("source") == "rennacs"
                    and valid_timestamp(parsed.get("observed_at"))
                    and valid_timestamp(parsed.get("retrieved_at"))
                    and isinstance(parsed.get("payload_sha256"), str)
                    and bool(_SHA256.fullmatch(parsed["payload_sha256"]))
                    and "reference" not in parsed)
        validate_import(parsed)
    except (TypeError, ValueError):
        return False
    return True


def scan_provenance(evidence: dict, observed_at: str) -> dict:
    """Attribute captured active-observation evidence internally, never to a provider."""
    if not valid_timestamp(observed_at):
        raise ValueError("scan observed_at must be a timezone-aware ISO8601 timestamp")
    payload = json.dumps(evidence, sort_keys=True, separators=(",", ":"), allow_nan=False)
    result = {"kind": "scan", "source": "rennacs", "observed_at": observed_at,
              "retrieved_at": datetime.now(timezone.utc).isoformat(),
              "payload_sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest()}
    if "banner" in evidence:
        result["banner_sha256"] = hashlib.sha256(evidence["banner"].encode("utf-8")).hexdigest()
    return result
