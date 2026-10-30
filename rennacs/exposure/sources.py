"""Bounded official-source adapters. No asset connections or Shodan scan calls."""
import gzip
import ipaddress
import json
import os
import re
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime
from urllib.parse import urlencode, urlsplit

from .scope import stamp
from .store import encoded

VENDOR_HOSTS = {
    "microsoft": {"api.msrc.microsoft.com", "msrc.microsoft.com"},
    "citrix": {"support.citrix.com", "www.netscaler.com", "support.netscaler.com"},
    "aruba": {"www.arubanetworks.com", "csaf.arubanetworks.com", "support.hpe.com"},
}
CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
CAP = 16 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def trusted_url(url, hosts):
    u = urlsplit(url)
    if (u.scheme != "https" or u.hostname not in hosts or u.username or u.password
            or u.port not in (None, 443) or u.fragment):
        raise ValueError("source URL must use an approved official HTTPS host")
    return url


class Remote:
    def __init__(self, interval=1.0):
        self.opener = urllib.request.build_opener(NoRedirect())
        self.last = 0.0
        self.interval = interval

    def get(self, url, hosts, *, json_body=True, max_bytes=CAP):
        trusted_url(url, hosts)
        time.sleep(max(0, self.interval - (time.monotonic() - self.last)))
        self.last = time.monotonic()
        req = urllib.request.Request(url, headers={"User-Agent": "Rennacs-PassiveExposure/1.0",
                                                  "Accept": "application/json" if json_body else "application/xml"})
        try:
            with self.opener.open(req, timeout=15) as response:
                body = response.read(max_bytes + 1)
                if len(body) > max_bytes:
                    raise ValueError("upstream response exceeds configured size limit")
        except (OSError, ValueError) as exc:
            # Never include request URLs: Shodan authenticates via a query parameter.
            status = getattr(exc, "code", "network")
            raise ValueError(f"upstream request failed ({status}); check connectivity, credentials and entitlements") from None
        if not json_body:
            return body
        try:
            return json.loads(body)
        except (ValueError, UnicodeError):
            raise ValueError("upstream did not return valid JSON") from None


class Shodan:
    def __init__(self, remote=None):
        self.key = os.environ.get("SHODAN_API_KEY", "")
        if not self.key:
            raise ValueError("set SHODAN_API_KEY in the process environment; never commit it")
        self.remote = remote or Remote()

    def _get(self, path, **params):
        return self.remote.get("https://api.shodan.io/" + path + "?" +
                               urlencode({**params, "key": self.key}), {"api.shodan.io"})

    def capabilities(self):
        raw = self._get("api-info")
        return {k: raw.get(k) for k in ("plan", "query_credits", "scan_credits", "monitored_ips", "unlocked")}

    def host(self, ip, scope, history=False):
        ip = str(ipaddress.ip_address(ip))
        scope.authorize(ip)  # gate before request, including cached/history lookups
        return self._get("shodan/host/" + ip, history=str(history).lower(), minify="false")


def observation(raw, scope, now=None):
    if not isinstance(raw, dict):
        raise ValueError("Shodan banner must be an object")
    ip = str(ipaddress.ip_address(raw["ip_str"]))
    authorization = scope.authorize(ip, now)
    port = raw["port"]
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid service port")
    transport = raw.get("transport", "tcp")
    if transport not in {"tcp", "udp"}:
        raise ValueError("invalid transport")
    observed = raw["timestamp"]
    # Shodan's documented banner timestamp is UTC, often without a suffix.
    if isinstance(observed, str) and not re.search(r"(?:Z|[+-][0-9]{2}:[0-9]{2})$", observed):
        observed += "+00:00"
    observed = stamp(observed)
    if observed > stamp(now):
        raise ValueError("observation timestamp is in the future")
    for k in ("product", "version"):
        if not isinstance(raw.get(k, ""), str):
            raise ValueError(f"invalid Shodan {k}")
    return {"ip": ip, "port": port, "transport": transport,
            "product": raw.get("product", ""), "version": raw.get("version", ""),
            "observed_at": observed, "source": "shodan", "authorization": authorization,
            "raw": raw}


def import_shodan(path, scope, store):
    # Shodan Terminal exports are NDJSON, optionally gzip; a host-lookup JSON
    # object or a {matches:[...]} search export also works. Fail atomically.
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rb") as f:
        body = f.read(CAP + 1)
    if len(body) > CAP:
        raise ValueError("export exceeds 16 MiB uncompressed; split into batches")
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        data = [json.loads(line) for line in body.splitlines() if line.strip()]
    if isinstance(data, dict):
        data = [data] if "port" in data and "ip_str" in data else data.get("matches", data.get("data", []))
    if not isinstance(data, list) or len(data) > 10000:
        raise ValueError("export must contain at most 10000 banners")
    rows = [observation(row, scope) for row in data]
    for row in rows:
        encoded(row)  # validate finite JSON before storing any record in this batch
    return sum(store.observation(row) for row in rows)


def published(value):
    if not isinstance(value, str) or not value:
        raise ValueError("vendor disclosure date missing")
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        return stamp(value + "T00:00:00Z")
    try:
        return stamp(value)
    except ValueError:
        return stamp(parsedate_to_datetime(value).isoformat())


def validate_advisory(row):
    if not isinstance(row, dict) or not CVE.fullmatch(row.get("id", "")):
        raise ValueError("advisory requires an exact CVE ID")
    vendor = row.get("vendor")
    if vendor not in VENDOR_HOSTS:
        raise ValueError("unsupported vendor")
    trusted_url(row["source_url"], VENDOR_HOSTS[vendor])
    out = {**row, "published_at": published(row["published_at"])}
    if out["published_at"] > stamp():
        raise ValueError("disclosure date is in the future")
    if not isinstance(row.get("affected"), list):
        raise ValueError("affected product list required (may be empty)")
    for affected in row["affected"]:
        if not isinstance(affected, dict) or not isinstance(affected.get("product"), str):
            raise ValueError("affected entry requires product")
        if not isinstance(affected.get("ranges", []), list):
            raise ValueError("ranges must be a list")
    if any(a.get("ranges") or a.get("versions") for a in row["affected"]):
        if not row.get("reviewed_by") or not row.get("range_evidence_ref"):
            raise ValueError("machine-matchable rules require reviewed_by and range_evidence_ref")
    return out


def parse_feed(body, vendor, source_url):
    """RSS/Atom discovers CVEs/dates; prose is retained, never regexed into fixes."""
    if b"<!DOCTYPE" in body.upper() or b"<!ENTITY" in body.upper():
        raise ValueError("DTD/entity declarations are forbidden")
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        raise ValueError("vendor feed is not valid XML") from None
    rows = []
    for item in root.iter():
        if item.tag.split("}")[-1] not in {"item", "entry"}:
            continue
        values = {}
        for child in item:
            key = child.tag.split("}")[-1]
            values[key] = child.get("href") or "".join(child.itertext())
        text = " ".join(values.values())
        ids = sorted(set(CVE.findall(text)))
        if not ids:
            continue
        date = values.get("pubDate") or values.get("published") or values.get("updated")
        # Updated-only feeds cannot establish original disclosure: leave un-ingested.
        if not (values.get("pubDate") or values.get("published")):
            raise ValueError("feed lacks original publication date; ingest a reviewed advisory")
        for cve in ids:
            rows.append(validate_advisory({"id": cve, "vendor": vendor,
                "title": values.get("title", cve), "published_at": published(date),
                "source_url": values.get("link") or source_url, "affected": [],
                "affected_text": text, "raw": values,
                "date_basis": "vendor feed publication; verify original disclosure"}))
    return rows


def parse_msrc(raw, source_url):
    """CVRF preserves affected Windows editions, KB remediations and raw evidence.

    A network service version is never treated as a Windows patch/KB inventory.
    """
    names = {p["ProductID"]: p.get("Value", p["ProductID"])
             for p in raw.get("ProductTree", {}).get("FullProductName", [])}
    result = []
    for vuln in raw.get("Vulnerability", []):
        cve = vuln.get("CVE", "")
        if not CVE.fullmatch(cve):
            continue
        dates = [r["Date"] for r in vuln.get("RevisionHistory", []) if r.get("Date")]
        # Do not substitute the monthly document's date for an individual CVE.
        if not dates:
            continue
        affected = [{"product": names.get(pid, pid), "ranges": [], "product_id": pid}
                    for status in vuln.get("ProductStatuses", []) if status.get("Type") in (3, "Known Affected", "KnownAffected")
                    for pid in status.get("ProductID", [])]
        title = vuln.get("Title", {})
        result.append(validate_advisory({"id": cve, "vendor": "microsoft",
            "title": title.get("Value", cve) if isinstance(title, dict) else title,
            "published_at": min(published(d + "Z" if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?", d) else d)
                                for d in dates), "source_url": source_url,
            "affected": affected, "remediations": vuln.get("Remediations", []),
            "affected_text": "\n".join(a["product"] for a in affected),
            "date_basis": "earliest vulnerability revision in vendor CVRF; timezone-omitted vendor dates interpreted as UTC", "raw": vuln}))
    return result


def sync_microsoft(store, since, limit=2, remote=None):
    if not 1 <= limit <= 12:
        raise ValueError("MSRC document limit must be 1..12")
    remote = remote or Remote()
    cutoff = published(since)
    base = "https://api.msrc.microsoft.com/cvrf/v3.0/"
    listing = remote.get(base + "updates", VENDOR_HOSTS["microsoft"])
    updates = listing.get("value")
    if not isinstance(updates, list):
        raise ValueError("unexpected MSRC update-list schema")
    candidates = sorted([u for u in updates if published(u["CurrentReleaseDate"]) >= cutoff],
                        key=lambda u: u["CurrentReleaseDate"], reverse=True)
    candidates = [u for u in candidates if store.source_revision("msrc:" + u["ID"]) != u["CurrentReleaseDate"]]
    count = 0
    for update in candidates[:limit]:
        identifier = update["ID"]
        if not re.fullmatch(r"[0-9]{4}-[A-Za-z]{3}", identifier):
            raise ValueError("unexpected MSRC document ID")
        url = base + "cvrf/" + identifier
        rows = parse_msrc(remote.get(url, VENDOR_HOSTS["microsoft"], max_bytes=64 * 1024 * 1024), url)
        for row in rows:
            # Store all CVEs in a revised month, including earlier disclosures.
            store.advisory(row)
            count += 1
        store.checkpoint_source("msrc:" + identifier, update["CurrentReleaseDate"])
    return {"documents": min(limit, len(candidates)), "advisories": count,
            "remaining_documents": max(0, len(candidates) - limit),
            "index_has_next_page": bool(listing.get("@odata.nextLink")),
            "coverage": "bounded monthly documents from one update-index response; not complete vendor coverage"}
