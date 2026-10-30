"""Authorization is explicit, expiring, and independent of scan policy."""
import ipaddress
import json
from datetime import datetime, timezone


def stamp(value=None):
    if value is None:
        return datetime.now(timezone.utc).isoformat()
    if not isinstance(value, str):
        raise ValueError("timestamp must be an ISO-8601 string")
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp requires a timezone")
    return dt.astimezone(timezone.utc).isoformat()


def age_hours(start, end):
    return (datetime.fromisoformat(stamp(end)) - datetime.fromisoformat(stamp(start))).total_seconds() / 3600


class Scope:
    def __init__(self, data, now=None):
        self.data = data
        self.now = stamp(now)
        if not isinstance(data, dict) or not data.get("engagement") or not data.get("networks"):
            raise ValueError("scope requires engagement and nonempty networks")
        self.networks = []
        for row in data["networks"]:
            net = ipaddress.ip_network(row["cidr"], strict=True)
            # Avoid accidental Internet-wide grants; no implicit private/localhost access.
            if net.prefixlen < (16 if net.version == 4 else 48):
                raise ValueError("scope networks must be /16 (IPv4) or /48 (IPv6) or narrower")
            if not isinstance(row.get("authorization_ref"), str) or not row["authorization_ref"].strip():
                raise ValueError("each network requires an authorization_ref")
            expires = stamp(row["expires_at"])
            if expires <= self.now:
                raise ValueError("scope authorization has expired")
            self.networks.append((net, {**row, "expires_at": expires}))

    @classmethod
    def load(cls, path, **kwargs):
        with open(path, encoding="utf-8") as f:
            return cls(json.load(f), **kwargs)

    def authorize(self, ip, now=None):
        address = ipaddress.ip_address(ip)  # never resolves hostnames
        for net, row in self.networks:
            if address.version == net.version and address in net:
                if row["expires_at"] <= stamp(now):
                    raise ValueError("scope authorization has expired")
                return {**row, "engagement": self.data["engagement"]}
        raise ValueError("address outside explicit authorization allowlist")
