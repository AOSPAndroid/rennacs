"""Authorization gate.

Shodan scans the whole public Internet. Rennacs deliberately refuses to, unless the
operator explicitly asserts they are authorized for a given public target. This module
is the single choke point every scan must pass through, so the policy lives in one
place and is easy to audit.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass


# Reserved / private ranges we consider "safe to scan without extra assertions"
# because they can only refer to the operator's own loopback or lab networks.
_ALWAYS_ALLOWED = [
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("::1/128"),          # loopback v6
    ipaddress.ip_network("10.0.0.0/8"),       # RFC1918
    ipaddress.ip_network("172.16.0.0/12"),    # RFC1918
    ipaddress.ip_network("192.168.0.0/16"),   # RFC1918
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("fc00::/7"),         # unique local v6
    ipaddress.ip_network("fe80::/10"),        # link-local v6
]


class NotAuthorized(Exception):
    """Raised when a target is outside policy and no authorization was asserted."""


@dataclass
class Policy:
    """Scan policy. ``authorized`` is the operator asserting permission for public
    targets (the ``--i-am-authorized`` flag)."""

    authorized: bool = False

    def check(self, ip: str) -> None:
        """Raise :class:`NotAuthorized` unless ``ip`` may be scanned under this policy."""
        addr = ipaddress.ip_address(ip)
        for net in _ALWAYS_ALLOWED:
            if addr.version == net.version and addr in net:
                return
        if self.authorized:
            return
        raise NotAuthorized(
            f"{ip} is a public address. Rennacs only scans localhost and private "
            f"(RFC1918) ranges by default.\n"
            f"Scan it only if you own it or have explicit written permission "
            f"(e.g. your own server, or a sanctioned lab host). "
            f"Re-run with --i-am-authorized to confirm."
        )

    def is_allowed(self, ip: str) -> bool:
        try:
            self.check(ip)
            return True
        except NotAuthorized:
            return False

    def check_network(self, net) -> None:
        """Gate an entire CIDR before a sweep. This is the boundary of "network-wide".

        A network is allowed when it sits wholly inside a private/loopback range, or
        when the operator has asserted authorization (``--i-am-authorized``) for a
        public range they own. We check the WHOLE network up front, so a sweep can
        never quietly spill onto public space the operator didn't authorize.
        """
        net = ipaddress.ip_network(str(net), strict=False)
        for allowed in _ALWAYS_ALLOWED:
            if net.version == allowed.version and net.subnet_of(allowed):
                return
        if self.authorized:
            return
        raise NotAuthorized(
            f"{net} includes public address space. Rennacs only sweeps localhost and "
            f"private (RFC1918) ranges by default.\n"
            f"Sweep a public range only across hosts you own or are explicitly "
            f"permitted to test (your own fleet/VPC, or a sanctioned lab). "
            f"Re-run with --i-am-authorized to confirm you have that permission."
        )
