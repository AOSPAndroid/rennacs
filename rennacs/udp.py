"""UDP service probes — the half of the Internet a TCP-only scanner cannot see.

Three of these matter far more than the rest because they leak the *host OS and
kernel*, which no TCP banner ever does:

* SNMP ``sysDescr`` (UDP/161, community ``public``) — usually a full ``uname`` line.
* DNS ``version.bind`` CHAOS TXT (UDP/53) — resolver software and version.
* NTP mode-6 ``readvar`` (UDP/123) — daemon version, and on some builds the hostname.

Kernel text is what makes kernel CVEs (e.g. CVE-2026-98432) matchable at all, so the
extraction lives in :mod:`rennacs.kernel` and this module only carries the bytes.

Every probe is a single datagram with a short timeout: UDP is lossy and unprivileged,
so a miss is "no answer", never "closed".
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

# OID 1.3.6.1.2.1.1.1.0 — sysDescr.0
_SYSDESCR_OID = bytes([0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])


def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value


def snmp_get(community: str = "public", oid: bytes = _SYSDESCR_OID) -> bytes:
    """A minimal SNMPv1 GetRequest for one OID."""
    varbind = _tlv(0x30, _tlv(0x06, oid) + _tlv(0x05, b""))
    pdu = _tlv(0xA0, _tlv(0x02, b"\x01") + _tlv(0x02, b"\x00")
               + _tlv(0x02, b"\x00") + _tlv(0x30, varbind))
    return _tlv(0x30, _tlv(0x02, b"\x01") + _tlv(0x04, community.encode()) + pdu)


def ntp_readvar() -> bytes:
    """NTP mode 6, opcode 2 (READVAR), no association id."""
    return bytes([0x16, 0x02]) + b"\x00" * 46


def dns_version_bind() -> bytes:
    """CHAOS-class TXT query for ``version.bind``."""
    qname = b"".join(bytes([len(p)]) + p.encode() for p in "version.bind".split(".")) + b"\x00"
    header = struct.pack("!HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0)
    return header + qname + struct.pack("!HH", 16, 3)


def mdns_services() -> bytes:
    """mDNS PTR query for the service-type enumeration name."""
    qname = b"".join(bytes([len(p)]) + p.encode()
                     for p in "_services._dns-sd._udp.local".split(".")) + b"\x00"
    header = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
    return header + qname + struct.pack("!HH", 12, 1)


PROBES: dict[int, tuple[str, bytes]] = {
    161: ("snmp", snmp_get()),
    123: ("ntp", ntp_readvar()),
    53: ("dns", dns_version_bind()),
    5353: ("mdns", mdns_services()),
}


@dataclass
class UdpAnswer:
    port: int
    service: str
    payload: bytes

    @property
    def text(self) -> str:
        return self.payload.decode("latin-1", "replace")


def probe(ip: str, port: int, payload: bytes, timeout: float = 2.5) -> bytes | None:
    """Send one datagram, return the reply or ``None`` on timeout/ICMP."""
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(payload, (ip, port))
            data, _ = sock.recvfrom(8192)
            return data
        except (socket.timeout, OSError):
            return None


def scan(ip: str, ports: list[int] | None = None, timeout: float = 2.5) -> list[UdpAnswer]:
    """Probe the known UDP services on ``ip``; silent ports are simply absent."""
    answers = []
    for port in ports or sorted(PROBES):
        service, payload = PROBES.get(port, ("udp", b"\x00"))
        reply = probe(ip, port, payload, timeout)
        if reply:
            answers.append(UdpAnswer(port=port, service=service, payload=reply))
    return answers
