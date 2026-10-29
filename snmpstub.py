import socket

from rennacs.udp import _SYSDESCR_OID, _tlv

DESCR = b"Linux web01 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64"
vb = _tlv(0x30, _tlv(0x06, _SYSDESCR_OID) + _tlv(0x04, DESCR))
pdu = _tlv(0xA2, _tlv(0x02, b"\x01") + _tlv(0x02, b"\x00") + _tlv(0x02, b"\x00") + _tlv(0x30, vb))
resp = _tlv(0x30, _tlv(0x02, b"\x01") + _tlv(0x04, b"public") + pdu)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 161))
print("stub listening on 127.0.0.1:161", flush=True)
for _ in range(5):
    data, addr = s.recvfrom(4096)
    s.sendto(resp, addr)
