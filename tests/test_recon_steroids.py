"""Tests for the recon-steroids additions: edge classification, kernel extraction,
UDP packet builders and CT classification."""

from __future__ import annotations

import ipaddress

import pytest

from rennacs import cdn, ct, kernel, udp


# -- edge classification -------------------------------------------------------

def test_classifies_cloudflare_and_cloudfront():
    edges = cdn.EdgeMap()
    assert edges.classify("104.16.1.1") == "cloudflare"
    assert edges.classify("13.227.231.51") == "cloudfront"
    assert edges.is_proxy_edge("13.227.231.51")


def test_plain_hosting_ip_is_not_edge():
    edges = cdn.EdgeMap()
    assert edges.classify("141.94.132.37") is None
    assert edges.classify("46.105.32.100") is None


def test_garbage_input_is_not_edge():
    assert cdn.EdgeMap().classify("not-an-ip") is None


def test_seed_map_is_reported_stale():
    assert cdn.EdgeMap().stale is True


def test_cache_roundtrip(tmp_path):
    path = tmp_path / "ranges.json"
    edges = cdn.EdgeMap(path=path)
    edges._nets = {"cloudflare": cdn._parse(["104.16.0.0/13"])}
    edges.fetched_at = 1e12
    edges.source = "cache"
    path.write_text('{"fetched_at": 1000000000000, "ranges": {"cloudflare": ["104.16.0.0/13"]}}')
    reloaded = cdn.EdgeMap(path=path)
    assert reloaded.classify("104.16.5.5") == "cloudflare"
    assert reloaded.stale is False


def test_aws_extract_keeps_only_cloudfront():
    body = ('{"prefixes": [{"ip_prefix": "13.32.0.0/15", "service": "CLOUDFRONT"},'
            ' {"ip_prefix": "3.5.0.0/16", "service": "EC2"}]}')
    assert cdn._extract(body, "aws") == ["13.32.0.0/15"]


# -- kernel extraction ---------------------------------------------------------

def test_sysdescr_yields_confirmed_kernel():
    hint = kernel.from_sysdescr(
        "Linux web01 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64")
    assert hint is not None
    assert hint.kernel == "5.15.0-91-generic"
    assert hint.distro == "Ubuntu"
    assert hint.confidence == kernel.CONFIRMED


def test_ssh_banner_yields_inferred_distro():
    hint = kernel.from_ssh_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1")
    assert hint is not None
    assert hint.distro == "Ubuntu"
    assert hint.revision == "3ubuntu0.1"
    assert hint.confidence == kernel.INFERRED
    assert hint.kernel == ""


def test_debian_banner_family():
    hint = kernel.from_ssh_banner("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u1")
    assert hint is not None and hint.family == "debian"


def test_sysdescr_inside_ber_payload_still_parses():
    # A real SNMP reply carries the string right after a length octet ("Q"), so a
    # \b before "Linux" does not fire — the preceding byte is a word character.
    text = "\x04QLinux web01 5.15.0-91-generic #101-Ubuntu SMP x86_64"
    hint = kernel.from_sysdescr(text)
    assert hint is not None
    assert hint.kernel == "5.15.0-91-generic"
    assert hint.distro == "Ubuntu"


def test_non_ssh_banner_is_ignored():
    assert kernel.from_ssh_banner("220 mail ESMTP Postfix") is None


def test_sysdescr_beats_banner():
    hint = kernel.extract(sysdescr="Linux h 6.8.0-45-generic #45-Ubuntu SMP x86_64",
                          ssh_banner="SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13")
    assert hint is not None and hint.confidence == kernel.CONFIRMED


def test_usable_requires_kernel_or_distro_revision():
    assert kernel.KernelHint(distro="Ubuntu").usable is False
    assert kernel.KernelHint(distro="Ubuntu", revision="3ubuntu0.1").usable is True


# -- UDP packet builders -------------------------------------------------------

def test_snmp_get_is_well_formed_ber():
    packet = udp.snmp_get()
    assert packet[0] == 0x30                      # SEQUENCE
    assert b"public" in packet
    assert bytes([0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]) in packet


def test_snmp_long_community_uses_long_form_length():
    packet = udp.snmp_get(community="c" * 200)
    assert b"\x81" in packet                      # long-form length octet


def test_ntp_readvar_shape():
    packet = udp.ntp_readvar()
    assert len(packet) == 48
    assert packet[0] == 0x16 and packet[1] == 0x02


def test_dns_version_bind_query():
    packet = udp.dns_version_bind()
    assert b"version" in packet and b"bind" in packet
    assert packet[-4:] == b"\x00\x10\x00\x03"     # TXT, CH


def test_mdns_query_targets_service_enumeration():
    assert b"_services" in udp.mdns_services()


# -- CT classification ---------------------------------------------------------

def test_split_separates_origin_from_edge(monkeypatch):
    edges = cdn.EdgeMap()
    table = {"a.example.com": ["13.227.231.5"], "b.example.com": ["141.94.132.37"],
             "c.example.com": []}
    monkeypatch.setattr(ct, "resolve", lambda name, timeout=5.0: table[name])
    classes = ct.classify(sorted(table), edges)
    origins, protected = ct.split(classes)
    assert [c.name for c in origins] == ["b.example.com"]
    assert [c.name for c in protected] == ["a.example.com"]


def test_hostclass_is_origin_only_when_resolved_and_unprotected():
    assert ct.HostClass(name="x", addresses=["1.2.3.4"]).is_origin
    assert not ct.HostClass(name="x", addresses=[]).is_origin
    assert not ct.HostClass(name="x", addresses=["1.2.3.4"], edge="cloudflare").is_origin


# -- attack helpers ------------------------------------------------------------

def test_favicon_hash_is_stable_and_short():
    from rennacs import attack
    assert attack.favicon_hash(b"abc") == attack.favicon_hash(b"abc")
    assert attack.favicon_hash(b"abc") != attack.favicon_hash(b"abd")
    assert len(attack.favicon_hash(b"abc")) == 16
    assert attack.favicon_hash(b"") == ""


def test_compare_flags_unreachable_origin():
    from rennacs import attack
    edge = attack.Identity(ip="1.1.1.1", host="h", port=443, status=200, title="T")
    origin = attack.Identity(ip="2.2.2.2", host="h", port=443, error="timeout")
    assert attack.compare(edge, origin)["same"] is False


def test_compare_matches_on_shared_markers():
    from rennacs import attack
    edge = attack.Identity(ip="1.1.1.1", host="h", port=443, status=200,
                           title="Same", favicon="abc", server="nginx")
    origin = attack.Identity(ip="2.2.2.2", host="h", port=443, status=200,
                             title="Same", favicon="abc", server="nginx")
    verdict = attack.compare(edge, origin)
    assert verdict["same"] is True
    assert len(verdict["reasons"]) == 3


def test_rank_puts_kev_first_then_cvss():
    from rennacs.findings import rank_key
    kev_low = {"ip": "a", "port": 1, "advisories": [{"cvss": 5, "known_exploited_catalog": True}]}
    plain_high = {"ip": "b", "port": 1, "advisories": [{"cvss": 9.9}]}
    plain_low = {"ip": "c", "port": 1, "advisories": [{"cvss": 4.0}]}
    order = sorted([plain_low, plain_high, kev_low], key=rank_key)
    assert order == [kev_low, plain_high, plain_low]


def test_rank_prefers_confirmed_kernel_at_equal_severity():
    from rennacs.findings import rank_key
    confirmed = {"ip": "a", "port": 1, "service": {"kernel_confidence": "confirmed"},
                 "advisories": [{"cvss": 9.8}]}
    inferred = {"ip": "b", "port": 1, "service": {"kernel_confidence": "inferred"},
                "advisories": [{"cvss": 9.8}]}
    assert sorted([inferred, confirmed], key=rank_key)[0] is confirmed
