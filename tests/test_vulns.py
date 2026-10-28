"""Tests for the heuristic vulnerability tagger."""

import pytest

from rennacs.vulns import _cmp, _parse_version, check


def test_parse_version_strips_suffix():
    assert _parse_version("9.6p1") == (9, 6)
    assert _parse_version("1.24.0") == (1, 24, 0)
    assert _parse_version("2.4.49") == (2, 4, 49)
    assert _parse_version("") == ()


def test_cmp_pads_shorter():
    assert _cmp((1, 24), (1, 24, 0)) == 0
    assert _cmp((1, 20), (1, 21, 0)) < 0
    assert _cmp((9, 8), (9, 7, 1)) > 0


def test_openssh_in_regresssion_window_flagged():
    vulns = check("OpenSSH", "9.2p1")
    assert any(v.cve == "CVE-2024-6387" for v in vulns)


def test_openssh_patched_not_flagged():
    # 9.8 is the fixed release -> outside [8.5, 9.8)
    assert check("OpenSSH", "9.8p1") == []


def test_openssh_too_old_not_flagged():
    # below the vulnerable window
    assert check("OpenSSH", "7.9") == []


def test_apache_exact_version():
    cves = {v.cve for v in check("Apache httpd", "2.4.49")}
    assert "CVE-2021-41773" in cves
    assert check("Apache httpd", "2.4.52") == []


def test_vsftpd_backdoor_exact():
    vulns = check("vsftpd", "2.3.4")
    assert vulns and vulns[0].cve == "CVE-2011-2523"
    assert vulns[0].severity == "critical"


def test_unknown_product_returns_empty():
    assert check("TotallyMadeUp", "1.0") == []


def test_no_version_only_matches_exact_rules():
    # with no version, range rules can't fire
    assert check("OpenSSH", "") == []


def test_results_are_deduped_by_cve():
    vulns = check("Apache httpd", "2.4.49")
    ids = [v.cve for v in vulns]
    assert len(ids) == len(set(ids))
