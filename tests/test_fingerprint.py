"""Tests for banner -> product/version/os fingerprinting."""

import pytest

from rennacs.fingerprint import fingerprint
from rennacs.scanner import ServiceResult


def fp(port, banner):
    s = ServiceResult(port=port, banner=banner)
    fingerprint(s)
    return s


def test_openssh_full():
    s = fp(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4")
    assert s.product == "OpenSSH"
    assert s.version == "8.9p1"
    assert s.os == "Ubuntu"
    assert s.service == "ssh"


def test_nginx_server_header():
    s = fp(80, "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0 (Ubuntu)")
    assert s.product == "nginx" and s.version == "1.24.0"


def test_apache_header():
    s = fp(80, "HTTP/1.1 403 Forbidden\r\nServer: Apache/2.4.49 (CentOS)")
    assert s.product == "Apache httpd" and s.version == "2.4.49"


def test_iis_sets_windows_os():
    s = fp(80, "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0")
    assert s.product == "Microsoft IIS" and s.os == "Windows"


def test_vsftpd_banner():
    s = fp(21, "220 (vsFTPd 2.3.4)")
    assert s.product == "vsftpd" and s.version == "2.3.4"


def test_postfix_smtp():
    s = fp(25, "220 mail.lab.local ESMTP Postfix (Debian/GNU)")
    assert s.product == "Postfix" and s.service == "smtp"


def test_unknown_banner_leaves_product_empty():
    s = fp(9999, "some totally unknown banner blob")
    assert s.product == ""


def test_empty_banner_is_safe():
    s = fp(445, "")
    assert s.product == "" and s.version == ""
