"""Tests for the scan authorization gate — the project's main safety control."""

import pytest

from rennacs.authz import NotAuthorized, Policy


@pytest.mark.parametrize("ip", ["127.0.0.1", "127.5.5.5", "::1"])
def test_loopback_always_allowed(ip):
    Policy().check(ip)  # must not raise


@pytest.mark.parametrize("ip", ["10.0.0.1", "172.16.9.9", "192.168.1.50",
                                "169.254.1.1"])
def test_private_ranges_allowed(ip):
    assert Policy().is_allowed(ip)


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34"])
def test_public_refused_by_default(ip):
    assert not Policy().is_allowed(ip)
    with pytest.raises(NotAuthorized):
        Policy().check(ip)


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1"])
def test_public_allowed_when_authorized(ip):
    assert Policy(authorized=True).is_allowed(ip)


def test_refusal_message_mentions_the_flag():
    with pytest.raises(NotAuthorized) as e:
        Policy().check("8.8.8.8")
    assert "--i-am-authorized" in str(e.value)
