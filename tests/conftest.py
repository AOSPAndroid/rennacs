"""Shared pytest fixtures for the Rennacs test suite.

A root-level ``conftest.py`` would also work, but keeping fixtures here keeps the
project root clean. We make the project importable regardless of where pytest is
launched from.
"""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from rennacs.db import Index   # noqa: E402
import demo_seed               # noqa: E402


@pytest.fixture
def empty_index(tmp_path):
    """A fresh, empty index backed by a throwaway SQLite file."""
    idx = Index(str(tmp_path / "test.db"))
    yield idx
    idx.close()


@pytest.fixture
def seeded_index(tmp_path):
    """An index preloaded with the demo dataset."""
    path = str(tmp_path / "seeded.db")
    idx = Index(path)
    for doc in demo_seed.DEMO:
        idx.insert_raw(doc)
    idx.close()
    # reopen read-only-ish for the test
    idx = Index(path)
    yield idx
    idx.close()


@pytest.fixture
def client(tmp_path):
    """A Flask test client over a seeded database."""
    path = str(tmp_path / "web.db")
    idx = Index(path)
    for doc in demo_seed.DEMO:
        idx.insert_raw(doc)
    idx.close()
    from rennacs.app import create_app
    app = create_app(path)
    app.config.update(TESTING=True)
    return app.test_client()


@pytest.fixture
def demo():
    return demo_seed.DEMO


# -- cve.now enrichment, with a fake fetcher (no network) ----------------------

import urllib.error  # noqa: E402

# Canned cve.now entries for the CVEs the demo dataset flags.
_FAKE_ENTRIES = {
    "CVE-2024-6387": {
        "id": "CVE-2024-6387", "title": "OpenSSH regreSSHion RCE",
        "summary": {"text": "Signal handler race in sshd allows RCE."},
        "severity": {"cvss": 8.1, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "exploitation": {"kev": None},
        "affected": [{"vendor": "OpenSSH", "product": "OpenSSH",
                      "ranges": [{"introduced": "8.5p1", "fixed": ""}]}],
        "references": [{"url": "https://www.openssh.com/txt/release-9.8"}],
        "publishedAt": "2024-07-01T00:00:00Z",
    },
    "CVE-2021-41773": {
        "id": "CVE-2021-41773", "title": "Apache 2.4.49 path traversal",
        "summary": {"text": "Path traversal and file disclosure in Apache 2.4.49."},
        "severity": {"cvss": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        "exploitation": {"kev": {"dateAdded": "2021-11-03"}},
        "affected": [{"vendor": "Apache", "product": "Apache HTTP Server", "ranges": []}],
        "references": [{"url": "https://httpd.apache.org/security/"}],
        "publishedAt": "2021-10-05T00:00:00Z",
    },
    "CVE-2021-42013": {
        "id": "CVE-2021-42013", "title": "Apache 2.4.49/2.4.50 RCE",
        "summary": {"text": "Incomplete fix for CVE-2021-41773; RCE."},
        "severity": {"cvss": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "exploitation": {"kev": {"dateAdded": "2021-11-03"}},
        "affected": [{"vendor": "Apache", "product": "Apache HTTP Server", "ranges": []}],
        "references": [{"url": "https://httpd.apache.org/security/"}],
        "publishedAt": "2021-10-07T00:00:00Z",
    },
    "CVE-2011-2523": {
        "id": "CVE-2011-2523", "title": "vsftpd 2.3.4 backdoor",
        "summary": {"text": "Backdoor command execution in vsftpd 2.3.4."},
        "severity": {},                       # no CVSS published
        "exploitation": {"kev": None},
        "affected": [{"vendor": "vsftpd", "product": "vsftpd", "ranges": []}],
        "references": [{"url": "https://security-tracker.debian.org/tracker/CVE-2011-2523"}],
        "publishedAt": "2011-07-03T00:00:00Z",
    },
}
_FAKE_LIST = [
    {"id": "CVE-2026-104353", "title": "Adobe Campaign OS command injection",
     "publishedAt": "2026-10-27T17:00:00Z", "cvss": 9.9, "kev": False, "product": "ACC"},
    {"id": "CVE-2026-109618", "title": "PHP RCE via OOM corruption",
     "publishedAt": "2026-10-26T23:00:00Z", "cvss": 9.8, "kev": True, "product": "PHP"},
]
_FAKE_STATS = {"computedAt": "2026-10-27T19:00:00Z", "vulnerabilitiesTracked": 396719,
               "criticalThisWeek": 38}


class FakeNet:
    """Routes CVENow._get_json by URL against canned data; no network."""

    def __init__(self):
        self.calls = []

    def __call__(self, url):
        self.calls.append(url)
        if "/api/v1/entries/" in url:
            cve = url.rsplit("/", 1)[1]
            if cve in _FAKE_ENTRIES:
                return _FAKE_ENTRIES[cve]
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
        if "/api/v1/entries" in url:
            return {"entries": _FAKE_LIST, "nextCursor": "x"}
        if "/api/stats" in url:
            return _FAKE_STATS
        raise ValueError(f"unexpected url {url}")


@pytest.fixture
def enriched_client(tmp_path):
    """A Flask test client over a seeded + cve.now-enriched database (fake fetcher)."""
    from rennacs.cvenow import CVENow
    path = str(tmp_path / "enriched.db")
    idx = Index(path)
    for doc in demo_seed.DEMO:
        idx.insert_raw(doc)
    c = CVENow(path, now_iso="2026-10-27T00:00:00Z")
    c._get_json = FakeNet()
    idx.reenrich(c, allow_network=True)     # warms cache, then merges
    c.refresh_feed()
    c.refresh_stats()
    c.close()
    idx.close()
    from rennacs.app import create_app
    app = create_app(path)
    app.config.update(TESTING=True)
    return app.test_client()
