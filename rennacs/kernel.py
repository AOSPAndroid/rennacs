"""Kernel and distro extraction — the fingerprint a banner scanner usually misses.

Kernel CVEs are invisible to product/version matching because no TCP banner carries a
kernel version. Two sources do, and both are weak in different ways:

* **SNMP sysDescr** (UDP/161) is usually a literal ``uname`` line: distro, kernel,
  build string, architecture. Strongest signal available remotely.
* **SSH banner distro suffix** (``OpenSSH_8.9p1 Ubuntu-3ubuntu0.1``) gives the distro
  and its package revision, from which the kernel *series* can be inferred. Weaker,
  but present on almost every host.

Confidence is therefore explicit and never upgraded silently: ``confirmed`` means a
kernel string was read, ``inferred`` means it was derived from a distro revision. A
distro revision is also the only thing that can distinguish a patched host from an
unpatched one at the same kernel version, so it is kept even when no version is
derived.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ``Linux host 5.15.0-91-generic #101-Ubuntu SMP ... x86_64``
_UNAME = re.compile(
    r"Linux\s+(?P<host>\S+)\s+(?P<kernel>\d+\.\d+(?:\.\d+)?(?:[-.][\w.+~]+)*)"
    r"(?:\s+#\d+(?:-(?P<flavour>[A-Za-z]+))?)?",
    re.IGNORECASE,
)
# A bare kernel version, e.g. ``6.8.0-45-generic``.
_KERNEL = re.compile(r"\b(?P<kernel>\d+\.\d+\.\d+(?:[-.][\w.+~]+)?)\b")

# Distro suffixes as they appear in SSH identification strings.
_SSH_DISTRO = re.compile(
    r"(?:^|[-_ ])(?P<distro>Ubuntu|Debian|Debian GNU/Linux|Raspbian|"
    r"FreeBSD|OpenBSD|NetBSD|Alpine|CentOS|Red Hat|Fedora|SUSE|Amazon)"
    r"[-_ ]?(?P<revision>\d[\w.+~-]*)?",
    re.IGNORECASE,
)

_DISTRO_FAMILY = {
    "ubuntu": "debian",
    "debian": "debian",
    "debian gnu/linux": "debian",
    "raspbian": "debian",
    "alpine": "alpine",
    "centos": "rhel",
    "red hat": "rhel",
    "fedora": "rhel",
    "suse": "suse",
    "amazon": "rhel",
    "freebsd": "bsd",
    "openbsd": "bsd",
    "netbsd": "bsd",
}

CONFIRMED = "confirmed"
INFERRED = "inferred"


@dataclass(frozen=True)
class KernelHint:
    distro: str = ""
    revision: str = ""
    kernel: str = ""
    confidence: str = ""
    source: str = ""

    @property
    def family(self) -> str:
        return _DISTRO_FAMILY.get(self.distro.casefold(), "")

    @property
    def usable(self) -> bool:
        return bool(self.kernel or (self.distro and self.revision))


def from_sysdescr(text: str) -> KernelHint | None:
    """Parse an SNMP sysDescr (or any uname-like text)."""
    match = _UNAME.search(text)
    if match:
        return KernelHint(
            distro=(match.group("flavour") or "").strip(),
            kernel=match.group("kernel"),
            confidence=CONFIRMED,
            source="snmp-sysdescr",
        )
    match = _KERNEL.search(text)
    if match and "linux" in text.casefold():
        return KernelHint(kernel=match.group("kernel"), confidence=CONFIRMED,
                          source="sysdescr")
    return None


def from_ssh_banner(banner: str) -> KernelHint | None:
    """Parse the distro suffix of an SSH identification string."""
    if not banner.upper().startswith("SSH-"):
        return None
    match = _SSH_DISTRO.search(banner)
    if not match:
        return None
    return KernelHint(
        distro=match.group("distro").strip(),
        revision=(match.group("revision") or "").strip(),
        confidence=INFERRED,
        source="ssh-banner",
    )


def extract(*, sysdescr: str = "", ssh_banner: str = "") -> KernelHint | None:
    """Best available hint: a real kernel string beats a distro inference."""
    return from_sysdescr(sysdescr) or from_ssh_banner(ssh_banner)
