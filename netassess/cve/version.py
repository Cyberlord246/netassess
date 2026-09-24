"""Version parsing and comparison for CVE range matching.

Handles the common shapes seen in service banners:
    "2.4.49", "1.17.7", "7.7", "9.3p2" (OpenSSH portable), "4.91", "1.0.1f".
Letter suffixes (OpenSSL's "1.0.1f") are converted to a trailing numeric
component so ordering is preserved (a<b<...). OpenSSH's "pN" is treated as a
further-along patch level.

Comparison pads the shorter tuple with zeros, so "9.3" < "9.3p2".
"""
from __future__ import annotations

import re

_NUM_RE = re.compile(r"\d+")


def parse_version(value: str) -> tuple[int, ...] | None:
    if not value:
        return None
    v = value.strip().lower()
    # normalise OpenSSH portable "p" and separators to dots
    v = v.replace("p", ".")
    # convert a trailing single letter (openssl 1.0.1f) to ".<ord>"
    v = re.sub(r"(\d)([a-z])(?![a-z0-9])", lambda m: f"{m.group(1)}.{ord(m.group(2)) - 96}", v)
    nums = _NUM_RE.findall(v)
    if not nums:
        return None
    # cap component count to avoid pathological banners
    return tuple(int(n) for n in nums[:6])


def _pad(a: tuple[int, ...], b: tuple[int, ...]) -> tuple[tuple, tuple]:
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)), b + (0,) * (n - len(b))


def compare(a: str, b: str) -> int | None:
    """Return -1/0/1 for a<b / a==b / a>b, or None if either won't parse."""
    pa, pb = parse_version(a), parse_version(b)
    if pa is None or pb is None:
        return None
    xa, xb = _pad(pa, pb)
    return (xa > xb) - (xa < xb)


def in_range(version: str, introduced: str | None, fixed: str | None,
             last_affected: str | None = None) -> bool:
    """True if `version` falls in [introduced, fixed) or [introduced, last_affected].

    introduced=None means "from the beginning"; fixed=None with
    last_affected=None means "no upper bound recorded" -> not matched (we refuse
    to flag an open-ended range to avoid noise).
    """
    if parse_version(version) is None:
        return False
    if introduced is not None:
        c = compare(version, introduced)
        if c is None or c < 0:
            return False
    if fixed is not None:
        c = compare(version, fixed)
        if c is None or c >= 0:   # fixed is exclusive
            return False
        return True
    if last_affected is not None:
        c = compare(version, last_affected)
        if c is None or c > 0:    # last_affected is inclusive
            return False
        return True
    # no upper bound -> don't match
    return False
