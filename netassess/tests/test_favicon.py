"""Tests for favicon hashing (MurmurHash3 x86_32, Shodan-compatible).

Run: python -m netassess.tests.test_favicon
"""
from __future__ import annotations

from ..favicon import murmur3_x86_32, favicon_hash, identify, KNOWN


def test_empty_is_zero():
    # canonical MurmurHash3 x86_32 vector: empty input, seed 0 -> 0
    assert murmur3_x86_32(b"", 0) == 0


def test_deterministic_and_seed_sensitive():
    assert murmur3_x86_32(b"netassess", 0) == murmur3_x86_32(b"netassess", 0)
    assert murmur3_x86_32(b"netassess", 0) != murmur3_x86_32(b"netassess", 1)


def test_signed_32bit_range():
    for s in (b"", b"a", b"ab", b"abc", b"abcd", b"abcde", b"x" * 64):
        v = murmur3_x86_32(s, 0)
        assert -0x80000000 <= v <= 0x7FFFFFFF


def test_favicon_hash_stable_and_int():
    raw = b"\x00\x01\x02fake-ico-bytes" * 10
    h1 = favicon_hash(raw)
    h2 = favicon_hash(raw)
    assert isinstance(h1, int) and h1 == h2


def test_identify_unknown_is_empty():
    assert identify(1234567) == ""     # KNOWN is empty by default
    KNOWN[1234567] = "TestApp"
    try:
        assert identify(1234567) == "TestApp"
    finally:
        del KNOWN[1234567]


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()
