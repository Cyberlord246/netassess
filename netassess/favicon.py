"""Favicon hashing (Shodan-compatible) for web-app fingerprinting.

Shodan's ``http.favicon.hash`` is ``mmh3.hash(base64.encodebytes(favicon))``
using MurmurHash3 x86_32 (seed 0), returned as a signed 32-bit int. We
reimplement the hash so no third-party dependency is required; the value is
comparable to Shodan's favicon database and to published per-product hashes.

Pure, non-destructive: hashing is local; fetching is a single scope-gated GET.
"""
from __future__ import annotations

import base64

_C1 = 0xCC9E2D51
_C2 = 0x1B873593
_MASK = 0xFFFFFFFF


def _rotl32(x: int, r: int) -> int:
    return ((x << r) | (x >> (32 - r))) & _MASK


def _fmix32(h: int) -> int:
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & _MASK
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & _MASK
    h ^= h >> 16
    return h


def murmur3_x86_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86_32. Returns a SIGNED 32-bit int (matches Python mmh3)."""
    length = len(data)
    h1 = seed & _MASK
    nblocks = length // 4
    for i in range(nblocks):
        k1 = int.from_bytes(data[i * 4:i * 4 + 4], "little")
        k1 = (k1 * _C1) & _MASK
        k1 = _rotl32(k1, 15)
        k1 = (k1 * _C2) & _MASK
        h1 ^= k1
        h1 = _rotl32(h1, 13)
        h1 = (h1 * 5 + 0xE6546B64) & _MASK
    # tail
    tail = data[nblocks * 4:]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * _C1) & _MASK
        k1 = _rotl32(k1, 15)
        k1 = (k1 * _C2) & _MASK
        h1 ^= k1
    # finalization
    h1 ^= length
    h1 = _fmix32(h1)
    # to signed 32-bit (mmh3 returns signed)
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def favicon_hash(raw: bytes) -> int:
    """Shodan-style favicon hash of raw favicon bytes."""
    b64 = base64.encodebytes(raw)          # MIME base64: 76-col lines + trailing \n
    return murmur3_x86_32(b64, 0)


# Known favicon hash -> product. Intentionally empty by default: a wrong mapping
# is worse than none, so only add values you have verified (compute the hash with
# this module, or cross-check Shodan's http.favicon.hash). Users/orgs can extend.
KNOWN: dict[int, str] = {}


def identify(hash_val: int) -> str:
    """Return a product name for a known favicon hash, or '' if unknown."""
    return KNOWN.get(hash_val, "")
