"""Minimal ASN.1 BER encode/decode helpers.

Just enough to build/parse SNMP (v2c) and LDAP messages by hand — no external
dependencies. Encoders return bytes; the decoder is a lenient TLV walker that
tolerates the partial/odd responses real services send.
"""
from __future__ import annotations

# --- tags we use ---
INTEGER = 0x02
OCTET_STRING = 0x04
NULL = 0x05
OID = 0x06
ENUMERATED = 0x0A
SEQUENCE = 0x30


def enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + enc_len(len(value)) + value


def enc_int_content(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    neg = n < 0
    v = n if not neg else (-n - 1)
    out = b""
    while v > 0:
        out = bytes([v & 0xFF]) + out
        v >>= 8
    if not out:
        out = b"\x00"
    if neg:
        out = bytes([b ^ 0xFF for b in out])
        # ensure high bit set for negative
        if not (out[0] & 0x80):
            out = b"\xff" + out
    else:
        # ensure high bit clear for positive
        if out[0] & 0x80:
            out = b"\x00" + out
    return out


def int_tlv(n: int) -> bytes:
    return tlv(INTEGER, enc_int_content(n))


def octet_tlv(b) -> bytes:
    if isinstance(b, str):
        b = b.encode()
    return tlv(OCTET_STRING, b)


def null_tlv() -> bytes:
    return tlv(NULL, b"")


def enum_tlv(n: int) -> bytes:
    return tlv(ENUMERATED, enc_int_content(n))


def enc_oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.split(".")]
    if len(parts) < 2:
        raise ValueError("OID needs >= 2 arcs")
    out = [40 * parts[0] + parts[1]]
    body = bytearray()
    for arc in [out[0]] + parts[2:]:
        if arc < 0x80:
            body.append(arc)
        else:
            stack = []
            while arc:
                stack.append(arc & 0x7F)
                arc >>= 7
            stack.reverse()
            for i in range(len(stack) - 1):
                body.append(stack[i] | 0x80)
            body.append(stack[-1])
    return bytes(body)


def oid_tlv(oid: str) -> bytes:
    return tlv(OID, enc_oid(oid))


def seq(*parts: bytes) -> bytes:
    return tlv(SEQUENCE, b"".join(parts))


# --------------------------------------------------------------------------- #
# decoding
# --------------------------------------------------------------------------- #
def parse_tlv(data: bytes, off: int = 0):
    """Return (tag, value_bytes, next_offset) for one TLV, or None on truncation."""
    if off + 1 > len(data):
        return None
    tag = data[off]
    if off + 1 >= len(data):
        return None
    length_byte = data[off + 1]
    p = off + 2
    if length_byte < 0x80:
        length = length_byte
    else:
        num = length_byte & 0x7F
        if p + num > len(data):
            return None
        length = int.from_bytes(data[p:p + num], "big")
        p += num
    value = data[p:p + length]
    return tag, value, p + length


def children(value: bytes):
    """Yield (tag, value_bytes) for each TLV inside a constructed value."""
    off = 0
    while off < len(value):
        res = parse_tlv(value, off)
        if res is None:
            break
        tag, val, off = res
        yield tag, val


def decode_int(value: bytes) -> int:
    if not value:
        return 0
    n = int.from_bytes(value, "big", signed=True)
    return n


def find_octet_strings(value: bytes, out=None) -> list[bytes]:
    """Recursively collect OCTET STRING values (best-effort scrape)."""
    if out is None:
        out = []
    off = 0
    while off < len(value):
        res = parse_tlv(value, off)
        if res is None:
            break
        tag, val, off = res
        constructed = bool(tag & 0x20)
        if tag == OCTET_STRING:
            out.append(val)
        if constructed and val:
            find_octet_strings(val, out)
    return out
