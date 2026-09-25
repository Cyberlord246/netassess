"""Tests for BER helpers, SNMP/NTP packet build/parse, and UDP classification.

Run: python -m netassess.tests.test_udp
"""
from __future__ import annotations

from .. import ber
from ..config import Config
from ..models import PortState
from ..scope import ScopeEngine
from ..udp import (
    UDPScanner, build_ntp_request, build_snmp_get, parse_ntp,
    parse_snmp_sysdescr,
)


# --- BER ---------------------------------------------------------------- #
def test_ber_len_short_and_long():
    assert ber.enc_len(5) == b"\x05"
    assert ber.enc_len(200) == b"\x81\xc8"
    assert ber.enc_len(300) == b"\x82\x01\x2c"


def test_ber_int_roundtrip():
    for n in (0, 1, 127, 128, 255, 256, 65535, 0x7FFFFFFF):
        t = ber.int_tlv(n)
        tag, val, _ = ber.parse_tlv(t)
        assert tag == ber.INTEGER
        assert ber.decode_int(val) == n


def test_ber_oid_encoding():
    # 1.3.6.1.2.1.1.1.0 -> 2b 06 01 02 01 01 01 00
    assert ber.enc_oid("1.3.6.1.2.1.1.1.0") == bytes(
        [0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])


def test_ber_oid_multibyte_arc():
    # arc 2680 needs multi-byte base-128
    enc = ber.enc_oid("1.2.840.113549")
    # 840 -> 0x86 0x48 ; 113549 -> 0x86 0xf7 0x0d
    assert enc[:1] == bytes([42])          # 40*1+2
    assert b"\x86\x48" in enc


def test_ber_children_walk():
    msg = ber.seq(ber.int_tlv(1), ber.octet_tlv("public"), ber.int_tlv(9))
    tag, val, _ = ber.parse_tlv(msg)
    assert tag == ber.SEQUENCE
    kids = list(ber.children(val))
    assert ber.decode_int(kids[0][1]) == 1
    assert kids[1][1] == b"public"


# --- SNMP --------------------------------------------------------------- #
def test_snmp_get_is_wellformed():
    pkt = build_snmp_get("public", request_id=1234)
    tag, val, _ = ber.parse_tlv(pkt)
    assert tag == ber.SEQUENCE
    kids = list(ber.children(val))
    assert ber.decode_int(kids[0][1]) == 1        # v2c
    assert kids[1][1] == b"public"                # community
    assert kids[2][0] == 0xA0                      # GetRequest PDU


def test_snmp_parse_sysdescr():
    # craft a minimal GetResponse containing a sysDescr octet string
    varbind = ber.seq(ber.oid_tlv("1.3.6.1.2.1.1.1.0"),
                      ber.octet_tlv("Linux router 5.10"))
    pdu = ber.tlv(0xA2, ber.int_tlv(1) + ber.int_tlv(0) + ber.int_tlv(0)
                  + ber.seq(varbind))
    resp = ber.seq(ber.int_tlv(1), ber.octet_tlv("public"), pdu)
    assert parse_snmp_sysdescr(resp) == "Linux router 5.10"


# --- NTP ---------------------------------------------------------------- #
def test_ntp_request_byte():
    req = build_ntp_request()
    assert len(req) == 48 and req[0] == 0x23   # LI0 VN4 Mode3


def test_ntp_parse():
    # server response: LI0 VN4 Mode4, stratum 2
    data = bytes([0x24, 0x02]) + b"\x00" * 46
    info = parse_ntp(data)
    assert info["version"] == 4 and info["mode"] == 4 and info["stratum"] == 2


# --- UDP classification (no real network) ------------------------------- #
def _scanner():
    cfg = Config(targets=["192.0.2.10/32"])
    return UDPScanner(cfg, ScopeEngine(cfg))


def test_udp_open_on_response(monkeypatch=None):
    s = _scanner()
    s._send_recv = lambda ip, port, payload: ("open", b"\x24\x02" + b"\x00" * 46)
    p = s.scan_port("192.0.2.10", 123)
    assert p is not None and p.state == PortState.OPEN


def test_udp_closed_is_dropped():
    s = _scanner()
    s._send_recv = lambda ip, port, payload: ("closed", b"")
    assert s.scan_port("192.0.2.10", 161) is None


def test_udp_timeout_is_open_filtered():
    s = _scanner()
    s._send_recv = lambda ip, port, payload: ("open|filtered", b"")
    p = s.scan_port("192.0.2.10", 500)
    assert p is not None and p.state == PortState.OPEN_FILTERED


def test_udp_scope_denied_returns_none():
    cfg = Config(targets=["192.0.2.0/30"])
    s = UDPScanner(cfg, ScopeEngine(cfg))
    # out-of-scope target must never be scanned
    assert s.scan_port("203.0.113.9", 161) is None


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()
