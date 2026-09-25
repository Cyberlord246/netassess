"""Tests for RDP/VNC/rsync probe parsers (no network).

Run: python -m netassess.tests.test_remote
"""
from __future__ import annotations

import struct

from ..probers.remote_probes import (
    build_rdp_neg_request, parse_rdp_neg_response, parse_rsync_modules,
    parse_vnc_sectypes,
)


# --- RDP ---------------------------------------------------------------- #
def test_rdp_request_is_wellformed():
    pkt = build_rdp_neg_request(0)
    assert pkt[0] == 0x03 and pkt[1] == 0x00          # TPKT
    assert struct.unpack("!H", pkt[2:4])[0] == len(pkt)  # length field
    assert pkt[5] == 0xE0                              # X.224 CR
    assert pkt[11] == 0x01                             # RDP_NEG_REQ type


def _rdp_response(ntype, code):
    tpkt = b"\x03\x00\x00\x13"
    x224 = b"\x0e\xd0\x00\x00\x12\x34\x00"             # CC header (7 bytes)
    neg = struct.pack("<BBHI", ntype, 0x00, 0x0008, code)
    return tpkt + x224 + neg


def test_rdp_parse_rsp_standard():
    r = parse_rdp_neg_response(_rdp_response(0x02, 0))   # selected: RDP
    assert r["type"] == "rsp" and r["selected_protocol"] == 0


def test_rdp_parse_failure_nla_required():
    r = parse_rdp_neg_response(_rdp_response(0x03, 5))   # HYBRID_REQUIRED
    assert r["type"] == "failure" and r["failure_code"] == 5


def test_rdp_parse_garbage():
    assert parse_rdp_neg_response(b"\x00\x01") is None


# --- VNC ---------------------------------------------------------------- #
def test_vnc_sectypes_37_plus():
    # RFB 3.8: [count][types...]  -> None(1) and VNC(2)
    assert parse_vnc_sectypes(8, bytes([2, 1, 2])) == [1, 2]


def test_vnc_sectypes_33():
    # RFB 3.3: single 4-byte security type (2 = VNC auth)
    assert parse_vnc_sectypes(3, struct.pack("!I", 2)) == [2]


def test_vnc_sectypes_empty():
    assert parse_vnc_sectypes(8, b"") == []


# --- rsync -------------------------------------------------------------- #
def test_rsync_module_parse():
    listing = ("@RSYNCD: 31.0\n"
               "backups\tNightly backups\n"
               "www\tWeb root\n"
               "@RSYNCD: EXIT\n")
    assert parse_rsync_modules(listing) == ["backups", "www"]


def test_rsync_no_modules():
    assert parse_rsync_modules("@RSYNCD: 31.0\n@RSYNCD: EXIT\n") == []


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()
