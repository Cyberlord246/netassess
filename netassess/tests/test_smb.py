"""Tests for SMB version enumeration (SMB2 dialect + SMBv1 detection).

Run: python -m netassess.tests.test_smb
"""
from __future__ import annotations

import socket
import struct

from ..config import Config
from ..models import Host, Port, PortState, Service, Severity
from ..probers import SMBProbe
from ..probers.service_probes import (
    smb2_negotiate_request, parse_smb2_dialect, _SMB2_DIALECTS,
)
from ..scope import ScopeEngine


def _smb2_response(dialect: int) -> bytes:
    """Build a minimal SMB2 NEGOTIATE response with the given DialectRevision."""
    nb = b"\x00\x00\x00\x00"                 # 4-byte transport header
    hdr = b"\xfeSMB" + b"\x00" * 60          # 64-byte header (only magic matters)
    body = (struct.pack("<H", 65) + struct.pack("<H", 1)
            + struct.pack("<H", dialect) + b"\x00" * 8)
    return nb + hdr + body


def test_negotiate_request_is_smb2():
    pkt = smb2_negotiate_request()
    assert pkt[4:8] == b"\xfeSMB"            # after the 4-byte NetBIOS length
    assert struct.unpack(">I", pkt[:4])[0] == len(pkt) - 4   # length prefix


def test_parse_dialect_versions():
    for rev, label in _SMB2_DIALECTS.items():
        assert parse_smb2_dialect(_smb2_response(rev)) == rev
    assert parse_smb2_dialect(b"nope") is None


class _FakeSock:
    def __init__(self, replies):
        self._replies = replies          # shared queue (do NOT copy)
    def settimeout(self, *_): pass
    def connect(self, *_): pass
    def sendall(self, *_): pass
    def recv(self, n): return self._replies.pop(0) if self._replies else b""
    def close(self): pass


def _probe(replies):
    cfg = Config(targets=["10.0.0.9"])
    pr = SMBProbe(cfg, ScopeEngine(cfg))
    host = Host(ip="10.0.0.9")
    p = Port(number=445, state=PortState.OPEN, service=Service(name="microsoft-ds"))
    orig = socket.socket
    shared = list(replies)          # one queue shared across both _exchange sockets
    socket.socket = lambda *a, **k: _FakeSock(shared)
    try:
        return pr.probe(host, p), p
    finally:
        socket.socket = orig


def test_probe_reports_smb3_version_no_smbv1():
    # SMB2 negotiate -> 3.1.1; SMB1 negotiate -> no SMB1 reply
    res, p = _probe([_smb2_response(0x0311), b"\x00\x00\x00\x00rubbish"])
    assert p.service.version == "3.1.1"
    assert not any("SMBv1" in f.title for f in res.findings)
    assert any("reachable" in f.title for f in res.findings)


def test_probe_flags_smbv1():
    res, p = _probe([_smb2_response(0x0210),
                     b"\x00\x00\x00\x2f\xffSMB" + b"\x00" * 20])
    assert p.service.version == "2.1"
    v1 = [f for f in res.findings if "SMBv1" in f.title]
    assert v1 and v1[0].severity == Severity.HIGH


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()
