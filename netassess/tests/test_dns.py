"""DNS AXFR (zone transfer) + open-recursion detection.

Run: python -m netassess.tests.test_dns
"""
from __future__ import annotations

import socket
import struct

from ..config import Config
from ..models import Host, Port, PortState, Service, Severity
from ..probers import DNSProbe
from ..probers import service_probes as sp
from ..scope import ScopeEngine


def test_qname_encoding():
    assert sp._dns_qname("example.com") == b"\x07example\x03com\x00"
    assert sp._reverse_zone("10.1.2.3") == "2.1.10.in-addr.arpa"
    assert sp._reverse_zone("not-an-ip") == ""


def test_dns_query_sets_rd_and_qtype():
    q = sp.dns_query("example.com", 252, rd=False)
    assert struct.unpack("!H", q[2:4])[0] == 0x0000      # RD off
    assert q.endswith(struct.pack("!HH", 252, 1))        # AXFR, class IN
    q2 = sp.dns_query("example.com", 1, rd=True)
    assert struct.unpack("!H", q2[2:4])[0] == 0x0100     # RD on


def _probe():
    cfg = Config(targets=["10.0.0.9"])
    return DNSProbe(cfg, ScopeEngine(cfg))


def _candidates(host_hostnames):
    pr = _probe()
    h = Host(ip="10.0.0.9")
    h.hostnames = host_hostnames
    return pr._candidate_zones(h)


def test_candidate_zones_from_names_and_reverse():
    z = _candidates(["ns1.corp.example.com"])
    assert "corp.example.com" in z and "0.0.10.in-addr.arpa" in z


def _axfr_reply(ancount, rcode=0):
    # TCP: 2-byte length + DNS header (ancount at bytes 6:8, rcode in flags)
    hdr = struct.pack("!HHHHHH", 0x1337, 0x8000 | rcode, 1, ancount, 0, 0)
    body = hdr + b"\x00" * 10
    return struct.pack("!H", len(body)) + body


def test_axfr_allowed_is_high_finding(monkeypatch=None):
    pr = _probe()
    orig = sp._recv_banner
    # version query returns nothing; AXFR returns a zone with many records
    calls = {"n": 0}
    def fake(scope, cfg, ip, port, send=b"", read=512, **k):
        calls["n"] += 1
        return (_axfr_reply(12) if calls["n"] > 1 else (b"\x00\x00", "")), ""
    sp._recv_banner = fake
    # no recursion (UDP) in this test
    pr._recursion_open = lambda *a, **k: False
    try:
        host = Host(ip="10.0.0.9"); host.hostnames = ["ns1.example.com"]
        res = pr.probe(host, Port(number=53, state=PortState.OPEN,
                                  service=Service(name="dns")))
    finally:
        sp._recv_banner = orig
    axfr = [f for f in res.findings if "AXFR" in f.title]
    assert axfr and axfr[0].severity == Severity.HIGH


def test_axfr_refused_no_finding():
    pr = _probe()
    orig = sp._recv_banner
    sp._recv_banner = lambda *a, **k: (_axfr_reply(0, rcode=5), "")  # REFUSED
    pr._recursion_open = lambda *a, **k: False
    try:
        host = Host(ip="10.0.0.9"); host.hostnames = ["ns1.example.com"]
        res = pr.probe(host, Port(number=53, state=PortState.OPEN,
                                  service=Service(name="dns")))
    finally:
        sp._recv_banner = orig
    assert not any("AXFR" in f.title for f in res.findings)


def test_open_recursion_detected():
    pr = _probe()
    orig = sp._recv_banner
    sp._recv_banner = lambda *a, **k: (None, "")      # no TCP version/AXFR
    # fake a UDP recursive response: RA=1, rcode=0, ancount=1
    class _UDP:
        def settimeout(s, *a): pass
        def sendto(s, *a): pass
        def recv(s, n): return struct.pack("!HHHHHH", 0x1337, 0x8180, 1, 1, 0, 0)
        def close(s): pass
    osock = socket.socket
    socket.socket = lambda *a, **k: _UDP()
    try:
        res = pr.probe(Host(ip="10.0.0.9"), Port(number=53, state=PortState.OPEN,
                                                 service=Service(name="dns")))
    finally:
        socket.socket = osock
        sp._recv_banner = orig
    rec = [f for f in res.findings if "recursion" in f.title.lower()]
    assert rec and rec[0].severity == Severity.MEDIUM


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()
