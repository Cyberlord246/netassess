"""Tests for the MQTT prober (packet build + CONNACK handling).

Run: python -m netassess.tests.test_mqtt
"""
from __future__ import annotations

import socket

from ..config import Config
from ..models import Host, Port, PortState, Service, Severity, ValidationState
from ..probers import MQTTProbe
from ..probers.service_probes import mqtt_connect_packet
from ..scope import ScopeEngine


def test_connect_packet_structure():
    pkt = mqtt_connect_packet(b"abc")
    assert pkt[0] == 0x10                       # CONNECT type
    assert b"MQTT" in pkt
    assert pkt.endswith(b"\x00\x03abc")         # client-id length-prefixed


class _FakeSock:
    """Minimal socket stand-in returning a canned CONNACK."""
    def __init__(self, connack):
        self._connack = connack
        self.sent = b""

    def settimeout(self, *_): pass
    def connect(self, *_): pass
    def sendall(self, b): self.sent += b
    def recv(self, n): return self._connack
    def close(self): pass


def _probe_with(connack, port=1883):
    cfg = Config(targets=["192.0.2.10"])
    pr = MQTTProbe(cfg, ScopeEngine(cfg))
    host = Host(ip="192.0.2.10")
    p = Port(number=port, state=PortState.OPEN, service=Service(name="mqtt"))
    orig = socket.socket
    socket.socket = lambda *a, **k: _FakeSock(connack)
    try:
        return pr.probe(host, p), p
    finally:
        socket.socket = orig


def test_anonymous_accept_is_high_finding():
    connack = bytes([0x20, 0x02, 0x00, 0x00])    # rc=0 accepted
    res, p = _probe_with(connack)
    assert res.error == "" or res.error is None
    assert any(f.severity == Severity.HIGH and "anonymous" in f.title.lower()
               for f in res.findings)
    assert res.findings[0].validation == ValidationState.CONFIRMED
    assert p.service.name == "mqtt"


def test_auth_required_no_finding_but_identified():
    connack = bytes([0x20, 0x02, 0x00, 0x05])    # rc=5 not authorized
    res, p = _probe_with(connack)
    assert res.findings == []
    assert p.service.product == "MQTT broker"


def test_non_mqtt_response_errors():
    res, _p = _probe_with(b"HTTP/1.1 400\r\n")
    assert res.error


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()
