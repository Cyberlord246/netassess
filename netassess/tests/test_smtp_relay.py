"""Integration test for the SMTP open-relay check (in-process SMTP server).

Verifies: relay accepted -> open_relay True; relay denied -> False; and that the
client never sends DATA (no mail is transmitted).

Run: python -m netassess.tests.test_smtp_relay
"""
from __future__ import annotations

import socketserver
import threading

from ..config import Config
from ..probers.service_probes import SMTPProbe
from ..scope import ScopeEngine


def _make_server(rcpt_response: bytes):
    seen = {"data": False}

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.wfile.write(b"220 test ESMTP\r\n")
            while True:
                line = self.rfile.readline()
                if not line:
                    break
                u = line.upper()
                if u.startswith((b"EHLO", b"HELO")):
                    self.wfile.write(b"250-test\r\n250 OK\r\n")
                elif u.startswith(b"MAIL"):
                    self.wfile.write(b"250 OK\r\n")
                elif u.startswith(b"RCPT"):
                    self.wfile.write(rcpt_response + b"\r\n")
                elif u.startswith(b"DATA"):
                    seen["data"] = True                 # should never happen
                    self.wfile.write(b"354 go\r\n")
                elif u.startswith(b"RSET"):
                    self.wfile.write(b"250 OK\r\n")
                elif u.startswith(b"QUIT"):
                    self.wfile.write(b"221 bye\r\n")
                    break
                else:
                    self.wfile.write(b"250 OK\r\n")

    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1], seen


def _probe():
    cfg = Config(targets=["127.0.0.1/32"], smtp_relay_test=True, timeout=3.0)
    return SMTPProbe(cfg, ScopeEngine(cfg))


def test_open_relay_detected():
    srv, port, seen = _make_server(b"250 OK")     # server accepts external RCPT
    try:
        r = _probe()._relay_test("127.0.0.1", port)
        assert r["open_relay"] is True
        assert "accepted" in r["evidence"].lower()
        assert seen["data"] is False              # DATA never sent -> no mail
    finally:
        srv.shutdown()


def test_relay_denied():
    srv, port, seen = _make_server(b"554 5.7.1 relay denied")
    try:
        r = _probe()._relay_test("127.0.0.1", port)
        assert r["open_relay"] is False
        assert seen["data"] is False
    finally:
        srv.shutdown()


def test_relay_test_scope_denied():
    cfg = Config(targets=["192.0.2.0/30"], smtp_relay_test=True)
    p = SMTPProbe(cfg, ScopeEngine(cfg))
    r = p._relay_test("203.0.113.9", 25)          # out of scope
    assert r["open_relay"] is False and "scope denied" in r["evidence"]


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()
