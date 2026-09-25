"""Integration test for content discovery over persistent (keep-alive) conns.

Spins up a real threaded HTTP server on localhost and verifies scan_service finds
present paths, skips absent ones, and reuses the connection correctly.

Run: python -m netassess.tests.test_content
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ..config import Config
from ..content_discovery import ContentDiscovery
from ..models import Host, HTTPService, Severity
from ..scope import ScopeEngine


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.rstrip("/") == "/admin":
            body = b"<title>Admin Panel</title>"
            self.send_response(200)
        else:
            body = b"not found"
            self.send_response(404)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "keep-alive")     # allow reuse
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _serve():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, srv.server_address[1]


def test_content_discovery_finds_present_skips_absent():
    srv, port = _serve()
    try:
        cfg = Config(targets=["127.0.0.1/32"], timeout=2.0)
        cd = ContentDiscovery(cfg, ScopeEngine(cfg))
        # tiny wordlist: one present, one absent
        cd.paths = [("admin", "admin", Severity.MEDIUM),
                    ("does-not-exist", "common", Severity.LOW)]
        host = Host(ip="127.0.0.1")
        svc = HTTPService(url=f"http://127.0.0.1:{port}/", ip="127.0.0.1",
                          port=port, scheme="http")
        findings = cd.scan_service(host, svc)
        paths = {d["path"]: d for d in svc.discovered_paths}
        assert "/admin" in paths and paths["/admin"]["status"] == 200
        assert "/does-not-exist" not in paths          # 404 filtered
        assert any("/admin" in f.title for f in findings)
        assert paths["/admin"]["title"] == "Admin Panel"   # body was read
    finally:
        srv.shutdown()


def test_content_discovery_reuses_connection_across_many_paths():
    srv, port = _serve()
    try:
        cfg = Config(targets=["127.0.0.1/32"], timeout=2.0, concurrency=4)
        cd = ContentDiscovery(cfg, ScopeEngine(cfg))
        # many absent paths + the one present -> exercises reuse + drain
        cd.paths = [(f"p{i}", "common", Severity.LOW) for i in range(50)]
        cd.paths.append(("admin", "admin", Severity.MEDIUM))
        host = Host(ip="127.0.0.1")
        svc = HTTPService(url=f"http://127.0.0.1:{port}/", ip="127.0.0.1",
                          port=port, scheme="http")
        cd.scan_service(host, svc)
        found = {d["path"] for d in svc.discovered_paths}
        assert found == {"/admin"}                     # only the real one
    finally:
        srv.shutdown()


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()
