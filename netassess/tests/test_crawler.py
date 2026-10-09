"""Bounded crawler: same-host BFS, depth/page caps, feeds secret scanning.

Run: python -m netassess.tests.test_crawler
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ..config import Config
from ..endpoints import EndpointAnalyzer
from ..models import HTTPService, Host
from ..scope import ScopeEngine

# a tiny site: / links to /a and /b and an offsite link; /a has a JS with a key;
# /b links to /c; everything same-host.
_PAGES = {
    "/": b'<a href="/a">a</a><a href="/b">b</a><a href="https://evil.example/x">x</a>',
    "/a": b'<script src="/static/app.js"></script>',
    "/b": b'<a href="/c">c</a>',
    "/c": b"<p>leaf</p>",
    "/static/app.js": b'var k="AKIAIOSFODNN7EXAMPLE";',
}


class _H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = _PAGES.get(self.path.split("?")[0])
        if body is None:
            self.send_response(404); self.end_headers(); return
        self.send_response(200)
        ct = "application/javascript" if self.path.endswith(".js") else "text/html"
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _serve():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _svc(port):
    return HTTPService(url=f"http://127.0.0.1:{port}/", ip="127.0.0.1",
                       port=port, scheme="http")


def test_crawl_collects_same_host_endpoints_not_offsite():
    srv, port = _serve()
    try:
        cfg = Config(targets=["127.0.0.1/32"], timeout=2.0, crawl=True,
                     crawl_depth=3, crawl_max_pages=40)
        an = EndpointAnalyzer(cfg, ScopeEngine(cfg))
        host = Host(ip="127.0.0.1")
        svc = _svc(port)
        eps = an.analyze_service(host, svc)
        assert "/a" in eps and "/b" in eps and "/c" in eps   # BFS reached depth
        assert "/static/app.js" in eps
        assert not any("evil.example" in e for e in eps)      # offsite excluded
    finally:
        srv.shutdown()


def test_crawl_finds_secret_in_linked_js():
    srv, port = _serve()
    try:
        cfg = Config(targets=["127.0.0.1/32"], timeout=2.0, crawl=True)
        an = EndpointAnalyzer(cfg, ScopeEngine(cfg))
        host = Host(ip="127.0.0.1")
        svc = _svc(port)
        an.analyze_service(host, svc)
        findings = an.scan_js_secrets(host, svc)
        assert any("AWS" in f.title for f in findings)        # key in /static/app.js
    finally:
        srv.shutdown()


def test_page_cap_bounds_crawl():
    srv, port = _serve()
    try:
        cfg = Config(targets=["127.0.0.1/32"], timeout=2.0, crawl=True,
                     crawl_depth=5, crawl_max_pages=2)
        an = EndpointAnalyzer(cfg, ScopeEngine(cfg))
        an.analyze_service(Host(ip="127.0.0.1"), _svc(port))
        assert len(an._bodies) <= 2                           # hard page cap
    finally:
        srv.shutdown()


def test_crawl_off_by_default_root_only():
    srv, port = _serve()
    try:
        cfg = Config(targets=["127.0.0.1/32"], timeout=2.0)   # crawl defaults off
        an = EndpointAnalyzer(cfg, ScopeEngine(cfg))
        an.analyze_service(Host(ip="127.0.0.1"), _svc(port))
        assert len(an._bodies) == 1                           # only the root page
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
