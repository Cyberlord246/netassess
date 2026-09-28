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


def _mk(path, status, category="common", loc="", ct="", title="", length=100):
    return {"path": path, "url": f"http://h/{path}", "status": status,
            "category": category, "sev": Severity.LOW, "title": title,
            "location": loc, "content_type": ct, "length": length}


def test_redirects_grouped_by_destination_with_representatives():
    from ..content_discovery import make_findings
    hits = [_mk(f"page{i}", 302, loc="/login") for i in range(500)]
    fs = make_findings("h:80", hits, source="feroxbuster")
    red = [f for f in fs if f.title == "Redirects to /login"]
    assert len(red) == 1                       # 500 URLs -> ONE finding
    assert "500 URL" in red[0].evidence
    assert red[0].evidence.count("http://h/page") == 3   # 3 representatives
    assert "+497 more" in red[0].evidence


def test_different_redirect_destinations_stay_separate():
    from ..content_discovery import make_findings
    hits = [_mk("a", 302, loc="/login"), _mk("b", 302, loc="/login"),
            _mk("c", 301, loc="/home")]
    fs = make_findings("h:80", hits, source="feroxbuster")
    titles = {f.title for f in fs}
    assert "Redirects to /login" in titles and "Redirects to /home" in titles


def test_200s_deduplicated_by_signature():
    from ..content_discovery import make_findings
    # 3 identical junk 200s (same title+length) + 2 distinct pages
    hits = [_mk("j1", 200, title="Home", length=500),
            _mk("j2", 200, title="Home", length=500),
            _mk("j3", 200, title="Home", length=500),
            _mk("dashboard", 200, title="Dashboard", length=900),
            _mk("account", 200, title="Account", length=1200)]
    fs = make_findings("h:80", hits, source="feroxbuster")
    ok = [f for f in fs if f.title == "Reachable pages (HTTP 200)"][0]
    assert "3 unique 200 page(s)" in ok.evidence   # 3 signatures, not 5 entries
    assert "similar" in ok.evidence                # junk collapsed with a count


def test_static_assets_filtered_out():
    from ..content_discovery import make_findings
    hits = [_mk("style.css", 200), _mk("logo.png", 200),
            _mk("app.js", 200), _mk("font.woff2", 200),
            _mk("dashboard", 200, title="Dash")]
    fs = make_findings("h:80", hits, source="feroxbuster")
    # only the real page survives; css/png/js/woff2 dropped
    ok = [f for f in fs if f.title == "Reachable pages (HTTP 200)"]
    assert ok and "dashboard" in ok[0].evidence
    assert ".css" not in ok[0].evidence and ".png" not in ok[0].evidence


def test_static_filtered_by_content_type():
    from ..content_discovery import make_findings, _is_static
    assert _is_static(_mk("weird", 200, ct="text/css"))
    assert _is_static(_mk("x", 200, ct="image/png"))
    assert not _is_static(_mk("page", 200, ct="text/html"))


def test_other_statuses_grouped_with_representatives():
    from ..content_discovery import make_findings
    hits = ([_mk(f"a{i}", 403) for i in range(10)] +
            [_mk(f"b{i}", 401) for i in range(5)])
    fs = make_findings("h:80", hits, source="feroxbuster")
    f403 = [f for f in fs if "HTTP 403" in f.title][0]
    f401 = [f for f in fs if "HTTP 401" in f.title][0]
    assert "10 URL" in f403.evidence and f403.evidence.count("http://h/a") == 3
    assert "5 URL" in f401.evidence


def test_high_value_paths_stay_individual():
    from ..content_discovery import make_findings
    hits = [{"path": ".env", "url": "http://h/.env", "status": 200,
             "category": "secrets", "sev": Severity.HIGH, "title": "",
             "location": "", "content_type": "", "length": 40}]
    fs = make_findings("h:80", hits, source="feroxbuster")
    assert any(".env" in f.title for f in fs)


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()
