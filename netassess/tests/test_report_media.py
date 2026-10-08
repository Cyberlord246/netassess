"""Media/static assets must not appear in the human report (MD + HTML).

Run: python -m netassess.tests.test_report_media
"""
from __future__ import annotations

from ..config import Config
from ..models import HTTPService, Port, PortState, Service
from ..report import ReportGenerator, _visible_paths, _visible_endpoints
from ..report_html import HTMLReport
from ..scope import ScopeEngine
from ..state import AssetGraph


def _graph():
    g = AssetGraph()
    h = g.get_or_create("10.0.0.5")
    h.ports[8080] = Port(number=8080, state=PortState.OPEN,
                         service=Service(name="http"))
    svc = HTTPService(url="http://10.0.0.5:8080/", ip="10.0.0.5", port=8080,
                      scheme="http")
    svc.discovered_paths = [
        {"path": "/admin", "url": "http://10.0.0.5:8080/admin", "status": 200},
        {"path": "/logo.png", "url": "http://10.0.0.5:8080/logo.png", "status": 200},
        {"path": "/style.css", "url": "http://10.0.0.5:8080/style.css", "status": 200},
        {"path": "/app.js", "url": "http://10.0.0.5:8080/app.js", "status": 200},
    ]
    svc.endpoints = ["/app.js", "/banner.jpg", "/api/v1/users", "/fonts/x.woff2"]
    h.http_services.append(svc)
    return g, svc


def test_visible_paths_drops_media_and_js_css():
    _g, svc = _graph()
    paths = {p["path"] for p in _visible_paths(svc)}
    assert paths == {"/admin"}                 # png/css/js all dropped


def test_visible_endpoints_drops_media_keeps_js_and_api():
    _g, svc = _graph()
    eps = set(_visible_endpoints(svc))
    assert "/app.js" in eps and "/api/v1/users" in eps   # js + api kept
    assert "/banner.jpg" not in eps and "/fonts/x.woff2" not in eps


def _render():
    g, _svc = _graph()
    cfg = Config(targets=["10.0.0.5"])
    md = ReportGenerator(g, ScopeEngine(cfg), cfg).render_markdown()
    html = HTMLReport(g, ScopeEngine(cfg), cfg).render()
    return md, html


def test_media_absent_from_both_reports():
    md, html = _render()
    for blob in (md, html):
        assert "/admin" in blob and "/api/v1/users" in blob   # real content kept
        for media in ("logo.png", "style.css", "banner.jpg", "woff2"):
            assert media not in blob, f"{media} leaked into report"


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()
