"""Headless-render integration: merging a RenderResult into a service.

The real browser path (Playwright/Chromium) is not exercised here — it is an
optional dependency and a network action. We test the pure, deterministic parts:
the adapter's result model + availability probe, EndpointAnalyzer.ingest_rendered
(endpoints/tech/secret merge), and the engine's _render_service wiring driven by
a fake renderer.

Run: python -m netassess.tests.test_render
"""
from __future__ import annotations

from ..adapters.browser_render import BrowserRenderAdapter, RenderResult
from ..config import Config
from ..endpoints import EndpointAnalyzer
from ..engine import AssessmentEngine
from ..models import Host, HTTPService, Severity
from ..scope import ScopeEngine


def _svc(ip="10.0.0.5", port=80):
    return HTTPService(url=f"http://{ip}:{port}/", ip=ip, port=port, scheme="http")


def test_result_model_and_availability_is_bool():
    r = RenderResult(url="http://x/")
    assert r.endpoints == [] and r.bodies == [] and r.dom == ""
    assert isinstance(BrowserRenderAdapter.available(), bool)


def test_ingest_merges_endpoints_without_dupes():
    scope = ScopeEngine(Config(targets=["10.0.0.5"]))
    ea = EndpointAnalyzer(Config(targets=["10.0.0.5"]), scope)
    svc = _svc()
    svc.endpoints = ["/", "/app.js"]
    rr = RenderResult(url=svc.url,
                      endpoints=["/app.js", "/api/v2/users", "/config.json"])
    ea.ingest_rendered(Host(ip="10.0.0.5"), svc, rr)
    assert "/api/v2/users" in svc.endpoints        # runtime endpoint merged
    assert svc.endpoints.count("/app.js") == 1     # no duplicate


def test_ingest_detects_spa_tech_from_rendered_dom():
    scope = ScopeEngine(Config(targets=["10.0.0.5"]))
    ea = EndpointAnalyzer(Config(targets=["10.0.0.5"]), scope)
    svc = _svc()
    svc.technologies = []
    rr = RenderResult(url=svc.url, dom='<div ng-version="17.1.0">hydrated</div>')
    ea.ingest_rendered(Host(ip="10.0.0.5"), svc, rr)
    assert any(t.name == "Angular" for t in svc.technologies)


def test_ingest_finds_secret_in_rendered_dom_and_runtime_body():
    scope = ScopeEngine(Config(targets=["10.0.0.5"]))
    ea = EndpointAnalyzer(Config(targets=["10.0.0.5"]), scope)
    svc = _svc()
    # secret that only appears after JS builds the DOM / fetches config.json
    rr = RenderResult(
        url=svc.url,
        dom='<script>window.__CFG={k:"AKIAIOSFODNN7EXAMPLE"}</script>',
        bodies=[("http://10.0.0.5/config.json",
                 '{"google":"AIzaSyA1234567890abcdefghijklmnopqrstuv"}')],
    )
    fs = ea.ingest_rendered(Host(ip="10.0.0.5"), svc, rr)
    types = {f.title for f in fs}
    assert any("AWS access key id" in t for t in types)
    assert any("Google API key" in t for t in types)
    assert all(f.severity == Severity.HIGH for f in fs)


class _FakeRender:
    """Stands in for BrowserRenderAdapter: no browser, returns a canned result."""
    def __init__(self, result):
        self._result = result
        self.closed = False

    def render(self, url, ip, port, *, host_header=None):
        return self._result

    def close(self):
        self.closed = True


def test_render_service_adds_rendered_secret_finding():
    cfg = Config(targets=["10.0.0.5"], render=True, show_progress=False)
    eng = AssessmentEngine(cfg)
    host = Host(ip="10.0.0.5")
    svc = _svc()
    rr = RenderResult(url=svc.url,
                      dom='<b>key: AIzaSyA1234567890abcdefghijklmnopqrstuv</b>',
                      endpoints=["/api/live"])
    added = eng._render_service(_FakeRender(rr), host, svc)
    assert added == 1
    assert "/api/live" in svc.endpoints
    assert any("Google API key" in f.title for f in host.findings)


def test_open_renderer_is_none_when_flag_off():
    eng = AssessmentEngine(Config(targets=["10.0.0.5"], show_progress=False))
    assert eng._open_renderer() is None


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()
