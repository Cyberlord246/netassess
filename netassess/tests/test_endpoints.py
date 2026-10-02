"""Tests for endpoint / JS analysis.

Run: python -m netassess.tests.test_endpoints
"""
from __future__ import annotations

from urllib.parse import urlparse

from ..config import Config
from ..endpoints import EndpointAnalyzer
from ..models import HTTPService, Severity


class _Scope:
    def authorize(self, ip, port=None):
        return type("D", (), {"allowed": True})()


_HTML = """
<html><head>
<script src="/static/app.js"></script>
<link href="/css/site.css" rel="stylesheet">
</head><body>
<a href="/admin/login">admin</a>
<a href="/about">about</a>
<a href="https://evil.example.net/off">offsite</a>
<a href="mailto:x@y.z">mail</a>
<script>fetch("/api/v1/users"); var u="/graphql";</script>
</body></html>
"""


def _svc():
    return HTTPService(url="http://10.0.0.5:8080/", ip="10.0.0.5", port=8080,
                       scheme="http")


def test_extract_same_host_only_and_finds_paths():
    an = EndpointAnalyzer(Config(), _Scope())
    svc = _svc()
    eps = an._extract(_HTML, svc, urlparse(svc.url))
    assert "/static/app.js" in eps
    assert "/admin/login" in eps
    assert "/api/v1/users" in eps
    assert "/graphql" in eps
    # off-host and mailto are excluded
    assert not any("evil.example.net" in e for e in eps)
    assert not any(e.startswith("mailto") for e in eps)


def test_finding_flags_sensitive_and_js():
    an = EndpointAnalyzer(Config(), _Scope())
    svc = _svc()
    eps = an._extract(_HTML, svc, urlparse(svc.url))
    f = an.finding_for(svc, eps)
    assert f is not None
    assert f.category == "endpoint-discovery"
    # sensitive paths (admin/api/graphql) present -> LOW, not INFO
    assert f.severity == Severity.LOW
    assert ".js" in f.evidence or "JS file" in f.evidence


def test_no_endpoints_no_finding():
    an = EndpointAnalyzer(Config(), _Scope())
    assert an.finding_for(_svc(), []) is None


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()
