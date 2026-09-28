"""Tests for HTTP misconfiguration checks (network mocked).

Covers dangerous methods, TRACE/XST, directory listing, default pages —
NOT cookie flags / CORS / missing headers / CSP / clickjacking (excluded by design).

Run: python -m netassess.tests.test_http_misconfig
"""
from __future__ import annotations

from ..config import Config
from ..models import Host, HTTPService, Port, PortState, Service
from ..probers.http_probe import HTTPProbe
from ..scope import ScopeEngine


def _probe():
    cfg = Config(targets=["127.0.0.1/32"])
    return HTTPProbe(cfg, ScopeEngine(cfg))


def _svc(title=""):
    return HTTPService(url="http://127.0.0.1:80/", ip="127.0.0.1", port=80,
                       scheme="http", title=title)


def _hostport():
    h = Host(ip="127.0.0.1")
    p = Port(80, state=PortState.OPEN, service=Service(name="http"))
    return h, p


def test_directory_listing():
    p = _probe()
    p._request_method = lambda *a: None          # skip method checks
    h, port = _hostport()
    fs = p._misconfig_checks(h, port, _svc("Index of /files"))
    assert any(f.title == "Directory listing enabled" for f in fs)


def test_default_page():
    p = _probe()
    p._request_method = lambda *a: None
    h, port = _hostport()
    fs = p._misconfig_checks(h, port, _svc("Welcome to nginx!"))
    assert any("Default/sample" in f.title for f in fs)


def test_dangerous_methods():
    p = _probe()
    p._request_method = lambda ip, scheme, port, hh, method: (
        (200, {"allow": "GET, POST, PUT, DELETE"}, b"") if method == "OPTIONS"
        else None)
    h, port = _hostport()
    fs = p._misconfig_checks(h, port, _svc("Home"))
    m = [f for f in fs if f.title == "Dangerous HTTP methods enabled"]
    assert m and "PUT" in m[0].evidence


def test_trace_xst():
    p = _probe()
    p._request_method = lambda ip, scheme, port, hh, method: (
        (200, {"content-type": "message/http"}, b"TRACE / HTTP/1.1")
        if method == "TRACE" else None)
    h, port = _hostport()
    fs = p._misconfig_checks(h, port, _svc("Home"))
    assert any("TRACE" in f.title for f in fs)


def test_clean_server_no_findings():
    p = _probe()
    p._request_method = lambda *a: (200, {"allow": "GET, HEAD, POST"}, b"")
    h, port = _hostport()
    fs = p._misconfig_checks(h, port, _svc("My App"))
    assert fs == []          # no dir-listing, no default page, safe methods


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()
