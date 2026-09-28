"""Tests for TLS-SAN virtual-host probing (no network).

Run: python -m netassess.tests.test_vhost
"""
from __future__ import annotations

from ..config import Config
from ..models import Host, HTTPService, TLSInfo
from ..scope import ScopeEngine
from ..vhost import VhostProber


def _prober(targets=("192.0.2.10/32",)):
    cfg = Config(targets=list(targets))
    return VhostProber(cfg, ScopeEngine(cfg))


def _svc(sans=None, subject="", scheme="https", port=443):
    tls = TLSInfo(sans=sans or [], subject=subject)
    return HTTPService(url=f"{scheme}://192.0.2.10:{port}/", ip="192.0.2.10",
                       port=port, scheme=scheme, tls=tls)


def test_candidates_from_sans_and_cn():
    p = _prober()
    h = Host(ip="192.0.2.10")
    svc = _svc(sans=["app.example.com", "api.example.com"],
               subject="commonName=www.example.com, organizationName=Ex")
    cands = set(p._candidates(h, svc))
    assert cands == {"app.example.com", "api.example.com", "www.example.com"}


def test_candidates_skip_wildcards_ips_and_known():
    p = _prober()
    h = Host(ip="192.0.2.10")
    h.hostnames = ["www.example.com"]
    svc = _svc(sans=["*.example.com", "192.0.2.10", "www.example.com",
                     "admin.example.com"])
    cands = p._candidates(h, svc)
    assert cands == ["admin.example.com"]     # wildcard/IP/known filtered out


def test_candidates_dedupe_case():
    p = _prober()
    h = Host(ip="192.0.2.10")
    svc = _svc(sans=["App.Example.com", "app.example.com"])
    assert p._candidates(h, svc) == ["app.example.com"]


def test_differs_status_title_size():
    p = _prober()
    base = {"status": 200, "len": 1000, "title": "Default", "loc": ""}
    assert p._differs(base, {"status": 200, "len": 1000, "title": "Default", "loc": ""}) is False
    assert p._differs(base, {"status": 403, "len": 1000, "title": "Default", "loc": ""}) is True
    assert p._differs(base, {"status": 200, "len": 1000, "title": "Admin", "loc": ""}) is True
    assert p._differs(base, {"status": 200, "len": 5000, "title": "Default", "loc": ""}) is True
    # tiny variance is not a distinct vhost
    assert p._differs(base, {"status": 200, "len": 1010, "title": "Default", "loc": ""}) is False


def test_probe_service_records_distinct_vhost(monkeypatch=None):
    p = _prober()
    h = Host(ip="192.0.2.10")
    svc = _svc(sans=["secret.example.com"])
    # default (IP) response vs the vhost response
    responses = {
        "192.0.2.10": {"status": 200, "len": 500, "title": "It works", "loc": ""},
        "secret.example.com": {"status": 200, "len": 4000, "title": "Admin Console", "loc": ""},
    }
    p._get = lambda ip, port, scheme, host_header, sni=None: responses.get(host_header)
    findings = p.probe_service(h, svc)
    assert len(findings) == 1
    assert "secret.example.com" in findings[0].title
    # a new HTTPService entry was added for the vhost
    assert any(s.url == "https://secret.example.com:443/" for s in h.http_services)


def test_probe_service_scope_denied():
    cfg = Config(targets=["192.0.2.0/30"])
    p = VhostProber(cfg, ScopeEngine(cfg))
    h = Host(ip="203.0.113.9")               # out of scope
    svc = HTTPService(url="https://203.0.113.9/", ip="203.0.113.9", port=443,
                      scheme="https", tls=TLSInfo(sans=["x.example.com"]))
    assert p.probe_service(h, svc) == []


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()
