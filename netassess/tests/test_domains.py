"""Tests for consolidated domain/hostname collection.

Run: python -m netassess.tests.test_domains
"""
from __future__ import annotations

from ..domains import all_domains, collect_domains
from ..models import Host, HTTPService, TLSInfo
from ..state import AssetGraph


def test_collects_from_all_sources():
    h = Host(ip="192.0.2.10")
    h.hostnames = ["ptr.example.com"]
    h.tls[443] = TLSInfo(sans=["app.example.com", "api.example.com"],
                         subject="commonName=www.example.com, O=Ex")
    h.http_services.append(HTTPService(
        url="https://vhost.example.com:443/", ip="192.0.2.10", port=443,
        scheme="https", redirect_chain=["301 -> https://redirect.example.com/x"]))
    d = collect_domains(h)
    assert "ptr.example.com" in d and "reverse-dns (PTR)" in d["ptr.example.com"]
    assert "app.example.com" in d and any("SAN" in s for s in d["app.example.com"])
    assert "www.example.com" in d and any("CN" in s for s in d["www.example.com"])
    assert "redirect.example.com" in d and "HTTP redirect" in d["redirect.example.com"]
    assert "vhost.example.com" in d and "virtual host" in d["vhost.example.com"]


def test_excludes_ips_and_self():
    h = Host(ip="192.0.2.10")
    h.hostnames = ["192.0.2.10", "real.example.com"]
    d = collect_domains(h)
    assert "192.0.2.10" not in d
    assert "real.example.com" in d


def test_dedupe_and_case():
    h = Host(ip="192.0.2.10")
    h.hostnames = ["Example.COM"]
    h.tls[443] = TLSInfo(sans=["example.com"])
    d = collect_domains(h)
    assert "example.com" in d and len([k for k in d if k == "example.com"]) == 1
    # merged sources from both PTR and SAN
    assert len(d["example.com"]) == 2


def test_all_domains_global_view():
    g = AssetGraph()
    a = g.get_or_create("192.0.2.10"); a.hostnames = ["shared.example.com"]
    b = g.get_or_create("192.0.2.11"); b.hostnames = ["shared.example.com"]
    a.domains = collect_domains(a)
    b.domains = collect_domains(b)
    rows = all_domains(g)
    shared = [r for r in rows if r[0] == "shared.example.com"][0]
    assert shared[2] == ["192.0.2.10", "192.0.2.11"]   # seen on both IPs


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_all()
